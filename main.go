package main

import (
	"fmt"
	"log"
	"net/http"
	"net/url"

	"example.com/crypto"
	"github.com/gin-gonic/gin"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"encoding/gob"
	//**signup**//

	_ "github.com/jinzhu/gorm"
	_ "github.com/joho/godotenv"
	_ "github.com/joho/godotenv/autoload"

	//**login & signup**//
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"github.com/mattn/go-colorable"
	"golang.org/x/crypto/bcrypt"

	"io"
	"os"
)

// HTMLからリクエスト来た時にGo内でそのデータが受け取れるようにこのStructを用意する。
// **login**//
type LoginUser struct {
	Name string
	Hash string
}

// HTMLからリクエスト来た時にGo内でそのデータが受け取れるようにこのStructを用意する。
type Bookmark struct {
	Name    string `form:"bookName"`
	URL     string `form:"bookUrl"`
	Comment string `form:"bookcomment"`
}

type BookmarkJson struct {
	Name    string `json:"bookname"`
	URL     string `json:"URL"`
	Comment string `json:"Comment"`
}

type Record struct {
	ID       int
	Bookname string
	URL      string
	Comment  string
	Time     string
	ImageURL string
}

// loginで使用?
type User struct {
	ID        string
	Username  string
	Email     string
	pswdHash  string
	CreatedAt string
	Active    string
	verHash   string
	timeout   string
}

// **sign upで使用  Users モデルの宣言**//
type Users struct {
	gorm.Model
	Username string `form:"username" binding:"required" gorm:"unique;not null"`
	Password string `form:"password" binding:"required"`
}

type UsersRecord struct {
	Username string
	passwordEncrypt string
}

// // **sign up ユーザー登録処理**//
// func gormConnect() *gorm.DB {
// 	err := godotenv.Load()
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	DBMS := os.Getenv("mytweet_DBMS")
// 	USER := os.Getenv("mytweet_USER")
// 	PASS := os.Getenv("mytweet_PASS")
// 	DBNAME := os.Getenv("mytweet_DBNAME")
// 	CONNECT := USER + ":" + PASS + "@/" + DBNAME + "?parseTime=true"
// 	db, err := gorm.Open(DBMS, CONNECT)
// 	if err != nil {
// 		panic(err.Error())
// 	}
// 	return db
// }

// ******signup機能関数*****//

// ユーザー登録処理
func createUser(username string, password string) error {
	passwordEncrypt, _ := crypto.PasswordEncrypt(password)
	// // Insert処理
	// if err := db.Create(&User{Username: username, Password: passwordEncrypt}).GetErrors(); err != nil {
	// 	return err
	// }
	// return nil

	var form LoginUser
	// flag, _ := getUserByUsername(form.name)
	// if flag != false {
	// 	fmt.Println("error 既に登録済み")
	// 	return err
	// }


	dbc := conn.Raw(
		"insert into users(name,password) values(?, ?)",
		username, passwordEncrypt).Scan(&form)
	if dbc.Error != nil {
		fmt.Print(dbc.Error)
		return dbc.Error
	}

	return nil
}

// ******signup機能関数おわり*****//

// ******* login機能関数 ********//
var conn *gorm.DB
var err error

var store = sessions.NewCookieStore([]byte("super-secret"))

// cookie情報の漏洩対策 HttpOnly属性
func init() {
	store.Options.HttpOnly = true // since we are not accessing any cookies w/ JavaScript, set to true
	store.Options.Secure = true   // requires secuire HTTPS connection
	gob.Register(&User{})
}

// auth middleware
func auth(c *gin.Context) {
	fmt.Println("auth middleware running")
	session, _ := store.Get(c.Request, "session")
	fmt.Println("session:", session)
	_, ok := session.Values["user"]
	if !ok {
		c.HTML(http.StatusForbidden, "login.html", nil)
		c.Abort()
		return
	}
	fmt.Println("middleware done")
	c.Next()
}

// index page
func indexHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", nil)
}

// loginGEThandler displays form for login
func loginGEThandler(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", nil)
}

// loginPOSThandler verifies login credentials
func loginPOSThandler(c *gin.Context) {
	// var user User
	var user User
	user.Username = c.PostForm("username")
	password := c.PostForm("password")
	flag, hash := getUserByUsername(c, user.Username)
	if flag != true {
		fmt.Println("error selecting pswd_hash in db by Username")
		c.HTML(http.StatusUnauthorized, "login.html", gin.H{"message": "check username and password"})
		return
	}
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		fmt.Println("err from bycrypt:", err)
		c.HTML(http.StatusUnauthorized, "login.html", gin.H{"message": "check username and password"})
		return
	}
	session, _ := store.Get(c.Request, "session")
	// session struct has field Values map[interface{}]interface{}
	session.Values["user"] = user
	// save before writing to response/return from handler
	session.Save(c.Request, c.Writer)
	c.HTML(http.StatusOK, "loggedin.html", gin.H{"username": user.Username})
	return
}

// profileHandler displays profile information
func profileHandler(c *gin.Context) {
	session, _ := store.Get(c.Request, "session")
	var user = &User{}
	val := session.Values["user"]
	var ok bool
	if user, ok = val.(*User); !ok {
		fmt.Println("was not of type *User")
		c.HTML(http.StatusForbidden, "login.html", nil)
		return
	}
	c.HTML(http.StatusOK, "profile.html", gin.H{"user": user})
}

func getUserByUsername(c *gin.Context, name string) (bool, string) {
	var records []LoginUser
	dbc := conn.Raw("SELECT * FROM users WHERE name = ?", name).Scan(&records)

	if dbc.Error != nil {
		fmt.Print(dbc.Error)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return false, ""
	}

	if len(records) == 0 {
		// no user data
		return false, ""
	}
	return true, records[0].Hash
}

//*****login機能関数おわり*****//

func main() {
	// まずはデータベースに接続する。(パスワードは各々異なる)
	dsn := "host=localhost user=postgres password=Hach8686 dbname=test port=5432 sslmode=disable TimeZone=Asia/Tokyo"
	conn, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		// エラーでたらプロセス終了
		log.Fatalf("Some error occured. Err: %s", err)
	}

	gin.DefaultWriter = colorable.NewColorableStdout()
	r := gin.Default()
	// ginに対して、使うHTMLのテンプレートがどこに置いてあるかを知らせる。
	r.LoadHTMLGlob("temp/*")

	// 用意していないエンドポイント以外を叩かれたら内部で/showpage　GETを叩いてデフォルトページを表示する様にする。
	r.NoRoute(func(c *gin.Context) {
		location := url.URL{Path: "/showpage"}
		c.Redirect(http.StatusFound, location.RequestURI())
	})

	r.LoadHTMLGlob("temp/*.html")

	if err != nil {
		panic(err.Error())
	}

	//**signup**//

	// ユーザー登録画面 //
	r.GET("/signup", func(c *gin.Context) {
		c.HTML(200, "signup.html", gin.H{})
		// var form []UsersRecord
		// dbc := conn.Raw("SELECT name,password FROM users").Scan(&form)
		// if dbc.Error != nil {
		// 	fmt.Print(dbc.Error)
		// 	c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		// 	return
		// }

		// c.HTML(http.StatusOK, "signup.html", gin.H{
		// 	"Users": form,
		// })
	})

	// ユーザー登録
	r.POST("/signup", func(c *gin.Context) {
		var form Users
		// バリデーション処理
		if err := c.Bind(&form); err != nil {
			fmt.Print(err.Error())
			c.HTML(http.StatusBadRequest, "signup.html", gin.H{"err": err})
			c.Abort()
		} else {
			username := c.PostForm("username")
			password := c.PostForm("password")
			// 登録ユーザーが重複していた場合にはじく処理
			if err := createUser(username, password); err != nil {

				c.HTML(http.StatusBadRequest, "signup.html", gin.H{"message": "username is already registerd"})
				return

				// c.HTML(http.StatusBadRequest, "signup.html", gin.H{"err": err})
			}
			c.Redirect(302, "/")
		}

		location := url.URL{Path: "/postpage"}
		c.Redirect(http.StatusFound, location.RequestURI())

	})

	// 入れるならelseの上//
	// dbc := conn.Raw(
	// 	"insert into users(name,password) values(?, ?)",
	// 	form.Username, form.Password).Scan(&form)
	// if dbc.Error != nil {
	// 	fmt.Print(dbc.Error)
	// 	c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
	// 	return
	// }

	//*****sign upおわり*****//

	//****login機能はじめ*****//
	authRouter := r.Group("/user", auth)

	r.GET("/", indexHandler)
	r.GET("/login", loginGEThandler)
	r.POST("/login", loginPOSThandler)

	authRouter.GET("/profile", profileHandler)

	// ****login 機能終了******//

	// POST用のページ（post.html）を返す。
	// c.HTMLというのはこのAPIのレスポンスとしてHTMLファイルを返すよ、という意味
	r.GET("/postpage", func(c *gin.Context) {
		c.HTML(http.StatusOK, "post.html", gin.H{})
	})

	// 結果を表示するページを返す。
	r.GET("/showpage", func(c *gin.Context) {

		session, _ := store.Get(c.Request, "session")
		// var usertruct = &User{}
		val := session.Values["user"]
		var ok bool
		if _, ok = val.(*User); !ok {
			fmt.Println("was not of type *User")
			c.HTML(http.StatusForbidden, "login.html", nil)
			return
		}

		var records []Record
		// &recordsをDBに渡して、取得したデータを割り付ける。
		dbc := conn.Raw("SELECT id, image_url, bookname,url,comment,to_char(time,'YYYY-MM-DD HH24:MI:SS') AS time FROM booklist ORDER BY id").Scan(&records)
		if dbc.Error != nil {
			fmt.Print(dbc.Error)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}

		c.HTML(http.StatusOK, "show.html", gin.H{
			"Books": records,
		})
	})

	// データを登録するAPI。POST用のページ（post.html）の内部で送信ボタンを押すと呼ばれるAPI。
	r.POST("/book", func(c *gin.Context) {

		var book Bookmark
		if err := c.ShouldBind(&book); err != nil {
			fmt.Print(err.Error())
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid argument"})
			return
		}

		var record Record
		image, _, _ := c.Request.FormFile("image")
		filePath := "/images/" + uuid.New().String() + ".jpeg"
		saveFile, _ := os.Create("." + filePath)
		defer saveFile.Close()
		io.Copy(saveFile, image)

		// 以下の様にしてInsert文を書いて、リクエストデータをDBに書きこむ。.Scan(&record)はDBに書き込む際に必要らしい。
		// recordはbooklistテーブルと構造を同じにしている。(Gormのお作法)
		dbc := conn.Raw(
			"insert into booklist(Image_url,bookname, url, comment) values(?, ?, ?, ?)",
			filePath, book.Name, book.URL, book.Comment).Scan(&record)
		if dbc.Error != nil {
			fmt.Print(dbc.Error)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}

		// DBへの保存が成功したら結果を表示するページに戻るために/showpageのAPIを内部で読んでそちらでページの表示を行う。
		location := url.URL{Path: "/showpage"}
		c.Redirect(http.StatusFound, location.RequestURI())
	})

	// PUT 内容のupdate
	r.PUT("/bookupdate/:id", func(c *gin.Context) {
		id := c.Param("id")
		var book BookmarkJson
		if err := c.ShouldBind(&book); err != nil {
			fmt.Print(err.Error())
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid argument"})
			return
		}

		var record Record
		dbc := conn.Raw(
			"UPDATE booklist SET bookname=?, url=?, comment=? where id=?",
			book.Name, book.URL, book.Comment, id).Scan(&record)
		if dbc.Error != nil {
			fmt.Print(dbc.Error)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}
	})

	//*** PUT (画像のUpdate)****//
	r.POST("/bookupdate/image/:id", func(c *gin.Context) {
		id := c.Param("id")

		var record Record
		image, _, _ := c.Request.FormFile("image")
		filePath := "/images/" + uuid.New().String() + ".jpeg"
		saveFile, _ := os.Create("." + filePath)
		defer saveFile.Close()
		io.Copy(saveFile, image)

		dbc := conn.Raw(
			"UPDATE booklist SET image_url=? where id=?",
			filePath, id).Scan(&record)
		if dbc.Error != nil {
			fmt.Print(dbc.Error)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}

		location := url.URL{Path: "/showpage"}
		c.Redirect(http.StatusFound, location.RequestURI())

	})

	// データの削除
	r.DELETE("/book/:id", func(c *gin.Context) {
		id := c.Param("id")
		fmt.Println("id is ", id)
		var records []Record
		dbc := conn.Raw("DELETE FROM booklist where id=?", id).Scan(&records)

		if dbc.Error != nil {
			fmt.Print(dbc.Error)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}
	})

	// showpageで書籍名をinputしてボタン押したら→入力した書籍名とおなじ列をdeleteする
	r.DELETE("/book/select/:bookname", func(c *gin.Context) {
		bookname := c.Param("bookname")
		fmt.Println("bookname is ", bookname)

		// レコードが存在するか確認。
		var record Record
		dbc := conn.Raw("SELECT * FROM booklist where bookname=?", bookname).Scan(&record)
		if dbc.Error != nil {
			fmt.Print(dbc.Error)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}
		// レコードがなければNotFoundエラーを返す
		if dbc.RowsAffected == 0 {
			c.JSON(http.StatusNotFound, gin.H{})
			return
		}

		var records []Record
		dbc = conn.Raw("DELETE FROM booklist where bookname=?", bookname).Scan(&records)

		if dbc.Error != nil {
			fmt.Print(dbc.Error)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}
		c.JSON(http.StatusNoContent, gin.H{})
	})

	// GET APIでid(ここを押せるようにする)を押すと、そのデータだけが表示されたページに遷移する
	// 結果を表示するページを返す。

	r.GET("/book/transition/:id", func(c *gin.Context) {
		id := c.Param("id")
		fmt.Println("id is ", id)
		// c.HTML(http.StatusOK, "select.html", gin.H{"id": id})
		var records []Record
		dbc := conn.Raw("SELECT id,image_url,bookname,url,comment,to_char(time,'YYYY-MM-DD HH24:MI:SS') AS time FROM booklist where id=?", id).Scan(&records)

		if dbc.Error != nil {
			fmt.Print(dbc.Error)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}

		c.HTML(http.StatusOK, "select.html", gin.H{
			"Selects":   records[0],
			"UpdateURL": "http://localhost:8080/bookupdate/image/" + id,
		})
	})

	r.Static("/images", "./images")
	fmt.Println("server is up")

	r.Run()

}
