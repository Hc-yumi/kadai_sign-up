package main

import (
	"fmt"
	"log"
	"net/url"

	_ "crypto/sha256"
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	// **画像で使用↓**//
	"bytes"
	"encoding/base64"
	"image"
	"image/jpeg"
	"text/template"

	"github.com/nfnt/resize"

	//** 画像で使用↑**//
	"github.com/google/uuid"

	_ "database/sql"
	"encoding/gob"
	_ "image/png"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"

	_ "github.com/gin-gonic/contrib/static"
	"github.com/mattn/go-colorable"
	_ "github.com/olahol/go-imageupload"

	_ "encoding/base64"
	"io"
	_ "io/ioutil"
	"os"
	_ "path/filepath"
	_ "strings"
)

// HTMLからリクエスト来た時にGo内でそのデータが受け取れるようにこのStructを用意する。
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

// loginで使用
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

// ******* login機能 Userモデルの宣言********//
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

// *************画像関係*************//
// fileの表示(かえってくるところ)//
func IndexHandler(w http.ResponseWriter, r *http.Request) {
	dir, err := os.Open("images/")
	defer dir.Close()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	allImageNames, err := dir.Readdirnames(-1) // それぞれの画像ファイルの名前を配列に格納
	if err != nil {
		log.Fatalln("No files")
	}
	var decodeAllImages []image.Image
	for _, imageName := range allImageNames { // 全ての画像をデコード、リサイズしてdecodeAllImageseに格納
		file, _ := os.Open("images/" + imageName)
		defer file.Close()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		decodeImage, _, err := image.Decode(file)
		resizedDecodeImage := resize.Resize(300, 0, decodeImage, resize.Lanczos3) // サイズを揃えるために横幅を300に固定
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		decodeAllImages = append(decodeAllImages, resizedDecodeImage)
	}
	writeImageWithTemplate(w, decodeAllImages)
}

// writeImageWithTemplateで画像をエンコード**//
func writeImageWithTemplate(w http.ResponseWriter, decodeAllImages []image.Image) {
	var encordImages []string
	for _, decodeImage := range decodeAllImages {
		buffer := new(bytes.Buffer)
		if err := jpeg.Encode(buffer, decodeImage, nil); err != nil {
			log.Fatalln("Unable to encode image.")
		}
		str := base64.StdEncoding.EncodeToString(buffer.Bytes())
		encordImages = append(encordImages, str)
	}
	data := map[string]interface{}{"Images": encordImages}
	renderTemplate(w, data)
}

// renderTemplateで渡された画像をテンプレートエンジンに渡す。
func renderTemplate(w http.ResponseWriter, data interface{}) {
	var templates = template.Must(template.ParseFiles("temp/show.html"))
	if err := templates.ExecuteTemplate(w, "show.html", data); err != nil {
		log.Fatalln("Unable to execute template.")
	}

	// location := url.URL{Path: "/showpage"}
	// c.Redirect(http.StatusFound, location.RequestURI())
}

func main() {
	// まずはデータベースに接続する。(パスワードは各々異なる)
	dsn := "host=localhost user=postgres password=Hach8686 dbname=test port=5432 sslmode=disable TimeZone=Asia/Tokyo"
	conn, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		// エラーでたらプロセス終了
		log.Fatalf("Some error occured. Err: %s", err)
	}

	/*
	 * APIサーバーの設定をする。
	 * rはrouterの略で何のAPIを用意するかを定義する。
	 * postpage　GET、/showpage　GET、/user　POST
	 */

	// カラーテーブル？
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

	authRouter := r.Group("/user", auth)

	r.GET("/", indexHandler)
	r.GET("/login", loginGEThandler)
	r.POST("/login", loginPOSThandler)

	authRouter.GET("/profile", profileHandler)

	// ************login 機能終了***********************//

	// POST用のページ（post.html）を返す。
	// c.HTMLというのはこのAPIのレスポンスとしてHTMLファイルを返すよ、という意味
	r.GET("/postpage", func(c *gin.Context) {
		c.HTML(http.StatusOK, "post.html", gin.H{})
	})

	//******** 画像アップロード********//
	// r.POST("/upload", func(c *gin.Context) {
	//   // 画像の保存
	//   image, _, _ := c.Request.FormFile("image")
	//   // saveFile, _ := os.Create("./images/sample.jpeg")
	// 	saveFile, _ := os.Create("./images/" + header.Filename)
	//   defer saveFile.Close()
	//   io.Copy(saveFile, image)

	// 	location := url.URL{Path: "/showpage"}
	// 	c.Redirect(http.StatusFound, location.RequestURI())
	// })
	//******** 画像アップロードおわり********//

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

		// for idx := range records {
		// 	// records[idx].ImageURL = "/images/sample.jpeg"
		// 	records[idx].ImageURL = ""
		// }

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
		saveFile, _ := os.Create("."+filePath)
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
		// image, _, _ := c.Request.FormFile("image")
		// filePath := "./images/" + uuid.New().String() + ".jpeg"
		// saveFile, _ := os.Create(filePath)
		// defer saveFile.Close()
		// io.Copy(saveFile, image)

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
		// fmt.Println("id is ", id)
		// var book BookmarkJson
		// if err := c.ShouldBind(&book); err != nil {
		// 	fmt.Print(err.Error())
		// 	c.JSON(http.StatusBadRequest, gin.H{"error": "invalid argument"})
		// 	return
		// }

		var record Record
		image, _, _ := c.Request.FormFile("image")
		filePath := "/images/" + uuid.New().String() + ".jpeg"
		saveFile, _ := os.Create("."+filePath)
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
			"Selects": records[0],
			"UpdateURL":"http://localhost:8080/bookupdate/image/"+id,
		})
	})

	// サーバーを立ち上げた瞬間は一旦ここまで実行されてListening状態となる。
	// r.POST( や　r.GET(　等の関数はAPIが呼ばれる度に実行される。
	// http.HandleFunc("/", IndexHandlerr)
	// http.ListenAndServe(":8080", nil)
	r.Static("/images", "./images")
	fmt.Println("server is up")

	r.Run()

}
