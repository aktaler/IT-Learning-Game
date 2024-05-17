package main

//TODO implement Session Cookie Authentication when calling to /signin
//TODO implement Logout, /signout
//TODO implement TailwindCSS
import (
	"database/sql"
	"encoding/json"
	"html/template"
	"log"
	"net/http"

	"github.com/lib/pq"
	_ "github.com/lib/pq"

	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

// Create a struct that models the structure of a user, both in the request body, and in the DB
type Credentials struct {
	Username string `json:"username" db:"username"`
	Password string `json:"password" db:"password"`
}

type Viewdata struct {
	Loggedin bool
	ID       string
	Title    string
	Content  string
}

func main() {
	initDB()

	// This allows sending back static resources like the index.css located in the static folder
	http.Handle("/static/",
		http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	http.HandleFunc("/", LandingPage)
	http.HandleFunc("/signup/*", HandlerSignup)
	http.HandleFunc("/login/*", HandlerLogin)

	// initialize our database connection
	// start the server on port 8000
	log.Println("App running on 8000...")
	log.Fatal(http.ListenAndServe(":8000", nil))
}

func initDB() {
	var err error
	// Connect to the postgres db
	//you might have to change the connection string to add your database credentials
	db, err = sql.Open("postgres", "user=learninggame password=1234 dbname=learninggame sslmode=disable")
	if err != nil {
		log.Fatal(err)
		panic(err)
	}
}

func LandingPage(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)

	data := Viewdata{
		Loggedin: false,
	}

	tmpl := template.Must(template.ParseFiles("./templates/index.html", "./templates/fragments/user_details.html"))

	log.Println(data)

	tmpl.Execute(w, data)

}

func HandlerSignup(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	log.Println("Requestroute: " + r.URL.Path)
	subroute := r.URL.Path[len("/signup/"):]
	switch subroute {
	case "tile":
		data := Viewdata{
			ID: "signupView",
		}
		tmpl := template.Must(template.ParseFiles("./templates/fragments/tiles.html"))
		tmpl.Execute(w, data)
	case "signup":
		Signup(w, r)
	default:

	}
}

func Signup(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	switch r.Method {

	case "OPTIONS":
		w.WriteHeader(http.StatusOK)
		return

	case "POST":

		creds := &Credentials{}
		log.Println("Signup Content Type Header: " + r.Header.Get("Content-Type"))

		switch r.Header.Get("Content-Type") {

		case "application/x-www-form-urlencoded":
			// Parse form content into the struct
			r.ParseForm()

			creds.Username = r.Form.Get("username")
			creds.Password = r.Form.Get("password")

		case "application/json":
			// Parse JSON content into the struct
			err := json.NewDecoder(r.Body).Decode(creds)
			if err != nil {
				// If there is something wrong with the request body, return a 415 status
				log.Println(err)
				http.Error(w, "JSON decoding error:"+err.Error(), http.StatusUnsupportedMediaType)
				return
			}

		default:
			// Unsupported content type
			http.Error(w, "Unsupported Content-Type", http.StatusUnsupportedMediaType)
			return
		}

		// Salt and hash the password using the bcrypt algorithm
		// The second argument is the cost of hashing, which we arbitrarily set as 8 (this value can be more or less, depending on the computing power you wish to utilize)
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(creds.Password), 8)
		if err != nil {
			log.Println(err)
			http.Error(w, "Error hashing password", http.StatusInternalServerError)
			return
		}

		// Next, insert the username, along with the hashed password into the database
		_, err = db.Query("insert into users values ($1, $2)", creds.Username, string(hashedPassword))
		if err != nil {
			log.Printf("Error while inserting into database: %v\n", err)
			// assert type of err to be able to access pq.Error specific fields
			if pqErr, ok := err.(*pq.Error); ok {
				switch pqErr.Code.Name() {
				case "unique_violation":
					data := Viewdata{
						ID:      "infoView",
						Title:   "Error!",
						Content: "Username already exists. Please try again.",
					}
					tmpl := template.Must(template.ParseFiles("./templates/fragments/tiles.html"))
					tmpl.Execute(w, data)
					return
				}
			}
			// If there is any issue with inserting into the database, return a 500 error

			w.WriteHeader(http.StatusInternalServerError)
			log.Println(err)
			return
		}
		// We reach this point if the credentials we correctly stored in the database, and the default status of 200 is sent back along with a message
		data := Viewdata{
			ID:      "infoView",
			Title:   "Success!",
			Content: "Your account has been created. You can now log in.",
		}

		tmpl := template.Must(template.ParseFiles("./templates/fragments/tiles.html"))
		tmpl.Execute(w, data)
	}

}

func HandlerLogin(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	log.Println("Requestroute: " + r.URL.Path)
	subroute := r.URL.Path[len("/login/"):]

	switch subroute {
	case "tile":
		//TODO implement tile
		data := Viewdata{
			ID: "loginView",
		}

		tmpl := template.Must(template.ParseFiles("./templates/fragments/tiles.html"))
		tmpl.Execute(w, data)
	case "login":
		Login(w, r)
		return
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}
func Login(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	switch r.Method {
	case "OPTIONS":
		w.WriteHeader(http.StatusOK)
		return
	}
	// Parse and decode the request body into a new `Credentials` instance
	creds := &Credentials{}
	err := json.NewDecoder(r.Body).Decode(creds)
	if err != nil {
		// If there is something wrong with the request body, return a 400 status
		w.WriteHeader(http.StatusBadRequest)
		log.Println(err)
		return
	}
	// Get the existing entry present in the database for the given username
	result := db.QueryRow("select password from users where username=$1", creds.Username)

	// We create another instance of `Credentials` to store the credentials we get from the database
	storedCreds := &Credentials{}
	// Store the obtained password in `storedCreds`
	err = result.Scan(&storedCreds.Password)

	if err != nil {
		// If an entry with the username does not exist, send an "Unauthorized"(401) status
		if err == sql.ErrNoRows {
			w.WriteHeader(http.StatusUnauthorized)
			log.Println(err)
			return
		}
		// If the error is of any other type, send a 500 status
		w.WriteHeader(http.StatusInternalServerError)
		log.Println(err)
		return
	}

	// Compare the stored hashed password, with the hashed version of the password that was received
	err = bcrypt.CompareHashAndPassword([]byte(storedCreds.Password), []byte(creds.Password))
	if err != nil {
		// If the two passwords don't match, return a 401 status
		w.WriteHeader(http.StatusUnauthorized)
		log.Println(err)
	}

	// If we reach this point, that means the users password was correct, and that they are authorized
	// The default 200 status is sent
}

func enableCors(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
	(*w).Header().Set("Access-Control-Allow-Methods", "POST")         // Allowed methods
	(*w).Header().Set("Access-Control-Allow-Headers", "Content-Type") // Allow Content-Type header
}
