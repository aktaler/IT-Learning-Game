package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

// Create a struct that models the structure of a user, both in the request body, and in the DB
type Credentials struct {
	Username string `json:"username" db:"username"`
	Password string `json:"password" db:"password"`
}

// Scruct for filling html templates
type Viewdata struct {
	Loggedin     bool
	Username     string
	OobAttribute template.HTMLAttr
	ID           string
	Title        string
	Content      string
}

type session struct {
	username string
	expiry   time.Time
}

var sessions = map[string]session{}
var mu sync.Mutex

func (s session) isExpired() bool {
	return s.expiry.Before(time.Now())
}

// get the values of a session obj from the global sessions map
func getSessionFromMap(sessionToken string) (session, error) {
	mu.Lock()
	defer mu.Unlock()

	session, exists := sessions[sessionToken]
	if !exists {
		return session, errors.New("session token not present in session map")
	}

	return session, nil
}

// set the values of a session obj in the global sessions map
func setSessionInMap(sessionToken string, userSession session) {
	mu.Lock()
	defer mu.Unlock()

	sessions[sessionToken] = userSession
}

// Delete a session from the global sessions map
func deleteSessionFromMap(sessionToken string) {
	mu.Lock()
	defer mu.Unlock()

	delete(sessions, sessionToken)
}

// Trys to retrieve a session from the session map based on a given http.Request Cookie.
// Also refreshes the cookie in the http response.
func getSessionFromCookie(w http.ResponseWriter, r *http.Request) (session, error) {

	c, err := r.Cookie("session_token")
	if err != nil {
		// If the cookie is not set
		return session{}, err
	}

	// Get the JWT string from the cookie
	tokenString := c.Value

	// Get the session from the map
	userSession, err := getSessionFromMap(tokenString)
	if err != nil {
		return session{}, err
	}

	// If the session is present, but has expired, we can delete the session
	if userSession.isExpired() {
		deleteSessionFromMap(tokenString)
		return session{}, errors.New("session has expired")
	}

	// at this point, the session is valid, refresh it inside the map
	userSession.expiry = getNewExpiryTime()
	setSessionInMap(tokenString, userSession)
	// and refresh the cookie, tokenValue remains the same
	// TODO maybe move this action out of this func
	http.SetCookie(w, &http.Cookie{
		Name:    "session_token",
		Value:   tokenString,
		Expires: userSession.expiry,
	})

	return userSession, nil
}

func deleteSessionFromCookie(r *http.Request) error {
	c, err := r.Cookie("session_token")
	if err != nil {
		return err
	}

	// Get the JWT string from the cookie
	tokenString := c.Value

	deleteSessionFromMap(tokenString)
	return nil
}

// returns a fresh expiry time
func getNewExpiryTime() time.Time {
	return time.Now().Add(10 * time.Second)
}

func LandingPage(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	zeroSession := session{}
	session, err := getSessionFromCookie(w, r)

	if err != nil {
		log.Println(err)
	}

	data := Viewdata{}
	if session == zeroSession {
		data.Loggedin = false
	} else {
		data.Loggedin = true
		data.Username = session.username
	}

	log.Println("Loggedin: " + strconv.FormatBool(data.Loggedin))

	tmpl := template.Must(template.ParseFiles("./templates/index.html", "./templates/fragments/user_details.html"))

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
	switch r.Method {

	case "OPTIONS":
		w.WriteHeader(http.StatusOK)
		return

	case "POST":
		// initialize a Credentials struct with its values to be zero and the variable "creds" holds the pointer
		creds := &Credentials{}
		log.Println("Login Content Type Header: " + r.Header.Get("Content-Type"))

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

		// Get the existing entry present in the database for the given username
		result := db.QueryRow("select password from users where username=$1", creds.Username)

		// We create another instance of `Credentials` to store the credentials we get from the database
		storedCreds := &Credentials{}
		// Store the obtained password in `storedCreds`
		err := result.Scan(&storedCreds.Password)

		if err != nil {
			// If an entry with the username does not exist, send an "Unauthorized"(401) status
			if err == sql.ErrNoRows {
				log.Println(err)

				// add hx-reswap header
				w.Header().Add("HX-Reswap", "beforeend")
				w.WriteHeader(http.StatusUnauthorized)

				tmpl := template.Must(template.ParseFiles("./templates/fragments/tiles.html"))
				tmpl.Execute(w, Viewdata{
					ID:      "infoView",
					Title:   "Error!",
					Content: "Username does not exist. Please try again.",
				})
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
			return
		}
		// If we reach this point, that means the users password was correct, and that they are authorized
		// The default 200 status is sent
		var combinedOutput bytes.Buffer

		tmpl := template.Must(template.ParseFiles("./templates/fragments/tiles.html"))

		// Write desired html templates to a byte buffer
		tmpl.Execute(&combinedOutput, Viewdata{
			ID:      "accountView",
			Title:   "DummyTitle!",
			Content: "DummyContent!",
		})

		tmpl.Execute(&combinedOutput, Viewdata{
			ID:      "infoView",
			Title:   "Success!",
			Content: "You are now logged in.",
		})

		tmpl = template.Must(template.ParseFiles("./templates/fragments/user_details.html"))

		tmpl.ExecuteTemplate(&combinedOutput, "user_details", Viewdata{
			Loggedin:     true,
			Username:     creds.Username,
			OobAttribute: "hx-swap-oob=#user_details",
		})

		// create the session cookie, safe it inside the sessions map and write it to the http response header
		sessionToken := uuid.New().String()
		expiresAt := getNewExpiryTime()

		session := session{
			username: creds.Username,
			expiry:   expiresAt,
		}

		setSessionInMap(sessionToken, session)

		http.SetCookie(w, &http.Cookie{
			Name:    "session_token",
			Path:    "/",
			Value:   sessionToken,
			Expires: expiresAt,
		})
		// Write combinedOutput to the response Writer
		w.Write(combinedOutput.Bytes())
		return
	}
}
func Logout(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	err := deleteSessionFromCookie(r)
	if err != nil {
		log.Println(err)
		if err == http.ErrNoCookie {
			// send the user back to the landing page if no cookie is found.
			// expired cookies are not send from browser clients back to servers
			log.Println("redirect to landing page")
			tmpl := template.Must(template.ParseFiles("./templates/index.html", "./templates/fragments/user_details.html"))
			tmpl.Execute(w, Viewdata{
				Loggedin: false,
			})
			return
		}

		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// at this point, requesting session token was valid and session was found in the map and deleted
	// We need to let the client know that the cookie is expired
	// In the response, we set the session token to an empty
	// value and set its expiry as the current time
	http.SetCookie(w, &http.Cookie{
		Name:    "session_token",
		Value:   "",
		Expires: time.Now(),
	})
	log.Println("Logout Successful!")

	tmpl := template.Must(template.ParseFiles("./templates/index.html", "./templates/fragments/user_details.html"))

	tmpl.Execute(w, Viewdata{
		Loggedin: false,
	})

}
func enableCors(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
	(*w).Header().Set("Access-Control-Allow-Methods", "POST")         // Allowed methods
	(*w).Header().Set("Access-Control-Allow-Headers", "Content-Type") // Allow Content-Type header
}
