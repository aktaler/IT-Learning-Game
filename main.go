package main

//TODO implement Session Cookie Authentication when calling to /signin
import (
	"database/sql"
	"log"
	"net/http"
	"time"
)

// database connection object
var db *sql.DB

// Periodic cleanup interval
const cleanupInterval = 5 * time.Minute

func main() {
	initDB()
	go cleanupExpiredSessions()

	// This allows sending back static resources like the index.css located in the static folder
	http.Handle("/static/",
		http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	http.HandleFunc("/", LandingPage)
	http.HandleFunc("/signup/*", HandlerSignup)
	http.HandleFunc("/login/*", HandlerLogin)
	http.HandleFunc("/logout/", Logout)

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

// Function to remove expired sessions
func cleanupExpiredSessions() {
	defer mu.Unlock() // Ensure the mutex is always unlocked
	for {
		time.Sleep(cleanupInterval)
		mu.Lock()
		now := time.Now()
		for key, sess := range sessions {
			if now.After(sess.expiry) {
				delete(sessions, key)
			}
		}
		mu.Unlock()
	}
}
