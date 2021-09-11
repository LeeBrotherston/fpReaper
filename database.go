package main

import (
	"database/sql"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

// Created without timezone as we're going to convert to UTC before storage
// in the database.  This also makes the field immutable which is way better
// for indexing
const sqlCreateFingerprintDB = `
        /* Create the table */
        CREATE TABLE IF NOT EXISTS fingerprints (
			injesttime TIMESTAMP DEFAULT NOW(),
			ip varchar(48),
		);
        `

const sqlCreateWebConnect = `
		CREATE TABLE IF NOT EXISTS www (
			injesttime TIMESTAMP DEFAULT NOW(),
			ip varchar(48),
			useragent text,
		);

		CREATE INDEX IF NOT EXISTS idx_ip ON www (ip);
`

// Prepared statement for inserting into the events table
// This is intended to make inserts pretty consistent and not particularly subject to
// problems arising from input sanitization
const sqlInsertLoginHistory = `
        /* Create the table */
        INSERT INTO events (
			client,
			clientip,
			injesttime,
			timestamp,
			username,
			userhash,
			ip,
			authsuccess,
			failtype,
		)
          VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?
		  );
		  `

const sqlInsertWebConnect = `
		INSERT INTO www (
			ip,
			useragent
		)
		VALUES (?, ?);
`

// setupDB sets up.... the DB
// More specifically it's connects to it, and initializes it if it
// does not appear to have been already
func setupDB() *sql.DB {
	fileName := "sparkly.sqlite"
	db, rowcount := connectDB(fileName)
	log.Printf("Database init row count: %v\n", rowcount)
	if db == nil {
		panic("Exiting, no database")
	}

	return db
}

// connectDB connects to the DB type defined in the connString
// this allows us to save locally or to a remote pgsql server
func connectDB(fileName string) (*sql.DB, int64) {

	// Make the connection object
	db, err := sql.Open("sqlite3", fileName)
	if err != nil {
		log.Printf("Connection to db failed: %s", err)
		return nil, 0
	}
	log.Printf("Good connect string for db")

	// Check that a connection can be established
	err = db.Ping()
	if err != nil {
		log.Printf("Connection to db could not be established: %s\n", err)
		return nil, 0
	}
	log.Printf("Connected to db")

	// Create the relevant tables if they do not exist, this check is
	// in the SQL logic
	retval, retBool := sqlSingleShot(db, sqlCreateFingerprintDB)
	if retBool == true {
		retval, retBool = sqlSingleShot(db, sqlCreateFingerprintDB)
		if retBool == true {
			return db, retval
		}
	}

	return nil, 0

}

// sqlSingleShot is for sql commands that do not return rows (such as a select), rather
// just require confirmation of completion.
func sqlSingleShot(db *sql.DB, query string, args ...interface{}) (int64, bool) {

	result, err := db.Exec(query, args...)

	if err != nil {
		log.Printf("Error running database query: %s", err)
		return 0, false
	}

	rowCount, err := result.RowsAffected()

	if err != nil {
		log.Printf("Error in sqlSingleShot: %s", err)
	}

	return rowCount, true

}

// insertEvent takes a struct of type Event and inserts into the provided DB
// it returns the row count of inserts
/* func insertEvent(db *sql.DB, event Event) int64 {
	rows, success := sqlSingleShot(db, sqlInsertLoginHistory,
		event.client,
		event.clientip,
		event.injestTime,
		event.Timestamp,
		event.User,
		event.UserHash,
		event.IP,
		event.AuthSuccess,
		event.FailType)

	if success == true {
		return rows
	}

	return 0
}
*/
