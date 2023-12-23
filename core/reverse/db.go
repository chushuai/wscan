/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package reverse

import (
	"fmt"
	"go.etcd.io/bbolt"
	"sync"
	"time"
)

type DB struct {
	sync.Mutex
	path     string
	isTempDB bool
	*bbolt.DB
}

// Open opens the database at the specified path.
func (db *DB) Open(path string) error {
	db.Lock()
	defer db.Unlock()

	if db.DB != nil {
		return fmt.Errorf("database is already open")
	}

	bboltDB, err := bbolt.Open(path, 0600, &bbolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return err
	}

	db.path = path
	db.DB = bboltDB
	return nil
}

// Close closes the database.
func (db *DB) Close() error {
	db.Lock()
	defer db.Unlock()

	if db.DB == nil {
		return fmt.Errorf("database is not open")
	}

	err := db.DB.Close()
	if err != nil {
		return err
	}

	db.DB = nil
	return nil
}

// IsOpen checks if the database is open.
func (db *DB) IsOpen() bool {
	db.Lock()
	defer db.Unlock()

	return db.DB != nil
}

// IsTemporary checks if the database is temporary.
func (db *DB) IsTemporary() bool {
	db.Lock()
	defer db.Unlock()

	return db.isTempDB
}

// SetTemporary sets the temporary flag for the database.
func (db *DB) SetTemporary(temporary bool) {
	db.Lock()
	defer db.Unlock()

	db.isTempDB = temporary
}

// CustomOperation is an example of a custom database operation.
func (db *DB) CustomOperation() {
	// Implement your custom database operation here.
	fmt.Println("Performing custom database operation.")
}
