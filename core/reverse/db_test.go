/**
2 * @Author: shaochuyu
3 * @Date: 12/13/23
4 */

package reverse

import "testing"

func TestDBOperations(t *testing.T) {
	db := DB{}

	// Open the database
	err := db.Open("test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Perform some operations
	if !db.IsOpen() {
		t.Error("Database should be open")
	}

	db.CustomOperation()

	// Set and check temporary flag
	db.SetTemporary(true)
	if !db.IsTemporary() {
		t.Error("Database should be temporary")
	}
}

// http://127.0.0.1:88/_/api/health_check
// http://127.0.0.1:88/_/api/cland/event/list?lastID=&count=10&eventType=http&action=Next
// http://127.0.0.1:88/_/api/cland/generate/http_url
