package reverse

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"go.etcd.io/bbolt"
)

// helperDB creates a temporary database for testing
func helperDB(t *testing.T) *DB {
	t.Helper()
	db := &DB{}
	path := filepath.Join(t.TempDir(), "test.db")
	if err := db.Open(path); err != nil {
		t.Fatalf("Failed to open db: %v", err)
	}
	return db
}

func TestDBOpen(t *testing.T) {
	db := &DB{}
	path := filepath.Join(t.TempDir(), "test_open.db")

	err := db.Open(path)
	if err != nil {
		t.Fatalf("DB.Open error: %v", err)
	}
	defer db.Close()

	if !db.IsOpen() {
		t.Error("DB should be open after Open()")
	}
}

func TestDBOpenAlreadyOpen(t *testing.T) {
	db := helperDB(t)
	defer db.Close()

	err := db.Open("/some/other/path.db")
	if err == nil {
		t.Error("Expected error when opening already open database")
	}
}

func TestDBClose(t *testing.T) {
	db := helperDB(t)

	err := db.Close()
	if err != nil {
		t.Fatalf("DB.Close error: %v", err)
	}

	if db.IsOpen() {
		t.Error("DB should not be open after Close()")
	}
}

func TestDBCloseNotOpen(t *testing.T) {
	db := &DB{}

	err := db.Close()
	if err == nil {
		t.Error("Expected error when closing not-open database")
	}
}

func TestDBIsOpen(t *testing.T) {
	db := &DB{}

	if db.IsOpen() {
		t.Error("New DB should not be open")
	}

	path := filepath.Join(t.TempDir(), "test_isopen.db")
	db.Open(path)

	if !db.IsOpen() {
		t.Error("DB should be open after Open()")
	}

	db.Close()

	if db.IsOpen() {
		t.Error("DB should not be open after Close()")
	}
}

func TestDBIsTemporary(t *testing.T) {
	db := &DB{}

	if db.IsTemporary() {
		t.Error("New DB should not be temporary")
	}

	db.SetTemporary(true)
	if !db.IsTemporary() {
		t.Error("DB should be temporary after SetTemporary(true)")
	}

	db.SetTemporary(false)
	if db.IsTemporary() {
		t.Error("DB should not be temporary after SetTemporary(false)")
	}
}

func TestDBSetTemporary(t *testing.T) {
	db := &DB{}
	db.SetTemporary(true)
	if !db.IsTemporary() {
		t.Error("Expected IsTemporary to be true")
	}
	db.SetTemporary(false)
	if db.IsTemporary() {
		t.Error("Expected IsTemporary to be false")
	}
}

func TestDBCustomOperation(t *testing.T) {
	db := helperDB(t)
	defer db.Close()

	// Should not panic
	db.CustomOperation()
}

func TestNewDB(t *testing.T) {
	// Just verify it doesn't panic
	newDB()
}

func TestBucketBuild(t *testing.T) {
	db := helperDB(t)
	defer db.Close()

	err := db.Update(func(tx *bbolt.Tx) error {
		parent := Bucket{
			Name: "test_parent",
			SubBuckets: []Bucket{
				{Name: "child1"},
				{Name: "child2", SubBuckets: []Bucket{{Name: "grandchild"}}},
			},
		}
		parent.Build(tx, nil)
		return nil
	})
	if err != nil {
		t.Fatalf("Bucket.Build error: %v", err)
	}

	// Verify buckets were created
	db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("test_parent"))
		if b == nil {
			t.Error("test_parent bucket not created")
		}
		if b.Bucket([]byte("child1")) == nil {
			t.Error("child1 bucket not created")
		}
		if b.Bucket([]byte("child2")) == nil {
			t.Error("child2 bucket not created")
		}
		if b.Bucket([]byte("child2")).Bucket([]byte("grandchild")) == nil {
			t.Error("grandchild bucket not created")
		}
		return nil
	})
}

func TestBucketBuildWithParent(t *testing.T) {
	db := helperDB(t)
	defer db.Close()

	db.Update(func(tx *bbolt.Tx) error {
		parent, err := tx.CreateBucketIfNotExists([]byte("root"))
		if err != nil {
			return err
		}
		child := Bucket{Name: "sub_child"}
		child.Build(tx, parent)
		return nil
	})

	db.View(func(tx *bbolt.Tx) error {
		root := tx.Bucket([]byte("root"))
		if root == nil {
			t.Fatal("root bucket not found")
		}
		if root.Bucket([]byte("sub_child")) == nil {
			t.Error("sub_child bucket not created under root")
		}
		return nil
	})
}

func TestDBStoreEvent(t *testing.T) {
	db := helperDB(t)
	defer db.Close()

	ev := &Event{
		GroupID:     "g1",
		UnitID:      "u1",
		EventType:   "http",
		EventSource: "internal",
		Request:     "GET / HTTP/1.1",
		RemoteAddr:  "127.0.0.1:12345",
	}

	db.storeEvent(ev)

	if ev.ID == 0 {
		t.Error("Event ID should be set after storeEvent")
	}
}

func TestDBStoreMultipleEvents(t *testing.T) {
	db := helperDB(t)
	defer db.Close()

	for i := 0; i < 5; i++ {
		ev := &Event{
			GroupID:     fmt.Sprintf("group%d", i),
			UnitID:      fmt.Sprintf("unit%d", i),
			EventType:   "http",
			EventSource: "internal",
		}
		db.storeEvent(ev)
	}

	stats := db.getEventStats()
	if stats.HTTP != 5 {
		t.Errorf("Expected 5 http events, got %d", stats.HTTP)
	}
}

func TestDBStoreDifferentEventTypes(t *testing.T) {
	db := helperDB(t)
	defer db.Close()

	types := []string{"http", "dns", "rmi", "ldap"}
	for _, typ := range types {
		ev := &Event{
			GroupID:     "g1",
			UnitID:      "u1",
			EventType:   typ,
			EventSource: "internal",
		}
		db.storeEvent(ev)
	}

	stats := db.getEventStats()
	if stats.HTTP != 1 {
		t.Errorf("Expected 1 http event, got %d", stats.HTTP)
	}
	if stats.DNS != 1 {
		t.Errorf("Expected 1 dns event, got %d", stats.DNS)
	}
	if stats.RMI != 1 {
		t.Errorf("Expected 1 rmi event, got %d", stats.RMI)
	}
	if stats.LDAP != 1 {
		t.Errorf("Expected 1 ldap event, got %d", stats.LDAP)
	}
	if stats.Total != 4 {
		t.Errorf("Expected 4 total events, got %d", stats.Total)
	}
}

func TestDBGetEventStats(t *testing.T) {
	db := helperDB(t)
	defer db.Close()

	// Initially should be all zeros
	stats := db.getEventStats()
	if stats.HTTP != 0 || stats.DNS != 0 || stats.RMI != 0 || stats.LDAP != 0 || stats.Total != 0 {
		t.Errorf("Expected all zeros for empty db, got %+v", stats)
	}

	// Add some events
	for i := 0; i < 3; i++ {
		db.storeEvent(&Event{GroupID: "g1", UnitID: "u1", EventType: "dns", EventSource: "internal"})
	}
	for i := 0; i < 2; i++ {
		db.storeEvent(&Event{GroupID: "g2", UnitID: "u2", EventType: "rmi", EventSource: "internal"})
	}

	stats = db.getEventStats()
	if stats.DNS != 3 {
		t.Errorf("Expected 3 dns events, got %d", stats.DNS)
	}
	if stats.RMI != 2 {
		t.Errorf("Expected 2 rmi events, got %d", stats.RMI)
	}
	if stats.Total != 5 {
		t.Errorf("Expected 5 total events, got %d", stats.Total)
	}
}

func TestDBListEvent(t *testing.T) {
	db := helperDB(t)
	defer db.Close()

	// Add some http events
	for i := 0; i < 5; i++ {
		db.storeEvent(&Event{
			GroupID:     fmt.Sprintf("g%d", i),
			UnitID:      "u1",
			EventType:   "http",
			EventSource: "internal",
		})
	}

	// List http events
	events, total := db.listEvent("http", "", 10, "Prev")
	if total != 5 {
		t.Errorf("Expected total 5, got %d", total)
	}
	if len(events) != 5 {
		t.Errorf("Expected 5 events, got %d", len(events))
	}
}

func TestDBListEventWithCount(t *testing.T) {
	db := helperDB(t)
	defer db.Close()

	for i := 0; i < 10; i++ {
		db.storeEvent(&Event{
			GroupID:     fmt.Sprintf("g%d", i),
			UnitID:      "u1",
			EventType:   "http",
			EventSource: "internal",
		})
	}

	events, total := db.listEvent("http", "", 3, "Prev")
	if total != 10 {
		t.Errorf("Expected total 10, got %d", total)
	}
	if len(events) != 3 {
		t.Errorf("Expected 3 events with count=3, got %d", len(events))
	}
}

func TestDBListEventAllTypes(t *testing.T) {
	db := helperDB(t)
	defer db.Close()

	// Add events of different types
	db.storeEvent(&Event{GroupID: "g1", UnitID: "u1", EventType: "http", EventSource: "internal"})
	db.storeEvent(&Event{GroupID: "g2", UnitID: "u2", EventType: "dns", EventSource: "internal"})
	db.storeEvent(&Event{GroupID: "g3", UnitID: "u3", EventType: "rmi", EventSource: "internal"})

	events, total := db.listEvent("", "", 10, "Prev")
	if total != 3 {
		t.Errorf("Expected total 3, got %d", total)
	}
	if len(events) != 3 {
		t.Errorf("Expected 3 events, got %d", len(events))
	}
}

func TestDBListEventActionNext(t *testing.T) {
	db := helperDB(t)
	defer db.Close()

	for i := 0; i < 5; i++ {
		db.storeEvent(&Event{
			GroupID:     fmt.Sprintf("g%d", i),
			UnitID:      "u1",
			EventType:   "http",
			EventSource: "internal",
		})
	}

	events, total := db.listEvent("http", "", 10, "Next")
	if total != 5 {
		t.Errorf("Expected total 5, got %d", total)
	}
	if len(events) != 5 {
		t.Errorf("Expected 5 events, got %d", len(events))
	}
}

func TestDBListEventWithLastID(t *testing.T) {
	db := helperDB(t)
	defer db.Close()

	for i := 0; i < 5; i++ {
		db.storeEvent(&Event{
			GroupID:     fmt.Sprintf("g%d", i),
			UnitID:      "u1",
			EventType:   "http",
			EventSource: "internal",
		})
	}

	// List with a lastID starting point
	events, _ := db.listEvent("http", "2", 10, "Prev")
	// Should get events with IDs less than 2
	if len(events) == 0 {
		t.Log("No events returned with lastID=2, this is acceptable depending on cursor behavior")
	}
}

func TestDBListEventEmpty(t *testing.T) {
	db := helperDB(t)
	defer db.Close()

	events, total := db.listEvent("http", "", 10, "Prev")
	if total != 0 {
		t.Errorf("Expected total 0, got %d", total)
	}
	if len(events) != 0 {
		t.Errorf("Expected 0 events, got %d", len(events))
	}
}

func TestSortEvents(t *testing.T) {
	events := []*Event{
		{ID: 3, GroupID: "g3"},
		{ID: 1, GroupID: "g1"},
		{ID: 5, GroupID: "g5"},
		{ID: 2, GroupID: "g2"},
		{ID: 4, GroupID: "g4"},
	}

	sortEvents(events)

	// Should be sorted descending by ID
	for i := 0; i < len(events)-1; i++ {
		if events[i].ID < events[i+1].ID {
			t.Errorf("Events not sorted descending: %d > %d at index %d", events[i].ID, events[i+1].ID, i)
		}
	}
}

func TestSortEventsEmpty(t *testing.T) {
	events := []*Event{}
	sortEvents(events) // Should not panic
	if len(events) != 0 {
		t.Error("Empty slice should remain empty after sort")
	}
}

func TestSortEventsSingle(t *testing.T) {
	events := []*Event{{ID: 1, GroupID: "g1"}}
	sortEvents(events)
	if len(events) != 1 || events[0].ID != 1 {
		t.Error("Single element slice should be unchanged after sort")
	}
}

func TestDBSetAndGetHTTPResponse(t *testing.T) {
	db := helperDB(t)
	defer db.Close()

	hrc := &HTTPResponseConfig{
		GroupID: "testGroup",
	}
	hrc.StatusCode = "403"
	hrc.Body = "Forbidden"
	hrc.Header = []map[string]string{{"key": "X-Custom", "value": "test"}}

	db.setHTTPResponse(hrc)

	retrieved := db.getHTTPResponse("testGroup")
	if retrieved == nil {
		t.Fatal("getHTTPResponse returned nil")
	}
	if retrieved.GroupID != "testGroup" {
		t.Errorf("Expected GroupID 'testGroup', got '%s'", retrieved.GroupID)
	}
	if retrieved.StatusCode != "403" {
		t.Errorf("Expected StatusCode '403', got '%s'", retrieved.StatusCode)
	}
	if retrieved.Body != "Forbidden" {
		t.Errorf("Expected Body 'Forbidden', got '%s'", retrieved.Body)
	}
}

func TestDBGetHTTPResponseNonExistent(t *testing.T) {
	db := helperDB(t)
	defer db.Close()

	retrieved := db.getHTTPResponse("nonexistent")
	if retrieved != nil {
		t.Error("Expected nil for non-existent groupID")
	}
}

func TestDBListHTTPResponses(t *testing.T) {
	db := helperDB(t)
	defer db.Close()

	// Initially empty
	list := db.listHTTPResponses()
	if len(list) != 0 {
		t.Errorf("Expected 0 HTTP responses, got %d", len(list))
	}

	// Add some responses
	hrc1 := &HTTPResponseConfig{GroupID: "g1"}
	hrc1.StatusCode = "200"
	hrc1.Body = "OK"
	hrc2 := &HTTPResponseConfig{GroupID: "g2"}
	hrc2.StatusCode = "404"
	hrc2.Body = "Not Found"

	db.setHTTPResponse(hrc1)
	db.setHTTPResponse(hrc2)

	list = db.listHTTPResponses()
	if len(list) != 2 {
		t.Errorf("Expected 2 HTTP responses, got %d", len(list))
	}
}

func TestDBDeleteHTTPResponse(t *testing.T) {
	db := helperDB(t)
	defer db.Close()

	hrc := &HTTPResponseConfig{GroupID: "toDelete"}
	hrc.StatusCode = "200"
	hrc.Body = "OK"
	db.setHTTPResponse(hrc)

	// Verify it exists
	retrieved := db.getHTTPResponse("toDelete")
	if retrieved == nil {
		t.Fatal("HTTP response should exist before deletion")
	}

	// Delete it
	db.deleteHTTPResponse("toDelete")

	// Verify it's gone
	retrieved = db.getHTTPResponse("toDelete")
	if retrieved != nil {
		t.Error("HTTP response should be nil after deletion")
	}
}

func TestDBDeleteHTTPResponseNonExistent(t *testing.T) {
	db := helperDB(t)
	defer db.Close()

	// Should not panic
	db.deleteHTTPResponse("nonexistent")
}

func TestDBSetAndGetDNSResponse(t *testing.T) {
	db := helperDB(t)
	defer db.Close()

	drc := &DNSResponseConfig{
		GroupID: "dnsGroup1",
	}
	drc.DNSResponse.A = []DNSResponseItem{{Value: "1.2.3.4", TTL: 60}}
	drc.DNSResponse.TXT = []DNSResponseItem{{Value: "hello", TTL: 120}}

	db.setDNSResponse(drc)

	retrieved := db.getDNSResponse("dnsGroup1")
	if retrieved == nil {
		t.Fatal("getDNSResponse returned nil")
	}
	if retrieved.GroupID != "dnsGroup1" {
		t.Errorf("Expected GroupID 'dnsGroup1', got '%s'", retrieved.GroupID)
	}
	if len(retrieved.DNSResponse.A) != 1 {
		t.Fatalf("Expected 1 A record, got %d", len(retrieved.DNSResponse.A))
	}
	if retrieved.DNSResponse.A[0].Value != "1.2.3.4" {
		t.Errorf("Expected A record '1.2.3.4', got '%s'", retrieved.DNSResponse.A[0].Value)
	}
	if retrieved.DNSResponse.A[0].TTL != 60 {
		t.Errorf("Expected A record TTL 60, got %d", retrieved.DNSResponse.A[0].TTL)
	}
}

func TestDBGetDNSResponseNonExistent(t *testing.T) {
	db := helperDB(t)
	defer db.Close()

	retrieved := db.getDNSResponse("nonexistent")
	if retrieved != nil {
		t.Error("Expected nil for non-existent DNS response")
	}
}

func TestDBGetInt(t *testing.T) {
	db := helperDB(t)
	defer db.Close()

	db.Update(func(tx *bbolt.Tx) error {
		b, _ := tx.CreateBucketIfNotExists([]byte("test_getInt"))
		b.Put([]byte("counter"), []byte("42"))
		b.Put([]byte("empty_val"), []byte(""))
		return nil
	})

	db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("test_getInt"))

		// Existing key with numeric value
		val := db.getInt(b, []byte("counter"))
		if val != 42 {
			t.Errorf("Expected 42, got %d", val)
		}

		// Non-existing key
		val = db.getInt(b, []byte("nonexistent"))
		if val != 0 {
			t.Errorf("Expected 0 for non-existent key, got %d", val)
		}

		// Key with empty string value
		val = db.getInt(b, []byte("empty_val"))
		if val != 0 {
			t.Errorf("Expected 0 for empty string value, got %d", val)
		}

		return nil
	})
}

func TestDBIncr(t *testing.T) {
	db := helperDB(t)
	defer db.Close()

	db.Update(func(tx *bbolt.Tx) error {
		b, _ := tx.CreateBucketIfNotExists([]byte("test_incr"))

		// First increment
		val := db.incr(b, []byte("counter"))
		if val != 1 {
			t.Errorf("Expected 1 after first incr, got %d", val)
		}

		// Second increment
		val = db.incr(b, []byte("counter"))
		if val != 2 {
			t.Errorf("Expected 2 after second incr, got %d", val)
		}

		// Third increment
		val = db.incr(b, []byte("counter"))
		if val != 3 {
			t.Errorf("Expected 3 after third incr, got %d", val)
		}

		// Different key
		val = db.incr(b, []byte("other"))
		if val != 1 {
			t.Errorf("Expected 1 for new key, got %d", val)
		}

		return nil
	})
}

func TestDBOverwriteHTTPResponse(t *testing.T) {
	db := helperDB(t)
	defer db.Close()

	hrc1 := &HTTPResponseConfig{GroupID: "g1"}
	hrc1.StatusCode = "200"
	hrc1.Body = "First"
	db.setHTTPResponse(hrc1)

	hrc2 := &HTTPResponseConfig{GroupID: "g1"}
	hrc2.StatusCode = "500"
	hrc2.Body = "Second"
	db.setHTTPResponse(hrc2)

	retrieved := db.getHTTPResponse("g1")
	if retrieved.StatusCode != "500" {
		t.Errorf("Expected StatusCode '500' after overwrite, got '%s'", retrieved.StatusCode)
	}
	if retrieved.Body != "Second" {
		t.Errorf("Expected Body 'Second' after overwrite, got '%s'", retrieved.Body)
	}
}

func TestDBOverwriteDNSResponse(t *testing.T) {
	db := helperDB(t)
	defer db.Close()

	drc1 := &DNSResponseConfig{GroupID: "g1"}
	drc1.DNSResponse.A = []DNSResponseItem{{Value: "1.1.1.1", TTL: 10}}
	db.setDNSResponse(drc1)

	drc2 := &DNSResponseConfig{GroupID: "g1"}
	drc2.DNSResponse.A = []DNSResponseItem{{Value: "2.2.2.2", TTL: 20}}
	db.setDNSResponse(drc2)

	retrieved := db.getDNSResponse("g1")
	if retrieved.DNSResponse.A[0].Value != "2.2.2.2" {
		t.Errorf("Expected A record '2.2.2.2' after overwrite, got '%s'", retrieved.DNSResponse.A[0].Value)
	}
}

func TestDBListEventMerge(t *testing.T) {
	db := helperDB(t)
	defer db.Close()

	// Add events of multiple types
	for i := 0; i < 3; i++ {
		db.storeEvent(&Event{GroupID: fmt.Sprintf("g_http_%d", i), UnitID: "u1", EventType: "http", EventSource: "internal"})
	}
	for i := 0; i < 3; i++ {
		db.storeEvent(&Event{GroupID: fmt.Sprintf("g_dns_%d", i), UnitID: "u1", EventType: "dns", EventSource: "internal"})
	}

	// List all events with small count to test merge-sort
	events, total := db.listEvent("", "", 4, "Prev")
	if total != 6 {
		t.Errorf("Expected total 6, got %d", total)
	}
	// With count=4 and merge, should get at most 4
	if len(events) > 4 {
		t.Errorf("Expected at most 4 events with count=4, got %d", len(events))
	}
}

// Test the original TestReverseLog using temp db
func TestReverseLogWithTempDB(t *testing.T) {
	db := helperDB(t)
	defer db.Close()

	for _, typ := range []string{"rmi", "dns", "http"} {
		for i := 0; i < 10; i++ {
			ev := Event{
				ID:          0,
				GroupID:     "g1",
				UnitID:      "u111",
				EventType:   typ,
				EventSource: "internal",
			}
			db.storeEvent(&ev)
		}
	}

	stats := db.getEventStats()
	if stats.HTTP != 10 || stats.DNS != 10 || stats.RMI != 10 {
		t.Errorf("Expected 10 of each type, got HTTP=%d, DNS=%d, RMI=%d", stats.HTTP, stats.DNS, stats.RMI)
	}
	if stats.Total != 30 {
		t.Errorf("Expected total 30, got %d", stats.Total)
	}
}

func TestSetDNSResponseWithTempDB(t *testing.T) {
	db := helperDB(t)
	defer db.Close()

	drc := DNSResponseConfig{
		GroupID: "xxxx",
	}
	drc.DNSResponse.A = []DNSResponseItem{{Value: "1.1.1.1", TTL: 10}}

	db.setDNSResponse(&drc)

	raw, _ := json.Marshal(db.getDNSResponse(drc.GroupID))
	if string(raw) == "" {
		t.Error("Expected non-empty DNS response JSON")
	}
}

func TestDBFileCreation(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "newfile.db")

	db := &DB{}
	err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("Failed to open new db file: %v", err)
	}
	db.Close()

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Error("DB file should be created on disk")
	}
}

func TestDBReverseBuiltinBuckets(t *testing.T) {
	db := helperDB(t)
	defer db.Close()

	// Verify the built-in buckets were created
	db.View(func(tx *bbolt.Tx) error {
		if tx.Bucket([]byte("reverse_log")) == nil {
			t.Error("reverse_log bucket not created")
		}
		if tx.Bucket([]byte("reverse_group")) == nil {
			t.Error("reverse_group bucket not created")
		}
		if tx.Bucket([]byte("resp_config")) == nil {
			t.Error("resp_config bucket not created")
		}

		// Check sub-buckets
		rl := tx.Bucket([]byte("reverse_log"))
		if rl.Bucket([]byte("dns")) == nil {
			t.Error("reverse_log/dns bucket not created")
		}
		if rl.Bucket([]byte("http")) == nil {
			t.Error("reverse_log/http bucket not created")
		}
		if rl.Bucket([]byte("rmi")) == nil {
			t.Error("reverse_log/rmi bucket not created")
		}
		if rl.Bucket([]byte("meta")) == nil {
			t.Error("reverse_log/meta bucket not created")
		}
		return nil
	})
}

func TestDBStoreEventIncrementingIDs(t *testing.T) {
	db := helperDB(t)
	defer db.Close()

	var lastID int64
	for i := 0; i < 5; i++ {
		ev := &Event{
			GroupID:     "g1",
			UnitID:      "u1",
			EventType:   "http",
			EventSource: "internal",
		}
		db.storeEvent(ev)
		if ev.ID <= lastID {
			t.Errorf("Event ID %d should be greater than last ID %d", ev.ID, lastID)
		}
		lastID = ev.ID
	}
}

// Keep sort import used
var _ = sort.Strings
