package filter

import (
	"os"
	"testing"
)

func TestNewBadgerFilter(t *testing.T) {
	dir, err := os.MkdirTemp("", "badger-filter-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	bf, err := NewBadgerFilter(dir)
	if err != nil {
		t.Fatalf("NewBadgerFilter() returned error: %v", err)
	}
	if bf == nil {
		t.Fatal("NewBadgerFilter() returned nil")
	}
	if bf.closed {
		t.Error("new filter should not be closed")
	}
	if bf.dbPath != dir {
		t.Errorf("dbPath = %q, expected %q", bf.dbPath, dir)
	}

	err = bf.Close()
	if err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
	if !bf.closed {
		t.Error("filter should be closed after Close()")
	}
}

func TestBadgerFilter_InsertAndIsInserted(t *testing.T) {
	dir, err := os.MkdirTemp("", "badger-filter-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	bf, err := NewBadgerFilter(dir)
	if err != nil {
		t.Fatalf("NewBadgerFilter() returned error: %v", err)
	}
	defer bf.Close()

	bf.Insert("key1", 100)
	bf.Insert("key2", 200)

	tests := []struct {
		name            string
		key             string
		insertIfMissing bool
		value           int64
		expect          bool
	}{
		{"key exists, value less than stored", "key1", false, 50, true},
		{"key exists, value equal to stored", "key1", false, 100, true},
		{"key exists, value greater than stored", "key1", false, 150, false},
		{"key does not exist, not inserted", "nonexistent", true, 50, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := bf.IsInserted(tt.key, tt.insertIfMissing, tt.value)
			if result != tt.expect {
				t.Errorf("IsInserted(%q, %v, %d) = %v, expected %v", tt.key, tt.insertIfMissing, tt.value, result, tt.expect)
			}
		})
	}
}

func TestBadgerFilter_IsInserted_MissingKey(t *testing.T) {
	dir, err := os.MkdirTemp("", "badger-filter-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	bf, err := NewBadgerFilter(dir)
	if err != nil {
		t.Fatalf("NewBadgerFilter() returned error: %v", err)
	}
	defer bf.Close()

	// Key doesn't exist, insertIfMissing=false means it gets inserted
	result := bf.IsInserted("newkey", false, 42)
	if result {
		t.Error("IsInserted for missing key should return false")
	}

	// After insertIfMissing=false, the key was inserted with value 42
	result = bf.IsInserted("newkey", true, 30)
	if !result {
		t.Error("key should now exist with value 42, check with 30 should be true")
	}
}

func TestBadgerFilter_IsInserted_Overwrite(t *testing.T) {
	dir, err := os.MkdirTemp("", "badger-filter-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	bf, err := NewBadgerFilter(dir)
	if err != nil {
		t.Fatalf("NewBadgerFilter() returned error: %v", err)
	}
	defer bf.Close()

	bf.Insert("key1", 100)
	bf.Insert("key1", 200)

	// Value should be 200 (overwritten)
	if !bf.IsInserted("key1", true, 150) {
		t.Error("key1 with value 200 should return true for check value 150")
	}
	if bf.IsInserted("key1", true, 250) {
		t.Error("key1 with value 200 should return false for check value 250")
	}
}

func TestBadgerFilter_Reset(t *testing.T) {
	dir, err := os.MkdirTemp("", "badger-filter-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	bf, err := NewBadgerFilter(dir)
	if err != nil {
		t.Fatalf("NewBadgerFilter() returned error: %v", err)
	}
	defer bf.Close()

	bf.Insert("key1", 100)
	bf.Insert("key2", 200)

	err = bf.Reset()
	if err != nil {
		t.Errorf("Reset() returned error: %v", err)
	}

	// After reset, keys should be gone
	if bf.IsInserted("key1", true, 50) {
		t.Error("key1 should not exist after reset")
	}
	if bf.IsInserted("key2", true, 50) {
		t.Error("key2 should not exist after reset")
	}
}

func TestBadgerFilter_ResetAndReinsert(t *testing.T) {
	dir, err := os.MkdirTemp("", "badger-filter-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	bf, err := NewBadgerFilter(dir)
	if err != nil {
		t.Fatalf("NewBadgerFilter() returned error: %v", err)
	}
	defer bf.Close()

	bf.Insert("key1", 100)
	bf.Reset()
	bf.Insert("key1", 200)

	if !bf.IsInserted("key1", true, 150) {
		t.Error("key1 should be inserted with value 200 after reset and reinsert")
	}
}

func TestBadgerFilter_LargeValues(t *testing.T) {
	dir, err := os.MkdirTemp("", "badger-filter-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	bf, err := NewBadgerFilter(dir)
	if err != nil {
		t.Fatalf("NewBadgerFilter() returned error: %v", err)
	}
	defer bf.Close()

	largeValue := int64(1<<62 - 1)
	bf.Insert("large_key", largeValue)

	if !bf.IsInserted("large_key", true, largeValue-1) {
		t.Error("large value should be inserted correctly")
	}
}

func TestBadgerFilter_NegativeValues(t *testing.T) {
	dir, err := os.MkdirTemp("", "badger-filter-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	bf, err := NewBadgerFilter(dir)
	if err != nil {
		t.Fatalf("NewBadgerFilter() returned error: %v", err)
	}
	defer bf.Close()

	bf.Insert("neg_key", -100)

	if !bf.IsInserted("neg_key", true, -200) {
		t.Error("negative value -200 should be less than stored -100")
	}
	if bf.IsInserted("neg_key", true, -50) {
		t.Error("value -50 should be greater than stored -100")
	}
}

func TestBadgerFilter_ConcurrentAccess(t *testing.T) {
	dir, err := os.MkdirTemp("", "badger-filter-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	bf, err := NewBadgerFilter(dir)
	if err != nil {
		t.Fatalf("NewBadgerFilter() returned error: %v", err)
	}
	defer bf.Close()

	done := make(chan bool, 2)

	go func() {
		for i := 0; i < 50; i++ {
			bf.Insert("concurrent_key", int64(i))
		}
		done <- true
	}()

	go func() {
		for i := 0; i < 50; i++ {
			bf.IsInserted("concurrent_key", true, int64(i))
		}
		done <- true
	}()

	<-done
	<-done
}
