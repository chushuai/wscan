package filter

import (
	"testing"
)

func TestNewSyncMapFilter(t *testing.T) {
	sf := NewSyncMapFilter()
	if sf == nil {
		t.Fatal("NewSyncMapFilter returned nil")
	}
	if sf.closed {
		t.Error("new filter should not be closed")
	}
}

func TestSyncMapFilter_Close(t *testing.T) {
	sf := NewSyncMapFilter()
	err := sf.Close()
	if err != nil {
		t.Errorf("Close() returned unexpected error: %v", err)
	}
	if !sf.closed {
		t.Error("filter should be closed after Close()")
	}
}

func TestSyncMapFilter_Insert(t *testing.T) {
	sf := NewSyncMapFilter()
	defer sf.Close()

	sf.Insert("key1", 100)
	sf.Insert("key2", 200)
	sf.Insert("key3", 300)

	// Verify values are inserted by checking IsInserted
	if !sf.IsInserted("key1", false, 50) {
		t.Error("key1 should be inserted with value 100, checking with value 50 should return true")
	}
	if !sf.IsInserted("key2", false, 150) {
		t.Error("key2 should be inserted with value 200, checking with value 150 should return true")
	}
}

func TestSyncMapFilter_IsInserted_Basic(t *testing.T) {
	sf := NewSyncMapFilter()
	defer sf.Close()

	sf.Insert("key1", 100)

	tests := []struct {
		name       string
		key        string
		shouldLock bool
		value      int64
		expect     bool
	}{
		{"key exists, value less than stored", "key1", false, 50, true},
		{"key exists, value equal to stored", "key1", false, 100, true},
		{"key exists, value greater than stored", "key1", false, 150, false},
		{"key does not exist", "nonexistent", false, 50, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sf.IsInserted(tt.key, tt.shouldLock, tt.value)
			if result != tt.expect {
				t.Errorf("IsInserted(%q, %v, %d) = %v, expected %v", tt.key, tt.shouldLock, tt.value, result, tt.expect)
			}
		})
	}
}

func TestSyncMapFilter_IsInserted_Overwrite(t *testing.T) {
	sf := NewSyncMapFilter()
	defer sf.Close()

	// Insert same key with higher value - should overwrite
	sf.Insert("key1", 100)
	sf.Insert("key1", 200)

	// The sync.Map Store overwrites, so value should be 200
	if !sf.IsInserted("key1", false, 150) {
		t.Error("key1 with value 200 should return true for check value 150")
	}
	if sf.IsInserted("key1", false, 250) {
		t.Error("key1 with value 200 should return false for check value 250")
	}
}

func TestSyncMapFilter_IsInserted_Concurrent(t *testing.T) {
	sf := NewSyncMapFilter()
	defer sf.Close()

	// Test concurrent access
	done := make(chan bool, 2)

	go func() {
		for i := 0; i < 100; i++ {
			sf.Insert("concurrent_key", int64(i))
		}
		done <- true
	}()

	go func() {
		for i := 0; i < 100; i++ {
			sf.IsInserted("concurrent_key", false, int64(i))
		}
		done <- true
	}()

	<-done
	<-done
}

func TestSyncMapFilter_Reset(t *testing.T) {
	sf := NewSyncMapFilter()
	defer sf.Close()

	sf.Insert("key1", 100)
	sf.Insert("key2", 200)

	// Verify key1 is inserted
	if !sf.IsInserted("key1", false, 50) {
		t.Error("key1 should be inserted before reset")
	}

	// Reset the filter
	err := sf.Reset()
	if err != nil {
		t.Errorf("Reset() returned unexpected error: %v", err)
	}

	// After reset, all keys should be gone
	if sf.IsInserted("key1", false, 50) {
		t.Error("key1 should not be inserted after reset")
	}
	if sf.IsInserted("key2", false, 50) {
		t.Error("key2 should not be inserted after reset")
	}
}

func TestSyncMapFilter_ResetAndReinsert(t *testing.T) {
	sf := NewSyncMapFilter()
	defer sf.Close()

	sf.Insert("key1", 100)
	sf.Reset()
	sf.Insert("key1", 200)

	if !sf.IsInserted("key1", false, 150) {
		t.Error("key1 should be inserted with value 200 after reset and reinsert")
	}
}

func TestSyncMapFilter_MultipleResets(t *testing.T) {
	sf := NewSyncMapFilter()
	defer sf.Close()

	for i := 0; i < 5; i++ {
		sf.Insert("key1", int64(i*100))
		err := sf.Reset()
		if err != nil {
			t.Errorf("Reset() %d returned unexpected error: %v", i, err)
		}
		if sf.IsInserted("key1", false, 0) {
			t.Errorf("key1 should not exist after reset %d", i)
		}
	}
}

func TestSyncMapFilter_EmptyFilter(t *testing.T) {
	sf := NewSyncMapFilter()
	defer sf.Close()

	// Check on empty filter
	if sf.IsInserted("nonexistent", false, 0) {
		t.Error("empty filter should return false for any key")
	}
}

func TestSyncMapFilter_LargeValues(t *testing.T) {
	sf := NewSyncMapFilter()
	defer sf.Close()

	largeValue := int64(1<<62 - 1) // near max int64
	sf.Insert("large_key", largeValue)

	if !sf.IsInserted("large_key", false, largeValue-1) {
		t.Error("large value should be inserted correctly")
	}
	if sf.IsInserted("large_key", false, largeValue+1) {
		t.Error("value larger than stored should return false")
	}
}

func TestSyncMapFilter_NegativeValues(t *testing.T) {
	sf := NewSyncMapFilter()
	defer sf.Close()

	sf.Insert("neg_key", -100)

	if !sf.IsInserted("neg_key", false, -200) {
		t.Error("negative value -200 should be less than stored -100")
	}
	if !sf.IsInserted("neg_key", false, -100) {
		t.Error("equal value -100 should match stored -100")
	}
	if sf.IsInserted("neg_key", false, -50) {
		t.Error("value -50 should be greater than stored -100, should return false")
	}
}

func TestSyncMapFilter_ZeroValues(t *testing.T) {
	sf := NewSyncMapFilter()
	defer sf.Close()

	sf.Insert("zero_key", 0)

	if !sf.IsInserted("zero_key", false, 0) {
		t.Error("zero value should match stored zero")
	}
	if sf.IsInserted("zero_key", false, 1) {
		t.Error("value 1 should be greater than stored 0, should return false")
	}
	if !sf.IsInserted("zero_key", false, -1) {
		t.Error("value -1 should be less than stored 0, should return true")
	}
}
