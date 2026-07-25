package reverse

import (
	"fmt"
	"sync"
	"testing"
)

func TestTransferSynMapEntries(t *testing.T) {
	src := &sync.Map{}
	dst := &sync.Map{}

	// Populate source
	src.Store("key1", "value1")
	src.Store("key2", "value2")
	src.Store("key3", "value3")

	TransferSynMapEntries(src, dst)

	// Verify all entries moved to dst
	count := 0
	dst.Range(func(key, value any) bool {
		count++
		return true
	})
	if count != 3 {
		t.Errorf("Expected 3 entries in dst, got %d", count)
	}

	// Verify specific values
	if v, ok := dst.Load("key1"); !ok || v != "value1" {
		t.Errorf("dst[key1] = %v, want 'value1'", v)
	}
	if v, ok := dst.Load("key2"); !ok || v != "value2" {
		t.Errorf("dst[key2] = %v, want 'value2'", v)
	}
	if v, ok := dst.Load("key3"); !ok || v != "value3" {
		t.Errorf("dst[key3] = %v, want 'value3'", v)
	}

	// Verify source is empty
	srcCount := 0
	src.Range(func(key, value any) bool {
		srcCount++
		return true
	})
	if srcCount != 0 {
		t.Errorf("Expected 0 entries in src after transfer, got %d", srcCount)
	}
}

func TestTransferSynMapEntriesEmpty(t *testing.T) {
	src := &sync.Map{}
	dst := &sync.Map{}

	TransferSynMapEntries(src, dst)

	// dst should still be empty
	count := 0
	dst.Range(func(key, value any) bool {
		count++
		return true
	})
	if count != 0 {
		t.Errorf("Expected 0 entries in dst, got %d", count)
	}
}

func TestTransferSynMapEntriesOverwrite(t *testing.T) {
	src := &sync.Map{}
	dst := &sync.Map{}

	src.Store("key1", "new_value")
	dst.Store("key1", "old_value")

	TransferSynMapEntries(src, dst)

	if v, ok := dst.Load("key1"); !ok || v != "new_value" {
		t.Errorf("dst[key1] = %v, want 'new_value'", v)
	}
}

func TestSplitKeyToGroupUnit(t *testing.T) {
	tests := []struct {
		key   string
		group string
		unit  string
	}{
		{"g1_u1", "g1", "u1"},
		{"groupA_unitB", "groupA", "unitB"},
		{"abc_def_ghi", "abc", "def"}, // takes first two fields
		{"single", "", ""},            // not enough fields
		{"", "", ""},                  // empty string
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			group, unit := SplitKeyToGroupUnit(tt.key)
			if group != tt.group {
				t.Errorf("SplitKeyToGroupUnit(%q) group = %q, want %q", tt.key, group, tt.group)
			}
			if unit != tt.unit {
				t.Errorf("SplitKeyToGroupUnit(%q) unit = %q, want %q", tt.key, unit, tt.unit)
			}
		})
	}
}

func TestLocalFetchEvent(t *testing.T) {
	r := createTestReverse(t)
	db := helperDB(t)
	defer db.Close()
	r.db = db

	// No callbacks registered - should return empty
	ret, err := r.localFetchEvent()
	if err != nil {
		t.Fatalf("localFetchEvent error: %v", err)
	}
	if len(ret) != 0 {
		t.Errorf("Expected 0 events, got %d", len(ret))
	}
}

func TestLocalFetchEventWithCallback(t *testing.T) {
	r := createTestReverse(t)
	db := helperDB(t)
	defer db.Close()
	r.db = db

	// Register a unit with a callback
	ug := r.NewUnitGroup()
	unit := r.RegisterWithGroup(nil, ug)

	callbackCalled := false
	unit.OnVisit(func(ev *Event) error {
		callbackCalled = true
		return nil
	})

	// Store the unit in the callback map
	r.groupUnitCallbackMap.Store(fmt.Sprintf("%s_%s", ug.id, unit.id), unit)

	// Store an event in the internal group event map using the UnitGroup pointer as key
	// This matches how localFetchEvent loads: r.internalGroupEventMap.Load(u.group)
	// where u.group is a *UnitGroup pointer
	ev := &Event{
		GroupID:   ug.id,
		UnitID:    unit.id,
		EventType: "http",
	}
	r.internalGroupEventMap.Store(ug, ev)

	// Now fetch should find the event and call the callback
	r.localFetchEvent()

	if !callbackCalled {
		t.Error("Callback should have been called")
	}

	// After callback, the entry should be deleted from the map
	_, loaded := r.groupUnitCallbackMap.Load(fmt.Sprintf("%s_%s", ug.id, unit.id))
	if loaded {
		t.Error("Callback entry should be deleted after fetch")
	}
}

func TestLocalFetchEventNoMatchingEvent(t *testing.T) {
	r := createTestReverse(t)
	db := helperDB(t)
	defer db.Close()
	r.db = db

	// Register a unit with a callback but no event in the map
	ug := r.NewUnitGroup()
	unit := r.RegisterWithGroup(nil, ug)

	callbackCalled := false
	unit.OnVisit(func(ev *Event) error {
		callbackCalled = true
		return nil
	})

	r.groupUnitCallbackMap.Store(fmt.Sprintf("%s_%s", ug.id, unit.id), unit)

	// No event stored for this group - callback should NOT be called
	r.localFetchEvent()

	if callbackCalled {
		t.Error("Callback should not be called when no matching event exists")
	}
}

func TestLocalCallUnitCallback(t *testing.T) {
	r := createTestReverse(t)
	// Should not panic
	r.localCallUnitCallback()
}
