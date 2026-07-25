package knowledge

import (
	"context"
	"fmt"
	"testing"

	"wscan/core/http"
	"wscan/core/resource"
)

func TestNewKBItem(t *testing.T) {
	kb := NewKBItem()
	if kb == nil {
		t.Fatal("expected non-nil KBItem")
	}
	if kb.m == nil {
		t.Error("expected map to be initialized")
	}
	// Check default fingerprint key
	fp, ok := kb.m["fingerprint"]
	if !ok {
		t.Error("expected 'fingerprint' key to be initialized")
	}
	fps, ok := fp.([]string)
	if !ok {
		t.Error("expected fingerprint to be []string")
	}
	if len(fps) != 0 {
		t.Errorf("expected empty fingerprint slice, got %d items", len(fps))
	}
}

func TestKBItem_SetAndGet(t *testing.T) {
	kb := NewKBItem()
	kb.Set("key1", "value1")
	val := kb.Get("key1")
	if val != "value1" {
		t.Errorf("expected 'value1', got %v", val)
	}
}

func TestKBItem_Get_NonExistent(t *testing.T) {
	kb := NewKBItem()
	val := kb.Get("nonexistent")
	if val != nil {
		t.Errorf("expected nil for non-existent key, got %v", val)
	}
}

func TestKBItem_Exist(t *testing.T) {
	kb := NewKBItem()
	kb.Set("key1", "value1")
	if !kb.Exist("key1") {
		t.Error("expected key1 to exist")
	}
	if kb.Exist("nonexistent") {
		t.Error("expected nonexistent key to not exist")
	}
}

func TestKBItem_Remove(t *testing.T) {
	kb := NewKBItem()
	kb.Set("key1", "value1")
	if !kb.Exist("key1") {
		t.Error("expected key1 to exist before remove")
	}
	kb.Remove("key1")
	if kb.Exist("key1") {
		t.Error("expected key1 to not exist after remove")
	}
}

func TestKBItem_Remove_NonExistent(t *testing.T) {
	kb := NewKBItem()
	kb.Remove("nonexistent") // should not panic
}

func TestKBItem_Set_Overwrite(t *testing.T) {
	kb := NewKBItem()
	kb.Set("key1", "value1")
	kb.Set("key1", "value2")
	val := kb.Get("key1")
	if val != "value2" {
		t.Errorf("expected 'value2' after overwrite, got %v", val)
	}
}

func TestNewKnowledgeDB(t *testing.T) {
	kb := NewKnowledgeDB(nil)
	if kb == nil {
		t.Fatal("expected non-nil KnowledgeDB")
	}
	if kb.stub == nil {
		t.Error("expected stub map to be initialized")
	}
}

func TestKnowledgeDB_SaveAndGet(t *testing.T) {
	kb := NewKnowledgeDB(nil)
	item := NewKBItem()
	item.Set("test_key", "test_value")
	kb.Save("host1", item)

	retrieved := kb.Get("host1")
	if retrieved == nil {
		t.Fatal("expected to retrieve saved KBItem")
	}
	val := retrieved.Get("test_key")
	if val != "test_value" {
		t.Errorf("expected 'test_value', got %v", val)
	}
}

func TestKnowledgeDB_Get_NonExistent(t *testing.T) {
	kb := NewKnowledgeDB(nil)
	retrieved := kb.Get("nonexistent")
	if retrieved != nil {
		t.Error("expected nil for non-existent key")
	}
}

func TestKnowledgeDB_SaveFingerprint(t *testing.T) {
	kb := NewKnowledgeDB(nil)
	flow := http.Flow{}

	// First save should return true (new fingerprint)
	result := kb.SaveFingerprint(&flow, "is_php")
	if !result {
		t.Error("expected true for first fingerprint save")
	}

	// Second save of same fingerprint should return false (duplicate)
	result = kb.SaveFingerprint(&flow, "is_php")
	if result {
		t.Error("expected false for duplicate fingerprint save")
	}

	// Save different fingerprint should return true
	result = kb.SaveFingerprint(&flow, "is_asp")
	if !result {
		t.Error("expected true for new fingerprint save")
	}
}

func TestKnowledgeDB_AddCheckRule(t *testing.T) {
	kb := NewKnowledgeDB(nil)
	kb.AddCheckRule(func(ctx context.Context, res resource.Resource) error {
		return nil
	})
	if len(kb.checkRules) != 1 {
		t.Errorf("expected 1 check rule, got %d", len(kb.checkRules))
	}
}

func TestKnowledgeDB_Process(t *testing.T) {
	kb := NewKnowledgeDB(nil)
	ruleCalled := false
	kb.AddCheckRule(func(ctx context.Context, res resource.Resource) error {
		ruleCalled = true
		return nil
	})
	flow := http.Flow{Request: &http.Request{}}
	kb.Process(context.Background(), &flow)
	if !ruleCalled {
		t.Error("expected check rule to be called during Process")
	}
}

func TestKnowledgeDB_Process_Error(t *testing.T) {
	kb := NewKnowledgeDB(nil)
	firstCalled := false
	secondCalled := false
	kb.AddCheckRule(func(ctx context.Context, res resource.Resource) error {
		firstCalled = true
		return fmt.Errorf("test error")
	})
	kb.AddCheckRule(func(ctx context.Context, res resource.Resource) error {
		secondCalled = true
		return nil
	})
	flow := http.Flow{Request: &http.Request{}}
	kb.Process(context.Background(), &flow)
	if !firstCalled {
		t.Error("expected first rule to be called")
	}
	if secondCalled {
		t.Error("expected second rule to NOT be called after first returns error")
	}
}

func TestKnowledgeDB_Resolve(t *testing.T) {
	kb := NewKnowledgeDB(nil)
	flow := http.Flow{}
	item := kb.Resolve(&flow)
	if item == nil {
		t.Fatal("expected non-nil KBItem from Resolve")
	}
	// Resolve should always return an item (creating if needed)
	item2 := kb.Resolve(&flow)
	if item2 == nil {
		t.Fatal("expected non-nil KBItem from second Resolve")
	}
	// Should return the same item for the same resource
	if item != item2 {
		t.Error("expected same KBItem for same resource")
	}
}

func TestKBItem_ConcurrentAccess(t *testing.T) {
	kb := NewKBItem()
	// Run concurrent set/get operations to verify thread safety
	done := make(chan bool, 2)
	go func() {
		for i := 0; i < 100; i++ {
			kb.Set("key", i)
		}
		done <- true
	}()
	go func() {
		for i := 0; i < 100; i++ {
			kb.Get("key")
		}
		done <- true
	}()
	<-done
	<-done
	// If we get here without deadlock or panic, the test passes
}
