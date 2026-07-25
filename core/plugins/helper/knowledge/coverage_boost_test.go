package knowledge

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"wscan/core/http"
	"wscan/core/resource"
	"wscan/core/utils/checker/filter"
)

// --- KBItem tests ---

func TestNewKBItem_CoverageBoost(t *testing.T) {
	item := NewKBItem()
	assert.NotNil(t, item, "NewKBItem should return non-nil")
	assert.NotNil(t, item.m, "internal map should be initialized")

	fp, ok := item.m["fingerprint"]
	assert.True(t, ok, "fingerprint key should exist")
	fps, ok := fp.([]string)
	assert.True(t, ok, "fingerprint should be []string")
	assert.Empty(t, fps, "fingerprint slice should be empty initially")
}

func TestKBItem_Exist_CoverageBoost(t *testing.T) {
	item := NewKBItem()

	// Key that doesn't exist
	assert.False(t, item.Exist("missing"), "missing key should not exist")

	// Key that exists
	item.Set("present", 42)
	assert.True(t, item.Exist("present"), "set key should exist")

	// Default fingerprint key
	assert.True(t, item.Exist("fingerprint"), "default fingerprint key should exist")
}

func TestKBItem_Get_CoverageBoost(t *testing.T) {
	item := NewKBItem()

	// Get non-existent key
	assert.Nil(t, item.Get("missing"), "missing key should return nil")

	// Get existing key
	item.Set("name", "test")
	assert.Equal(t, "test", item.Get("name"), "should return set value")

	// Get with different types
	item.Set("count", 99)
	assert.Equal(t, 99, item.Get("count"), "should return int value")
}

func TestKBItem_Remove_CoverageBoost(t *testing.T) {
	item := NewKBItem()

	item.Set("toRemove", "value")
	assert.True(t, item.Exist("toRemove"), "key should exist before remove")

	item.Remove("toRemove")
	assert.False(t, item.Exist("toRemove"), "key should not exist after remove")
	assert.Nil(t, item.Get("toRemove"), "removed key should return nil")

	// Remove non-existent key should not panic
	item.Remove("neverExisted")
}

func TestKBItem_Set_CoverageBoost(t *testing.T) {
	item := NewKBItem()

	// Set and verify
	item.Set("key1", "val1")
	assert.Equal(t, "val1", item.Get("key1"))

	// Overwrite
	item.Set("key1", "val2")
	assert.Equal(t, "val2", item.Get("key1"), "Set should overwrite existing value")

	// Set multiple keys
	item.Set("key2", "val2")
	item.Set("key3", "val3")
	assert.Equal(t, "val2", item.Get("key2"))
	assert.Equal(t, "val3", item.Get("key3"))
}

func TestKBItem_ConcurrentAccess_CoverageBoost(t *testing.T) {
	item := NewKBItem()
	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			item.Set("key", i)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			item.Get("key")
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			item.Exist("key")
		}
	}()

	wg.Wait()
	// If we reach here without deadlock, test passes
}

// --- KnowledgeDB tests ---

func TestNewKnowledgeDB_CoverageBoost(t *testing.T) {
	kb := NewKnowledgeDB(nil)
	assert.NotNil(t, kb, "NewKnowledgeDB should return non-nil")
	assert.NotNil(t, kb.stub, "stub map should be initialized")
	assert.NotNil(t, kb.checkRules, "checkRules should be initialized")
	assert.Empty(t, kb.checkRules, "checkRules should be empty initially")
	assert.NotNil(t, kb.httpClient, "httpClient should be initialized")
}

func TestNewKnowledgeDB_WithFilter(t *testing.T) {
	f := filter.NewSyncMapFilter()
	kb := NewKnowledgeDB(f)
	assert.NotNil(t, kb)
	assert.Equal(t, f, kb.filter)
}

func TestKnowledgeDB_Close_CoverageBoost(t *testing.T) {
	f := filter.NewSyncMapFilter()
	kb := NewKnowledgeDB(f)
	// Close should not panic and should call filter.Close()
	kb.Close()
}

func TestKnowledgeDB_Get_CoverageBoost(t *testing.T) {
	kb := NewKnowledgeDB(nil)

	// Get non-existent key
	assert.Nil(t, kb.Get("missing"), "non-existent key should return nil")

	// Save then get
	item := NewKBItem()
	item.Set("innerKey", "innerVal")
	kb.Save("host1", item)

	retrieved := kb.Get("host1")
	assert.NotNil(t, retrieved, "saved key should return non-nil")
	assert.Equal(t, "innerVal", retrieved.Get("innerKey"), "retrieved item should have correct value")
}

func TestKnowledgeDB_Save_CoverageBoost(t *testing.T) {
	kb := NewKnowledgeDB(nil)

	item1 := NewKBItem()
	item1.Set("a", 1)
	kb.Save("key1", item1)
	assert.Equal(t, item1, kb.Get("key1"), "saved item should be retrievable")

	// Overwrite with new item
	item2 := NewKBItem()
	item2.Set("b", 2)
	kb.Save("key1", item2)
	assert.Equal(t, item2, kb.Get("key1"), "Save should overwrite existing item")
}

func TestKnowledgeDB_Resolve_CoverageBoost(t *testing.T) {
	kb := NewKnowledgeDB(nil)
	flow := http.Flow{}

	// First resolve creates a new item
	item1 := kb.Resolve(&flow)
	assert.NotNil(t, item1, "Resolve should return non-nil KBItem")

	// Second resolve should return the same item (same key "xxxx")
	item2 := kb.Resolve(&flow)
	assert.Equal(t, item1, item2, "Resolve should return same item for same resource")
}

func TestKnowledgeDB_SaveFingerprint_CoverageBoost(t *testing.T) {
	kb := NewKnowledgeDB(nil)
	flow := http.Flow{}

	// First save of a fingerprint returns true
	result := kb.SaveFingerprint(&flow, "is_php")
	assert.True(t, result, "first fingerprint save should return true")

	// Duplicate save returns false
	result = kb.SaveFingerprint(&flow, "is_php")
	assert.False(t, result, "duplicate fingerprint save should return false")

	// Different fingerprint returns true
	result = kb.SaveFingerprint(&flow, "is_asp")
	assert.True(t, result, "new fingerprint save should return true")

	// Different resource resolves to same key "xxxx" in current implementation,
	// so duplicate fingerprint from a different Flow still returns false
	flow2 := http.Flow{}
	result = kb.SaveFingerprint(&flow2, "is_php")
	assert.False(t, result, "duplicate fingerprint on different resource still returns false since Resolve uses same key")

	// But a new fingerprint on the second resource returns true
	result = kb.SaveFingerprint(&flow2, "is_java")
	assert.True(t, result, "new fingerprint on different resource should return true")
}

func TestKnowledgeDB_AddCheckRule_CoverageBoost(t *testing.T) {
	kb := NewKnowledgeDB(nil)

	assert.Empty(t, kb.checkRules, "should start with no rules")

	kb.AddCheckRule(func(ctx context.Context, res resource.Resource) error {
		return nil
	})
	assert.Len(t, kb.checkRules, 1, "should have 1 rule after adding")

	kb.AddCheckRule(func(ctx context.Context, res resource.Resource) error {
		return fmt.Errorf("test error")
	})
	assert.Len(t, kb.checkRules, 2, "should have 2 rules after adding another")
}

func TestKnowledgeDB_Process_CoverageBoost(t *testing.T) {
	kb := NewKnowledgeDB(nil)
	ruleCalled := false
	kb.AddCheckRule(func(ctx context.Context, res resource.Resource) error {
		ruleCalled = true
		return nil
	})

	flow := http.Flow{Request: &http.Request{}}
	kb.Process(context.Background(), &flow)
	assert.True(t, ruleCalled, "check rule should be called during Process")
}

func TestKnowledgeDB_Process_ErrorStopsProcessing(t *testing.T) {
	kb := NewKnowledgeDB(nil)
	firstCalled := false
	secondCalled := false

	kb.AddCheckRule(func(ctx context.Context, res resource.Resource) error {
		firstCalled = true
		return fmt.Errorf("rule error")
	})
	kb.AddCheckRule(func(ctx context.Context, res resource.Resource) error {
		secondCalled = true
		return nil
	})

	flow := http.Flow{Request: &http.Request{}}
	kb.Process(context.Background(), &flow)

	assert.True(t, firstCalled, "first rule should be called")
	assert.False(t, secondCalled, "second rule should NOT be called after first returns error")
}

func TestKnowledgeDB_Process_MultipleRules(t *testing.T) {
	kb := NewKnowledgeDB(nil)
	callCount := 0

	kb.AddCheckRule(func(ctx context.Context, res resource.Resource) error {
		callCount++
		return nil
	})
	kb.AddCheckRule(func(ctx context.Context, res resource.Resource) error {
		callCount++
		return nil
	})
	kb.AddCheckRule(func(ctx context.Context, res resource.Resource) error {
		callCount++
		return nil
	})

	flow := http.Flow{Request: &http.Request{}}
	kb.Process(context.Background(), &flow)
	assert.Equal(t, 3, callCount, "all three rules should be called")
}

func TestKnowledgeDB_checkDVWA_CoverageBoost(t *testing.T) {
	kb := NewKnowledgeDB(nil)
	flow := http.Flow{}
	// Empty function, just ensure it doesn't panic
	kb.checkDVWA(context.Background(), &flow)
}

func TestKnowledgeDB_checkPHP_CoverageBoost(t *testing.T) {
	kb := NewKnowledgeDB(nil)
	flow := http.Flow{}
	kb.checkPHP(context.Background(), &flow)
}

func TestKnowledgeDB_checkStruts_CoverageBoost(t *testing.T) {
	kb := NewKnowledgeDB(nil)
	flow := http.Flow{}
	kb.checkStruts(context.Background(), &flow)
}

func TestKnowledgeDB_saveResult_CoverageBoost(t *testing.T) {
	kb := NewKnowledgeDB(nil)
	// Empty function, just ensure it doesn't panic
	kb.saveResult()
}

func TestKnowledgeDB_SaveFingerprint_MultipleDifferent(t *testing.T) {
	kb := NewKnowledgeDB(nil)
	flow := http.Flow{}

	fingerprints := []string{"fp1", "fp2", "fp3", "fp4", "fp5"}
	for i, fp := range fingerprints {
		result := kb.SaveFingerprint(&flow, fp)
		assert.True(t, result, "first save of %s should return true", fp)

		// Verify duplicate returns false
		result = kb.SaveFingerprint(&flow, fp)
		assert.False(t, result, "duplicate save of %s should return false", fp)

		_ = i
	}
}

func TestKnowledgeDB_SaveAndGet_MultipleKeys(t *testing.T) {
	kb := NewKnowledgeDB(nil)

	for i := 0; i < 10; i++ {
		item := NewKBItem()
		item.Set("index", i)
		kb.Save(fmt.Sprintf("key%d", i), item)
	}

	for i := 0; i < 10; i++ {
		retrieved := kb.Get(fmt.Sprintf("key%d", i))
		assert.NotNil(t, retrieved, "key%d should be retrievable", i)
		assert.Equal(t, i, retrieved.Get("index"), "key%d should have correct value", i)
	}
}
