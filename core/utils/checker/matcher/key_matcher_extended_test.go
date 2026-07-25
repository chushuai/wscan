package matcher

import (
	"testing"
)

func TestNewKeyMatcher_IsEmpty(t *testing.T) {
	km := NewKeyMatcher()
	if !km.IsEmpty() {
		t.Error("new KeyMatcher should be empty")
	}
}

func TestKeyMatcher_Add_Empty(t *testing.T) {
	km := NewKeyMatcher()
	err := km.Add([]string{})
	if err == nil {
		t.Error("Add() with empty slice should return error")
	}
}

func TestKeyMatcher_Add_Single(t *testing.T) {
	km := NewKeyMatcher()
	err := km.Add([]string{"key1"})
	if err != nil {
		t.Errorf("Add() returned error: %v", err)
	}
	if km.IsEmpty() {
		t.Error("KeyMatcher should not be empty after Add")
	}
}

func TestKeyMatcher_Match_Found(t *testing.T) {
	km := NewKeyMatcher()
	km.Add([]string{"abc", "def"})

	if !km.Match("abc") {
		t.Error("should match existing key 'abc'")
	}
	if !km.Match("def") {
		t.Error("should match existing key 'def'")
	}
}

func TestKeyMatcher_Match_NotFound(t *testing.T) {
	km := NewKeyMatcher()
	km.Add([]string{"abc", "def"})

	if km.Match("xyz") {
		t.Error("should not match non-existing key 'xyz'")
	}
}

func TestKeyMatcher_Add_MultipleBatches(t *testing.T) {
	km := NewKeyMatcher()
	km.Add([]string{"key1"})
	km.Add([]string{"key2", "key3"})

	if !km.Match("key1") {
		t.Error("should match key1 from first batch")
	}
	if !km.Match("key2") {
		t.Error("should match key2 from second batch")
	}
	if !km.Match("key3") {
		t.Error("should match key3 from second batch")
	}
	if !km.IsEmpty() {
		// Should not be empty
	}
}

func TestKeyMatcher_Add_DuplicateKeys(t *testing.T) {
	km := NewKeyMatcher()
	km.Add([]string{"key1"})
	km.Add([]string{"key1"})

	// Should still work - duplicates are just overwritten
	if !km.Match("key1") {
		t.Error("should match key1 even after duplicate add")
	}
}

func TestKeyMatcher_IsEmpty_AfterAdd(t *testing.T) {
	km := NewKeyMatcher()
	if !km.IsEmpty() {
		t.Error("should be empty initially")
	}
	km.Add([]string{"key1"})
	if km.IsEmpty() {
		t.Error("should not be empty after Add")
	}
}

func TestKeyMatcher_Match_SpecialCharacters(t *testing.T) {
	km := NewKeyMatcher()
	km.Add([]string{"key-with-dash", "key.with.dot", "key_with_underscore"})

	if !km.Match("key-with-dash") {
		t.Error("should match key with dash")
	}
	if !km.Match("key.with.dot") {
		t.Error("should match key with dot")
	}
	if !km.Match("key_with_underscore") {
		t.Error("should match key with underscore")
	}
}
