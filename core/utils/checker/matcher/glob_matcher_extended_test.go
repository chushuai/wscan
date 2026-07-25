package matcher

import (
	"testing"
)

func TestGlobMatcher_Add_Empty(t *testing.T) {
	m := NewGlobMatcher()
	err := m.Add([]string{})
	if err != nil {
		t.Errorf("Add() with empty slice returned error: %v", err)
	}
	if !m.IsEmpty() {
		t.Error("should be empty after adding empty slice")
	}
}

func TestGlobMatcher_Add_DuplicatePattern(t *testing.T) {
	m := NewGlobMatcher()
	err := m.Add([]string{"*test*"})
	if err != nil {
		t.Fatalf("first Add() returned error: %v", err)
	}
	// Adding same pattern again should not add duplicate
	err = m.Add([]string{"*test*"})
	if err != nil {
		t.Errorf("second Add() returned error: %v", err)
	}
	if !m.Match("mytestvalue") {
		t.Error("should still match after duplicate add")
	}
}

func TestGlobMatcher_Add_InvalidPattern(t *testing.T) {
	m := NewGlobMatcher()
	// Test with an invalid glob pattern
	err := m.Add([]string{"[invalid"})
	if err == nil {
		t.Error("expected error for invalid glob pattern")
	}
}

func TestGlobMatcher_Match_ExactPattern(t *testing.T) {
	m := NewGlobMatcher()
	m.Add([]string{"exact"})

	if !m.Match("exact") {
		t.Error("should match exact string")
	}
	if m.Match("notexact") {
		t.Error("should not match different string")
	}
}

func TestGlobMatcher_Match_WildcardPrefix(t *testing.T) {
	m := NewGlobMatcher()
	m.Add([]string{"*suffix"})

	if !m.Match("testsuffix") {
		t.Error("should match with prefix wildcard")
	}
	if !m.Match("suffix") {
		t.Error("should match exact suffix")
	}
	if m.Match("other") {
		t.Error("should not match string not ending with suffix")
	}
}

func TestGlobMatcher_Match_MultiplePatterns(t *testing.T) {
	m := NewGlobMatcher()
	m.Add([]string{"*admin*", "*config*"})

	if !m.Match("my_admin_page") {
		t.Error("should match admin pattern")
	}
	if !m.Match("config_file") {
		t.Error("should match config pattern")
	}
	if m.Match("random_page") {
		t.Error("should not match random page")
	}
}

func TestGlobMatcher_IsEmpty_AfterAdd(t *testing.T) {
	m := NewGlobMatcher()
	if !m.IsEmpty() {
		t.Error("should be empty initially")
	}
	m.Add([]string{"*"})
	if m.IsEmpty() {
		t.Error("should not be empty after Add")
	}
}

func TestNewGlobMatcher_NilPattern(t *testing.T) {
	m := NewGlobMatcher()
	// Initially pattern map is initialized but empty
	if !m.IsEmpty() {
		t.Error("new matcher should be empty")
	}
}
