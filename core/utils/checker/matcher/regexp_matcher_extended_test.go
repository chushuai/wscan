package matcher

import (
	"testing"
)

func TestNewRegexpMatcher_IsEmpty(t *testing.T) {
	r := NewRegexpMatcher()
	if !r.IsEmpty() {
		t.Error("new RegexpMatcher should be empty")
	}
}

func TestRegexpMatcher_Add_Empty(t *testing.T) {
	r := NewRegexpMatcher()
	err := r.Add([]string{})
	if err != nil {
		t.Errorf("Add() with empty slice returned error: %v", err)
	}
	if !r.IsEmpty() {
		t.Error("should still be empty after adding empty slice")
	}
}

func TestRegexpMatcher_Add_InvalidPattern(t *testing.T) {
	r := NewRegexpMatcher()
	err := r.Add([]string{"[invalid"})
	if err == nil {
		t.Error("expected error for invalid regexp pattern")
	}
}

func TestRegexpMatcher_Add_MultiplePatterns(t *testing.T) {
	r := NewRegexpMatcher()
	err := r.Add([]string{"^test[0-9]+$", "^example$"})
	if err != nil {
		t.Errorf("Add() returned error: %v", err)
	}
	if r.IsEmpty() {
		t.Error("should not be empty after Add")
	}
}

func TestRegexpMatcher_Match_EmailPattern(t *testing.T) {
	r := NewRegexpMatcher()
	r.Add([]string{`^[a-zA-Z0-9]+@example\.com$`})

	if !r.Match("user@example.com") {
		t.Error("should match valid email")
	}
	if r.Match("user@other.com") {
		t.Error("should not match email at different domain")
	}
	if r.Match("invalid-email") {
		t.Error("should not match invalid email")
	}
}

func TestRegexpMatcher_Match_IPPattern(t *testing.T) {
	r := NewRegexpMatcher()
	r.Add([]string{`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`})

	if !r.Match("192.168.1.1") {
		t.Error("should match IP address pattern")
	}
	if r.Match("not-an-ip") {
		t.Error("should not match non-IP string")
	}
}

func TestRegexpMatcher_Add_SinglePattern(t *testing.T) {
	r := NewRegexpMatcher()
	err := r.Add([]string{"^hello$"})
	if err != nil {
		t.Errorf("Add() returned error: %v", err)
	}
	if r.IsEmpty() {
		t.Error("should not be empty after Add")
	}
	if !r.Match("hello") {
		t.Error("should match 'hello'")
	}
	if r.Match("world") {
		t.Error("should not match 'world'")
	}
}
