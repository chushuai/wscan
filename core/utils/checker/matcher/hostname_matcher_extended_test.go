package matcher

import (
	"testing"
)

func TestHostsMatcher_IsEmpty_Initially(t *testing.T) {
	hm := NewHostsMatcher()
	if !hm.IsEmpty() {
		t.Error("new HostsMatcher should be empty")
	}
}

func TestHostsMatcher_Add_Hostname(t *testing.T) {
	hm := NewHostsMatcher()
	err := hm.Add([]string{"www.example.com"})
	if err != nil {
		t.Errorf("Add() returned error: %v", err)
	}
	if hm.IsEmpty() {
		t.Error("HostsMatcher should not be empty after Add")
	}
}

func TestHostsMatcher_Match_Hostname(t *testing.T) {
	hm := NewHostsMatcher()
	hm.Add([]string{"www.example.com"})

	if !hm.Match("www.example.com") {
		t.Error("should match exact hostname")
	}
	if hm.Match("other.example.com") {
		t.Error("should not match different hostname")
	}
}

func TestHostsMatcher_Match_Wildcard(t *testing.T) {
	hm := NewHostsMatcher()
	hm.Add([]string{"*.example.com"})

	if !hm.Match("www.example.com") {
		t.Error("should match wildcard *.example.com with www.example.com")
	}
	if !hm.Match("api.example.com") {
		t.Error("should match wildcard *.example.com with api.example.com")
	}
	if hm.Match("example.org") {
		t.Error("should not match different domain")
	}
}

func TestHostsMatcher_Add_IPv4(t *testing.T) {
	hm := NewHostsMatcher()
	err := hm.Add([]string{"1.1.1.1"})
	if err != nil {
		t.Errorf("Add() with IPv4 returned error: %v", err)
	}
	if hm.IsEmpty() {
		t.Error("should not be empty after adding IPv4")
	}
}

func TestHostsMatcher_Add_IPv6(t *testing.T) {
	hm := NewHostsMatcher()
	err := hm.Add([]string{"::1"})
	if err != nil {
		t.Errorf("Add() with IPv6 returned error: %v", err)
	}
	if hm.IsEmpty() {
		t.Error("should not be empty after adding IPv6")
	}
}

func TestHostsMatcher_Add_Multiple(t *testing.T) {
	hm := NewHostsMatcher()
	err := hm.Add([]string{"host1.com", "host2.com", "*.host3.com"})
	if err != nil {
		t.Errorf("Add() returned error: %v", err)
	}

	if !hm.Match("host1.com") {
		t.Error("should match host1.com")
	}
	if !hm.Match("host2.com") {
		t.Error("should match host2.com")
	}
	if !hm.Match("api.host3.com") {
		t.Error("should match wildcard for host3.com")
	}
}

func TestHostsMatcher_Match_NoGlobs(t *testing.T) {
	// If globs is nil, Match should return false
	hm := &HostsMatcher{}
	result := hm.Match("anything")
	if result {
		t.Error("Match on nil globs should return false")
	}
}

func TestHostsMatcher_Add_Empty(t *testing.T) {
	hm := NewHostsMatcher()
	err := hm.Add([]string{})
	if err != nil {
		t.Errorf("Add() with empty slice returned error: %v", err)
	}
	if !hm.IsEmpty() {
		t.Error("should still be empty after adding empty slice")
	}
}
