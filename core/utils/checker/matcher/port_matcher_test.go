package matcher

import (
	"testing"
)

func TestNewPortMatcher_IsEmpty(t *testing.T) {
	pm := NewPortMatcher()
	if !pm.IsEmpty() {
		t.Error("new PortMatcher should be empty")
	}
}

func TestPortMatcher_Add_SinglePort(t *testing.T) {
	pm := NewPortMatcher()
	err := pm.Add([]string{"80"})
	if err != nil {
		t.Errorf("Add() returned error: %v", err)
	}
	if pm.IsEmpty() {
		t.Error("PortMatcher should not be empty after Add")
	}
}

func TestPortMatcher_Match_SinglePort(t *testing.T) {
	pm := NewPortMatcher()
	pm.Add([]string{"80", "443"})

	if !pm.Match("80") {
		t.Error("should match port 80")
	}
	if !pm.Match("443") {
		t.Error("should match port 443")
	}
	if pm.Match("22") {
		t.Error("should not match port 22")
	}
}

func TestPortMatcher_Add_PortRange(t *testing.T) {
	pm := NewPortMatcher()
	err := pm.Add([]string{"8080-8090"})
	if err != nil {
		t.Errorf("Add() with range returned error: %v", err)
	}
	if pm.IsEmpty() {
		t.Error("should not be empty after adding range")
	}
}

func TestPortMatcher_Match_PortRange(t *testing.T) {
	pm := NewPortMatcher()
	pm.Add([]string{"8080-8090"})

	if !pm.Match("8080") {
		t.Error("should match start of range")
	}
	if !pm.Match("8085") {
		t.Error("should match middle of range")
	}
	if !pm.Match("8090") {
		t.Error("should match end of range")
	}
	if pm.Match("8079") {
		t.Error("should not match below range")
	}
	if pm.Match("8091") {
		t.Error("should not match above range")
	}
}

func TestPortMatcher_Add_Mixed(t *testing.T) {
	pm := NewPortMatcher()
	err := pm.Add([]string{"80", "443", "8080-8090"})
	if err != nil {
		t.Errorf("Add() returned error: %v", err)
	}

	if !pm.Match("80") {
		t.Error("should match single port 80")
	}
	if !pm.Match("8085") {
		t.Error("should match port in range 8080-8090")
	}
	if pm.Match("22") {
		t.Error("should not match port 22")
	}
}

func TestPortMatcher_Match_EmptyPort(t *testing.T) {
	pm := NewPortMatcher()
	pm.Add([]string{"80"})

	if pm.Match("") {
		t.Error("empty port string should not match")
	}
}

func TestPortMatcher_Match_InvalidPort(t *testing.T) {
	pm := NewPortMatcher()
	pm.Add([]string{"80"})

	if pm.Match("abc") {
		t.Error("non-numeric port should not match")
	}
}

func TestPortMatcher_Add_InvalidPort(t *testing.T) {
	pm := NewPortMatcher()
	err := pm.Add([]string{"notaport"})
	if err == nil {
		t.Error("Add() with invalid port should return error")
	}
}

func TestPortMatcher_Add_InvalidRange(t *testing.T) {
	tests := []struct {
		name  string
		input []string
	}{
		{"invalid range format", []string{"80-90-100"}},
		{"non-numeric range start", []string{"abc-90"}},
		{"non-numeric range end", []string{"80-abc"}},
		{"start > end", []string{"90-80"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm := NewPortMatcher()
			err := pm.Add(tt.input)
			if err == nil {
				t.Error("expected error for invalid input")
			}
		})
	}
}

func TestPortMatcher_Add_Empty(t *testing.T) {
	pm := NewPortMatcher()
	err := pm.Add([]string{})
	if err != nil {
		t.Errorf("Add() with empty slice should not return error, got: %v", err)
	}
	if !pm.IsEmpty() {
		t.Error("should still be empty after adding empty slice")
	}
}

func TestPortMatcher_MultipleRanges(t *testing.T) {
	pm := NewPortMatcher()
	pm.Add([]string{"80-85", "443-445"})

	if !pm.Match("82") {
		t.Error("should match port in first range")
	}
	if !pm.Match("444") {
		t.Error("should match port in second range")
	}
	if pm.Match("86") {
		t.Error("should not match port outside both ranges")
	}
}

func TestPortMatcher_Match_SinglePortString(t *testing.T) {
	pm := NewPortMatcher()
	pm.Add([]string{"8080"})

	// Match takes string, should parse it
	if !pm.Match("8080") {
		t.Error("should match port '8080'")
	}
}
