package utils

import (
	"testing"
)

func TestIStringContains(t *testing.T) {
	tests := []struct {
		s      string
		substr string
		expect bool
	}{
		{"Hello World", "hello", true},
		{"Hello World", "WORLD", true},
		{"Hello World", "lo wo", true},
		{"Hello World", "xyz", false},
		{"", "", true},
		{"abc", "", true},
		{"", "a", false},
		{"ABC", "abc", true},
	}
	for _, tt := range tests {
		result := IStringContains(tt.s, tt.substr)
		if result != tt.expect {
			t.Errorf("IStringContains(%q, %q) = %v, want %v", tt.s, tt.substr, result, tt.expect)
		}
	}
}

func TestIStringHasPrefix(t *testing.T) {
	tests := []struct {
		s      string
		prefix string
		expect bool
	}{
		{"Hello World", "hello", true},
		{"Hello World", "HELLO", true},
		{"Hello World", "world", false},
		{"", "", true},
		{"abc", "A", true},
		{"ABC", "a", true},
	}
	for _, tt := range tests {
		result := IStringHasPrefix(tt.s, tt.prefix)
		if result != tt.expect {
			t.Errorf("IStringHasPrefix(%q, %q) = %v, want %v", tt.s, tt.prefix, result, tt.expect)
		}
	}
}

func TestIBytesHasPrefix(t *testing.T) {
	tests := []struct {
		b      []byte
		prefix []byte
		expect bool
	}{
		{[]byte("Hello"), []byte("hello"), true},
		{[]byte("Hello"), []byte("HELLO"), true},
		{[]byte("Hello"), []byte("world"), false},
		{[]byte(""), []byte(""), true},
		{[]byte("ABC"), []byte("ab"), true},
	}
	for _, tt := range tests {
		result := IBytesHasPrefix(tt.b, tt.prefix)
		if result != tt.expect {
			t.Errorf("IBytesHasPrefix(%q, %q) = %v, want %v", tt.b, tt.prefix, result, tt.expect)
		}
	}
}

func TestIBytesContains(t *testing.T) {
	tests := []struct {
		b        []byte
		subslice []byte
		expect   bool
	}{
		{[]byte("Hello World"), []byte("hello"), true},
		{[]byte("Hello World"), []byte("WORLD"), true},
		{[]byte("Hello World"), []byte("xyz"), false},
		{[]byte(""), []byte(""), true},
		{[]byte("ABC"), []byte("bc"), true},
	}
	for _, tt := range tests {
		result := IBytesContains(tt.b, tt.subslice)
		if result != tt.expect {
			t.Errorf("IBytesContains(%q, %q) = %v, want %v", tt.b, tt.subslice, result, tt.expect)
		}
	}
}

func TestStringIIn(t *testing.T) {
	tests := []struct {
		s      string
		a      []string
		expect bool
	}{
		{"hello", []string{"HELLO", "world"}, true},
		{"WORLD", []string{"hello", "world"}, true},
		{"xyz", []string{"hello", "world"}, false},
		{"a", []string{}, false},
		{"", []string{""}, true},
		{"Go", []string{"go", "rust"}, true},
	}
	for _, tt := range tests {
		result := StringIIn(tt.s, tt.a)
		if result != tt.expect {
			t.Errorf("StringIIn(%q, %v) = %v, want %v", tt.s, tt.a, result, tt.expect)
		}
	}
}
