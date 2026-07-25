package utils

import (
	"testing"
)

func TestIsValidInteger(t *testing.T) {
	tests := []struct {
		input  string
		expect bool
	}{
		{"42", true},
		{"0", true},
		{"-1", true},
		{"123456789", true},
		{"3.14", false},
		{"abc", false},
		{"", false},
		{"12abc", false},
		{"99999999999999999999", false}, // overflows int64
	}
	for _, tt := range tests {
		result := IsValidInteger(tt.input)
		if result != tt.expect {
			t.Errorf("IsValidInteger(%q) = %v, want %v", tt.input, result, tt.expect)
		}
	}
}

func TestIsValidFloat(t *testing.T) {
	tests := []struct {
		input  string
		expect bool
	}{
		{"3.14", true},
		{"0.0", true},
		{"-1.5", true},
		{"42", false}, // valid float but no dot after trimming dots
		{"abc", false},
		{"", false},
		{"1.", true}, // has a dot
		{".5", true}, // has a dot
	}
	for _, tt := range tests {
		result := IsValidFloat(tt.input)
		if result != tt.expect {
			t.Errorf("IsValidFloat(%q) = %v, want %v", tt.input, result, tt.expect)
		}
	}
}

func TestIsValidBool(t *testing.T) {
	tests := []struct {
		input  string
		expect bool
	}{
		{"true", true},
		{"false", true},
		{"True", true},
		{"False", true},
		{"1", true},
		{"0", true},
		{"yes", false},
		{"no", false},
		{"", false},
		{"abc", false},
	}
	for _, tt := range tests {
		result := IsValidBool(tt.input)
		if result != tt.expect {
			t.Errorf("IsValidBool(%q) = %v, want %v", tt.input, result, tt.expect)
		}
	}
}
