package utils

import (
	"testing"
)

func TestInterfaceToBytes(t *testing.T) {
	tests := []struct {
		input  any
		expect string
	}{
		{"hello", "hello"},
		{[]byte("bytes"), "bytes"},
		{42, "42"},
		{true, "true"},
		{3.14, "3.14"},
		{nil, ""},
		{int64(100), "100"},
		{uint(50), "50"},
	}
	for _, tt := range tests {
		result := InterfaceToBytes(tt.input)
		if string(result) != tt.expect {
			t.Errorf("InterfaceToBytes(%v) = %q, want %q", tt.input, string(result), tt.expect)
		}
	}
}

func TestInterfaceToString(t *testing.T) {
	// Test with regular types
	tests := []struct {
		input  any
		expect string
	}{
		{"hello", "hello"},
		{42, "42"},
		{true, "true"},
		{nil, ""},
		{3.14, "3.14"},
	}
	for _, tt := range tests {
		result := InterfaceToString(tt.input)
		if result != tt.expect {
			t.Errorf("InterfaceToString(%v) = %q, want %q", tt.input, result, tt.expect)
		}
	}

	// Test with Stringer interface
	s := stringerTest{"custom"}
	result := InterfaceToString(s)
	if result != "custom" {
		t.Errorf("InterfaceToString(Stringer) = %q, want %q", result, "custom")
	}
}

type stringerTest struct {
	val string
}

func (s stringerTest) String() string {
	return s.val
}

func TestInterfaceToStringSlice(t *testing.T) {
	// Test with nil
	result := InterfaceToStringSlice(nil)
	if len(result) != 0 {
		t.Errorf("InterfaceToStringSlice(nil) should return empty slice, got %v", result)
	}

	// Test with single string
	result = InterfaceToStringSlice("hello")
	if len(result) != 1 || result[0] != "hello" {
		t.Errorf("InterfaceToStringSlice(\"hello\") = %v, want [hello]", result)
	}

	// Test with slice of strings
	result = InterfaceToStringSlice([]string{"a", "b", "c"})
	if len(result) != 3 || result[0] != "a" || result[1] != "b" || result[2] != "c" {
		t.Errorf("InterfaceToStringSlice([]string{\"a\",\"b\",\"c\"}) = %v, want [a b c]", result)
	}

	// Test with slice of ints
	result = InterfaceToStringSlice([]int{1, 2, 3})
	if len(result) != 3 || result[0] != "1" || result[1] != "2" || result[2] != "3" {
		t.Errorf("InterfaceToStringSlice([]int{1,2,3}) = %v, want [1 2 3]", result)
	}
}

func TestFilterUniqueStrings(t *testing.T) {
	tests := []struct {
		input  []string
		expect []string
	}{
		{[]string{}, []string{}},
		{[]string{"a"}, []string{"a"}},
		{[]string{"a", "b", "c"}, []string{"a", "b", "c"}},
		{[]string{"a", "a", "b", "b", "c"}, []string{"a", "b", "c"}},
		{[]string{"a", "a", "a"}, []string{"a"}},
		{nil, []string{}},
	}
	for _, tt := range tests {
		result := FilterUniqueStrings(tt.input)
		if len(result) != len(tt.expect) {
			t.Errorf("FilterUniqueStrings(%v) length = %d, want %d", tt.input, len(result), len(tt.expect))
			continue
		}
		// Check order is preserved and elements match
		for i, v := range result {
			if v != tt.expect[i] {
				t.Errorf("FilterUniqueStrings(%v)[%d] = %q, want %q", tt.input, i, v, tt.expect[i])
			}
		}
	}
}
