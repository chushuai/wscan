package utils

import (
	"testing"
)

func TestAtoi(t *testing.T) {
	tests := []struct {
		input  string
		expect int
	}{
		{"42", 42},
		{"0", 0},
		{"-1", -1},
		{"12345", 12345},
		{"", 0},    // invalid, returns 0
		{"abc", 0}, // invalid, returns 0
	}
	for _, tt := range tests {
		result := Atoi(tt.input)
		if result != tt.expect {
			t.Errorf("Atoi(%q) = %d, want %d", tt.input, result, tt.expect)
		}
	}
}

func TestItoa(t *testing.T) {
	tests := []struct {
		input  int
		expect string
	}{
		{42, "42"},
		{0, "0"},
		{-1, "-1"},
	}
	for _, tt := range tests {
		result := Itoa(tt.input)
		if result != tt.expect {
			t.Errorf("Itoa(%d) = %q, want %q", tt.input, result, tt.expect)
		}
	}
}

func TestAtof(t *testing.T) {
	tests := []struct {
		input  string
		expect float64
	}{
		{"3.14", 3.14},
		{"0", 0.0},
		{"-1.5", -1.5},
		{"", 0},    // invalid, returns 0
		{"abc", 0}, // invalid, returns 0
	}
	for _, tt := range tests {
		result := Atof(tt.input)
		// Use approximate comparison for floats
		if (result-tt.expect) > 0.0001 || (tt.expect-result) > 0.0001 {
			t.Errorf("Atof(%q) = %f, want %f", tt.input, result, tt.expect)
		}
	}
}

func TestAtob(t *testing.T) {
	tests := []struct {
		input  string
		expect bool
	}{
		{"true", true},
		{"false", false},
		{"True", true},
		{"1", true},
		{"0", false},
		{"abc", false}, // invalid, returns false
	}
	for _, tt := range tests {
		result := Atob(tt.input)
		if result != tt.expect {
			t.Errorf("Atob(%q) = %v, want %v", tt.input, result, tt.expect)
		}
	}
}

func TestAnyToBytes(t *testing.T) {
	tests := []struct {
		input  any
		expect string
	}{
		{nil, ""},
		{"hello", "hello"},
		{[]byte("bytes"), "bytes"},
		{true, "true"},
		{false, "false"},
		{float64(3.14), "3.14"},
		{float32(2.5), "2.5"},
		{int(42), "42"},
		{int64(100), "100"},
		{int32(50), "50"},
		{int16(10), "10"},
		{int8(5), "5"},
		{uint(99), "99"},
		{uint64(200), "200"},
		{uint32(150), "150"},
		{uint16(20), "20"},
		{uint8(8), "8"},
	}
	for _, tt := range tests {
		result := AnyToBytes(tt.input)
		if string(result) != tt.expect {
			t.Errorf("AnyToBytes(%v) = %q, want %q", tt.input, string(result), tt.expect)
		}
	}

	// Test with error type
	err := testError("error message")
	result := AnyToBytes(err)
	if string(result) != "error message" {
		t.Errorf("AnyToBytes(error) = %q, want %q", string(result), "error message")
	}

	// Test with fmt.Stringer
	s := stringerTest{"stringer output"}
	result = AnyToBytes(s)
	if string(result) != "stringer output" {
		t.Errorf("AnyToBytes(Stringer) = %q, want %q", string(result), "stringer output")
	}

	// Test with unknown type (falls through to default - %v format without field names)
	result = AnyToBytes(struct{ A int }{A: 42})
	if string(result) != "{42}" {
		t.Errorf("AnyToBytes(struct) = %q, want %q", string(result), "{42}")
	}
}

type testError string

func (e testError) Error() string {
	return string(e)
}

func TestAnyToString(t *testing.T) {
	tests := []struct {
		input  any
		expect string
	}{
		{nil, ""},
		{"hello", "hello"},
		{42, "42"},
		{true, "true"},
		{3.14, "3.14"},
	}
	for _, tt := range tests {
		result := AnyToString(tt.input)
		if result != tt.expect {
			t.Errorf("AnyToString(%v) = %q, want %q", tt.input, result, tt.expect)
		}
	}
}
