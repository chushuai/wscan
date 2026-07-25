package utils

import (
	"strings"
	"testing"
	"unicode"
)

func TestRandFromChoices(t *testing.T) {
	// Test with lowercase letters
	result := RandFromChoices(10, AsciiLowercase)
	if len(result) != 10 {
		t.Errorf("RandFromChoices returned wrong length: got %d, want 10", len(result))
	}
	for _, r := range result {
		if !unicode.IsLower(r) {
			t.Errorf("RandFromChoices returned non-lowercase char: %c", r)
		}
	}

	// Test with digits
	result = RandFromChoices(5, AsciiDigits)
	if len(result) != 5 {
		t.Errorf("RandFromChoices returned wrong length: got %d, want 5", len(result))
	}
	for _, r := range result {
		if r < '0' || r > '9' {
			t.Errorf("RandFromChoices returned non-digit char: %c", r)
		}
	}

	// Test with zero length
	result = RandFromChoices(0, AsciiLowercase)
	if len(result) != 0 {
		t.Errorf("RandFromChoices(0, ...) should return empty string, got %q", result)
	}

	// Test with single character choices
	result = RandFromChoices(3, "a")
	if result != "aaa" {
		t.Errorf("RandFromChoices with single choice 'a' should return 'aaa', got %q", result)
	}
}

func TestRandLetters(t *testing.T) {
	result := RandLetters(20)
	if len(result) != 20 {
		t.Errorf("RandLetters returned wrong length: got %d, want 20", len(result))
	}
	for _, r := range result {
		if !unicode.IsLower(r) {
			t.Errorf("RandLetters returned non-lowercase char: %c", r)
		}
	}
}

func TestRandLetterNumbers(t *testing.T) {
	result := RandLetterNumbers(15)
	if len(result) != 15 {
		t.Errorf("RandLetterNumbers returned wrong length: got %d, want 15", len(result))
	}
	for _, r := range result {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			t.Errorf("RandLetterNumbers returned invalid char: %c", r)
		}
	}
}

func TestRandLowLetterNumber(t *testing.T) {
	result := RandLowLetterNumber(12)
	if len(result) != 12 {
		t.Errorf("RandLowLetterNumber returned wrong length: got %d, want 12", len(result))
	}
	for _, r := range result {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
			t.Errorf("RandLowLetterNumber returned invalid char: %c", r)
		}
	}
}

func TestRandomStr(t *testing.T) {
	result := RandomStr("abc", 10)
	if len(result) != 10 {
		t.Errorf("RandomStr returned wrong length: got %d, want 10", len(result))
	}
	for _, r := range result {
		if r != 'a' && r != 'b' && r != 'c' {
			t.Errorf("RandomStr returned char outside choices: %c", r)
		}
	}

	// Test zero length
	result = RandomStr("abc", 0)
	if len(result) != 0 {
		t.Errorf("RandomStr with n=0 should return empty string, got %q", result)
	}
}

func TestMD5(t *testing.T) {
	tests := []struct {
		input  string
		expect string
	}{
		{"", "d41d8cd98f00b204e9800998ecf8427e"},
		{"hello", "5d41402abc4b2a76b9719d911017c592"},
		{"world", "7d793037a0760186574b0282f2f435e7"},
		{"test", "098f6bcd4621d373cade4e832627b4f6"},
	}
	for _, tt := range tests {
		result := MD5(tt.input)
		if result != tt.expect {
			t.Errorf("MD5(%q) = %q, want %q", tt.input, result, tt.expect)
		}
	}
}

func TestMD5String(t *testing.T) {
	// MD5String should produce the same result as MD5
	tests := []string{"", "hello", "world", "test"}
	for _, input := range tests {
		result := MD5String(input)
		expected := MD5(input)
		if result != expected {
			t.Errorf("MD5String(%q) = %q, MD5(%q) = %q, they should match", input, result, input, expected)
		}
	}
}

func TestSha256(t *testing.T) {
	tests := []struct {
		input  []byte
		expect string
	}{
		{[]byte(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{[]byte("hello"), "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"},
	}
	for _, tt := range tests {
		result := Sha256(tt.input)
		if result != tt.expect {
			t.Errorf("Sha256(%q) = %q, want %q", tt.input, result, tt.expect)
		}
	}
}

func TestReverseString(t *testing.T) {
	tests := []struct {
		input  string
		expect string
	}{
		{"", ""},
		{"a", "a"},
		{"ab", "ba"},
		{"hello", "olleh"},
		{"abc123", "321cba"},
		// Test with unicode
		{"中文", "文中"},
	}
	for _, tt := range tests {
		result := ReverseString(tt.input)
		if result != tt.expect {
			t.Errorf("ReverseString(%q) = %q, want %q", tt.input, result, tt.expect)
		}
	}
}

func TestStringHasPrefix(t *testing.T) {
	tests := []struct {
		s      string
		prefix string
		expect bool
	}{
		{"hello", "hel", true},
		{"hello", "hello", true},
		{"hello", "helloo", false},
		{"hello", "world", false},
		{"", "", true},
		{"abc", "", true},
		{"", "a", false},
	}
	for _, tt := range tests {
		result := StringHasPrefix(tt.s, tt.prefix)
		if result != tt.expect {
			t.Errorf("StringHasPrefix(%q, %q) = %v, want %v", tt.s, tt.prefix, result, tt.expect)
		}
	}
}

func TestEscapeInvalidUTF8Byte(t *testing.T) {
	tests := []struct {
		s           string
		replacement string
		expect      string
	}{
		{"hello", "?", "hello"},
		{"\xff\xfe", "?", "??"},
		{"a\xffb", "??", "a??b"},
		{"", "?", ""},
		{"valid utf8", "_", "valid utf8"},
	}
	for _, tt := range tests {
		result := EscapeInvalidUTF8Byte(tt.s, tt.replacement)
		if result != tt.expect {
			t.Errorf("EscapeInvalidUTF8Byte(%q, %q) = %q, want %q", tt.s, tt.replacement, result, tt.expect)
		}
	}
}

func TestLimitStringLength(t *testing.T) {
	tests := []struct {
		input  string
		maxLen int
		expect string
	}{
		{"hello", 10, "hello"},
		{"hello", 5, "hello"},
		{"hello", 3, "hel"},
		{"hello", 0, ""},
		{"", 5, ""},
	}
	for _, tt := range tests {
		result := LimitStringLength(tt.input, tt.maxLen)
		if result != tt.expect {
			t.Errorf("LimitStringLength(%q, %d) = %q, want %q", tt.input, tt.maxLen, result, tt.expect)
		}
	}
}

func TestRandomUpper(t *testing.T) {
	result := RandomUpper("hello")
	if len(result) != 5 {
		t.Errorf("RandomUpper returned wrong length: got %d, want 5", len(result))
	}
	// The result should have the same characters (possibly uppercased)
	resultLower := strings.ToLower(result)
	if resultLower != "hello" {
		t.Errorf("RandomUpper changed characters unexpectedly: got %q, lowered to %q", result, resultLower)
	}

	// Test with empty string
	result = RandomUpper("")
	if result != "" {
		t.Errorf("RandomUpper(\"\") should return \"\", got %q", result)
	}
}
