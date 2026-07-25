package http

import (
	"net/http"
	"testing"
	"time"
)

func TestIsNotToken(t *testing.T) {
	tests := []struct {
		r        rune
		expected bool
	}{
		{'a', false}, // valid token
		{'Z', false}, // valid token
		{'0', false}, // valid token
		{'!', false}, // valid token
		{' ', true},  // space is not a token
		{',', true},  // comma is not a token
		{'(', true},  // paren is not a token
	}

	for _, tt := range tests {
		result := isNotToken(tt.r)
		if result != tt.expected {
			t.Errorf("isNotToken(%q) = %v, want %v", tt.r, result, tt.expected)
		}
	}
}

func TestValidCookieValueByte(t *testing.T) {
	tests := []struct {
		b        byte
		expected bool
	}{
		{0x20, true},  // space
		{'a', true},   // letter
		{'Z', true},   // letter
		{'0', true},   // digit
		{'~', true},   // tilde
		{0x7f, false}, // DEL
		{0x1f, false}, // control char
		{'"', false},  // double quote
		{';', false},  // semicolon
		{'\\', false}, // backslash
		{0x00, false}, // null
	}

	for _, tt := range tests {
		result := validCookieValueByte(tt.b)
		if result != tt.expected {
			t.Errorf("validCookieValueByte(%d/%q) = %v, want %v", tt.b, tt.b, result, tt.expected)
		}
	}
}

func TestIsCookieNameValid(t *testing.T) {
	tests := []struct {
		raw      string
		expected bool
	}{
		{"", false},
		{"validName", true},
		{"session_id", true},
		{"name123", true},
		{"invalid name", false},  // space
		{"invalid(name)", false}, // parens
		{"a", true},
	}

	for _, tt := range tests {
		result := isCookieNameValid(tt.raw)
		if result != tt.expected {
			t.Errorf("isCookieNameValid(%q) = %v, want %v", tt.raw, result, tt.expected)
		}
	}
}

func TestParseCookieValue(t *testing.T) {
	tests := []struct {
		raw              string
		allowDoubleQuote bool
		expectedValue    string
		expectedOK       bool
	}{
		{"value", false, "value", true},
		{"", false, "", true},
		{"\"quoted\"", true, "quoted", true},
		{"\"quoted\"", false, "", false},            // not allowed to strip quotes
		{"val;ue", false, "", false},                // semicolon is invalid
		{"val\\ue", false, "", false},               // backslash is invalid
		{"hello world", false, "hello world", true}, // space (0x20) is valid in cookie value
	}

	for _, tt := range tests {
		val, ok := parseCookieValue(tt.raw, tt.allowDoubleQuote)
		if ok != tt.expectedOK {
			t.Errorf("parseCookieValue(%q, %v): ok = %v, want %v", tt.raw, tt.allowDoubleQuote, ok, tt.expectedOK)
		}
		if ok && val != tt.expectedValue {
			t.Errorf("parseCookieValue(%q, %v): value = %q, want %q", tt.raw, tt.allowDoubleQuote, val, tt.expectedValue)
		}
	}
}

func TestReadCookies_Empty(t *testing.T) {
	h := http.Header{}
	cookies := readCookies(h, "")
	if len(cookies) != 0 {
		t.Errorf("expected 0 cookies, got %d", len(cookies))
	}
}

func TestReadCookies_SingleCookie(t *testing.T) {
	h := http.Header{}
	h.Set("Cookie", "name=value")
	cookies := readCookies(h, "")
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	if cookies[0].Name != "name" {
		t.Errorf("expected cookie name 'name', got %q", cookies[0].Name)
	}
	if cookies[0].Value != "value" {
		t.Errorf("expected cookie value 'value', got %q", cookies[0].Value)
	}
}

func TestReadCookies_MultipleCookies(t *testing.T) {
	h := http.Header{}
	h.Set("Cookie", "name1=value1; name2=value2")
	cookies := readCookies(h, "")
	if len(cookies) != 2 {
		t.Fatalf("expected 2 cookies, got %d", len(cookies))
	}
}

func TestReadCookies_WithFilter(t *testing.T) {
	h := http.Header{}
	h.Set("Cookie", "name1=value1; name2=value2")
	cookies := readCookies(h, "name1")
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie with filter, got %d", len(cookies))
	}
	if cookies[0].Name != "name1" {
		t.Errorf("expected cookie name 'name1', got %q", cookies[0].Name)
	}
}

func TestReadCookies_InvalidName(t *testing.T) {
	h := http.Header{}
	h.Set("Cookie", "invalid name=value")
	cookies := readCookies(h, "")
	if len(cookies) != 0 {
		t.Errorf("expected 0 cookies for invalid name, got %d", len(cookies))
	}
}

func TestReadCookies_EmptyPart(t *testing.T) {
	h := http.Header{}
	h.Set("Cookie", ";;name=value;;")
	cookies := readCookies(h, "")
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie (ignoring empty parts), got %d", len(cookies))
	}
}

func TestSanitizeCookieName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"normal", "normal"},
		{"with\nnewline", "with-newline"},
		{"with\rreturn", "with-return"},
		{"with\n\rboth", "with--both"},
	}

	for _, tt := range tests {
		result := sanitizeCookieName(tt.input)
		if result != tt.expected {
			t.Errorf("sanitizeCookieName(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestSanitizeOrWarn(t *testing.T) {
	// All valid bytes
	result := sanitizeOrWarn("field", validCookieValueByte, "abc123")
	if result != "abc123" {
		t.Errorf("expected 'abc123', got %q", result)
	}

	// With invalid bytes
	result = sanitizeOrWarn("field", validCookieValueByte, "a;b")
	if result != "ab" {
		t.Errorf("expected 'ab' (semicolon dropped), got %q", result)
	}
}

func TestSanitizeCookieValue(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"simple", "simple"},
		{"", ""},
		{"with space", `"with space"`},
		{"with,comma", `"with,comma"`},
		{"with space,comma", `"with space,comma"`},
		{"nospecial", "nospecial"},
	}

	for _, tt := range tests {
		result := sanitizeCookieValue(tt.input)
		if result != tt.expected {
			t.Errorf("sanitizeCookieValue(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestIsCookieExpired_NoExpiry(t *testing.T) {
	cookie := &http.Cookie{
		Name:  "session",
		Value: "abc",
	}
	if IsCookieExpired(cookie) {
		t.Error("cookie with zero Expires should not be expired")
	}
}

func TestIsCookieExpired_PastExpiry(t *testing.T) {
	cookie := &http.Cookie{
		Name:    "session",
		Value:   "abc",
		Expires: time.Now().Add(-1 * time.Hour),
	}
	if !IsCookieExpired(cookie) {
		t.Error("cookie with past Expires should be expired")
	}
}

func TestIsCookieExpired_FutureExpiry(t *testing.T) {
	cookie := &http.Cookie{
		Name:    "session",
		Value:   "abc",
		Expires: time.Now().Add(1 * time.Hour),
	}
	if IsCookieExpired(cookie) {
		t.Error("cookie with future Expires should not be expired")
	}
}

func TestCheckSameSite(t *testing.T) {
	tests := []struct {
		sameSite http.SameSite
		expected string
	}{
		{http.SameSiteDefaultMode, "DefaultMode"},
		{http.SameSiteLaxMode, "LaxMode"},
		{http.SameSiteStrictMode, "StrictMode"},
		{http.SameSiteNoneMode, "NoneMode"},
		{http.SameSite(99), ""},
	}

	for _, tt := range tests {
		cookie := &http.Cookie{
			Name:     "test",
			Value:    "val",
			SameSite: tt.sameSite,
		}
		result := CheckSameSite(cookie)
		if result != tt.expected {
			t.Errorf("CheckSameSite(sameSite=%d) = %q, want %q", tt.sameSite, result, tt.expected)
		}
	}
}
