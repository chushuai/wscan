package utils

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestMmh3Hash32(t *testing.T) {
	// Test with empty input
	result := Mmh3Hash32([]byte{})
	if result == 0 {
		// murmur3 of empty is 0, verify
		t.Log("Mmh3Hash32 of empty is 0")
	}

	// Test with known input
	result = Mmh3Hash32([]byte("hello"))
	if result == 0 {
		t.Errorf("Mmh3Hash32 of 'hello' should not be 0")
	}

	// Test determinism
	result2 := Mmh3Hash32([]byte("hello"))
	if result != result2 {
		t.Errorf("Mmh3Hash32 should be deterministic: got %d then %d", result, result2)
	}

	// Test different inputs produce different hashes
	result3 := Mmh3Hash32([]byte("world"))
	if result == result3 {
		t.Logf("Warning: Mmh3Hash32('hello') == Mmh3Hash32('world') = %d (collision)", result)
	}
}

func TestBase64Encode(t *testing.T) {
	// Test with short input (no line breaks expected)
	input := []byte("hello")
	result := Base64Encode(input)
	expected := base64.StdEncoding.EncodeToString(input)
	// The result includes newlines at position 76 and at the end
	// For short input, just one trailing newline
	if !bytes.HasSuffix(result, []byte("\n")) {
		t.Errorf("Base64Encode should end with newline")
	}

	// Verify the content without newlines matches standard base64
	resultStr := string(result)
	resultStr = replaceNewlines(resultStr)
	if resultStr != expected {
		t.Errorf("Base64Encode(%q) content = %q, want %q", input, resultStr, expected)
	}

	// Test with empty input
	result = Base64Encode([]byte{})
	if !bytes.HasSuffix(result, []byte("\n")) {
		t.Errorf("Base64Encode of empty should end with newline")
	}

	// Test with long input (should have line breaks at position 76)
	longInput := make([]byte, 100)
	for i := range longInput {
		longInput[i] = byte(i % 256)
	}
	result = Base64Encode(longInput)
	expectedLong := base64.StdEncoding.EncodeToString(longInput)
	resultStr = string(result)
	resultStr = replaceNewlines(resultStr)
	if resultStr != expectedLong {
		t.Errorf("Base64Encode of long input mismatch")
	}
}

func replaceNewlines(s string) string {
	bytes := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\n' {
			bytes = append(bytes, s[i])
		}
	}
	return string(bytes)
}
