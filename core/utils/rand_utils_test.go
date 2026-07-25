package utils

import (
	"testing"
)

func TestRandStringBytes(t *testing.T) {
	result := RandStringBytes(10)
	if len(result) != 10 {
		t.Errorf("RandStringBytes(10) returned wrong length: got %d, want 10", len(result))
	}
	for _, r := range result {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			t.Errorf("RandStringBytes returned invalid char: %c", r)
		}
	}

	// Test zero length
	result = RandStringBytes(0)
	if len(result) != 0 {
		t.Errorf("RandStringBytes(0) should return empty string")
	}
}
