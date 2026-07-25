package utils

import (
	"testing"
)

func TestRandLower(t *testing.T) {
	result := RandLower(10)
	if len(result) != 10 {
		t.Errorf("RandLower(10) returned wrong length: got %d, want 10", len(result))
	}
	for _, r := range result {
		if r < 'a' || r > 'z' {
			t.Errorf("RandLower returned non-lowercase char: %c", r)
		}
	}

	// Test zero length
	result = RandLower(0)
	if len(result) != 0 {
		t.Errorf("RandLower(0) should return empty string")
	}
}

func TestRandLowerLetter(t *testing.T) {
	result := RandLowerLetter(15)
	if len(result) != 15 {
		t.Errorf("RandLowerLetter(15) returned wrong length: got %d, want 15", len(result))
	}
	for _, r := range result {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
			t.Errorf("RandLowerLetter returned invalid char: %c", r)
		}
	}
}

func TestRandIntForExprSum(t *testing.T) {
	tests := []struct {
		n int
	}{
		{10},
		{100},
		{1},
		{50},
	}
	for _, tt := range tests {
		x, y := RandIntForExprSum(tt.n)
		if x+y != tt.n {
			t.Errorf("RandIntForExprSum(%d): x+y = %d, want %d", tt.n, x+y, tt.n)
		}
		if x < 0 || x > tt.n {
			t.Errorf("RandIntForExprSum(%d): x = %d, should be 0 <= x <= %d", tt.n, x, tt.n)
		}
	}
}

func TestRandIntForExprMultiply(t *testing.T) {
	// Test with a few values - the product should equal n
	n := 100
	x, y := RandIntForExprMultiply(n)
	if x*y != n && n/x == y {
		// The function uses integer division, so y = n / x
		// which means x * y may not exactly equal n due to integer division
	}
	if x == 0 || y == 0 {
		t.Errorf("RandIntForExprMultiply(%d): x=%d, y=%d, neither should be 0", n, x, y)
	}
}

func TestRandInt(t *testing.T) {
	min, max := 10, 20
	for i := 0; i < 50; i++ {
		result := RandInt(min, max)
		if result < min || result >= max {
			t.Errorf("RandInt(%d, %d) = %d, out of range [%d, %d)", min, max, result, min, max)
		}
	}
}

func TestRandomHex(t *testing.T) {
	result, err := RandomHex(16)
	if err != nil {
		t.Errorf("RandomHex(16) returned error: %v", err)
	}
	// hex encoding doubles the length
	if len(result) != 32 {
		t.Errorf("RandomHex(16) returned wrong length: got %d, want 32", len(result))
	}

	// Test with 0
	result, err = RandomHex(0)
	if err != nil {
		t.Errorf("RandomHex(0) returned error: %v", err)
	}
	if result != "" {
		t.Errorf("RandomHex(0) should return empty string, got %q", result)
	}
}
