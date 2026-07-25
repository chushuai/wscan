package utils

import (
	"testing"
)

func TestRandomHex_Large(t *testing.T) {
	// Test with a larger size
	result, err := RandomHex(32)
	if err != nil {
		t.Errorf("RandomHex(32) returned error: %v", err)
	}
	if len(result) != 64 {
		t.Errorf("RandomHex(32) returned wrong length: got %d, want 64", len(result))
	}
}

func TestRandIntForExprMultiply_SmallN(t *testing.T) {
	// Test with a small value
	x, y := RandIntForExprMultiply(12)
	if x == 0 || y == 0 {
		t.Errorf("RandIntForExprMultiply(12): x=%d, y=%d, neither should be 0", x, y)
	}
}

func TestRandStringBytes_Various(t *testing.T) {
	// Test with various lengths
	for _, n := range []int{0, 1, 5, 50} {
		result := RandStringBytes(n)
		if len(result) != n {
			t.Errorf("RandStringBytes(%d) returned wrong length: got %d, want %d", n, len(result), n)
		}
	}
}
