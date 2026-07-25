package utils

import (
	"testing"
)

func TestCalcMd5(t *testing.T) {
	// Test with single argument
	result := CalcMd5("hello")
	if result == "" {
		t.Errorf("CalcMd5 returned empty string")
	}

	// Test determinism
	result2 := CalcMd5("hello")
	if result != result2 {
		t.Errorf("CalcMd5 is not deterministic: %q != %q", result, result2)
	}

	// Test different inputs produce different results
	result3 := CalcMd5("world")
	if result == result3 {
		t.Errorf("CalcMd5(\"hello\") == CalcMd5(\"world\") -- unlikely collision")
	}

	// Test with multiple arguments
	result = CalcMd5("a", "b", "c")
	if result == "" {
		t.Errorf("CalcMd5 with multiple args returned empty string")
	}

	// Test with no arguments
	result = CalcMd5()
	if result == "" {
		t.Errorf("CalcMd5() returned empty string")
	}
}

func TestCalcSha1(t *testing.T) {
	// Test with single argument
	result := CalcSha1("hello")
	if result == "" {
		t.Errorf("CalcSha1 returned empty string")
	}

	// Test determinism
	result2 := CalcSha1("hello")
	if result != result2 {
		t.Errorf("CalcSha1 is not deterministic: %q != %q", result, result2)
	}

	// Test different inputs produce different results
	result3 := CalcSha1("world")
	if result == result3 {
		t.Errorf("CalcSha1(\"hello\") == CalcSha1(\"world\") -- unlikely collision")
	}

	// Test with multiple arguments
	result = CalcSha1(1, 2, 3)
	if result == "" {
		t.Errorf("CalcSha1 with multiple args returned empty string")
	}
}
