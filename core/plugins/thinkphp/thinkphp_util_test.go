package thinkphp

import (
	"strconv"
	"testing"
)

func TestExtractValueFromURL_Valid(t *testing.T) {
	url := "/index.php?s=/aa/bb/name/${@printf(43775*44642)}"
	result, err := extractValueFromURL(url)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := strconv.Itoa(43775 * 44642)
	if result != expected {
		t.Errorf("expected %s, got %s", expected, result)
	}
}

func TestExtractValueFromURL_Simple(t *testing.T) {
	url := "123*456"
	result, err := extractValueFromURL(url)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "56088" {
		t.Errorf("expected 56088, got %s", result)
	}
}

func TestExtractValueFromURL_NoMatch(t *testing.T) {
	url := "no multiplication here"
	_, err := extractValueFromURL(url)
	if err == nil {
		t.Error("expected error for no match")
	}
}

func TestExtractValueFromURL_Empty(t *testing.T) {
	_, err := extractValueFromURL("")
	if err == nil {
		t.Error("expected error for empty input")
	}
}

func TestIsRandomPhp_Valid(t *testing.T) {
	if !isRandomPhp("/805483697.php") {
		t.Error("expected true for /805483697.php")
	}
	if !isRandomPhp("/1.php") {
		t.Error("expected true for /1.php")
	}
}

func TestIsRandomPhp_Invalid(t *testing.T) {
	if isRandomPhp("/x.php") {
		t.Error("expected false for /x.php (non-numeric)")
	}
	if isRandomPhp("/abc.php") {
		t.Error("expected false for /abc.php")
	}
	if isRandomPhp("805483697.php") {
		t.Error("expected false for missing leading slash")
	}
	if isRandomPhp("/123.txt") {
		t.Error("expected false for non-php extension")
	}
	if isRandomPhp("/123.php4") {
		t.Error("expected false for /123.php4 (extra char)")
	}
}

func TestSqliPayloadsDefinitions(t *testing.T) {
	// Verify sqliPayloads are properly defined
	if len(sqliPayloads) == 0 {
		t.Fatal("expected at least one sqli payload definition")
	}
	for i, p := range sqliPayloads {
		if p.Path == "" {
			t.Errorf("payload[%d]: Path should not be empty", i)
		}
		if p.ParamKey == "" {
			t.Errorf("payload[%d]: ParamKey should not be empty", i)
		}
		if p.Payload == "" {
			t.Errorf("payload[%d]: Payload should not be empty", i)
		}
		if p.Check == nil {
			t.Errorf("payload[%d]: Check should not be nil", i)
		}
	}
}

func TestSqliPayloads_CheckFunctions(t *testing.T) {
	marker := "testmarker123"

	// Test XPATH syntax error detection
	for i, p := range sqliPayloads {
		// Check with XPATH syntax error
		if !p.Check("XPATH syntax error", marker) {
			t.Errorf("payload[%d]: expected Check to return true for XPATH syntax error", i)
		}
		// Check with marker pattern
		if !p.Check("~"+marker+"~", marker) {
			t.Errorf("payload[%d]: expected Check to return true for marker pattern ~%s~", i, marker)
		}
		// Check with no match
		if p.Check("normal response", marker) {
			t.Errorf("payload[%d]: expected Check to return false for normal response", i)
		}
	}
}
