package http

import (
	"testing"
)

func TestParameter_Clone(t *testing.T) {
	p := &Parameter{
		Position:    PositionQuery,
		Key:         "key1",
		Value:       "value1",
		Prefix:      "pre",
		Suffix:      "suf",
		ContentType: "text/plain",
		Filename:    "test.txt",
		Content:     []byte("content"),
	}

	cloned := p.Clone()

	if cloned == p {
		t.Error("Clone should return a different pointer")
	}
	if cloned.Key != p.Key {
		t.Errorf("cloned Key = %q, want %q", cloned.Key, p.Key)
	}
	if cloned.Value != p.Value {
		t.Errorf("cloned Value = %q, want %q", cloned.Value, p.Value)
	}
	if cloned.Position != p.Position {
		t.Errorf("cloned Position = %q, want %q", cloned.Position, p.Position)
	}
	if cloned.Prefix != p.Prefix {
		t.Errorf("cloned Prefix = %q, want %q", cloned.Prefix, p.Prefix)
	}
	if cloned.Suffix != p.Suffix {
		t.Errorf("cloned Suffix = %q, want %q", cloned.Suffix, p.Suffix)
	}
	if cloned.ContentType != p.ContentType {
		t.Errorf("cloned ContentType = %q, want %q", cloned.ContentType, p.ContentType)
	}
	if cloned.Filename != p.Filename {
		t.Errorf("cloned Filename = %q, want %q", cloned.Filename, p.Filename)
	}
}

func TestParameter_Assign(t *testing.T) {
	p := &Parameter{
		Position: PositionQuery,
		Key:      "old_key",
		Value:    "old_value",
	}

	other := Parameter{
		Position: PositionBody,
		Key:      "new_key",
		Value:    "new_value",
		Prefix:   "pre",
		Suffix:   "suf",
	}

	p.Assign(other)

	if p.Position != PositionBody {
		t.Errorf("Position = %q, want %q", p.Position, PositionBody)
	}
	if p.Key != "new_key" {
		t.Errorf("Key = %q, want %q", p.Key, "new_key")
	}
	if p.Value != "new_value" {
		t.Errorf("Value = %q, want %q", p.Value, "new_value")
	}
	if p.Prefix != "pre" {
		t.Errorf("Prefix = %q, want %q", p.Prefix, "pre")
	}
	if p.Suffix != "suf" {
		t.Errorf("Suffix = %q, want %q", p.Suffix, "suf")
	}
}

func TestParameter_DeepCopy(t *testing.T) {
	p := &Parameter{
		Position: PositionQuery,
		Key:      "key1",
		Value:    "value1",
		Content:  []byte("content"),
	}

	copied := p.DeepCopy()

	if copied.Key != p.Key {
		t.Errorf("DeepCopy Key = %q, want %q", copied.Key, p.Key)
	}
	if copied.Value != p.Value {
		t.Errorf("DeepCopy Value = %q, want %q", copied.Value, p.Value)
	}

	// Verify deep copy of slice
	if len(copied.Content) != len(p.Content) {
		t.Errorf("DeepCopy Content length mismatch")
	}

	// Modify the copy and verify original is unaffected
	copied.Content[0] = 'x'
	if p.Content[0] == 'x' {
		t.Error("modifying deepcopy Content should not affect original")
	}
}

func TestParameter_String(t *testing.T) {
	tests := []struct {
		p        Parameter
		expected string
	}{
		{Parameter{Prefix: "", Value: "hello", Suffix: ""}, "hello"},
		{Parameter{Prefix: "pre_", Value: "hello", Suffix: "_suf"}, "pre_hello_suf"},
		{Parameter{Prefix: "[", Value: "val", Suffix: "]"}, "[val]"},
	}

	for _, tt := range tests {
		result := tt.p.String()
		if result != tt.expected {
			t.Errorf("Parameter.String() = %q, want %q", result, tt.expected)
		}
	}
}

func TestCloneParameters(t *testing.T) {
	pList := map[string]*Parameter{
		"key1": {Position: PositionQuery, Key: "key1", Value: "value1"},
		"key2": {Position: PositionBody, Key: "key2", Value: "value2"},
	}

	cloned := cloneParameters(pList)

	if len(cloned) != 2 {
		t.Fatalf("expected 2 parameters, got %d", len(cloned))
	}

	// Verify independence
	cloned["key1"].Value = "modified"
	if pList["key1"].Value != "value1" {
		t.Error("modifying cloned parameter should not affect original")
	}
}

func TestCloneParameters_Empty(t *testing.T) {
	pList := map[string]*Parameter{}
	cloned := cloneParameters(pList)
	if len(cloned) != 0 {
		t.Errorf("expected 0 parameters, got %d", len(cloned))
	}
}

func TestParameterConstants(t *testing.T) {
	if PositionQuery != "query" {
		t.Errorf("PositionQuery = %q, want %q", PositionQuery, "query")
	}
	if PositionBody != "body" {
		t.Errorf("PositionBody = %q, want %q", PositionBody, "body")
	}
	if PositionHeader != "header" {
		t.Errorf("PositionHeader = %q, want %q", PositionHeader, "header")
	}
	if PositionCookie != "cookie" {
		t.Errorf("PositionCookie = %q, want %q", PositionCookie, "cookie")
	}
	if PositionStatus != "status" {
		t.Errorf("PositionStatus = %q, want %q", PositionStatus, "status")
	}
	if PositionPath != "path" {
		t.Errorf("PositionPath = %q, want %q", PositionPath, "path")
	}

	if ParameterTypeValue != "value" {
		t.Errorf("ParameterTypeValue = %q, want %q", ParameterTypeValue, "value")
	}
	if ParameterTypePrefix != "prefix" {
		t.Errorf("ParameterTypePrefix = %q, want %q", ParameterTypePrefix, "prefix")
	}
	if ParameterTypeSuffix != "suffix" {
		t.Errorf("ParameterTypeSuffix = %q, want %q", ParameterTypeSuffix, "suffix")
	}
}
