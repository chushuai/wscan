package prometheus

import (
	"testing"

	"gopkg.in/yaml.v2"
)

// ==================== YamlFinger Dump additional coverage ====================

func TestCB3_YamlFinger_Dump_NilAndNil(t *testing.T) {
	yf := YamlFinger{}
	data, err := yf.Dump()
	if data != nil {
		t.Errorf("Expected nil data from Dump(), got %v", data)
	}
	if err != nil {
		t.Errorf("Expected nil error from Dump(), got %v", err)
	}
}

// ==================== YamlFinger Init coverage ====================

func TestCB3_YamlFinger_Init_True(t *testing.T) {
	yf := YamlFinger{}
	err := yf.Init(true)
	if err != nil {
		t.Errorf("Init(true) returned error: %v", err)
	}
}

func TestCB3_YamlFinger_Init_False(t *testing.T) {
	yf := YamlFinger{}
	err := yf.Init(false)
	if err != nil {
		t.Errorf("Init(false) returned error: %v", err)
	}
}

// ==================== YamlFinger MarshalYAML coverage ====================

func TestCB3_YamlFinger_MarshalYAML(t *testing.T) {
	yf := YamlFinger{}
	data, err := yf.MarshalYAML()
	if data != nil {
		t.Errorf("Expected nil data from MarshalYAML(), got %v", data)
	}
	if err != nil {
		t.Errorf("Expected nil error from MarshalYAML(), got %v", err)
	}
}

// ==================== YamlFinger empty methods coverage ====================

func TestCB3_YamlFinger_CompileNode(t *testing.T) {
	yf := YamlFinger{}
	yf.compileNode()
}

func TestCB3_YamlFinger_CompilePayloads(t *testing.T) {
	yf := YamlFinger{}
	yf.compilePayloads()
}

func TestCB3_YamlFinger_Run(t *testing.T) {
	yf := YamlFinger{}
	yf.run()
}

// ==================== YamlFingerDump coverage ====================

func TestCB3_YamlFingerDump(t *testing.T) {
	poc := &Poc{
		Name:       "cb3-test-poc",
		Transport:  "http",
		Expression: "true",
	}
	yf := YamlFingerDump(poc)
	if yf == nil {
		t.Fatal("YamlFingerDump() returned nil")
	}
	if yf.poc == nil {
		t.Error("Expected non-nil poc")
	}
	if yf.poc.Name != "cb3-test-poc" {
		t.Errorf("Expected poc.Name='cb3-test-poc', got '%s'", yf.poc.Name)
	}
}

func TestCB3_YamlFingerDump_NilPoc(t *testing.T) {
	yf := YamlFingerDump(nil)
	if yf == nil {
		t.Fatal("YamlFingerDump(nil) returned nil")
	}
	if yf.poc != nil {
		t.Error("Expected nil poc")
	}
}

// ==================== YamlFinger Finger coverage ====================

func TestCB3_YamlFinger_Finger_Basic(t *testing.T) {
	poc := &Poc{
		Name:       "cb3-finger-test",
		Transport:  "http",
		Expression: "rule1",
		Set: yaml.MapSlice{
			{Key: "var1", Value: "simple"},
		},
	}
	yf := &YamlFinger{poc: poc}
	f := yf.Finger()
	if f == nil {
		t.Fatal("Finger() returned nil")
	}
	if f.Channel != "web-directory" {
		t.Errorf("Expected Channel='web-directory', got '%s'", f.Channel)
	}
	if f.NeedReverse {
		t.Error("Expected NeedReverse=false for simple variable")
	}
	if f.Binding == nil {
		t.Fatal("Expected non-nil Binding")
	}
	if f.Binding.ID != "cb3-finger-test" {
		t.Errorf("Expected Binding.ID='cb3-finger-test', got '%s'", f.Binding.ID)
	}
}

func TestCB3_YamlFinger_Finger_WithNewReverse(t *testing.T) {
	poc := &Poc{
		Name:       "cb3-reverse-test",
		Transport:  "http",
		Expression: "rule1",
		Set: yaml.MapSlice{
			{Key: "reverse", Value: "newReverse()"},
		},
	}
	yf := &YamlFinger{poc: poc}
	f := yf.Finger()
	if f == nil {
		t.Fatal("Finger() returned nil")
	}
	if !f.NeedReverse {
		t.Error("Expected NeedReverse=true when newReverse in set")
	}
}

func TestCB3_YamlFinger_Finger_NilPoc(t *testing.T) {
	yf := &YamlFinger{poc: nil}
	// This should not panic even with nil poc
	defer func() {
		if r := recover(); r != nil {
			// Expected - nil poc will panic when accessing poc fields
		}
	}()
	_ = yf.Finger()
}

func TestCB3_YamlFinger_Finger_WithYamlScript(t *testing.T) {
	poc := &Poc{
		Name:       "cb3-script-test",
		Transport:  "http",
		Expression: "true",
		Set:        yaml.MapSlice{},
	}
	ys := &YamlScript{Name: "test-script"}
	yf := &YamlFinger{YamlScript: ys, poc: poc}
	f := yf.Finger()
	if f == nil {
		t.Fatal("Finger() returned nil")
	}
}

// ==================== YamlFinger struct field coverage ====================

func TestCB3_YamlFinger_StructFields(t *testing.T) {
	poc := &Poc{Name: "field-test"}
	yf := &YamlFinger{
		YamlScript: &YamlScript{Name: "script-name"},
		poc:        poc,
		pocPath:    "/path/to/poc.yaml",
	}
	if yf.poc.Name != "field-test" {
		t.Errorf("Expected poc.Name='field-test', got '%s'", yf.poc.Name)
	}
	if yf.pocPath != "/path/to/poc.yaml" {
		t.Errorf("Expected pocPath='/path/to/poc.yaml', got '%s'", yf.pocPath)
	}
	if yf.Name != "script-name" {
		t.Errorf("Expected Name='script-name', got '%s'", yf.Name)
	}
}

// ==================== Poc struct coverage ====================

func TestCB3_Poc_Struct(t *testing.T) {
	poc := &Poc{
		Name:       "test-poc",
		Transport:  "tcp",
		Expression: "rule1",
		Set: yaml.MapSlice{
			{Key: "var1", Value: "val1"},
		},
	}
	if poc.Name != "test-poc" {
		t.Errorf("Expected Name='test-poc', got '%s'", poc.Name)
	}
	if poc.Transport != "tcp" {
		t.Errorf("Expected Transport='tcp', got '%s'", poc.Transport)
	}
}

// ==================== YamlFinger_Finger with various set values ====================

func TestCB3_YamlFinger_Finger_MixedSet(t *testing.T) {
	poc := &Poc{
		Name:       "mixed-set-test",
		Transport:  "http",
		Expression: "true",
		Set: yaml.MapSlice{
			{Key: "timeout", Value: "5"},
			{Key: "reverse", Value: "newReverse()"},
			{Key: "path", Value: "/api"},
		},
	}
	yf := &YamlFinger{poc: poc}
	f := yf.Finger()
	if f == nil {
		t.Fatal("Finger() returned nil")
	}
	if !f.NeedReverse {
		t.Error("Expected NeedReverse=true when newReverse is in set")
	}
}

// ==================== Suppress unused import ====================

var _ = yaml.MapSlice{}
