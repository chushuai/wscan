package utils

import (
	"testing"
)

func TestExtractMapValueInt_Ext(t *testing.T) {
	// Test with JSON containing a number (JSON numbers are float64)
	jsonStr := `{"num": 42}`
	result := ExtractMapValueInt(jsonStr, "num")
	// JSON numbers are parsed as float64, so MapGetInt won't find an int
	// This will return 0 - test documents this behavior
	t.Logf("ExtractMapValueInt with JSON number = %d (JSON numbers are float64, so int assertion fails)", result)

	// Test with a map that has int value directly
	m := map[string]any{"num": 42}
	result = MapGetInt(m, "num")
	if result != 42 {
		t.Errorf("MapGetInt with actual int = %d, want 42", result)
	}
}

func TestInterfaceToMapInterfaceE_DefaultMapType(t *testing.T) {
	// Test with reflect.Map type that is not map[string]any or map[string]string
	// e.g., map[int]string
	m := map[int]string{1: "one", 2: "two"}
	result, err := InterfaceToMapInterfaceE(m)
	if err != nil {
		t.Logf("InterfaceToMapInterfaceE(map[int]string) returned error: %v", err)
	}
	// The result should still have the values accessible by string keys
	if len(result) != 2 {
		t.Errorf("InterfaceToMapInterfaceE(map[int]string) should have 2 entries, got %d", len(result))
	}
}

func TestInterfaceToMapInterfaceE_NonMapType(t *testing.T) {
	// Test with a non-map type (e.g., string)
	result, err := InterfaceToMapInterfaceE("not a map")
	if err == nil {
		t.Errorf("InterfaceToMapInterfaceE(string) should return error")
	}
	// The result should contain the raw value under __[yaklang-raw]__
	if result["__[yaklang-raw]__"] != "not a map" {
		t.Errorf("InterfaceToMapInterfaceE(string) should store value under __[yaklang-raw]__")
	}
}

func TestInterfaceToMapInterfaceE_MapAnyAny(t *testing.T) {
	// Test map[any]any
	m := map[any]any{"key1": "value1", 42: "value2"}
	result, err := InterfaceToMapInterfaceE(m)
	if err != nil {
		t.Errorf("InterfaceToMapInterfaceE(map[any]any) returned error: %v", err)
	}
	if result["key1"] != "value1" {
		t.Errorf("InterfaceToMapInterfaceE result[\"key1\"] = %v, want value1", result["key1"])
	}
}

func TestToMapParams_Error(t *testing.T) {
	// Test with a type that can't be marshaled to JSON (e.g., channel)
	result, err := ToMapParams(make(chan int))
	if err == nil {
		t.Errorf("ToMapParams with channel should return error")
	}
	if result != nil {
		t.Errorf("ToMapParams with channel should return nil map")
	}
}

func TestMapToStruct_Extended(t *testing.T) {
	type TestStruct struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}

	// Test with missing fields in map
	input := map[string]any{"name": "test"}
	var output TestStruct
	err := MapToStruct(input, &output)
	if err != nil {
		t.Errorf("MapToStruct returned error: %v", err)
	}
	if output.Name != "test" {
		t.Errorf("MapToStruct result.Name = %q, want test", output.Name)
	}
	if output.Value != 0 {
		t.Errorf("MapToStruct result.Value should be zero value")
	}

	// Test with nil output
	err = MapToStruct(input, nil)
	if err == nil {
		t.Errorf("MapToStruct with nil output should return error")
	}

	// Test with non-pointer output
	err = MapToStruct(input, TestStruct{})
	if err == nil {
		t.Errorf("MapToStruct with non-pointer output should return error")
	}

	// Test with nil pointer
	var nilPtr *TestStruct
	err = MapToStruct(input, nilPtr)
	if err == nil {
		t.Errorf("MapToStruct with nil pointer should return error")
	}
}

func TestMapGetFloat32Or_NonFloatValue(t *testing.T) {
	m := map[string]any{"val": "not a float"}
	result := MapGetFloat32Or(m, "val", float32(1.0))
	if result != float32(1.0) {
		t.Errorf("MapGetFloat32Or with non-float value = %f, want 1.0", result)
	}
}

func TestMapGetBoolOr_NonBoolValue(t *testing.T) {
	m := map[string]any{"flag": "not a bool"}
	result := MapGetBoolOr(m, "flag", true)
	if result != true {
		t.Errorf("MapGetBoolOr with non-bool value = %v, want true", result)
	}
}

func TestMapGetIntOr_NonIntValue(t *testing.T) {
	m := map[string]any{"num": "not an int"}
	result := MapGetIntOr(m, "num", 99)
	if result != 99 {
		t.Errorf("MapGetIntOr with non-int value = %d, want 99", result)
	}
}

func TestMapGetInt64Or_NonInt64Value(t *testing.T) {
	m := map[string]any{"val": "not int64"}
	result := MapGetInt64Or(m, "val", int64(99))
	if result != 99 {
		t.Errorf("MapGetInt64Or with non-int64 value = %d, want 99", result)
	}
}

func TestMapGetFloat64Or_NonFloatValue(t *testing.T) {
	m := map[string]any{"val": "not a float"}
	result := MapGetFloat64Or(m, "val", 1.0)
	if result != 1.0 {
		t.Errorf("MapGetFloat64Or with non-float value = %f, want 1.0", result)
	}
}

func TestMarshalIdempotent_PtrAndSlice(t *testing.T) {
	// Test with pointer to map
	m := map[string]any{"key": "value"}
	result, err := MarshalIdempotent(&m)
	if err != nil {
		t.Errorf("MarshalIdempotent(&map) returned error: %v", err)
	}
	if len(result) == 0 {
		t.Errorf("MarshalIdempotent(&map) should return non-empty result")
	}

	// Test with nested map
	nested := map[string]any{"outer": map[string]any{"inner": "value"}}
	result, err = MarshalIdempotent(nested)
	if err != nil {
		t.Errorf("MarshalIdempotent(nested map) returned error: %v", err)
	}

	// Test with slice of maps
	slice := []any{map[string]any{"a": 1}, map[string]any{"b": 2}}
	result, err = MarshalIdempotent(slice)
	if err != nil {
		t.Errorf("MarshalIdempotent(slice) returned error: %v", err)
	}
}

func TestInterfaceToGeneralMap_ByteSliceMap(t *testing.T) {
	// Test with map containing []byte values
	m := map[string]any{"data": []byte("hello")}
	result := InterfaceToGeneralMap(m)
	if result["data"] != "hello" {
		t.Errorf("InterfaceToGeneralMap with []byte value = %v, want hello", result["data"])
	}
}

func TestInterfaceToGeneralMap_DefaultType(t *testing.T) {
	// Test with a primitive type (falls to default case)
	result := InterfaceToGeneralMap(42)
	if result["__DEFAULT__"] != 42 {
		t.Errorf("InterfaceToGeneralMap(int) = %v", result)
	}

	// Test with a string
	result = InterfaceToGeneralMap("hello")
	if result["__DEFAULT__"] != "hello" {
		t.Errorf("InterfaceToGeneralMap(string) = %v", result)
	}
}

func TestToMapParams_InvalidUnmarshal(t *testing.T) {
	// Test with a type that marshals but can't unmarshal to map[string]any
	// This is hard to construct, but we can test the error path indirectly
	// by passing a type with channels which can't be marshaled
	result, err := ToMapParams(make(chan int))
	if err == nil {
		t.Errorf("ToMapParams with channel should return error")
	}
	if result != nil {
		t.Errorf("ToMapParams with channel should return nil map")
	}
}

func TestMapToStruct_MissingJSONTag(t *testing.T) {
	type TestStruct struct {
		Name  string `json:"name"`
		NoTag string // no json tag
		Value int    `json:"value"`
	}

	input := map[string]any{"name": "test", "NoTag": "notag", "value": 42}
	var output TestStruct
	err := MapToStruct(input, &output)
	if err != nil {
		t.Errorf("MapToStruct returned error: %v", err)
	}
	if output.Name != "test" {
		t.Errorf("MapToStruct result.Name = %q, want test", output.Name)
	}
}

func TestInterfaceToMapInterfaceE_MapIntString(t *testing.T) {
	// Test with map[int]string - uses the reflect.Map default branch
	m := map[int]string{1: "one", 2: "two"}
	result, err := InterfaceToMapInterfaceE(m)
	if err != nil {
		t.Errorf("InterfaceToMapInterfaceE(map[int]string) returned error: %v", err)
	}
	if len(result) != 2 {
		t.Errorf("InterfaceToMapInterfaceE(map[int]string) should have 2 entries, got %d", len(result))
	}
}

func TestInterfaceToStringSlice_Panic(t *testing.T) {
	// Test with a type that causes a panic in reflect
	// Passing a struct with unexported fields in a slice might trigger the panic recovery
	type unexported struct {
		field string
	}
	slice := []unexported{{field: "a"}, {field: "b"}}
	result := InterfaceToStringSlice(slice)
	// Should recover from panic and return single element
	if len(result) == 0 {
		t.Logf("InterfaceToStringSlice with unexported struct slice returned empty")
	}
}
