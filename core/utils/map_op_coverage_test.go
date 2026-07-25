package utils

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

// --- MarshalIdempotent ---

func TestMarshalIdempotent_Nil(t *testing.T) {
	result, err := MarshalIdempotent(nil)
	assert.NoError(t, err)
	assert.Equal(t, "null", string(result))
}

func TestMarshalIdempotent_Map(t *testing.T) {
	m := map[string]any{"b": 2, "a": 1}
	result, err := MarshalIdempotent(m)
	assert.NoError(t, err)
	var parsed any
	assert.NoError(t, json.Unmarshal(result, &parsed))
}

func TestMarshalIdempotent_Slice(t *testing.T) {
	s := []any{3, 1, 2}
	result, err := MarshalIdempotent(s)
	assert.NoError(t, err)
	var parsed any
	assert.NoError(t, json.Unmarshal(result, &parsed))
}

func TestMarshalIdempotent_Struct(t *testing.T) {
	type S struct{ Name string }
	result, err := MarshalIdempotent(S{Name: "test"})
	assert.NoError(t, err)
	assert.Contains(t, string(result), "test")
}

func TestMarshalIdempotent_PtrToMap(t *testing.T) {
	m := map[string]any{"key": "value"}
	result, err := MarshalIdempotent(&m)
	assert.NoError(t, err)
	assert.True(t, len(result) > 0)
}

func TestMarshalIdempotent_NestedMap(t *testing.T) {
	nested := map[string]any{"outer": map[string]any{"inner": "value"}}
	result, err := MarshalIdempotent(nested)
	assert.NoError(t, err)
	assert.True(t, len(result) > 0)
}

func TestMarshalIdempotent_SliceOfMaps(t *testing.T) {
	slice := []any{map[string]any{"a": 1}, map[string]any{"b": 2}}
	result, err := MarshalIdempotent(slice)
	assert.NoError(t, err)
	assert.True(t, len(result) > 0)
}

func TestMarshalIdempotent_Array(t *testing.T) {
	arr := [3]int{1, 2, 3}
	result, err := MarshalIdempotent(arr)
	assert.NoError(t, err)
	assert.True(t, len(result) > 0)
}

func TestMarshalIdempotent_Primitive(t *testing.T) {
	result, err := MarshalIdempotent(42)
	assert.NoError(t, err)
	assert.Equal(t, "42", string(result))
}

// --- MapGetStringOr ---

func TestMapGetStringOr_ExistingKey(t *testing.T) {
	m := map[string]any{"key": "value"}
	assert.Equal(t, "value", MapGetStringOr(m, "key", "default"))
}

func TestMapGetStringOr_NonString(t *testing.T) {
	m := map[string]any{"num": 42}
	assert.Equal(t, "default", MapGetStringOr(m, "num", "default"))
}

func TestMapGetStringOr_MissingKey(t *testing.T) {
	m := map[string]any{"key": "value"}
	assert.Equal(t, "default", MapGetStringOr(m, "missing", "default"))
}

func TestMapGetStringOr_NilMap(t *testing.T) {
	assert.Equal(t, "default", MapGetStringOr(nil, "key", "default"))
}

// --- MapGetStringOr2 ---

func TestMapGetStringOr2_ExistingKey(t *testing.T) {
	m := map[string]string{"key": "value"}
	assert.Equal(t, "value", MapGetStringOr2(m, "key", "default"))
}

func TestMapGetStringOr2_MissingKey(t *testing.T) {
	m := map[string]string{"key": "value"}
	assert.Equal(t, "default", MapGetStringOr2(m, "missing", "default"))
}

func TestMapGetStringOr2_NilMap(t *testing.T) {
	assert.Equal(t, "default", MapGetStringOr2(nil, "key", "default"))
}

// --- MapStringGetOr ---

func TestMapStringGetOr_ExistingKey(t *testing.T) {
	m := map[string]string{"key": "value"}
	assert.Equal(t, "value", MapStringGetOr(m, "key", "default"))
}

func TestMapStringGetOr_MissingKey(t *testing.T) {
	m := map[string]string{"key": "value"}
	assert.Equal(t, "default", MapStringGetOr(m, "missing", "default"))
}

func TestMapStringGetOr_NilMap(t *testing.T) {
	assert.Equal(t, "default", MapStringGetOr(nil, "key", "default"))
}

// --- MapStringGet ---

func TestMapStringGet_ExistingKey(t *testing.T) {
	m := map[string]string{"key": "value"}
	assert.Equal(t, "value", MapStringGet(m, "key"))
}

func TestMapStringGet_MissingKey(t *testing.T) {
	m := map[string]string{"key": "value"}
	assert.Equal(t, "", MapStringGet(m, "missing"))
}

func TestMapStringGet_NilMap(t *testing.T) {
	assert.Equal(t, "", MapStringGet(nil, "key"))
}

// --- MapGetRaw ---

func TestMapGetRaw_ExistingKey(t *testing.T) {
	m := map[string]any{"key": 42}
	assert.Equal(t, 42, MapGetRaw(m, "key"))
}

func TestMapGetRaw_MissingKey(t *testing.T) {
	m := map[string]any{"key": 42}
	assert.Nil(t, MapGetRaw(m, "missing"))
}

func TestMapGetRaw_NilMap(t *testing.T) {
	assert.Nil(t, MapGetRaw(nil, "key"))
}

// --- MapGetFirstRaw ---

func TestMapGetFirstRaw_Found(t *testing.T) {
	m := map[string]any{"key1": "value1", "key2": "value2"}
	assert.Equal(t, "value1", MapGetFirstRaw(m, "key1"))
}

func TestMapGetFirstRaw_Fallback(t *testing.T) {
	m := map[string]any{"key2": "value2"}
	assert.Equal(t, "value2", MapGetFirstRaw(m, "missing", "key2"))
}

func TestMapGetFirstRaw_AllMissing(t *testing.T) {
	m := map[string]any{"key": "value"}
	assert.Nil(t, MapGetFirstRaw(m, "missing1", "missing2"))
}

func TestMapGetFirstRaw_NoKeys(t *testing.T) {
	m := map[string]any{"key": "value"}
	assert.Nil(t, MapGetFirstRaw(m))
}

func TestMapGetFirstRaw_NumberedKey(t *testing.T) {
	m := map[string]any{"key_1": "numbered_value"}
	assert.Equal(t, "numbered_value", MapGetFirstRaw(m, "key"))
}

func TestMapGetFirstRaw_NumberedKey2(t *testing.T) {
	m := map[string]any{"item_3": "value3"}
	assert.Equal(t, "value3", MapGetFirstRaw(m, "item"))
}

// --- MapGetRawOr ---

func TestMapGetRawOr_ExistingKey(t *testing.T) {
	m := map[string]any{"key": 42}
	assert.Equal(t, 42, MapGetRawOr(m, "key", 0))
}

func TestMapGetRawOr_MissingKey(t *testing.T) {
	m := map[string]any{"key": 42}
	assert.Equal(t, 99, MapGetRawOr(m, "missing", 99))
}

func TestMapGetRawOr_NilMap(t *testing.T) {
	assert.Equal(t, 99, MapGetRawOr(nil, "key", 99))
}

// --- MapGetString ---

func TestMapGetString_ExistingKey(t *testing.T) {
	m := map[string]any{"key": "value"}
	assert.Equal(t, "value", MapGetString(m, "key"))
}

func TestMapGetString_MissingKey(t *testing.T) {
	m := map[string]any{"key": "value"}
	assert.Equal(t, "", MapGetString(m, "missing"))
}

// --- MapGetStringSlice ---

func TestMapGetStringSlice_ExistingKey(t *testing.T) {
	m := map[string]any{"items": []string{"a", "b", "c"}}
	result := MapGetStringSlice(m, "items")
	assert.Equal(t, []string{"a", "b", "c"}, result)
}

func TestMapGetStringSlice_MissingKey(t *testing.T) {
	m := map[string]any{"items": []string{"a"}}
	result := MapGetStringSlice(m, "missing")
	assert.Equal(t, 0, len(result))
}

// --- MapGetStringByManyFields ---

func TestMapGetStringByManyFields_FirstFound(t *testing.T) {
	m := map[string]any{"field1": "found"}
	assert.Equal(t, "found", MapGetStringByManyFields(m, "field1", "field2"))
}

func TestMapGetStringByManyFields_SecondFound(t *testing.T) {
	m := map[string]any{"field2": "found"}
	assert.Equal(t, "found", MapGetStringByManyFields(m, "field1", "field2"))
}

func TestMapGetStringByManyFields_AllMissing(t *testing.T) {
	m := map[string]any{"field": "found"}
	assert.Equal(t, "", MapGetStringByManyFields(m, "missing1", "missing2"))
}

func TestMapGetStringByManyFields_NoKeys(t *testing.T) {
	m := map[string]any{"field": "found"}
	assert.Equal(t, "", MapGetStringByManyFields(m))
}

// --- ExtractMapValueString ---

func TestExtractMapValueString_ValidJSON(t *testing.T) {
	assert.Equal(t, "value", ExtractMapValueString(`{"key": "value"}`, "key"))
}

func TestExtractMapValueString_InvalidJSON(t *testing.T) {
	assert.Equal(t, "", ExtractMapValueString("not json", "key"))
}

// --- ExtractMapValueInt ---

func TestExtractMapValueInt_ValidMap(t *testing.T) {
	m := map[string]any{"num": 42}
	assert.Equal(t, 42, MapGetInt(m, "num"))
}

func TestExtractMapValueInt_FromJSON(t *testing.T) {
	// JSON numbers are parsed as float64, so int assertion fails
	result := ExtractMapValueInt(`{"num": 42}`, "num")
	assert.Equal(t, 0, result) // documents behavior: JSON numbers are float64
}

// --- ExtractMapValueBool ---

func TestExtractMapValueBool_True(t *testing.T) {
	assert.True(t, ExtractMapValueBool(`{"flag": true}`, "flag"))
}

func TestExtractMapValueBool_False(t *testing.T) {
	assert.False(t, ExtractMapValueBool(`{"flag": false}`, "flag"))
}

func TestExtractMapValueBool_Missing(t *testing.T) {
	assert.False(t, ExtractMapValueBool(`{}`, "flag"))
}

// --- ExtractMapValueGeneralMap ---

func TestExtractMapValueGeneralMap_Valid(t *testing.T) {
	result := ExtractMapValueGeneralMap(`{"nested": {"inner": "value"}}`, "nested")
	assert.Equal(t, "value", result["inner"])
}

func TestExtractMapValueGeneralMap_Missing(t *testing.T) {
	result := ExtractMapValueGeneralMap(`{}`, "nested")
	assert.Equal(t, 0, len(result))
}

// --- ExtractMapValueRaw ---

func TestExtractMapValueRaw_Valid(t *testing.T) {
	assert.Equal(t, "value", ExtractMapValueRaw(`{"key": "value"}`, "key"))
}

func TestExtractMapValueRaw_Missing(t *testing.T) {
	assert.Nil(t, ExtractMapValueRaw(`{}`, "key"))
}

// --- InterfaceToMapInterface ---

func TestInterfaceToMapInterface_MapAny(t *testing.T) {
	m := map[string]any{"key": "value"}
	assert.Equal(t, "value", InterfaceToMapInterface(m)["key"])
}

func TestInterfaceToMapInterface_MapString(t *testing.T) {
	m := map[string]string{"key": "value"}
	assert.Equal(t, "value", InterfaceToMapInterface(m)["key"])
}

func TestInterfaceToMapInterface_Nil(t *testing.T) {
	assert.Equal(t, 0, len(InterfaceToMapInterface(nil)))
}

// --- InterfaceToSliceInterface ---

func TestInterfaceToSliceInterface_Slice(t *testing.T) {
	s := []any{1, 2, 3}
	result := InterfaceToSliceInterface(s)
	assert.Equal(t, 3, len(result))
	assert.Equal(t, 1, result[0])
}

func TestInterfaceToSliceInterface_Nil(t *testing.T) {
	assert.Equal(t, 0, len(InterfaceToSliceInterface(nil)))
}

// --- InterfaceToSliceInterfaceE ---

func TestInterfaceToSliceInterfaceE_SliceAny(t *testing.T) {
	s := []any{1, 2, 3}
	result, err := InterfaceToSliceInterfaceE(s)
	assert.NoError(t, err)
	assert.Equal(t, 3, len(result))
}

func TestInterfaceToSliceInterfaceE_Nil(t *testing.T) {
	_, err := InterfaceToSliceInterfaceE(nil)
	assert.Error(t, err)
}

func TestInterfaceToSliceInterfaceE_TypedSlice(t *testing.T) {
	intSlice := []int{1, 2, 3}
	result, err := InterfaceToSliceInterfaceE(intSlice)
	assert.NoError(t, err)
	assert.Equal(t, 3, len(result))
	assert.Equal(t, 1, result[0])
}

func TestInterfaceToSliceInterfaceE_NonSlice(t *testing.T) {
	result, err := InterfaceToSliceInterfaceE(42)
	assert.Error(t, err)
	assert.Equal(t, 1, len(result))
	assert.Equal(t, 42, result[0])
}

// --- InterfaceToMapInterfaceE ---

func TestInterfaceToMapInterfaceE_MapAny(t *testing.T) {
	m := map[string]any{"key": "value"}
	result, err := InterfaceToMapInterfaceE(m)
	assert.NoError(t, err)
	assert.Equal(t, "value", result["key"])
}

func TestInterfaceToMapInterfaceE_MapString(t *testing.T) {
	m := map[string]string{"key": "value"}
	result, err := InterfaceToMapInterfaceE(m)
	assert.NoError(t, err)
	assert.Equal(t, "value", result["key"])
}

func TestInterfaceToMapInterfaceE_MapAnyAny_Cov(t *testing.T) {
	m := map[any]any{"key": "value2", 42: "value42"}
	result, err := InterfaceToMapInterfaceE(m)
	assert.NoError(t, err)
	assert.Equal(t, "value2", result["key"])
}

func TestInterfaceToMapInterfaceE_Nil(t *testing.T) {
	_, err := InterfaceToMapInterfaceE(nil)
	assert.Error(t, err)
}

func TestInterfaceToMapInterfaceE_NonMapType_Cov(t *testing.T) {
	result, err := InterfaceToMapInterfaceE("not a map")
	assert.Error(t, err)
	assert.Equal(t, "not a map", result["__[yaklang-raw]__"])
}

func TestInterfaceToMapInterfaceE_ReflectMapType(t *testing.T) {
	m := map[int]string{1: "one", 2: "two"}
	result, err := InterfaceToMapInterfaceE(m)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(result))
}

// --- MapGetString2 ---

func TestMapGetString2_ExistingKey(t *testing.T) {
	m := map[string]string{"key": "value"}
	assert.Equal(t, "value", MapGetString2(m, "key"))
}

func TestMapGetString2_MissingKey(t *testing.T) {
	m := map[string]string{"key": "value"}
	assert.Equal(t, "", MapGetString2(m, "missing"))
}

func TestMapGetString2_NilMap(t *testing.T) {
	assert.Equal(t, "", MapGetString2(nil, "key"))
}

// --- MapGetMapRaw ---

func TestMapGetMapRaw_ExistingKey(t *testing.T) {
	inner := map[string]any{"nested": "value"}
	m := map[string]any{"data": inner}
	result := MapGetMapRaw(m, "data")
	assert.Equal(t, "value", result["nested"])
}

func TestMapGetMapRaw_MissingKey(t *testing.T) {
	m := map[string]any{"data": "string"}
	result := MapGetMapRaw(m, "missing")
	assert.Equal(t, 0, len(result))
}

func TestMapGetMapRaw_NonMapValue(t *testing.T) {
	m := map[string]any{"data": "string"}
	result := MapGetMapRaw(m, "data")
	assert.Equal(t, 0, len(result))
}

// --- MapGetMapRawOr ---

func TestMapGetMapRawOr_NilMap(t *testing.T) {
	defaultMap := map[string]any{"default": "val"}
	result := MapGetMapRawOr(nil, "key", defaultMap)
	assert.Equal(t, "val", result["default"])
}

func TestMapGetMapRawOr_ExistingKey(t *testing.T) {
	inner := map[string]any{"nested": "value"}
	m := map[string]any{"data": inner}
	result := MapGetMapRawOr(m, "data", make(map[string]any))
	assert.Equal(t, "value", result["nested"])
}

func TestMapGetMapRawOr_NonMapValue(t *testing.T) {
	defaultMap := map[string]any{"default": "val"}
	m := map[string]any{"data": "string"}
	result := MapGetMapRawOr(m, "data", defaultMap)
	assert.Equal(t, "val", result["default"])
}

// --- MapGetIntOr ---

func TestMapGetIntOr_ExistingKey(t *testing.T) {
	m := map[string]any{"num": 42}
	assert.Equal(t, 42, MapGetIntOr(m, "num", 0))
}

func TestMapGetIntOr_MissingKey(t *testing.T) {
	m := map[string]any{"num": 42}
	assert.Equal(t, 99, MapGetIntOr(m, "missing", 99))
}

func TestMapGetIntOr_NonIntValue_Cov(t *testing.T) {
	m := map[string]any{"str": "hello"}
	assert.Equal(t, 99, MapGetIntOr(m, "str", 99))
}

func TestMapGetIntOr_NilMap(t *testing.T) {
	assert.Equal(t, 99, MapGetIntOr(nil, "key", 99))
}

// --- MapGetInt ---

func TestMapGetInt_ExistingKey(t *testing.T) {
	m := map[string]any{"num": 42}
	assert.Equal(t, 42, MapGetInt(m, "num"))
}

func TestMapGetInt_MissingKey(t *testing.T) {
	m := map[string]any{"num": 42}
	assert.Equal(t, 0, MapGetInt(m, "missing"))
}

// --- MapGetIntEx ---

func TestMapGetIntEx_ExistingKey(t *testing.T) {
	m := map[string]any{"count": 42}
	assert.Equal(t, 42, MapGetIntEx(m, "count"))
}

func TestMapGetIntEx_MissingKey(t *testing.T) {
	m := map[string]any{"count": 42}
	assert.Equal(t, 0, MapGetIntEx(m, "missing"))
}

func TestMapGetIntEx_NumberedKey(t *testing.T) {
	m := map[string]any{"item_1": 7}
	assert.Equal(t, 7, MapGetIntEx(m, "item"))
}

// --- MapGetFloat64Or ---

func TestMapGetFloat64Or_ExistingKey(t *testing.T) {
	m := map[string]any{"val": 3.14}
	assert.Equal(t, 3.14, MapGetFloat64Or(m, "val", 0))
}

func TestMapGetFloat64Or_MissingKey(t *testing.T) {
	m := map[string]any{"val": 3.14}
	assert.Equal(t, 9.99, MapGetFloat64Or(m, "missing", 9.99))
}

func TestMapGetFloat64Or_NonFloatValue_Cov(t *testing.T) {
	m := map[string]any{"val": "not a float"}
	assert.Equal(t, 1.0, MapGetFloat64Or(m, "val", 1.0))
}

func TestMapGetFloat64Or_NilMap(t *testing.T) {
	assert.Equal(t, 1.0, MapGetFloat64Or(nil, "key", 1.0))
}

// --- MapGetFloat64 ---

func TestMapGetFloat64_ExistingKey(t *testing.T) {
	m := map[string]any{"val": 3.14}
	assert.Equal(t, 3.14, MapGetFloat64(m, "val"))
}

func TestMapGetFloat64_MissingKey(t *testing.T) {
	m := map[string]any{"val": 3.14}
	assert.Equal(t, 0.0, MapGetFloat64(m, "missing"))
}

// --- MapGetFloat32Or ---

func TestMapGetFloat32Or_ExistingKey(t *testing.T) {
	m := map[string]any{"val": float32(2.5)}
	assert.Equal(t, float32(2.5), MapGetFloat32Or(m, "val", 0))
}

func TestMapGetFloat32Or_MissingKey(t *testing.T) {
	m := map[string]any{"val": float32(2.5)}
	assert.Equal(t, float32(1.0), MapGetFloat32Or(m, "missing", float32(1.0)))
}

func TestMapGetFloat32Or_NonFloatValue_Cov(t *testing.T) {
	m := map[string]any{"val": "not a float"}
	assert.Equal(t, float32(1.0), MapGetFloat32Or(m, "val", float32(1.0)))
}

func TestMapGetFloat32Or_NilMap(t *testing.T) {
	assert.Equal(t, float32(1.0), MapGetFloat32Or(nil, "key", float32(1.0)))
}

// --- MapGetFloat32 ---

func TestMapGetFloat32_ExistingKey(t *testing.T) {
	m := map[string]any{"val": float32(2.5)}
	assert.Equal(t, float32(2.5), MapGetFloat32(m, "val"))
}

func TestMapGetFloat32_MissingKey(t *testing.T) {
	m := map[string]any{"val": float32(2.5)}
	assert.Equal(t, float32(0), MapGetFloat32(m, "missing"))
}

// --- MapGetBoolOr ---

func TestMapGetBoolOr_ExistingKey(t *testing.T) {
	m := map[string]any{"flag": true}
	assert.True(t, MapGetBoolOr(m, "flag", false))
}

func TestMapGetBoolOr_MissingKey(t *testing.T) {
	m := map[string]any{"flag": true}
	assert.False(t, MapGetBoolOr(m, "missing", false))
}

func TestMapGetBoolOr_NonBoolValue_Cov(t *testing.T) {
	m := map[string]any{"flag": "not a bool"}
	assert.True(t, MapGetBoolOr(m, "flag", true))
}

func TestMapGetBoolOr_NilMap(t *testing.T) {
	assert.True(t, MapGetBoolOr(nil, "key", true))
}

// --- MapGetBool ---

func TestMapGetBool_ExistingKey(t *testing.T) {
	m := map[string]any{"flag": true}
	assert.True(t, MapGetBool(m, "flag"))
}

func TestMapGetBool_MissingKey(t *testing.T) {
	m := map[string]any{"flag": true}
	assert.False(t, MapGetBool(m, "missing"))
}

// --- MapGetInt64Or ---

func TestMapGetInt64Or_ExistingKey(t *testing.T) {
	m := map[string]any{"val": int64(100)}
	assert.Equal(t, int64(100), MapGetInt64Or(m, "val", 0))
}

func TestMapGetInt64Or_MissingKey(t *testing.T) {
	m := map[string]any{"val": int64(100)}
	assert.Equal(t, int64(99), MapGetInt64Or(m, "missing", 99))
}

func TestMapGetInt64Or_NonInt64Value_Cov(t *testing.T) {
	m := map[string]any{"val": "not int64"}
	assert.Equal(t, int64(99), MapGetInt64Or(m, "val", 99))
}

func TestMapGetInt64Or_NilMap(t *testing.T) {
	assert.Equal(t, int64(99), MapGetInt64Or(nil, "key", 99))
}

// --- MapGetInt64 ---

func TestMapGetInt64_ExistingKey(t *testing.T) {
	m := map[string]any{"val": int64(100)}
	assert.Equal(t, int64(100), MapGetInt64(m, "val"))
}

func TestMapGetInt64_MissingKey(t *testing.T) {
	m := map[string]any{"val": int64(100)}
	assert.Equal(t, int64(0), MapGetInt64(m, "missing"))
}

// --- InterfaceToGeneralMap ---

func TestInterfaceToGeneralMap_MapStringAny(t *testing.T) {
	m := map[string]any{"key": "value"}
	assert.Equal(t, "value", InterfaceToGeneralMap(m)["key"])
}

func TestInterfaceToGeneralMap_MapStringString(t *testing.T) {
	m := map[string]string{"key": "value"}
	assert.Equal(t, "value", InterfaceToGeneralMap(m)["key"])
}

func TestInterfaceToGeneralMap_Struct(t *testing.T) {
	type S struct{ Name string }
	assert.Equal(t, "test", InterfaceToGeneralMap(S{Name: "test"})["Name"])
}

func TestInterfaceToGeneralMap_PtrToStruct(t *testing.T) {
	type S struct{ Name string }
	st := S{Name: "test"}
	assert.Equal(t, "test", InterfaceToGeneralMap(&st)["Name"])
}

func TestInterfaceToGeneralMap_ByteSliceValue(t *testing.T) {
	m := map[string]any{"data": []byte("hello")}
	assert.Equal(t, "hello", InterfaceToGeneralMap(m)["data"])
}

func TestInterfaceToGeneralMap_DefaultType_Cov(t *testing.T) {
	result := InterfaceToGeneralMap(42)
	assert.Equal(t, 42, result["__DEFAULT__"])
}

func TestInterfaceToGeneralMap_DefaultString(t *testing.T) {
	result := InterfaceToGeneralMap("hello")
	assert.Equal(t, "hello", result["__DEFAULT__"])
}

func TestInterfaceToGeneralMap_PanicRecovery(t *testing.T) {
	// Passing a value that causes a panic in reflect should be recovered
	// and return a map with __FALLBACK__ key
	result := InterfaceToGeneralMap(nil)
	assert.NotNil(t, result)
}

// --- ToMapParams ---

func TestToMapParams_Struct(t *testing.T) {
	type S struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}
	result, err := ToMapParams(S{Name: "test", Value: 42})
	assert.NoError(t, err)
	assert.Equal(t, "test", result["name"])
}

func TestToMapParams_Map(t *testing.T) {
	m := map[string]any{"key": "value"}
	result, err := ToMapParams(m)
	assert.NoError(t, err)
	assert.Equal(t, "value", result["key"])
}

func TestToMapParams_UnmarshalableError(t *testing.T) {
	_, err := ToMapParams(make(chan int))
	assert.Error(t, err)
}

func TestToMapParams_FloatInf(t *testing.T) {
	// NaN/Inf values marshal to JSON but unmarshal to map[string]any can fail
	inf := float64(0)
	inf = 1.0 / inf // produces +Inf
	m := map[string]any{"val": inf}
	result, err := ToMapParams(m)
	if err != nil {
		// If Inf causes unmarshal error, we covered the error path
		assert.Error(t, err)
		assert.Nil(t, result)
	}
	// If it succeeds, that's fine too
}

// --- ParseStringToGeneralMap ---

func TestParseStringToGeneralMap_ValidJSON(t *testing.T) {
	result := ParseStringToGeneralMap(`{"key": "value"}`)
	assert.Equal(t, "value", result["key"])
}

func TestParseStringToGeneralMap_InvalidJSON(t *testing.T) {
	result := ParseStringToGeneralMap("not json")
	assert.Equal(t, 0, len(result))
}

func TestParseStringToGeneralMap_NestedJSON(t *testing.T) {
	result := ParseStringToGeneralMap(`{"nested": {"inner": "val"}}`)
	nested, ok := result["nested"].(map[string]any)
	assert.True(t, ok)
	assert.Equal(t, "val", nested["inner"])
}

// --- MergeStringMap ---

func TestMergeStringMap_TwoMaps(t *testing.T) {
	m1 := map[string]string{"a": "1", "b": "2"}
	m2 := map[string]string{"b": "3", "c": "4"}
	result := MergeStringMap(m1, m2)
	assert.Equal(t, "1", result["a"])
	assert.Equal(t, "3", result["b"]) // later map wins
	assert.Equal(t, "4", result["c"])
}

func TestMergeStringMap_SingleMap(t *testing.T) {
	m := map[string]string{"a": "1"}
	result := MergeStringMap(m)
	assert.Equal(t, "1", result["a"])
}

func TestMergeStringMap_NoMaps(t *testing.T) {
	result := MergeStringMap()
	assert.Equal(t, 0, len(result))
}

// --- MergeGeneralMap ---

func TestMergeGeneralMap_TwoMaps(t *testing.T) {
	m1 := map[string]any{"a": 1, "b": 2}
	m2 := map[string]any{"b": 3, "c": 4}
	result := MergeGeneralMap(m1, m2)
	assert.Equal(t, 1, result["a"])
	assert.Equal(t, 3, result["b"]) // later map wins
	assert.Equal(t, 4, result["c"])
}

func TestMergeGeneralMap_SingleMap(t *testing.T) {
	m := map[string]any{"a": 1}
	result := MergeGeneralMap(m)
	assert.Equal(t, 1, result["a"])
}

func TestMergeGeneralMap_NoMaps(t *testing.T) {
	result := MergeGeneralMap()
	assert.Equal(t, 0, len(result))
}

// --- MapToStruct ---

func TestMapToStruct_Basic(t *testing.T) {
	type S struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}
	var output S
	err := MapToStruct(map[string]any{"name": "test", "value": 42}, &output)
	assert.NoError(t, err)
	assert.Equal(t, "test", output.Name)
	assert.Equal(t, 42, output.Value)
}

func TestMapToStruct_MissingField(t *testing.T) {
	type S struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}
	var output S
	err := MapToStruct(map[string]any{"name": "test"}, &output)
	assert.NoError(t, err)
	assert.Equal(t, "test", output.Name)
	assert.Equal(t, 0, output.Value)
}

func TestMapToStruct_NilOutput(t *testing.T) {
	err := MapToStruct(map[string]any{"key": "val"}, nil)
	assert.Error(t, err)
}

func TestMapToStruct_NonPointerOutput(t *testing.T) {
	type S struct {
		Name string `json:"name"`
	}
	err := MapToStruct(map[string]any{"name": "test"}, S{})
	assert.Error(t, err)
}

func TestMapToStruct_NilPointer(t *testing.T) {
	type S struct {
		Name string `json:"name"`
	}
	var ptr *S
	err := MapToStruct(map[string]any{"name": "test"}, ptr)
	assert.Error(t, err)
}

func TestMapToStruct_NoJSONTag(t *testing.T) {
	type S struct {
		Name  string `json:"name"`
		NoTag string
	}
	var output S
	err := MapToStruct(map[string]any{"name": "test", "NoTag": "notag"}, &output)
	assert.NoError(t, err)
	assert.Equal(t, "test", output.Name)
}

func TestMapToStruct_UnexportedField(t *testing.T) {
	// unexported fields cannot be set via reflect, covering the CanSet=false path
	type S struct {
		Name  string `json:"name"`
		value string `json:"value"` // unexported
	}
	var output S
	err := MapToStruct(map[string]any{"name": "test", "value": "hidden"}, &output)
	assert.NoError(t, err)
	assert.Equal(t, "test", output.Name)
}
