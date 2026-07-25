/**
2 * @Author: shaochuyu
3 * @Date: 4/24/24
4 */

package utils

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"reflect"
	"sort"
	"strings"
	"wscan/core/utils/log"
)

func MarshalIdempotent(v any) ([]byte, error) {
	var order func(v any) any
	order = func(v any) any {
		if v == nil {
			return nil
		}
		refV := reflect.ValueOf(v)
		if refV.Kind() == reflect.Ptr {
			refV = refV.Elem()
		}
		switch refV.Kind() {
		case reflect.Map:
			res := [][2]any{}
			keys := refV.MapKeys()
			sort.Slice(keys, func(i, j int) bool {
				return InterfaceToString(keys[i].Interface()) < InterfaceToString(keys[j].Interface())
			})
			for _, k := range keys {
				res = append(res, [2]any{k.Interface(), order(refV.MapIndex(k).Interface())})
			}
			return res
		case reflect.Slice, reflect.Array:
			res := []any{}
			for i := 0; i < refV.Len(); i++ {
				res = append(res, order(refV.Index(i).Interface()))
			}
			return res
		}
		return v
	}
	// 执行JSON编码
	return json.Marshal(order(v))
}

func MapGetStringOr(m map[string]any, key string, value string) string {
	if m == nil {
		return value
	}

	r, ok := m[key]
	if ok {
		v, typeOk := r.(string)
		if typeOk {
			return v
		}
	}
	return value
}

func MapGetStringOr2(m map[string]string, key string, value string) string {
	if m == nil {
		return value
	}

	r, ok := m[key]
	if ok {
		return r
	}
	return value
}

func MapStringGetOr(m map[string]string, key string, value string) string {
	if m == nil {
		return value
	}

	r, ok := m[key]
	if ok {
		return r
	}

	return value
}

func MapStringGet(m map[string]string, key string) string {
	return MapStringGetOr(m, key, "")
}

func MapGetRaw(m map[string]any, key string) any {
	return MapGetRawOr(m, key, nil)
}

func MapGetFirstRaw(m map[string]any, key ...string) any {
	if len(key) <= 0 {
		return nil
	}

	for _, i := range key {
		result := MapGetRawOr(m, i, nil)
		if result != nil {
			return result
		}

		// If not, try to find the key with "request_%d" format
		for j := 1; j <= 20; j++ {
			reqKey := fmt.Sprintf("%s_%d", i, j)
			result := MapGetRawOr(m, reqKey, nil)
			if result != nil {
				return result
			}
		}
	}
	return nil
}

func MapGetRawOr(m map[string]any, key string, value any) any {
	if m == nil {
		return value
	}

	r, ok := m[key]
	if ok {
		return r
	} else {
		return value
	}
}

func MapGetString(m map[string]any, key string) string {
	return MapGetStringOr(m, key, "")
}
func MapGetStringSlice(m map[string]any, key string) []string {
	return InterfaceToStringSlice(MapGetRaw(m, key))
}
func MapGetStringByManyFields(m map[string]any, key ...string) string {
	if len(key) <= 0 {
		return ""
	}

	for _, i := range key {
		result := MapGetStringOr(m, i, "")
		if result != "" {
			return result
		}
	}
	return ""
}

func ExtractMapValueString(m any, key string) string {
	return MapGetString(ParseStringToGeneralMap(m), key)
}

func ExtractMapValueInt(m any, key string) int {
	return MapGetInt(ParseStringToGeneralMap(m), key)
}

func ExtractMapValueBool(m any, key string) bool {
	return MapGetBool(ParseStringToGeneralMap(m), key)
}

func ExtractMapValueGeneralMap(m any, key string) map[string]any {
	return MapGetMapRaw(ParseStringToGeneralMap(m), key)
}

func ExtractMapValueRaw(m any, key string) any {
	return MapGetRaw(ParseStringToGeneralMap(m), key)
}

func InterfaceToMapInterface(i any) map[string]any {
	raw, _ := InterfaceToMapInterfaceE(i)
	return raw
}

func InterfaceToSliceInterface(i any) []any {
	raw, _ := InterfaceToSliceInterfaceE(i)
	return raw
}

func InterfaceToSliceInterfaceE(i any) ([]any, error) {
	result := make([]any, 0)
	if i == nil {
		return result, errors.New("empty")
	}
	switch ret := i.(type) {
	case []any:
		for _, v := range ret {
			result = append(result, v)
		}
		return result, nil
	default:
		if reflect.TypeOf(i).Kind() == reflect.Slice {
			v := reflect.ValueOf(i)
			for j := 0; j < v.Len(); j++ {
				result = append(result, v.Index(j).Interface())
			}
			return result, nil
		} else {
			result = append(result, i)
			return result, errors.New(fmt.Sprintf("interfaceToRawMap error, got: %v", spew.Sdump(i)))
		}
	}
}

func InterfaceToMapInterfaceE(i any) (map[string]any, error) {
	result := make(map[string]any)
	if i == nil {
		return result, errors.New("empty")
	}
	switch ret := i.(type) {
	case map[string]any:
		return ret, nil
	case map[string]string:
		for k, v := range ret {
			result[k] = v
		}
		return result, nil
	case map[any]any:
		result := make(map[string]any)
		for k, v := range ret {
			result[InterfaceToString(k)] = v
		}
		return result, nil
	default:
		if reflect.TypeOf(i).Kind() == reflect.Map {
			v := reflect.ValueOf(i)
			for _, k := range v.MapKeys() {
				result[InterfaceToString(k.Interface())] = v.MapIndex(k).Interface()
			}
			return result, nil
		} else {
			result["__[yaklang-raw]__"] = i
			return result, errors.New(fmt.Sprintf("interfaceToRawMap error, got: %v", spew.Sdump(i)))
		}
	}
}

func MapGetString2(m map[string]string, key string) string {
	return MapGetStringOr2(m, key, "")
}

func MapGetMapRaw(m map[string]any, key string) map[string]any {
	return MapGetMapRawOr(m, key, make(map[string]any))
}

func MapGetMapRawOr(m map[string]any, key string, value map[string]any) map[string]any {
	if m == nil {
		return value
	}

	r, ok := m[key]
	if ok {
		data, typeOk := r.(map[string]any)
		if typeOk {
			return data
		}
	}
	return value
}

func MapGetIntOr(m map[string]any, key string, value int) int {
	if m == nil {
		return value
	}

	r, ok := m[key]
	if ok {
		v, typeOk := r.(int)
		if typeOk {
			return v
		}
	}
	return value
}

func MapGetInt(m map[string]any, key string) int {
	return MapGetIntOr(m, key, 0)
}

func MapGetIntEx(m map[string]any, key ...string) int {
	return Atoi(InterfaceToString(MapGetFirstRaw(m, key...)))
}

func MapGetFloat64Or(m map[string]any, key string, value float64) float64 {
	if m == nil {
		return value
	}

	r, ok := m[key]
	if ok {
		v, typeOk := r.(float64)
		if typeOk {
			return v
		}
	}
	return value
}

func MapGetFloat64(m map[string]any, key string) float64 {
	return MapGetFloat64Or(m, key, 0)
}

func MapGetFloat32Or(m map[string]any, key string, value float32) float32 {
	if m == nil {
		return value
	}

	r, ok := m[key]
	if ok {
		v, typeOk := r.(float32)
		if typeOk {
			return v
		}
	}
	return value
}

func MapGetFloat32(m map[string]any, key string) float32 {
	return MapGetFloat32Or(m, key, 0)
}

func MapGetBoolOr(m map[string]any, key string, value bool) bool {
	if m == nil {
		return value
	}

	r, ok := m[key]
	if ok {
		v, typeOk := r.(bool)
		if typeOk {
			return v
		}
	}
	return value
}

func MapGetBool(m map[string]any, key string) bool {
	return MapGetBoolOr(m, key, false)
}

func MapGetInt64Or(m map[string]any, key string, value int64) int64 {
	if m == nil {
		return value
	}

	r, ok := m[key]
	if ok {
		v, typeOk := r.(int64)
		if typeOk {
			return v
		}
	}
	return value
}

func MapGetInt64(m map[string]any, key string) int64 {
	return MapGetInt64Or(m, key, 0)
}

func InterfaceToGeneralMap(params any) (finalResult map[string]any) {
	defer func() {
		if err := recover(); err != nil {
			log.Errorf("handle ptr/struct to map failed: %s", err)
			finalResult = map[string]any{
				"__FALLBACK__": params,
			}
		}
	}()

	var p = map[string]any{}
	setField := func(r reflect.Type, v reflect.Value, i int) {
		defer func() {
			if err := recover(); err != nil {
				key := r.Field(i)
				p[key.Name] = v.FieldByName(key.Name).Interface()
			}
		}()
	}
	pType := reflect.TypeOf(params)
	switch pType.Kind() {
	case reflect.Ptr:
		mapValue := reflect.ValueOf(params)
		res := mapValue.Elem()
		pType = reflect.TypeOf(res.Interface())
		for i := 0; i < res.NumField(); i++ {
			setField(pType, res, i)
		}
	case reflect.Struct:
		res := reflect.ValueOf(params)
		for i := 0; i < res.NumField(); i++ {
			setField(pType, res, i)
		}
	case reflect.Map:
		mapValue := reflect.ValueOf(params)
		for _, k := range mapValue.MapKeys() {
			valueRaw := mapValue.MapIndex(k)
			value := valueRaw.Interface()
			switch ret := value.(type) {
			case []byte:
				mapValue.SetMapIndex(k, reflect.ValueOf(string(ret)))
				p[k.String()] = string(ret)
			default:
				p[k.String()] = value
			}
		}
		return p
	default:
		p["__DEFAULT__"] = params
		return p
	}
	return p
}

func ToMapParams(params any) (map[string]any, error) {
	var p = map[string]any{}
	raw, err := json.Marshal(params)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("marshal params failed: %s", err))
	}

	err = json.Unmarshal(raw, &p)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("unmarshal map params failed: %s", err))
	}

	return p, nil
}

func ParseStringToGeneralMap(i any) map[string]any {
	data := InterfaceToString(i)
	data = strings.TrimSpace(data)
	var target any
	err := json.Unmarshal([]byte(data), &target)
	if err != nil {
		log.Warnf("parse `%v` to map[string]any failed: %s", data, err)
		return make(map[string]any)
	}
	return InterfaceToGeneralMap(target)
}

func MergeStringMap(ms ...map[string]string) map[string]string {
	res := map[string]string{}
	for _, m := range ms {
		for k, v := range m {
			res[k] = v
		}
	}
	return res
}

func MergeGeneralMap(ms ...map[string]any) map[string]any {
	res := map[string]any{}
	for _, m := range ms {
		for k, v := range m {
			res[k] = v
		}
	}
	return res
}

func MapToStruct(input map[string]any, output any) error {
	outputValue := reflect.ValueOf(output)
	if outputValue.Kind() != reflect.Ptr || outputValue.IsNil() {
		return fmt.Errorf("output must be a non-nil pointer to a struct")
	}

	outputType := outputValue.Elem().Type()

	for i := 0; i < outputType.NumField(); i++ {
		field := outputType.Field(i)
		fieldName := field.Tag.Get("json")

		if fieldName == "" {
			fieldName = field.Name
		}

		value, ok := input[fieldName]
		if !ok {
			continue
		}

		fieldValue := outputValue.Elem().FieldByName(field.Name)
		if !fieldValue.IsValid() {
			continue
		}

		if fieldValue.CanSet() {
			fieldValue.Set(reflect.ValueOf(value))
		}
	}

	return nil
}
