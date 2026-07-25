package jsonpath

import (
	"encoding/json"
	"reflect"
	"wscan/core/utils"
	logger "wscan/core/utils/log"
)

func ReplaceAll(j any, jpath string, replaceValue any) map[string]any {
	raw := utils.InterfaceToBytes(j)
	var m map[string]any
	err := json.Unmarshal(raw, &m)
	if err != nil {
		logger.Errorf("unmarshal json failed: %s", err)
		return nil
	}
	result, err := Replace(m, jpath, replaceValue)
	if err != nil {
		logger.Errorf("replace jsonpath failed: %s", err)
		return nil
	}
	return result
}

func Find(j any, jpath string) any {
	raw := utils.InterfaceToBytes(j)
	var i any
	err := json.Unmarshal(raw, &i)
	if err != nil {
		logger.Errorf("unmarshal json failed: %s", err)
		return nil
	}
	result, err := Read(i, jpath)
	if err != nil {
		logger.Errorf("read jsonpath failed: %s", err)
		return nil
	}
	return result
}

func FindFirst(j any, jpath string) any {
	result := Find(j, jpath)
	if result == nil {
		return result
	}
	switch reflect.TypeOf(result).Kind() {
	case reflect.Slice, reflect.Array:
		value := reflect.ValueOf(result)
		if value.Len() > 0 {
			return value.Index(0).Interface()
		}
		return nil
	default:
		return result
	}
}
