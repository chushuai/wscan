package jsonpath

import (
	"container/list"
	"encoding/json"
	"fmt"

	"reflect"
	"wscan/core/utils/log"

	"wscan/core/utils"
)

type iterKey struct {
	Key      string
	JsonPath string
}

func iterKeys(l *list.List, raw any, prefix string) *list.List {
	if l == nil {
		l = list.New()
	}

	if prefix == "" {
		prefix = "$."
	}

	if raw == nil {
		return l
	}

	refType := reflect.TypeOf(raw)
	switch refType.Kind() {
	case reflect.Map:
		for k, v := range utils.InterfaceToMapInterface(raw) {
			l.PushBack(&iterKey{Key: utils.InterfaceToString(k), JsonPath: prefix + k})
			fixedVal, err := utils.InterfaceToMapInterfaceE(v)
			if err == nil {
				iterKeys(l, fixedVal, prefix+k+".")
				continue
			}

			if raw, err := utils.InterfaceToSliceInterfaceE(v); err == nil {
				for index, val := range raw {
					jp := prefix + fmt.Sprintf("%v[%v]", k, index)
					l.PushBack(&iterKey{JsonPath: jp})
					iterKeys(l, val, jp+".")
				}
				continue
			}
		}
	case reflect.Slice:
		for index, val := range utils.InterfaceToSliceInterface(raw) {
			jp := prefix + fmt.Sprintf("[%v]", index)
			l.PushBack(&iterKey{JsonPath: jp})
			iterKeys(l, val, jp+".")
		}
	}

	return l
}

func fetchAllIterKey(i any) []*iterKey {
	var (
		raw       any
		err       error
		originObj any
	)

	raw, originObj, err = ToMapInterface(i)
	if err != nil {
		gSlice, err := utils.InterfaceToSliceInterfaceE(originObj)
		if err != nil {
			return nil
		}
		raw = gSlice
	}

	var a = iterKeys(nil, raw, "$.")
	var result []*iterKey
	el := a.Front()
	for el != nil {
		v, ok := el.Value.(*iterKey)
		if !ok {
			break
		}
		result = append(result, v)
		el = el.Next()
	}
	return result
}

func RecursiveDeepReplaceString(i string, val any) []string {
	r := RecursiveDeepReplace(i, val)
	m := make([]string, len(r))
	for k, v := range r {
		rStr, ok := v.(string)
		if !ok {
			rStr = utils.InterfaceToString(v)
		}
		m[k] = rStr
	}
	return m
}

func ReplaceString(i string, jp string, replaced any) string {
	if jp == "" {
		return i
	}

	data, err := Replace(i, jp, replaced)
	if err != nil {
		log.Warnf("jsonpath(jp) replace %s failed: %s", jp, err)
		return ""
	}
	raw, _ := json.Marshal(data)
	return string(raw)
}

func RecursiveDeepJsonPath(i any) []string {
	var results []string
	for _, k := range fetchAllIterKey(i) {
		results = append(results, k.JsonPath)
	}
	return results
}

func RecursiveDeepReplace(i any, val any) []any {
	var isRawStr bool
	switch i.(type) {
	case string, []byte, []rune:
		isRawStr = true
	}

	extractedIterKey := fetchAllIterKey(i)
	var results []any
	for _, k := range extractedIterKey {
		data, err := ReplaceEx(i, k.JsonPath, val)
		if err != nil {
			log.Warnf("replace %s failed: %s", k.JsonPath, err)
			continue
		}
		if isRawStr {
			raw, err := json.Marshal(data)
			if err != nil {
				log.Warnf("marshal %s failed: %s", k.JsonPath, err)
			}
			if raw != nil {
				results = append(results, string(raw))
			}
		}
	}
	return results
}
