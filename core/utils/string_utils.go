/**
2 * @Author: shaochuyu
3 * @Date: 4/24/24
4 */

package utils

import (
	"github.com/davecgh/go-spew/spew"
	"reflect"
	logger "wscan/core/utils/log"
)

func InterfaceToBytes(i any) (result []byte) {
	return AnyToBytes(i)
}

func InterfaceToString(i any) string {
	if a, ok := i.(interface{ String() string }); ok {
		return a.String()
	}
	return AnyToString(i)
}

// ToStringSlice 将任意类型的数据转换为字符串切片
// Example:
// ```
// str.ToStringSlice("hello") // ["hello"]
// str.ToStringSlice([1, 2]) // ["1", "2"]
// ```
func InterfaceToStringSlice(i any) (result []string) {
	defer func() {
		if err := recover(); err != nil {
			logger.Errorf("str.ToStringSlice failed: %s", err)
			spew.Dump(i)
			PrintCurrentGoroutineRuntimeStack()
			result = []string{InterfaceToString(i)}
		}
	}()

	if i == nil {
		return []string{}
	}

	va := reflect.ValueOf(i)
	switch reflect.TypeOf(i).Kind() {
	case reflect.Slice, reflect.Array:
		for i := 0; i < va.Len(); i++ {
			result = append(result, InterfaceToString(va.Index(i).Interface()))
		}
	default:
		result = append(result, InterfaceToString(i))
	}
	return result
}

func FilterUniqueStrings(strSlice []string) []string {
	// 使用map来存储已经出现过的字符串，map的键是字符串，值可以是任意类型（这里我们不需要值，所以用bool）
	keys := make(map[string]bool)
	list := []string{} // 用来存储结果的新切片
	// 遍历输入切片，将未出现过的字符串添加到结果切片和map中
	for _, entry := range strSlice {
		if _, exists := keys[entry]; !exists {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}
