/**
2 * @Author: shaochuyu
3 * @Date: 4/24/24
4 */

package utils

import (
	"fmt"
	"strconv"
)

func Atoi(i string) int {
	raw, _ := strconv.Atoi(i)
	return raw
}

func Itoa(i int) string {
	return fmt.Sprint(i)
}

func Atof(i string) float64 {
	raw, _ := strconv.ParseFloat(i, 64)
	return raw
}

func Atob(i string) bool {
	raw, _ := strconv.ParseBool(i)
	return raw
}

func AnyToBytes(i any) (result []byte) {
	var b []byte
	defer func() {
		if err := recover(); err != nil {
			result = []byte(fmt.Sprintf("%v", i))
		}
	}()

	if i == nil {
		return []byte{}
	}

	switch s := i.(type) {
	case nil:
		return []byte{}
	case string:
		b = []byte(s)
	case []byte:
		b = s[0:]
	case bool:
		b = []byte(strconv.FormatBool(s))
	case float64:
		return []byte(strconv.FormatFloat(s, 'f', -1, 64))
	case float32:
		return []byte(strconv.FormatFloat(float64(s), 'f', -1, 32))
	case int:
		return []byte(strconv.Itoa(s))
	case int64:
		return []byte(strconv.FormatInt(s, 10))
	case int32:
		return []byte(strconv.Itoa(int(s)))
	case int16:
		return []byte(strconv.FormatInt(int64(s), 10))
	case int8:
		return []byte(strconv.FormatInt(int64(s), 10))
	case uint:
		return []byte(strconv.FormatUint(uint64(s), 10))
	case uint64:
		return []byte(strconv.FormatUint(s, 10))
	case uint32:
		return []byte(strconv.FormatUint(uint64(s), 10))
	case uint16:
		return []byte(strconv.FormatUint(uint64(s), 10))
	case uint8:
		return []byte(strconv.FormatUint(uint64(s), 10))
	case fmt.Stringer:
		return []byte(s.String())
	case error:
		return []byte(s.Error())
	//case io.Reader:
	//	if ret != nil && ret.Read != nil {
	//		bytes, _ = io.ReadAll(ret)
	//		return bytes
	//	}
	//	return []byte(fmt.Sprintf("%v", i))
	default:
		b = []byte(fmt.Sprintf("%v", i))
	}

	return b
}

func AnyToString(i any) string {
	return string(AnyToBytes(i))
}
