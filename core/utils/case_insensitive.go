/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package utils

import (
	"bytes"
	"strings"
)

// IStringContains 判断字符串 s 是否包含子串 substr，忽略大小写
func IStringContains(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

// IStringHasPrefix 判断字符串 s 是否以前缀 prefix 开头，忽略大小写
func IStringHasPrefix(s, prefix string) bool {
	return strings.HasPrefix(strings.ToLower(s), strings.ToLower(prefix))
}

// IBytesHasPrefix 判断字节切片 b 是否以前缀 prefix 开头，忽略大小写
func IBytesHasPrefix(b, prefix []byte) bool {
	return bytes.HasPrefix(bytes.ToLower(b), bytes.ToLower(prefix))
}

// IBytesContains 判断字节切片 b 是否包含子切片 subslice，忽略大小写
func IBytesContains(b, subslice []byte) bool {
	return bytes.Contains(bytes.ToLower(b), bytes.ToLower(subslice))
}

// StringIIn 判断字符串 s 是否在字符串切片 a 中出现，忽略大小写
func StringIIn(s string, a []string) bool {
	for _, v := range a {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}
