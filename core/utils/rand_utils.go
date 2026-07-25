/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package utils

import (
	"math/rand"
	"time"
)

func RandStringBytes(n int) string {
	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	rand.Seed(time.Now().UnixNano())

	// 创建一个切片，其中包含所有可用的字母
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}

	// 将字节数组转换为字符串并返回
	return string(b)
}
