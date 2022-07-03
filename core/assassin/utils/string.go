/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package utils

import (
	"crypto/md5"
	"encoding/hex"
	"math/rand"
	"time"
)

const (
	AsciiLowercase          = "abcdefghijklmnopqrstuvwxyz"
	AsciiUppercase          = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	AsciiLetters            = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	AsciiDigits             = "0123456789"
	AsciiLowercaseAndDigits = AsciiLowercase + AsciiDigits
	AsciiUppercaseAndDigits = AsciiUppercase + AsciiDigits
	AsciiLettersAndDigits   = AsciiLetters + AsciiDigits
)

// 获取随机字符串
func RandomStr(letterBytes string, n int) string {
	randSource := rand.New(rand.NewSource(time.Now().Unix()))
	const (
		letterIdxBits = 6                    // 6 bits to represent a letter index
		letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
		letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
		//letterBytes   = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	)
	randBytes := make([]byte, n)
	for i, cache, remain := n-1, randSource.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = randSource.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			randBytes[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}
	return string(randBytes)
}

// 获取字符串md5
func MD5(str string) string {
	c := md5.New()
	c.Write([]byte(str))
	bytes := c.Sum(nil)
	return hex.EncodeToString(bytes)
}

//反向string

func ReverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}
