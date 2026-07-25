/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package utils

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"math/rand"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
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

const letterBytes = "abcdefghijklmnopqrstuvwxyz"
const letterNumberBytes = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const lowletterNumberBytes = "0123456789abcdefghijklmnopqrstuvwxyz"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

// RandFromChoices 从choices里面随机获取
func RandFromChoices(n int, choices string) string {
	b := make([]byte, n)
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	// A rand.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, r.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = r.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(choices) {
			b[i] = choices[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}

// RandLetters 随机小写字母
func RandLetters(n int) string {
	return RandFromChoices(n, letterBytes)
}

// RandLetterNumbers 随机大小写字母和数字
func RandLetterNumbers(n int) string {
	return RandFromChoices(n, letterNumberBytes)
}

// RandLowLetterNumber 随机小写字母和数字
func RandLowLetterNumber(n int) string {
	return RandFromChoices(n, lowletterNumberBytes)
}

// 获取随机字符串
func RandomStr(letterBytes string, n int) string {
	randSource := rand.New(rand.NewSource(time.Now().UnixNano()))
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

func StringHasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func Sha256(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func MD5String(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

func EscapeInvalidUTF8Byte(s string, replacement string) string {
	var b strings.Builder
	for len(s) > 0 {
		r, size := utf8.DecodeRuneInString(s)
		if r == utf8.RuneError {
			b.WriteString(replacement)
		} else {
			b.WriteRune(r)
		}
		s = s[size:]
	}
	return b.String()
}

func LimitStringLength(input string, maxLength int) string {
	if len(input) <= maxLength {
		return input
	}
	return input[:maxLength]
}

func RandomUpper(text string) string {
	rand.Seed(time.Now().UnixNano())
	length := len(text)
	runes := []rune(text) // Convert the string to a slice of runes to handle Unicode characters

	for i := 0; i < length/2; i++ {
		randIdx := rand.Intn(length)
		for unicode.IsUpper(runes[randIdx]) {
			randIdx = rand.Intn(length)
		}
		runes[randIdx] = unicode.ToUpper(runes[randIdx])
	}

	return string(runes)
}
