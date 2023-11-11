/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package utils

import (
	"math/rand"
	"time"
)

// RandLower returns a random string of lowercase letters with length n.
func RandLower(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// RandLowerLetter returns a random string of lowercase letters and digits with length n.
func RandLowerLetter(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// RandIntForExprSum returns two random integers x and y where x + y = n.
func RandIntForExprSum(n int) (x, y int) {
	x = rand.Intn(n)
	y = n - x
	return
}

// RandIntForExprMultiply returns two random integers x and y where x * y = n.
func RandIntForExprMultiply(n int) (x, y int) {
	for x == 0 || y == 0 {
		x = rand.Intn(n)
		y = n / x
	}
	return
}

// 生成随机范围整数
func RandInt(min, max int) int {
	rand.Seed(time.Now().Unix())
	randNum := rand.Intn(max - min)
	randNum = randNum + min
	return randNum
}
