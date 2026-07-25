/**
2 * @Author: shaochuyu
3 * @Date: 10/27/24
4 */

package utils

import (
	"strconv"
	"strings"
)

func IsValidInteger(raw string) bool {
	_, err := strconv.ParseInt(raw, 10, 64)
	return err == nil
}

func IsValidFloat(raw string) bool {
	_, err := strconv.ParseFloat(raw, 64)
	return err == nil && strings.Contains(raw, ".")
}

func IsValidBool(raw string) bool {
	_, err := strconv.ParseBool(raw)
	return err == nil
}
