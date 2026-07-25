package hexutil

import (
	"encoding/hex"
	"strings"
)

// Encode encodes data to hex string using the specified format
// format can be:
//   - "x" for escaped format (\x6d\x65\x6f\x77)
//   - any other value or empty for standard hex format (6d656f77)
func Encode(data any, format ...string) string {
	var dataStr string
	switch v := any(data).(type) {
	case string:
		dataStr = v
	case []byte:
		dataStr = string(v)
	default:
		dataStr = ""
	}

	hexString := hex.EncodeToString([]byte(dataStr))

	if len(format) == 0 {
		return hexString
	}

	switch strings.ToLower(format[0]) {
	case "x":
		var result strings.Builder
		for i := 0; i < len(hexString); i += 2 {
			if i+1 < len(hexString) {
				result.WriteString("\\x")
				result.WriteString(hexString[i : i+2])
			}
		}
		return result.String()
	default:
		return hexString
	}
}

func EncodeStandard(data any) string {
	return Encode(data)
}

func EncodeEscaped(data any) string {
	return Encode(data, "x")
}
