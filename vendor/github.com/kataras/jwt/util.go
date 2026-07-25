package jwt

import "unsafe"

// BytesToString converts a slice of bytes to string without memory allocation.
func BytesToString(b []byte) string {
	return unsafe.String(unsafe.SliceData(b), len(b))
}
