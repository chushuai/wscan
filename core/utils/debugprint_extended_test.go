package utils

import (
	"testing"
)

func TestPrintCurrentGoroutineRuntimeStack_Ext(t *testing.T) {
	// Just verify it doesn't panic
	PrintCurrentGoroutineRuntimeStack()
}
