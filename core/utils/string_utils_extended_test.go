package utils

import (
	"testing"
)

func TestInterfaceToStringSlice_Array(t *testing.T) {
	// Test with array type
	arr := [3]int{1, 2, 3}
	result := InterfaceToStringSlice(arr)
	if len(result) != 3 {
		t.Errorf("InterfaceToStringSlice([3]int) = %v, want length 3", result)
	}
	if result[0] != "1" || result[1] != "2" || result[2] != "3" {
		t.Errorf("InterfaceToStringSlice([3]int) = %v, want [1 2 3]", result)
	}
}

func TestInterfaceToStringSlice_EmptySlice(t *testing.T) {
	// Test with empty slice
	result := InterfaceToStringSlice([]string{})
	if len(result) != 0 {
		t.Errorf("InterfaceToStringSlice([]string{}) = %v, want empty", result)
	}
}

func TestInterfaceToStringSlice_Nil(t *testing.T) {
	result := InterfaceToStringSlice(nil)
	if len(result) != 0 {
		t.Errorf("InterfaceToStringSlice(nil) should return empty slice")
	}
}

func TestInterfaceToString_Nil(t *testing.T) {
	result := InterfaceToString(nil)
	if result != "" {
		t.Errorf("InterfaceToString(nil) = %q, want empty string", result)
	}
}

func TestInterfaceToBytes_Nil(t *testing.T) {
	result := InterfaceToBytes(nil)
	if len(result) != 0 {
		t.Errorf("InterfaceToBytes(nil) should return empty byte slice")
	}
}
