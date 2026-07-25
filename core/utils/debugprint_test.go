package utils

import (
	"testing"
)

func TestTryWriteChannel(t *testing.T) {
	// Test writing to open channel
	ch := make(chan int, 1)
	result := TryWriteChannel(ch, 42)
	if !result {
		t.Errorf("TryWriteChannel to open channel should return true")
	}
	if val := <-ch; val != 42 {
		t.Errorf("Channel value = %d, want 42", val)
	}

	// Test writing to closed channel
	ch2 := make(chan int, 1)
	close(ch2)
	result = TryWriteChannel(ch2, 42)
	if result {
		t.Errorf("TryWriteChannel to closed channel should return false")
	}
}

func TestTryCloseChannel(t *testing.T) {
	// Test closing open channel
	ch := make(chan int)
	TryCloseChannel(ch)
	// Verify it's closed
	_, ok := <-ch
	if ok {
		t.Errorf("Channel should be closed")
	}

	// Test closing nil
	TryCloseChannel(nil) // should not panic

	// Test closing already closed channel (should not panic)
	ch2 := make(chan int)
	close(ch2)
	TryCloseChannel(ch2) // should not panic

	// Test with non-channel type
	TryCloseChannel(42) // should not panic
}
