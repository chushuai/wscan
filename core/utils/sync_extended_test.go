package utils

import (
	"context"
	"testing"
	"time"
)

func TestSizedWaitGroup_AddWithContext(t *testing.T) {
	swg := NewSizedWaitGroup(2)

	// Test normal add - should succeed
	err := swg.AddWithContext(context.Background())
	if err != nil {
		t.Errorf("AddWithContext should succeed with valid context: %v", err)
	}
	swg.Done()

	// Test with cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Fill up the wait group first
	swg.Add()
	swg.Add()
	// Now the next AddWithContext should fail due to cancelled context
	err = swg.AddWithContext(ctx)
	if err == nil {
		t.Errorf("AddWithContext should return error with cancelled context")
		// If it somehow succeeded, clean up
		swg.Done()
	}
	if err != context.Canceled {
		t.Logf("AddWithContext error = %v, want context.Canceled", err)
	}

	// Clean up
	swg.Done()
	swg.Done()
	swg.Wait()
}

func TestSizedWaitGroup_AddWithContext_Concurrency(t *testing.T) {
	swg := NewSizedWaitGroup(3)

	// Test multiple goroutines using AddWithContext
	done := make(chan struct{})
	for i := 0; i < 3; i++ {
		err := swg.AddWithContext(context.Background())
		if err != nil {
			t.Errorf("AddWithContext failed: %v", err)
		}
		go func() {
			defer swg.Done()
			time.Sleep(10 * time.Millisecond)
		}()
	}

	go func() {
		swg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second):
		t.Errorf("SizedWaitGroup.Wait timed out")
	}
}

func TestSizedWaitGroup_AddWithContext_Timeout(t *testing.T) {
	swg := NewSizedWaitGroup(1)

	// Fill the group
	swg.Add()

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// This should timeout since the group is full
	err := swg.AddWithContext(ctx)
	if err == nil {
		t.Errorf("AddWithContext should return error when context times out")
		swg.Done() // clean up if it unexpectedly succeeded
	}

	// Clean up
	swg.Done()
	swg.Wait()
}
