package collector

import (
	"context"
	"testing"

	"wscan/core/resource"
)

// mockFitter is a test implementation of the Fitter interface
type mockFitter struct {
	out chan resource.Resource
	err error
}

func (m *mockFitter) FitOut(_ context.Context, _ []string) (chan resource.Resource, error) {
	return m.out, m.err
}

func TestFitterInterface_NilChannel(t *testing.T) {
	var f Fitter = &mockFitter{out: nil, err: nil}
	ch, err := f.FitOut(context.Background(), []string{})
	if ch != nil {
		t.Errorf("expected nil channel, got %v", ch)
	}
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestFitterInterface_WithChannel(t *testing.T) {
	ch := make(chan resource.Resource, 10)
	var f Fitter = &mockFitter{out: ch, err: nil}
	result, err := f.FitOut(context.Background(), []string{"http://example.com"})
	if result != ch {
		t.Error("expected same channel returned")
	}
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestFitterInterface_WithError(t *testing.T) {
	var f Fitter = &mockFitter{out: nil, err: context.Canceled}
	_, err := f.FitOut(context.Background(), []string{})
	if err != context.Canceled {
		t.Errorf("expected context.Canceled error, got %v", err)
	}
}

func TestFitterInterface_WithTargets(t *testing.T) {
	ch := make(chan resource.Resource, 10)
	var f Fitter = &mockFitter{out: ch, err: nil}
	targets := []string{"http://a.com", "http://b.com", "http://c.com"}
	result, err := f.FitOut(context.Background(), targets)
	if result != ch {
		t.Error("expected same channel returned")
	}
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestFitterInterface_CancelledContext(t *testing.T) {
	ch := make(chan resource.Resource, 10)
	var f Fitter = &mockFitter{out: ch, err: nil}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := f.FitOut(ctx, []string{})
	if result != ch {
		t.Error("expected same channel returned even with cancelled context")
	}
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestDummyCollector_ImplementsFitter(t *testing.T) {
	// Verify that dummyCollector satisfies the Fitter interface at compile time
	var _ Fitter = (*dummyCollector)(nil)
}
