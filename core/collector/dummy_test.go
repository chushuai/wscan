package collector

import (
	"context"
	"testing"

	"wscan/core/resource"
)

func TestDummyCollector_FitOut(t *testing.T) {
	dc := &dummyCollector{}
	ch, err := dc.FitOut(context.Background(), []string{})
	if ch != nil {
		t.Errorf("expected nil channel from dummyCollector.FitOut, got %v", ch)
	}
	if err != nil {
		t.Errorf("expected nil error from dummyCollector.FitOut, got %v", err)
	}
}

func TestDummyCollector_FitOut_WithTargets(t *testing.T) {
	dc := &dummyCollector{}
	targets := []string{"http://example.com", "http://test.com"}
	ch, err := dc.FitOut(context.Background(), targets)
	if ch != nil {
		t.Errorf("expected nil channel from dummyCollector.FitOut with targets, got %v", ch)
	}
	if err != nil {
		t.Errorf("expected nil error from dummyCollector.FitOut with targets, got %v", err)
	}
}

func TestDummyCollector_FitOut_CancelledContext(t *testing.T) {
	dc := &dummyCollector{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately
	ch, err := dc.FitOut(ctx, []string{})
	// dummyCollector ignores context and always returns nil, nil
	if ch != nil {
		t.Errorf("expected nil channel, got %v", ch)
	}
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestDummyCollector_FromChannel(t *testing.T) {
	ch := make(chan resource.Resource, 1)
	dc := &dummyCollector{from: ch}
	if dc.from == nil {
		t.Error("expected from channel to be set")
	}
}

func TestDummyCollector_NilFrom(t *testing.T) {
	dc := &dummyCollector{}
	if dc.from != nil {
		t.Error("expected default from channel to be nil")
	}
}
