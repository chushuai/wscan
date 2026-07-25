package collector

import (
	"context"
	"io"
	"strings"
	"testing"

	"wscan/core/resource"
)

func TestServiceListCollect_FitOut(t *testing.T) {
	slc := &serviceListCollect{}
	ch, err := slc.FitOut(context.Background(), []string{})
	if ch != nil {
		t.Errorf("expected nil channel, got %v", ch)
	}
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestServiceListCollect_FitOut_WithTargets(t *testing.T) {
	slc := &serviceListCollect{}
	targets := []string{"192.168.1.1:80", "10.0.0.1:443"}
	ch, err := slc.FitOut(context.Background(), targets)
	if ch != nil {
		t.Errorf("expected nil channel, got %v", ch)
	}
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestServiceListCollect_WithReader(t *testing.T) {
	data := "192.168.1.1:80\n10.0.0.1:443\n"
	slc := &serviceListCollect{
		r: io.NopCloser(strings.NewReader(data)),
	}
	if slc.r == nil {
		t.Error("expected reader to be set")
	}
}

func TestServiceListCollect_CancelledContext(t *testing.T) {
	slc := &serviceListCollect{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ch, err := slc.FitOut(ctx, []string{})
	// serviceListCollect ignores context
	if ch != nil {
		t.Errorf("expected nil channel, got %v", ch)
	}
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestServiceListCollect_NilReader(t *testing.T) {
	slc := &serviceListCollect{}
	if slc.r != nil {
		t.Error("expected default reader to be nil")
	}
}

func TestServiceListCollect_ImplementsFitter(t *testing.T) {
	// Verify that serviceListCollect satisfies the Fitter interface at compile time
	var _ Fitter = (*serviceListCollect)(nil)
}

func TestServiceListCollect_FitOut_MultipleTargets(t *testing.T) {
	slc := &serviceListCollect{}
	ch, err := slc.FitOut(context.Background(), []string{"192.168.1.1:80", "10.0.0.1:443", "172.16.0.1:8080"})
	if ch != nil {
		t.Errorf("expected nil channel, got %v", ch)
	}
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestServiceListCollect_ReaderContents(t *testing.T) {
	data := "192.168.1.1:80\n10.0.0.1:443\n172.16.0.1:8080\n"
	r := io.NopCloser(strings.NewReader(data))
	slc := &serviceListCollect{r: r}

	// Verify the reader can be read
	content, err := io.ReadAll(slc.r)
	if err != nil {
		t.Fatalf("failed to read from reader: %v", err)
	}
	if string(content) != data {
		t.Errorf("expected content %q, got %q", data, string(content))
	}
}

func TestServiceListCollect_FitOut_CallsServiceFromAddr(t *testing.T) {
	// FitOut internally calls resource.ServiceFromAddr()
	// This test verifies the call doesn't panic
	slc := &serviceListCollect{}
	_, err := slc.FitOut(context.Background(), []string{"192.168.1.1:80"})
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

// Ensure resource.ServiceFromAddr is available (compile-time check)
var _ = resource.ServiceFromAddr
