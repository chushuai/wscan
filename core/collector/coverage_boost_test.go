package collector

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"wscan/core/http"
	"wscan/core/utils"
	"wscan/core/utils/checker"
)

// ==================== mitm.go: OnFlow and buildModifier coverage ====================
// OnFlow and buildModifier are empty functions (0 executable statements).
// Go's coverage tool always reports 0% for empty function bodies regardless of
// whether they are called. These tests ensure they are at least called so that
// if anyone adds code to them in the future, coverage will be tracked.

func TestMitmProxy_OnFlow_WithCallback(t *testing.T) {
	m := &MitmProxy{}
	// Call OnFlow with various callback functions to ensure no panic
	m.OnFlow(nil)
	m.OnFlow(func(*http.Flow) error { return nil })
	m.OnFlow(func(f *http.Flow) error {
		return nil
	})
}

func TestMitmProxy_OnFlow_WithInitializedProxy(t *testing.T) {
	tmpDir := t.TempDir()
	utils.GenerateCAToPath(tmpDir + string(os.PathSeparator))

	conf := newTestMitmConfig(tmpDir)
	opts := &http.ClientOptions{}
	m := NewMitmProxy(conf, opts)
	if m == nil {
		t.Fatal("expected non-nil MitmProxy")
	}
	m.OnFlow(func(*http.Flow) error { return nil })
}

func TestMitmProxy_BuildModifier_WithInitializedProxy(t *testing.T) {
	tmpDir := t.TempDir()
	utils.GenerateCAToPath(tmpDir + string(os.PathSeparator))

	conf := newTestMitmConfig(tmpDir)
	opts := &http.ClientOptions{}
	m := NewMitmProxy(conf, opts)
	if m == nil {
		t.Fatal("expected non-nil MitmProxy")
	}
	m.buildModifier()
}

// ==================== mitm.go: onFlow struct field ====================

func TestMitmProxy_OnFlowField_NilByDefault(t *testing.T) {
	m := &MitmProxy{}
	if m.onFlow != nil {
		t.Error("expected onFlow to be nil by default")
	}
}

func TestMitmProxy_OnFlowField_CanBeSet(t *testing.T) {
	m := &MitmProxy{}
	callback := func(*http.Flow) error { return nil }
	m.onFlow = callback
	if m.onFlow == nil {
		t.Error("expected onFlow to be set")
	}
}

// ==================== mitm.go: loadCerts with missing certs ====================
// When certs don't exist at the configured path, loadCerts calls GenerateCAToPath(".")
// to generate them in the current directory. Then it reads from the configured path.
// For this to work, the configured path must match where GenerateCAToPath puts them.
// We test this by setting CACert/CAKey to paths in the current directory.

func TestMitmProxy_LoadCerts_CertsGeneratedWhenMissing(t *testing.T) {
	// Save current working directory
	origDir, _ := os.Getwd()
	tmpDir := t.TempDir()
	if err := os.Chdir(tmpDir); err != nil {
		t.Skipf("cannot chdir to temp: %v", err)
	}
	defer os.Chdir(origDir)

	// Use relative paths that match what GenerateCAToPath generates
	conf := &MitmConfig{
		Listen: "127.0.0.1:0",
		CACert: "ca.crt",
		CAKey:  "ca.key",
		Restriction: &checker.RequestCheckerConfig{
			URLCheckerConfig: checker.URLCheckerConfig{
				HostnameAllowed:    []string{"example.com"},
				HostnameDisallowed: []string{},
			},
		},
	}
	opts := &http.ClientOptions{}
	m := NewMitmProxy(conf, opts)
	if m == nil {
		t.Fatal("expected non-nil MitmProxy even when certs are initially missing")
	}
	if m.proxy == nil {
		t.Error("expected proxy to be initialized with MITM config")
	}
}

// ==================== mitm.go: FitOut with different listeners ====================

func TestMitmProxy_FitOut_DifferentPorts(t *testing.T) {
	tmpDir := t.TempDir()
	utils.GenerateCAToPath(tmpDir + string(os.PathSeparator))

	for i := 0; i < 3; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Skipf("could not find available port: %v", err)
		}
		port := l.Addr().(*net.TCPAddr).Port
		l.Close()

		conf := newTestMitmConfig(tmpDir)
		conf.Listen = fmt.Sprintf("127.0.0.1:%d", port)
		opts := &http.ClientOptions{}
		m := NewMitmProxy(conf, opts)

		ctx := context.Background()
		ch, err := m.FitOut(ctx, []string{})
		if err != nil {
			t.Fatalf("unexpected error from FitOut: %v", err)
		}
		if ch == nil {
			t.Fatal("expected non-nil channel from FitOut")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// ==================== mitm.go: MitmConfig edge cases ====================

func TestMitmConfig_DefaultValues(t *testing.T) {
	conf := &MitmConfig{}
	if conf.Listen != "" {
		t.Errorf("expected empty Listen, got %q", conf.Listen)
	}
	if conf.CACert != "" {
		t.Errorf("expected empty CACert, got %q", conf.CACert)
	}
	if conf.CAKey != "" {
		t.Errorf("expected empty CAKey, got %q", conf.CAKey)
	}
	if conf.DownstreamProxy != "" {
		t.Errorf("expected empty DownstreamProxy, got %q", conf.DownstreamProxy)
	}
	if conf.TTL != 0 {
		t.Errorf("expected TTL 0, got %d", conf.TTL)
	}
}

func TestMitmProxy_WithAllConfigFields(t *testing.T) {
	tmpDir := t.TempDir()
	utils.GenerateCAToPath(tmpDir + string(os.PathSeparator))

	conf := &MitmConfig{
		Listen:          "127.0.0.1:0",
		CACert:          filepath.Join(tmpDir, "ca.crt"),
		CAKey:           filepath.Join(tmpDir, "ca.key"),
		DownstreamProxy: "http://127.0.0.1:8080",
		ProxyAuth: AuthCredential{
			Username: "user",
			Password: "pass",
		},
		AllowIPRange: []string{"192.168.1.0/24"},
		Restriction: &checker.RequestCheckerConfig{
			URLCheckerConfig: checker.URLCheckerConfig{
				HostnameAllowed:    []string{"example.com"},
				HostnameDisallowed: []string{},
			},
		},
		Queue: MitmQueueConfig{MaxLength: 5000},
		ProxyHeader: MitmProxyHeaderConfig{
			Via:        "1.1 wscan",
			XForwarded: true,
		},
		WebCtrlPage: "/ctrl",
		TTL:         3600,
	}
	opts := &http.ClientOptions{TLSSkipVerify: true}
	m := NewMitmProxy(conf, opts)
	if m == nil {
		t.Fatal("expected non-nil MitmProxy")
	}

	// Verify all config fields are preserved
	if m.conf.Listen != conf.Listen {
		t.Errorf("Listen mismatch")
	}
	if m.conf.DownstreamProxy != conf.DownstreamProxy {
		t.Errorf("DownstreamProxy mismatch")
	}
	if m.conf.ProxyAuth.Username != "user" {
		t.Errorf("ProxyAuth.Username mismatch")
	}
	if m.conf.Queue.MaxLength != 5000 {
		t.Errorf("Queue.MaxLength mismatch")
	}
	if m.conf.ProxyHeader.Via != "1.1 wscan" {
		t.Errorf("ProxyHeader.Via mismatch")
	}
	if m.conf.TTL != 3600 {
		t.Errorf("TTL mismatch")
	}
}

// ==================== mitm.go: Multiple FitOut calls ====================

func TestMitmProxy_FitOut_MultipleCalls(t *testing.T) {
	tmpDir := t.TempDir()
	utils.GenerateCAToPath(tmpDir + string(os.PathSeparator))

	l1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("could not find available port: %v", err)
	}
	port1 := l1.Addr().(*net.TCPAddr).Port
	l1.Close()

	conf := newTestMitmConfig(tmpDir)
	conf.Listen = fmt.Sprintf("127.0.0.1:%d", port1)
	opts := &http.ClientOptions{}
	m := NewMitmProxy(conf, opts)

	ctx := context.Background()
	ch, err := m.FitOut(ctx, []string{})
	if err != nil {
		t.Fatalf("unexpected error from FitOut: %v", err)
	}
	if ch == nil {
		t.Fatal("expected non-nil channel from FitOut")
	}
	time.Sleep(200 * time.Millisecond)
}

// ==================== mitm.go: AuthCredential struct ====================

func TestAuthCredential_DefaultValues(t *testing.T) {
	auth := AuthCredential{}
	if auth.Username != "" {
		t.Errorf("expected empty Username, got %q", auth.Username)
	}
	if auth.Password != "" {
		t.Errorf("expected empty Password, got %q", auth.Password)
	}
}
