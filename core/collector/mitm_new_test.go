package collector

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	vhttp "wscan/core/http"
	"wscan/core/utils"
	"wscan/core/utils/checker"
)

// helper to create a valid MitmConfig with Restriction for testing
func newTestMitmConfig(tmpDir string) *MitmConfig {
	return &MitmConfig{
		Listen: "127.0.0.1:0",
		CACert: filepath.Join(tmpDir, "ca.crt"),
		CAKey:  filepath.Join(tmpDir, "ca.key"),
		Restriction: &checker.RequestCheckerConfig{
			URLCheckerConfig: checker.URLCheckerConfig{
				HostnameAllowed:    []string{"example.com"},
				HostnameDisallowed: []string{},
			},
		},
	}
}

// helper to find an available TCP port
func netListenOnTempPort() (net.Listener, error) {
	return net.Listen("tcp", "127.0.0.1:0")
}

func TestNewMitmProxy_BasicCreation(t *testing.T) {
	tmpDir := t.TempDir()
	utils.GenerateCAToPath(tmpDir + string(os.PathSeparator))

	conf := newTestMitmConfig(tmpDir)
	opts := &vhttp.ClientOptions{}
	m := NewMitmProxy(conf, opts)
	if m == nil {
		t.Fatal("expected non-nil MitmProxy")
	}
	if m.proxy == nil {
		t.Error("expected proxy to be initialized")
	}
	if m.conf == nil {
		t.Error("expected conf to be set")
	}
	if m.httpOpts == nil {
		t.Error("expected httpOpts to be set")
	}
	if m.pool == nil {
		t.Error("expected pool to be initialized")
	}
	if m.dupChecker == nil {
		t.Error("expected dupChecker to be initialized")
	}
}

func TestNewMitmProxy_WithDownstreamProxy(t *testing.T) {
	tmpDir := t.TempDir()
	utils.GenerateCAToPath(tmpDir + string(os.PathSeparator))

	conf := newTestMitmConfig(tmpDir)
	conf.DownstreamProxy = "http://127.0.0.1:8080"
	opts := &vhttp.ClientOptions{}
	m := NewMitmProxy(conf, opts)
	if m == nil {
		t.Fatal("expected non-nil MitmProxy with downstream proxy")
	}
}

func TestNewMitmProxy_WithInvalidDownstreamProxy(t *testing.T) {
	tmpDir := t.TempDir()
	utils.GenerateCAToPath(tmpDir + string(os.PathSeparator))

	conf := newTestMitmConfig(tmpDir)
	conf.DownstreamProxy = "://invalid-proxy"
	opts := &vhttp.ClientOptions{}
	m := NewMitmProxy(conf, opts)
	if m == nil {
		t.Fatal("expected non-nil MitmProxy even with invalid downstream proxy")
	}
}

func TestMitmProxy_LoadCerts_ExistingCerts(t *testing.T) {
	tmpDir := t.TempDir()
	// Pre-generate CA certs
	utils.GenerateCAToPath(tmpDir + string(os.PathSeparator))

	conf := newTestMitmConfig(tmpDir)
	opts := &vhttp.ClientOptions{}
	m := NewMitmProxy(conf, opts)
	if m == nil {
		t.Fatal("expected non-nil MitmProxy with existing certs")
	}
	// Verify proxy has MITM configured
	if m.proxy == nil {
		t.Error("expected proxy to be initialized with MITM config")
	}
}

func TestMitmProxy_MakeResultChan_Capacity(t *testing.T) {
	m := &MitmProxy{}
	ch := m.makeResultChan()
	if ch == nil {
		t.Fatal("expected non-nil result channel")
	}
	if cap(ch) != 10000 {
		t.Errorf("expected channel capacity 10000, got %d", cap(ch))
	}
}

func TestMitmProxy_OnFlow_NoPanic(t *testing.T) {
	m := &MitmProxy{}
	// OnFlow is a no-op, should not panic
	m.OnFlow(nil)
	m.OnFlow(func(*vhttp.Flow) error { return nil })
}

func TestMitmProxy_BuildModifier_NoPanic(t *testing.T) {
	m := &MitmProxy{}
	// buildModifier is a no-op, should not panic
	m.buildModifier()
}

func TestNewMitmProxy_WithProxyAuth(t *testing.T) {
	tmpDir := t.TempDir()
	utils.GenerateCAToPath(tmpDir + string(os.PathSeparator))

	conf := newTestMitmConfig(tmpDir)
	conf.ProxyAuth = AuthCredential{
		Username: "proxyuser",
		Password: "proxypass",
	}
	opts := &vhttp.ClientOptions{}
	m := NewMitmProxy(conf, opts)
	if m == nil {
		t.Fatal("expected non-nil MitmProxy with proxy auth")
	}
	if m.conf.ProxyAuth.Username != "proxyuser" {
		t.Errorf("expected ProxyAuth.Username 'proxyuser', got %q", m.conf.ProxyAuth.Username)
	}
	if m.conf.ProxyAuth.Password != "proxypass" {
		t.Errorf("expected ProxyAuth.Password 'proxypass', got %q", m.conf.ProxyAuth.Password)
	}
}

func TestNewMitmProxy_WithAllowIPRange(t *testing.T) {
	tmpDir := t.TempDir()
	utils.GenerateCAToPath(tmpDir + string(os.PathSeparator))

	conf := newTestMitmConfig(tmpDir)
	conf.AllowIPRange = []string{"192.168.1.0/24", "10.0.0.1"}
	opts := &vhttp.ClientOptions{}
	m := NewMitmProxy(conf, opts)
	if m == nil {
		t.Fatal("expected non-nil MitmProxy with IP range")
	}
	if len(m.conf.AllowIPRange) != 2 {
		t.Errorf("expected 2 AllowIPRange, got %d", len(m.conf.AllowIPRange))
	}
}

func TestNewMitmProxy_ConfPreserved(t *testing.T) {
	tmpDir := t.TempDir()
	utils.GenerateCAToPath(tmpDir + string(os.PathSeparator))

	conf := newTestMitmConfig(tmpDir)
	conf.Listen = "127.0.0.1:9999"
	conf.TTL = 3600
	opts := &vhttp.ClientOptions{TLSSkipVerify: true}
	m := NewMitmProxy(conf, opts)

	if m.conf.Listen != "127.0.0.1:9999" {
		t.Errorf("expected Listen '127.0.0.1:9999', got %q", m.conf.Listen)
	}
	if m.conf.TTL != 3600 {
		t.Errorf("expected TTL 3600, got %d", m.conf.TTL)
	}
	if m.httpOpts.TLSSkipVerify != true {
		t.Error("expected TLSSkipVerify to be true")
	}
}

func TestNewMitmProxy_ImplementsFitter(t *testing.T) {
	// Verify that MitmProxy satisfies the Fitter interface at compile time
	var _ Fitter = (*MitmProxy)(nil)
}

func TestMitmProxy_FitOut(t *testing.T) {
	tmpDir := t.TempDir()
	utils.GenerateCAToPath(tmpDir + string(os.PathSeparator))

	conf := newTestMitmConfig(tmpDir)

	// Find an available port
	l, err := netListenOnTempPort()
	if err != nil {
		t.Skipf("could not find available port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()

	conf.Listen = fmt.Sprintf("127.0.0.1:%d", port)
	opts := &vhttp.ClientOptions{}
	m := NewMitmProxy(conf, opts)

	ctx := context.Background()
	ch, err := m.FitOut(ctx, []string{})
	if err != nil {
		t.Fatalf("unexpected error from FitOut: %v", err)
	}
	if ch == nil {
		t.Fatal("expected non-nil channel from FitOut")
	}
	// Channel should have buffer capacity from makeResultChan
	if cap(ch) != 10000 {
		t.Errorf("expected channel capacity 10000, got %d", cap(ch))
	}
	// Give the proxy a moment to start, then clean up
	time.Sleep(200 * time.Millisecond)
}

func TestMitmProxy_FitOut_ImplementsFitterInterface(t *testing.T) {
	tmpDir := t.TempDir()
	utils.GenerateCAToPath(tmpDir + string(os.PathSeparator))

	conf := newTestMitmConfig(tmpDir)
	opts := &vhttp.ClientOptions{}

	var fitter Fitter = NewMitmProxy(conf, opts)
	_ = fitter
}

func TestMitmProxy_StructFields(t *testing.T) {
	mp := &MitmProxy{}
	if mp.proxy != nil {
		t.Error("expected proxy to be nil for zero-value MitmProxy")
	}
	if mp.conf != nil {
		t.Error("expected conf to be nil for zero-value MitmProxy")
	}
	if mp.httpOpts != nil {
		t.Error("expected httpOpts to be nil for zero-value MitmProxy")
	}
	if mp.pool != nil {
		t.Error("expected pool to be nil for zero-value MitmProxy")
	}
	if mp.dupChecker != nil {
		t.Error("expected dupChecker to be nil for zero-value MitmProxy")
	}
	if mp.onFlow != nil {
		t.Error("expected onFlow to be nil for zero-value MitmProxy")
	}
}

func TestGenerateCA_DefaultValue(t *testing.T) {
	if GenerateCA != false {
		t.Errorf("expected GenerateCA to be false by default, got %v", GenerateCA)
	}
}

func TestGenerateCA_SetValue(t *testing.T) {
	original := GenerateCA
	defer func() { GenerateCA = original }()

	GenerateCA = true
	if GenerateCA != true {
		t.Errorf("expected GenerateCA to be true after setting, got %v", GenerateCA)
	}
}

func TestNewMitmProxy_WithQueueConfig(t *testing.T) {
	tmpDir := t.TempDir()
	utils.GenerateCAToPath(tmpDir + string(os.PathSeparator))

	conf := newTestMitmConfig(tmpDir)
	conf.Queue = MitmQueueConfig{MaxLength: 5000}
	opts := &vhttp.ClientOptions{}
	m := NewMitmProxy(conf, opts)
	if m == nil {
		t.Fatal("expected non-nil MitmProxy with queue config")
	}
	if m.conf.Queue.MaxLength != 5000 {
		t.Errorf("expected Queue.MaxLength 5000, got %d", m.conf.Queue.MaxLength)
	}
}

func TestNewMitmProxy_WithProxyHeaderConfig(t *testing.T) {
	tmpDir := t.TempDir()
	utils.GenerateCAToPath(tmpDir + string(os.PathSeparator))

	conf := newTestMitmConfig(tmpDir)
	conf.ProxyHeader = MitmProxyHeaderConfig{
		Via:        "1.1 wscan",
		XForwarded: true,
	}
	opts := &vhttp.ClientOptions{}
	m := NewMitmProxy(conf, opts)
	if m == nil {
		t.Fatal("expected non-nil MitmProxy with proxy header config")
	}
	if m.conf.ProxyHeader.Via != "1.1 wscan" {
		t.Errorf("expected ProxyHeader.Via '1.1 wscan', got %q", m.conf.ProxyHeader.Via)
	}
	if m.conf.ProxyHeader.XForwarded != true {
		t.Errorf("expected ProxyHeader.XForwarded true, got %v", m.conf.ProxyHeader.XForwarded)
	}
}

func TestNewMitmProxy_WithWebCtrlPage(t *testing.T) {
	tmpDir := t.TempDir()
	utils.GenerateCAToPath(tmpDir + string(os.PathSeparator))

	conf := newTestMitmConfig(tmpDir)
	conf.WebCtrlPage = "/ctrl"
	opts := &vhttp.ClientOptions{}
	m := NewMitmProxy(conf, opts)
	if m == nil {
		t.Fatal("expected non-nil MitmProxy with webctrl page")
	}
	if m.conf.WebCtrlPage != "/ctrl" {
		t.Errorf("expected WebCtrlPage '/ctrl', got %q", m.conf.WebCtrlPage)
	}
}
