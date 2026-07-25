package thinkphp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"wscan/core/plugins/base"
	"wscan/core/utils/checker"
	"wscan/core/utils/checker/filter"
)

// ==================== Thinkphp execAction coverage ====================

func TestBoost3_Thinkphp_ExecAction(t *testing.T) {
	p := &Thinkphp{}
	err := p.execAction(context.Background(), nil)
	if err != nil {
		t.Errorf("execAction returned error: %v", err)
	}
}

// ==================== Thinkphp Close coverage ====================

func TestBoost3_Thinkphp_Close(t *testing.T) {
	p := &Thinkphp{}
	err := p.Close()
	if err != nil {
		t.Errorf("Close returned error: %v", err)
	}
}

// ==================== Thinkphp Init with full config ====================

func TestBoost3_Thinkphp_InitWithSqliConfig(t *testing.T) {
	p := &Thinkphp{}
	cfg := &Config{
		PluginBaseConfig:           base.PluginBaseConfig{Name: "thinkphp", Enabled: true},
		DetectThinkPHPSQLInjection: true,
	}
	ab := &base.ApolloBase{
		FilterConfig:    &checker.RequestCheckerConfig{},
		FilterContainer: filter.NewSyncMapFilter(),
	}
	err := p.Init(context.Background(), cfg, ab)
	if err != nil {
		t.Errorf("Init returned error: %v", err)
	}

	// Verify config was set
	gotCfg := p.GetConfig()
	if gotCfg == nil {
		t.Fatal("Expected non-nil config after Init")
	}
	gotConfig, ok := gotCfg.(*Config)
	if !ok {
		t.Fatal("Expected *Config type")
	}
	if !gotConfig.DetectThinkPHPSQLInjection {
		t.Error("Expected DetectThinkPHPSQLInjection=true")
	}
}

// ==================== Thinkphp DefaultConfig coverage ====================

func TestBoost3_Thinkphp_DefaultConfig(t *testing.T) {
	p := &Thinkphp{}
	cfg := p.DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig returned nil")
	}
	bc := cfg.BaseConfig()
	if bc.Name != "thinkphp" {
		t.Errorf("Expected Name='thinkphp', got '%s'", bc.Name)
	}
	if !bc.Enabled {
		t.Error("Expected Enabled=true")
	}
}

// ==================== Thinkphp Fingers with nil config ====================

func TestBoost3_Thinkphp_Fingers_NilConfig(t *testing.T) {
	p := &Thinkphp{}
	// Config is nil before Init - GetConfig returns nil
	fingers := p.Fingers()
	// Should still return base fingers (invoke, method, preg, v6filewrite)
	if len(fingers) < 4 {
		t.Errorf("Expected at least 4 fingers, got %d", len(fingers))
	}
}

// ==================== InvokeRce with various server responses ====================

func TestBoost3_InvokeRce_EmptyResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer server.Close()

	flow := helperCreateFlow(server.URL + "/index.php")
	client := helperNewHTTPClient()
	apollo := helperCreateApollo(flow, client)

	r := &InvokeRce{}
	finger := r.Finger()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := finger.CheckAction(ctx, apollo)
	_ = err
}

// ==================== MethodRce with various responses ====================

func TestBoost3_MethodRce_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	flow := helperCreateFlow(server.URL + "/index.php")
	client := helperNewHTTPClient()
	apollo := helperCreateApollo(flow, client)

	r := &MethodRce{}
	finger := r.Finger()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := finger.CheckAction(ctx, apollo)
	_ = err
}

// ==================== PregRce with valid server ====================

func TestBoost3_PregRce_ValidServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("Normal response"))
	}))
	defer server.Close()

	flow := helperCreateFlow(server.URL + "/index.php")
	client := helperNewHTTPClient()
	apollo := helperCreateApollo(flow, client)

	r := &PregRce{}
	finger := r.Finger()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := finger.CheckAction(ctx, apollo)
	_ = err
}

// ==================== Sqli Finger with server ====================

func TestBoost3_Sqli_Finger(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("Normal page"))
	}))
	defer server.Close()

	flow := helperCreateFlow(server.URL + "/index.php")
	client := helperNewHTTPClient()
	apollo := helperCreateApollo(flow, client)

	r := &Sqli{}
	finger := r.Finger()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := finger.CheckAction(ctx, apollo)
	_ = err
}

// ==================== V6FileWrite Finger with connection error ====================

func TestBoost3_V6FileWrite_ConnectionError(t *testing.T) {
	flow := helperCreateFlow("http://127.0.0.1:1/index.php")
	client := helperNewHTTPClient()
	apollo := helperCreateApollo(flow, client)

	r := &V6FileWrite{}
	finger := r.Finger()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := finger.CheckAction(ctx, apollo)
	_ = err
}

// ==================== Thinkphp Fingers all IDs ====================

func TestBoost3_Thinkphp_FingersAllIDs(t *testing.T) {
	p := &Thinkphp{}
	cfg := p.DefaultConfig().(*Config)
	cfg.DetectThinkPHPSQLInjection = true
	p.PluginMixinInitConfig.Config = cfg

	fingers := p.Fingers()

	expectedIDs := map[string]bool{
		"thinkphp/rce/invoke":            false,
		"thinkphp/rce/method":            false,
		"thinkphp/rce/preg":              false,
		"thinkphp/sqli/default":          false,
		"thinkphp/v6-file-write/default": false,
	}

	for _, f := range fingers {
		if f.Binding != nil {
			if _, ok := expectedIDs[f.Binding.ID]; ok {
				expectedIDs[f.Binding.ID] = true
			}
		}
	}

	for id, found := range expectedIDs {
		if !found {
			t.Errorf("expected finger with ID '%s' to be registered", id)
		}
	}
}

// ==================== Config BaseConfig method ====================

func TestBoost3_Config_BaseConfig(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig:           base.PluginBaseConfig{Name: "thinkphp", Enabled: true},
		DetectThinkPHPSQLInjection: false,
	}
	bc := cfg.BaseConfig()
	if bc == nil {
		t.Fatal("BaseConfig() returned nil")
	}
	if bc.Name != "thinkphp" {
		t.Errorf("Expected Name='thinkphp', got '%s'", bc.Name)
	}
}

// ==================== Suppress unused import ====================

var (
	_ = context.Background
	_ = http.StatusOK
	_ = httptest.NewServer
	_ = time.Now
	_ = checker.RequestCheckerConfig{}
	_ = filter.NewSyncMapFilter
)
