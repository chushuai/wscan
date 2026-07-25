package thinkphp

import (
	"context"
	nethttp "net/http"
	"net/http/httptest"
	"testing"
	"time"

	"wscan/core/plugins/base"
	"wscan/core/utils/checker"
	"wscan/core/utils/checker/filter"
)

// ==================== Thinkphp Init with URLChecker ====================

func TestBoostThinkphp_Init(t *testing.T) {
	p := &Thinkphp{}
	cfg := p.DefaultConfig()
	ab := &base.ApolloBase{
		FilterConfig:    &checker.RequestCheckerConfig{},
		FilterContainer: filter.NewSyncMapFilter(),
	}
	err := p.Init(context.Background(), cfg, ab)
	if err != nil {
		t.Errorf("Init returned error: %v", err)
	}
}

// ==================== Thinkphp Fingers with sqli disabled ====================

func TestBoostThinkphp_Fingers_SqliDisabled(t *testing.T) {
	p := &Thinkphp{}
	cfg := p.DefaultConfig().(*Config)
	cfg.DetectThinkPHPSQLInjection = false
	p.PluginMixinInitConfig.Config = cfg

	fingers := p.Fingers()

	foundSqli := false
	for _, f := range fingers {
		if f.Binding != nil && f.Binding.ID == "thinkphp/sqli/default" {
			foundSqli = true
		}
	}
	if foundSqli {
		t.Error("sqli finger should not be registered when DetectThinkPHPSQLInjection=false")
	}
}

// ==================== Thinkphp Fingers with sqli enabled ====================

func TestBoostThinkphp_Fingers_SqliEnabled(t *testing.T) {
	p := &Thinkphp{}
	cfg := p.DefaultConfig().(*Config)
	cfg.DetectThinkPHPSQLInjection = true
	p.PluginMixinInitConfig.Config = cfg

	fingers := p.Fingers()

	foundSqli := false
	for _, f := range fingers {
		if f.Binding != nil && f.Binding.ID == "thinkphp/sqli/default" {
			foundSqli = true
		}
	}
	if !foundSqli {
		t.Error("sqli finger should be registered when DetectThinkPHPHSQLInjection=true")
	}
}

// ==================== Thinkphp Fingers binding verification ====================

func TestBoostThinkphp_Fingers_BindingIDs(t *testing.T) {
	p := &Thinkphp{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()

	fingers := p.Fingers()

	expectedIDs := map[string]bool{
		"thinkphp/rce/invoke":            false,
		"thinkphp/rce/method":            false,
		"thinkphp/rce/preg":              false,
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

// ==================== InvokeRce with server returning error ====================

func TestBoostInvokeRce_ServerError(t *testing.T) {
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.WriteHeader(500)
	}))
	defer server.Close()

	flow := helperCreateFlow(server.URL + "/index.php")
	client := helperNewHTTPClient()
	apollo := helperCreateApollo(flow, client)

	r := &InvokeRce{}
	finger := r.Finger()
	err := finger.CheckAction(context.Background(), apollo)
	_ = err
}

// ==================== MethodRce with non-ThinkPHP server ====================

func TestBoostMethodRce_NonThinkPHPServer(t *testing.T) {
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.WriteHeader(404)
		w.Write([]byte("Not Found"))
	}))
	defer server.Close()

	flow := helperCreateFlow(server.URL + "/index.php")
	client := helperNewHTTPClient()
	apollo := helperCreateApollo(flow, client)

	r := &MethodRce{}
	finger := r.Finger()
	err := finger.CheckAction(context.Background(), apollo)
	_ = err
}

// ==================== PregRce with connection error ====================

func TestBoostPregRce_ConnectionError(t *testing.T) {
	// Use a URL that will fail to connect
	flow := helperCreateFlow("http://127.0.0.1:1/index.php")
	client := helperNewHTTPClient()
	apollo := helperCreateApollo(flow, client)

	r := &PregRce{}
	finger := r.Finger()
	// Use short timeout context
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := finger.CheckAction(ctx, apollo)
	_ = err
}

// ==================== V6FileWrite with server ====================

func TestBoostV6FileWrite_NormalResponse(t *testing.T) {
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	flow := helperCreateFlow(server.URL + "/index.php")
	client := helperNewHTTPClient()
	apollo := helperCreateApollo(flow, client)

	r := &V6FileWrite{}
	finger := r.Finger()
	err := finger.CheckAction(context.Background(), apollo)
	_ = err
}

// ==================== Thinkphp plugin interface compliance ====================

func TestBoostThinkphp_PluginInterface(t *testing.T) {
	var _ base.Plugin = &Thinkphp{}
}

// ==================== Thinkphp GetConfig before Init ====================

func TestBoostThinkphp_GetConfig_BeforeInit(t *testing.T) {
	p := &Thinkphp{}
	cfg := p.GetConfig()
	if cfg != nil {
		t.Error("expected nil config before Init")
	}
}

// ==================== Thinkphp Config BaseConfig ====================

func TestBoostThinkphp_ConfigBaseConfig(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig:           base.PluginBaseConfig{Name: "thinkphp", Enabled: true},
		DetectThinkPHPSQLInjection: true,
	}
	bc := cfg.BaseConfig()
	if bc.Name != "thinkphp" {
		t.Errorf("expected Name 'thinkphp', got '%s'", bc.Name)
	}
	if !cfg.DetectThinkPHPSQLInjection {
		t.Error("expected DetectThinkPHPSQLInjection to be true")
	}
}
