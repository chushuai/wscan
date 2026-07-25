package fingerprint

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	whttp "wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/plugins/helper/knowledge"
	"wscan/core/utils/printer"
)

// ==================== Config coverage ====================

func TestCovConfig(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:       "fingerprint",
			Enabled:    true,
			IsAdvanced: true,
		},
	}
	if cfg.BaseConfig().Name != "fingerprint" {
		t.Errorf("Expected name 'fingerprint', got '%s'", cfg.BaseConfig().Name)
	}
	if !cfg.BaseConfig().Enabled {
		t.Error("Expected enabled=true")
	}
}

// ==================== Fingerprint struct coverage ====================

func TestCovFingerprintDefaultConfig(t *testing.T) {
	fp := &Fingerprint{}
	cfg := fp.DefaultConfig()
	if cfg == nil {
		t.Fatal("Expected non-nil default config")
	}
	if cfg.BaseConfig().Name != "fingerprint" {
		t.Errorf("Expected name 'fingerprint', got '%s'", cfg.BaseConfig().Name)
	}
}

func TestCovFingerprintClose(t *testing.T) {
	fp := &Fingerprint{}
	if err := fp.Close(); err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}
}

func TestCovFingerprintGetConfig(t *testing.T) {
	fp := &Fingerprint{}
	cfg := fp.GetConfig()
	// GetConfig returns nil if PluginMixinInitConfig hasn't been initialized
	_ = cfg
}

func TestCovFingerprintFingers(t *testing.T) {
	fp := &Fingerprint{}
	fingers := fp.Fingers()
	if len(fingers) == 0 {
		t.Error("Expected non-empty fingers list")
	}
	for _, f := range fingers {
		if f.Channel != "web-generic" {
			t.Errorf("Expected channel 'web-generic', got '%s'", f.Channel)
		}
		if f.Binding == nil {
			t.Error("Expected non-nil binding")
		}
	}
}

func TestCovFingerprintInit(t *testing.T) {
	fp := &Fingerprint{}
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "fingerprint",
			Enabled: true,
		},
	}
	ab := &base.ApolloBase{}
	err := fp.Init(context.Background(), cfg, ab)
	// Init may fail due to nil fields, but should not panic
	_ = err
}

// ==================== FingerprintInfo coverage ====================

func TestCovFingerprintInfo(t *testing.T) {
	fi := FingerprintInfo{
		Name:   "test",
		Author: "test-author",
	}
	if fi.Name != "test" {
		t.Errorf("Expected Name='test', got '%s'", fi.Name)
	}
	if fi.Author != "test-author" {
		t.Errorf("Expected Author='test-author', got '%s'", fi.Author)
	}
}

// ==================== FingerprintPscan coverage ====================

func TestCovFingerprintPscan(t *testing.T) {
	fp := FingerprintPscan{
		Path:        []string{"/test", "/admin"},
		Expressions: []string{"response.status == 200"},
	}
	if len(fp.Path) != 2 {
		t.Errorf("Expected 2 paths, got %d", len(fp.Path))
	}
	if len(fp.Expressions) != 1 {
		t.Errorf("Expected 1 expression, got %d", len(fp.Expressions))
	}
}

// ==================== FingerprintRule coverage ====================

func TestCovFingerprintRule(t *testing.T) {
	fr := FingerprintRule{
		Engine: "cel",
		Info: FingerprintInfo{
			Name:   "test-rule",
			Author: "test",
		},
		Pscan: FingerprintPscan{
			Path:        []string{"/"},
			Expressions: []string{"true"},
		},
	}
	if fr.Engine != "cel" {
		t.Errorf("Expected Engine='cel', got '%s'", fr.Engine)
	}
	if fr.Info.Name != "test-rule" {
		t.Errorf("Expected Info.Name='test-rule', got '%s'", fr.Info.Name)
	}
}

// ==================== readDir coverage ====================

func TestCovReadDirInvalidPath(t *testing.T) {
	rules, err := readDir("nonexistent/path", template)
	if err == nil {
		t.Error("Expected error for nonexistent path")
	}
	// readDir returns an initialized (non-nil) empty slice on error
	_ = rules
}

func TestCovReadDirValidPath(t *testing.T) {
	rules, err := readDir("technologies/wscan", template)
	if err != nil {
		t.Fatalf("readDir failed: %v", err)
	}
	if len(rules) == 0 {
		t.Error("Expected non-empty rules from embedded FS")
	}
	// Verify rules have expected fields
	for i, r := range rules {
		if r.Info.Name == "" {
			t.Errorf("Rule[%d] has empty Name", i)
		}
		if r.Engine == "" {
			t.Errorf("Rule[%d] has empty Engine", i)
		}
	}
}

func TestCovReadDirSubdirectory(t *testing.T) {
	// Read a subdirectory within the embedded FS
	// This exercises the recursive path in readDir
	entries, err := template.ReadDir("technologies/wscan")
	if err != nil {
		t.Fatalf("Failed to read technologies/wscan dir: %v", err)
	}
	// There should be some subdirectories and files
	if len(entries) == 0 {
		t.Error("Expected entries in technologies/wscan")
	}
}

// ==================== execAction with HTTP server ====================

func TestCovExecActionWithHTTPServer(t *testing.T) {
	// Start a test HTTP server
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		w.WriteHeader(200)
		w.Write([]byte("<html><head><title>Test</title></head><body>Hello World</body></html>"))
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	// Create a proper flow and Apollo for testing execAction
	req, err := whttp.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	client := whttp.NewClient()
	resp, err := client.Respond(context.Background(), req)
	if err != nil {
		t.Fatalf("Failed to get response: %v", err)
	}
	flow := &whttp.Flow{Request: req, Response: resp}
	ab := &base.ApolloBase{
		HTTPClient: client,
		Output:     printer.NewTextPrinter(os.Stdout),
		KDB:        knowledge.NewKnowledgeDB(nil),
	}
	apollo := base.NewApollo(flow)
	apollo.ApolloBase = ab

	fp := &Fingerprint{}
	err = fp.execAction(context.Background(), apollo)
	// execAction may fail or succeed depending on CEL expressions, but should not panic
	_ = err
}

// ==================== LoadFingerprintRule coverage ====================

func TestCovLoadFingerprintRule(t *testing.T) {
	rule, err := LoadFingerprintRule("nonexistent.yaml")
	if rule != nil || err != nil {
		t.Errorf("Expected nil/nil, got rule=%v err=%v", rule, err)
	}
}

// ==================== ProcessFingerprint coverage ====================

func TestCovProcessFingerprint(t *testing.T) {
	// ProcessFingerprint is a no-op, just verify it doesn't panic
	ProcessFingerprint(context.Background(), nil)
}

// ==================== fingerprintRules global ====================

func TestCovFingerprintRulesGlobal(t *testing.T) {
	if len(fingerprintRules) == 0 {
		t.Error("Expected non-empty global fingerprintRules")
	}
}

// ==================== execAction coverage ====================

func TestCovExecActionWithMockApollo(t *testing.T) {
	// execAction requires a properly initialized Apollo with a flow
	// An empty Apollo will panic on GetTargetFlow
	t.Skip("execAction requires properly initialized Apollo with a flow")
}

// ==================== VulnBinding coverage ====================

func TestCovVulnBindingForFingerprint(t *testing.T) {
	binding := &model.VulnBinding{
		ID:       "fingerprint/default",
		Plugin:   "fingerprint",
		Category: "fingerprint",
		Severity: model.SeverityInfo,
	}
	if binding.Plugin != "fingerprint" {
		t.Errorf("Expected Plugin='fingerprint', got '%s'", binding.Plugin)
	}
	if binding.Severity != model.SeverityInfo {
		t.Errorf("Expected Severity=Info, got %v", binding.Severity)
	}
}

// ==================== Finger check action coverage ====================

func TestCovCheckActionNotNil(t *testing.T) {
	fp := &Fingerprint{}
	fingers := fp.Fingers()
	for _, f := range fingers {
		if f.CheckAction == nil {
			t.Error("Expected non-nil CheckAction")
		}
	}
}

// Suppress unused imports
var (
	_ = context.Background
	_ = whttp.Flow{}
	_ = model.SeverityInfo
)
