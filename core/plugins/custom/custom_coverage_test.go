package custom

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	wscan_http "wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/utils/printer"
)

// ==================== Mock printer ====================

type customTestPrinter struct {
	vulns []*model.Vuln
}

func (p *customTestPrinter) Print(v any) error {
	if vuln, ok := v.(*model.Vuln); ok {
		p.vulns = append(p.vulns, vuln)
	}
	return nil
}
func (p *customTestPrinter) Close() error { return nil }
func (p *customTestPrinter) AddInterceptor(func(any) (any, error)) printer.Printer {
	return p
}
func (p *customTestPrinter) LogSubdomain(any) error { return nil }
func (p *customTestPrinter) LogVuln(any) error      { return nil }

// ==================== Custom.Close test ====================

func TestCustom_Close_Nil(t *testing.T) {
	c := &Custom{}
	if err := c.Close(); err != nil {
		t.Errorf("Close() error: %v", err)
	}
}

// ==================== Custom.DefaultConfig variations ====================

func TestCustom_DefaultConfig_Values(t *testing.T) {
	cfg := (&Custom{}).DefaultConfig().(*Config)
	if cfg.Depth != 0 {
		t.Errorf("Depth = %d, want 0", cfg.Depth)
	}
	if cfg.Exclusive {
		t.Error("Exclusive should be false by default")
	}
	if cfg.AutoLoadTmpl {
		t.Error("AutoLoadTmpl should be false by default")
	}
	if len(cfg.IncludeTmpl) != 0 {
		t.Errorf("IncludeTmpl = %v, want empty", cfg.IncludeTmpl)
	}
	if len(cfg.ExcludeTmpl) != 0 {
		t.Errorf("ExcludeTmpl = %v, want empty", cfg.ExcludeTmpl)
	}
}

// ==================== Custom.Init variations ====================

func TestCustom_Init_WithIncludeTmpl(t *testing.T) {
	c := &Custom{}
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{Name: "custom", Enabled: true},
		IncludeTmpl:      []string{"/nonexistent/*.yml"},
	}
	ab := &base.ApolloBase{}
	err := c.Init(context.Background(), cfg, ab)
	if err != nil {
		t.Errorf("Init() error: %v", err)
	}
	fingers := c.Fingers()
	if len(fingers) != 0 {
		t.Errorf("Expected 0 fingers with non-existent include, got %d", len(fingers))
	}
}

func TestCustom_Init_NilContext(t *testing.T) {
	c := &Custom{}
	cfg := c.DefaultConfig()
	ab := &base.ApolloBase{}
	err := c.Init(nil, cfg, ab)
	if err != nil {
		t.Errorf("Init() with nil context error: %v", err)
	}
}

// ==================== Custom.Fingers with multiple POCs ====================

func TestCustom_Fingers_MultipleEnabledPOC(t *testing.T) {
	c := &Custom{}
	f1 := &mockFingerFactory{finger: &base.Finger{Channel: "web-generic"}}
	f2 := &mockFingerFactory{finger: &base.Finger{Channel: "web-directory"}}
	c.enabledPOC = []base.FingerFactory{f1, f2}

	fingers := c.Fingers()
	if len(fingers) != 2 {
		t.Errorf("Expected 2 fingers, got %d", len(fingers))
	}
	for i, f := range fingers {
		if f.CheckAction == nil {
			t.Errorf("Finger %d CheckAction should be set to DepthCheck", i)
		}
	}
}

func TestCustom_Fingers_EmptyEnabledPOC(t *testing.T) {
	c := &Custom{}
	c.enabledPOC = []base.FingerFactory{}
	fingers := c.Fingers()
	if len(fingers) != 0 {
		t.Errorf("Expected 0 fingers, got %d", len(fingers))
	}
}

// ==================== Custom.DepthCheck comprehensive ====================

func TestCustom_DepthCheck_EqualDepth(t *testing.T) {
	c := &Custom{}
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{Name: "custom", Enabled: true},
		Depth:            2,
	}
	ab := &base.ApolloBase{}
	ab.Output = &customTestPrinter{}
	c.Init(context.Background(), cfg, ab)

	a := makeCustomTestApollo(2)
	err := c.DepthCheck(context.Background(), a)
	if err != nil {
		t.Errorf("DepthCheck with depth=2 and limit=2 should pass, got: %v", err)
	}
}

func TestCustom_DepthCheck_SingleSegment(t *testing.T) {
	c := &Custom{}
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{Name: "custom", Enabled: true},
		Depth:            0,
	}
	ab := &base.ApolloBase{}
	ab.Output = &customTestPrinter{}
	c.Init(context.Background(), cfg, ab)

	a := makeCustomTestApollo(0)
	err := c.DepthCheck(context.Background(), a)
	if err != nil {
		t.Errorf("DepthCheck with depth=0 and limit=0 should pass, got: %v", err)
	}
}

// ==================== Config variations ====================

func TestConfig_AllFields(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{Name: "custom", Enabled: true, IsAdvanced: true},
		Depth:            5,
		POC:              []string{"poc1", "poc2"},
		Exclusive:        true,
		AutoLoadTmpl:     true,
		IncludeTmpl:      []string{"./tmpl-*"},
		ExcludeTmpl:      []string{"*test*"},
	}
	if !cfg.PluginBaseConfig.IsAdvanced {
		t.Error("IsAdvanced should be true")
	}
	if cfg.Depth != 5 {
		t.Errorf("Depth = %d, want 5", cfg.Depth)
	}
	if len(cfg.POC) != 2 {
		t.Errorf("POC len = %d, want 2", len(cfg.POC))
	}
	if !cfg.Exclusive {
		t.Error("Exclusive should be true")
	}
	if !cfg.AutoLoadTmpl {
		t.Error("AutoLoadTmpl should be true")
	}
}

// ==================== LoadYamlTmpl edge cases ====================

func TestLoadYamlTmpl_YamlExtension(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := tmpDir + "/poc.yaml"
	yamlContent := `name: test-poc
payload:
  - test_value
expression: "response.status == 200"
`
	if err := writeTestFile(tmpFile, yamlContent); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{Name: "custom", Enabled: true},
		IncludeTmpl:      []string{tmpFile},
	}
	result := LoadYamlTmpl(cfg)
	if len(result) != 1 {
		t.Errorf("Expected 1 POC with .yaml extension, got %d", len(result))
	}
}

func TestLoadYamlTmpl_BothExtensions(t *testing.T) {
	tmpDir := t.TempDir()
	ymlFile := tmpDir + "/poc.yml"
	yamlFile := tmpDir + "/poc.yaml"
	content := `name: test-poc
payload:
  - test_value
expression: "response.status == 200"
`
	if err := writeTestFile(ymlFile, content); err != nil {
		t.Fatal(err)
	}
	if err := writeTestFile(yamlFile, content); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{Name: "custom", Enabled: true},
		IncludeTmpl:      []string{tmpDir + "/*.yml", tmpDir + "/*.yaml"},
	}
	result := LoadYamlTmpl(cfg)
	if len(result) != 2 {
		t.Errorf("Expected 2 POCs with both extensions, got %d", len(result))
	}
}

func TestLoadYamlTmpl_InvalidGlob(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{Name: "custom", Enabled: true},
		IncludeTmpl:      []string{"[invalid-glob"},
	}
	result := LoadYamlTmpl(cfg)
	if len(result) != 0 {
		t.Errorf("Expected 0 POCs with invalid glob, got %d", len(result))
	}
}

// ==================== LoadSingleTemplate edge cases ====================

func TestLoadSingleTemplate_EmptyPayloads(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := tmpDir + "/empty.yml"
	yamlContent := `name: empty-poc
payload:
expression: "response.status == 200"
`
	if err := writeTestFile(tmpFile, yamlContent); err != nil {
		t.Fatal(err)
	}

	yfs, err := LoadSingleTemplate(tmpFile, &Config{})
	if err != nil {
		t.Fatalf("LoadSingleTemplate() error: %v", err)
	}
	if len(yfs) != 0 {
		t.Errorf("Expected 0 YamlFingers for empty payloads, got %d", len(yfs))
	}
}

func TestLoadSingleTemplate_WithSetVariables(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := tmpDir + "/set.yml"
	yamlContent := `name: set-poc
set:
  - key: var1
    value: test123
payload:
  - payload_value
expression: "response.status == 200"
`
	if err := writeTestFile(tmpFile, yamlContent); err != nil {
		t.Fatal(err)
	}

	yfs, err := LoadSingleTemplate(tmpFile, &Config{})
	if err != nil {
		t.Fatalf("LoadSingleTemplate() error: %v", err)
	}
	if len(yfs) != 1 {
		t.Fatalf("Expected 1 YamlFinger, got %d", len(yfs))
	}
}

// ==================== YamlFinger.Finger comprehensive ====================

func TestYamlFinger_Finger_BindingDetails(t *testing.T) {
	tmpl := &Template{Name: "sqli-union"}
	ys := &YamlFinger{
		YamlScript: &YamlScript{
			Temp:    tmpl,
			Payload: "' OR 1=1--",
			Channel: "web-generic",
		},
	}
	finger := ys.Finger()
	if finger.Binding.ID != "custom/sqli-union" {
		t.Errorf("Binding.ID = %q, want 'custom/sqli-union'", finger.Binding.ID)
	}
	if finger.Binding.Plugin != "custom/sqli-union" {
		t.Errorf("Binding.Plugin = %q, want 'custom/sqli-union'", finger.Binding.Plugin)
	}
	if finger.Binding.Category != "custom/sqli-union" {
		t.Errorf("Binding.Category = %q, want 'custom/sqli-union'", finger.Binding.Category)
	}
	if finger.Binding.Severity != model.SeverityHigh {
		t.Errorf("Binding.Severity = %v, want SeverityHigh", finger.Binding.Severity)
	}
}

// ==================== YamlFinger.Run with httptest server ====================

func TestYamlFinger_Run_WithHTTPServer(t *testing.T) {
	// Create a test HTTP server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		fmt.Fprint(w, "<html>OK</html>")
	}))
	defer ts.Close()

	tsURL, _ := url.Parse(ts.URL)
	tsHost := tsURL.Host

	// Create request with a URL parameter
	testURL := fmt.Sprintf("http://%s/page?url=http://example.com", tsHost)
	req, err := wscan_http.NewRequest("GET", testURL, nil)
	if err != nil {
		t.Fatalf("NewRequest error: %v", err)
	}
	flow := &wscan_http.Flow{
		Request:  req,
		Response: &wscan_http.Response{StatusCode: 200},
	}

	// Create YamlFinger with simple expression
	tmpl := &Template{
		Name:       "test-poc",
		Expression: "response.status == 200",
		Set:        nil,
	}
	ys := &YamlFinger{
		YamlScript: &YamlScript{
			Temp:    tmpl,
			Payload: "test_payload",
			Channel: "web-generic",
		},
		cfg: &Config{},
	}

	ab := base.NewApollo(flow)
	ab.ApolloBase.Output = &customTestPrinter{}
	ab.ApolloBase.HTTPClient = wscan_http.NewClient()

	err = ys.Run(context.Background(), ab)
	// The Run method should execute without panic
	// Whether it finds a vulnerability depends on the expression evaluation
	_ = err
}

func TestYamlFinger_Run_NoParams(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "OK")
	}))
	defer ts.Close()

	tsURL, _ := url.Parse(ts.URL)
	tsHost := tsURL.Host

	// Request with no query parameters
	testURL := fmt.Sprintf("http://%s/page", tsHost)
	req, err := wscan_http.NewRequest("GET", testURL, nil)
	if err != nil {
		t.Fatalf("NewRequest error: %v", err)
	}
	flow := &wscan_http.Flow{
		Request:  req,
		Response: &wscan_http.Response{StatusCode: 200},
	}

	tmpl := &Template{
		Name:       "no-params-poc",
		Expression: "response.status == 200",
	}
	ys := &YamlFinger{
		YamlScript: &YamlScript{
			Temp:    tmpl,
			Payload: "payload",
			Channel: "web-generic",
		},
		cfg: &Config{},
	}

	ab := base.NewApollo(flow)
	ab.ApolloBase.Output = &customTestPrinter{}
	ab.ApolloBase.HTTPClient = wscan_http.NewClient()

	err = ys.Run(context.Background(), ab)
	if err != nil {
		t.Errorf("Run() with no params should succeed, got: %v", err)
	}
}

func TestYamlFinger_Run_WithSet(t *testing.T) {
	// Test Run with empty Set - should work fine
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "OK")
	}))
	defer ts.Close()

	tsURL, _ := url.Parse(ts.URL)
	tsHost := tsURL.Host

	testURL := fmt.Sprintf("http://%s/page?q=test", tsHost)
	req, err := wscan_http.NewRequest("GET", testURL, nil)
	if err != nil {
		t.Fatalf("NewRequest error: %v", err)
	}
	flow := &wscan_http.Flow{
		Request:  req,
		Response: &wscan_http.Response{StatusCode: 200},
	}

	tmpl := &Template{
		Name:       "set-poc",
		Expression: "response.status == 200",
	}
	ys := &YamlFinger{
		YamlScript: &YamlScript{
			Temp:    tmpl,
			Payload: "payload",
			Channel: "web-generic",
		},
		cfg: &Config{},
	}

	ab := base.NewApollo(flow)
	ab.ApolloBase.Output = &customTestPrinter{}
	ab.ApolloBase.HTTPClient = wscan_http.NewClient()

	err = ys.Run(context.Background(), ab)
	_ = err
}

func TestYamlFinger_Run_HTTPError(t *testing.T) {
	// Test Run when HTTP client returns an error (server not reachable)
	testURL := "http://127.0.0.1:1/page?url=http://example.com"
	req, err := wscan_http.NewRequest("GET", testURL, nil)
	if err != nil {
		t.Fatalf("NewRequest error: %v", err)
	}
	flow := &wscan_http.Flow{
		Request:  req,
		Response: &wscan_http.Response{StatusCode: 200},
	}

	tmpl := &Template{
		Name:       "error-poc",
		Expression: "response.status == 200",
	}
	ys := &YamlFinger{
		YamlScript: &YamlScript{
			Temp:    tmpl,
			Payload: "payload",
			Channel: "web-generic",
		},
		cfg: &Config{},
	}

	ab := base.NewApollo(flow)
	ab.ApolloBase.Output = &customTestPrinter{}
	ab.ApolloBase.HTTPClient = wscan_http.NewClient()

	err = ys.Run(context.Background(), ab)
	// Should handle HTTP errors gracefully (continue to next param)
	_ = err
}

// ==================== Case struct ====================

func TestCase_Struct(t *testing.T) {
	c := Case{
		Payloads:       []string{"p1"},
		Encoders:       []string{"Base64"},
		Placeholders:   []*Placeholder{{Name: "URLParam"}},
		Type:           "sqli",
		Set:            "var1=val1",
		Name:           "test-case",
		IsTruePositive: true,
	}
	if c.Type != "sqli" {
		t.Errorf("Type = %q, want 'sqli'", c.Type)
	}
	if !c.IsTruePositive {
		t.Error("IsTruePositive should be true")
	}
}

func TestPlaceholder_Struct(t *testing.T) {
	p := &Placeholder{Name: "URLParam", Config: map[string]string{"key": "val"}}
	if p.Name != "URLParam" {
		t.Errorf("Name = %q, want 'URLParam'", p.Name)
	}
}

// ==================== Template defaults ====================

func TestTemplate_DefaultType(t *testing.T) {
	tmpl := &Template{Name: "test"}
	if tmpl.Type != "" {
		t.Errorf("Default Type should be empty string before YAML decode, got %q", tmpl.Type)
	}
}

// ==================== YamlScript full coverage ====================

func TestYamlScript_AllFields(t *testing.T) {
	tmpl := &Template{
		Name:         "full-test",
		Payloads:     []string{"p1", "p2"},
		Encoders:     []string{"Base64", "URL"},
		Placeholders: []string{"URLParam"},
		Expression:   "response.status == 200",
		Type:         "rce",
	}
	ys := &YamlScript{
		Temp:    tmpl,
		Payload: "attack_payload",
		Channel: "web-directory",
	}
	if ys.Temp.Name != "full-test" {
		t.Errorf("Temp.Name = %q, want 'full-test'", ys.Temp.Name)
	}
	if ys.Channel != "web-directory" {
		t.Errorf("Channel = %q, want 'web-directory'", ys.Channel)
	}
}

// ==================== SetMapSlice type alias ====================

func TestSetMapSlice(t *testing.T) {
	var sms SetMapSlice
	_ = sms
}

// ==================== Helper ====================

func writeTestFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0644)
}
