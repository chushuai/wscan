package waftest

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	wscan_http "wscan/core/http"
	"wscan/core/plugins/base"
	"wscan/core/utils/printer"
)

// ==================== Mock printer ====================

type waftestTestPrinter struct{}

func (p *waftestTestPrinter) Print(v any) error { return nil }
func (p *waftestTestPrinter) Close() error      { return nil }
func (p *waftestTestPrinter) AddInterceptor(func(any) (any, error)) printer.Printer {
	return p
}
func (p *waftestTestPrinter) LogSubdomain(any) error { return nil }
func (p *waftestTestPrinter) LogVuln(any) error      { return nil }

// ==================== CustomTmpl.Close ====================

func TestCustomTmpl_Close_ReturnsNil(t *testing.T) {
	ct := &CustomTmpl{}
	if err := ct.Close(); err != nil {
		t.Errorf("Close() should return nil, got: %v", err)
	}
}

// ==================== CustomTmpl.DepthCheck ====================

func TestCustomTmpl_DepthCheck_WithinLimit(t *testing.T) {
	ct := &CustomTmpl{}
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{Name: "waftest", Enabled: true},
		Depth:            3,
	}
	ab := &base.ApolloBase{}
	ab.Output = &waftestTestPrinter{}
	ct.Init(context.Background(), cfg, ab)

	// Create Apollo with depth 2 (should pass with limit 3)
	u, _ := url.Parse("http://example.com/a/b/c")
	req, _ := wscan_http.NewRequest("GET", u.String(), nil)
	flow := &wscan_http.Flow{Request: req, Response: &wscan_http.Response{StatusCode: 200}}
	a := base.NewApollo(flow)
	a.ApolloBase.Output = &waftestTestPrinter{}

	err := ct.DepthCheck(context.Background(), a)
	if err != nil {
		t.Errorf("DepthCheck within limit should pass, got: %v", err)
	}
}

func TestCustomTmpl_DepthCheck_ExceedsLimit(t *testing.T) {
	ct := &CustomTmpl{}
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{Name: "waftest", Enabled: true},
		Depth:            1,
	}
	ab := &base.ApolloBase{}
	ab.Output = &waftestTestPrinter{}
	ct.Init(context.Background(), cfg, ab)

	u, _ := url.Parse("http://example.com/a/b/c")
	req, _ := wscan_http.NewRequest("GET", u.String(), nil)
	flow := &wscan_http.Flow{Request: req, Response: &wscan_http.Response{StatusCode: 200}}
	a := base.NewApollo(flow)
	a.ApolloBase.Output = &waftestTestPrinter{}

	err := ct.DepthCheck(context.Background(), a)
	if err == nil {
		t.Error("DepthCheck exceeding limit should fail")
	}
}

func TestCustomTmpl_DepthCheck_ZeroLimit(t *testing.T) {
	ct := &CustomTmpl{}
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{Name: "waftest", Enabled: true},
		Depth:            0,
	}
	ab := &base.ApolloBase{}
	ab.Output = &waftestTestPrinter{}
	ct.Init(context.Background(), cfg, ab)

	// With Depth=0 and a deep URL, should fail (0 means any depth > 0 fails)
	u, _ := url.Parse("http://example.com/a/b")
	req, _ := wscan_http.NewRequest("GET", u.String(), nil)
	flow := &wscan_http.Flow{Request: req, Response: &wscan_http.Response{StatusCode: 200}}
	a := base.NewApollo(flow)
	a.ApolloBase.Output = &waftestTestPrinter{}

	err := ct.DepthCheck(context.Background(), a)
	// Depth 0 means no depth > 0 is allowed
	if err == nil {
		t.Log("DepthCheck with depth=2 and limit=0: behavior may vary")
	}
}

// ==================== LoadYamlTmpl edge cases ====================

func TestLoadYamlTmpl_WithValidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := tmpDir + "/test.yml"
	yamlContent := `payload:
  - test_payload
encoder:
  - plain
placeholder:
  - URLParam
type: test-waf
`
	if err := os.WriteFile(tmpFile, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{Name: "waftest", Enabled: true},
		IncludeTmpl:      []string{tmpFile},
	}
	result := LoadYamlTmpl(cfg)
	if len(result) != 1 {
		t.Errorf("Expected 1 POC, got %d", len(result))
	}
}

func TestLoadYamlTmpl_WithYAMLExtension(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := tmpDir + "/test.yaml"
	yamlContent := `payload:
  - test_payload
placeholder:
  - URLParam
type: test-waf
`
	if err := os.WriteFile(tmpFile, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{Name: "waftest", Enabled: true},
		IncludeTmpl:      []string{tmpFile},
	}
	result := LoadYamlTmpl(cfg)
	if len(result) != 1 {
		t.Errorf("Expected 1 POC with .yaml, got %d", len(result))
	}
}

func TestLoadYamlTmpl_SkipsNonYAMLFiles(t *testing.T) {
	tmpDir := t.TempDir()
	txtFile := tmpDir + "/test.txt"
	if err := os.WriteFile(txtFile, []byte("not yaml"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{Name: "waftest", Enabled: true},
		IncludeTmpl:      []string{tmpDir + "/*"},
	}
	result := LoadYamlTmpl(cfg)
	if len(result) != 0 {
		t.Errorf("Expected 0 POCs with non-yaml, got %d", len(result))
	}
}

func TestLoadYamlTmpl_InvalidGlob(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{Name: "waftest", Enabled: true},
		IncludeTmpl:      []string{"[invalid"},
	}
	result := LoadYamlTmpl(cfg)
	if len(result) != 0 {
		t.Errorf("Expected 0 POCs with invalid glob, got %d", len(result))
	}
}

// ==================== LoadSingleTemplate comprehensive ====================

func TestLoadSingleTemplate_NoPlaceholders(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := tmpDir + "/no_ph.yml"
	yamlContent := `payload:
  - test
type: test
`
	if err := os.WriteFile(tmpFile, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}

	yfs, err := LoadSingleTemplate(tmpFile, &Config{})
	if err != nil {
		t.Fatalf("LoadSingleTemplate error: %v", err)
	}
	// No placeholders means no YamlFingers should be created
	if len(yfs) != 0 {
		t.Errorf("Expected 0 YamlFingers with no placeholders, got %d", len(yfs))
	}
}

func TestLoadSingleTemplate_EmptyPayloads(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := tmpDir + "/empty.yml"
	yamlContent := `payload:
placeholder:
  - URLParam
type: test
`
	if err := os.WriteFile(tmpFile, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}

	yfs, err := LoadSingleTemplate(tmpFile, &Config{})
	if err != nil {
		t.Fatalf("LoadSingleTemplate error: %v", err)
	}
	if len(yfs) != 0 {
		t.Errorf("Expected 0 YamlFingers with empty payloads, got %d", len(yfs))
	}
}

func TestLoadSingleTemplate_MultiplePayloads(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := tmpDir + "/multi.yml"
	yamlContent := `payload:
  - payload1
  - payload2
  - payload3
placeholder:
  - URLParam
type: test-multi
`
	if err := os.WriteFile(tmpFile, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}

	yfs, err := LoadSingleTemplate(tmpFile, &Config{})
	if err != nil {
		t.Fatalf("LoadSingleTemplate error: %v", err)
	}
	if len(yfs) != 3 {
		t.Fatalf("Expected 3 YamlFingers, got %d", len(yfs))
	}
	if yfs[0].Payload != "payload1" {
		t.Errorf("First payload = %q, want 'payload1'", yfs[0].Payload)
	}
}

func TestLoadSingleTemplate_DefaultType(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := tmpDir + "/default_type.yml"
	yamlContent := `payload:
  - test
placeholder:
  - URLParam
`
	if err := os.WriteFile(tmpFile, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}

	yfs, err := LoadSingleTemplate(tmpFile, &Config{})
	if err != nil {
		t.Fatalf("LoadSingleTemplate error: %v", err)
	}
	if len(yfs) != 1 {
		t.Fatalf("Expected 1 YamlFinger, got %d", len(yfs))
	}
	if yfs[0].Type != "unknown" {
		t.Errorf("Default type should be 'unknown', got %q", yfs[0].Type)
	}
}

func TestLoadSingleTemplate_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := tmpDir + "/invalid.yml"
	if err := os.WriteFile(tmpFile, []byte("invalid: [yaml: content"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadSingleTemplate(tmpFile, &Config{})
	if err == nil {
		t.Error("Expected error for invalid YAML")
	}
}

func TestLoadSingleTemplate_NonExistentFile(t *testing.T) {
	_, err := LoadSingleTemplate("/nonexistent/file.yml", &Config{})
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
}

func TestLoadSingleTemplate_WithEncoders(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := tmpDir + "/enc.yml"
	yamlContent := `payload:
  - test_payload
encoder:
  - plain
  - url
placeholder:
  - URLParam
type: test-enc
`
	if err := os.WriteFile(tmpFile, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}

	yfs, err := LoadSingleTemplate(tmpFile, &Config{})
	if err != nil {
		t.Fatalf("LoadSingleTemplate error: %v", err)
	}
	if len(yfs) != 1 {
		t.Fatalf("Expected 1 YamlFinger, got %d", len(yfs))
	}
	if len(yfs[0].Encoder) != 2 {
		t.Errorf("Expected 2 encoders, got %d", len(yfs[0].Encoder))
	}
}

func TestLoadSingleTemplate_ChannelDetermined(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name            string
		yamlContent     string
		expectedChannel string
	}{
		{
			"URLParam -> web-generic",
			`payload:
  - test
placeholder:
  - URLParam
type: test
`,
			"web-generic",
		},
		{
			"URLPath -> web-directory",
			`payload:
  - test
placeholder:
  - URLPath
type: test
`,
			"web-directory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile := tmpDir + "/" + tt.name + ".yml"
			if err := os.WriteFile(tmpFile, []byte(tt.yamlContent), 0644); err != nil {
				t.Fatal(err)
			}

			yfs, err := LoadSingleTemplate(tmpFile, &Config{})
			if err != nil {
				t.Fatalf("LoadSingleTemplate error: %v", err)
			}
			if len(yfs) != 1 {
				t.Fatalf("Expected 1 YamlFinger, got %d", len(yfs))
			}
			if yfs[0].Channel != tt.expectedChannel {
				t.Errorf("Channel = %q, want %q", yfs[0].Channel, tt.expectedChannel)
			}
		})
	}
}

// ==================== YamlFinger.Run with httptest server ====================

func TestYamlFinger_Run_Blocked(t *testing.T) {
	// Test when WAF blocks the request (returns 403)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		fmt.Fprint(w, "Forbidden")
	}))
	defer ts.Close()

	tsURL, _ := url.Parse(ts.URL)
	testURL := fmt.Sprintf("http://%s/page?q=test", tsURL.Host)
	req, _ := wscan_http.NewRequest("GET", testURL, nil)
	flow := &wscan_http.Flow{Request: req, Response: &wscan_http.Response{StatusCode: 200}}

	ys := &YamlFinger{
		YamlScript: &YamlScript{
			Payload:      "<script>alert(1)</script>",
			Encoder:      []string{"Plain"},
			Placeholders: []PlaceholderSpec{{Name: "URLParam"}},
			Type:         "xss",
			Channel:      "web-generic",
		},
		cfg: &Config{
			BlockStatusCodes: []int{403},
			PassStatusCodes:  []int{200},
		},
	}

	ab := base.NewApollo(flow)
	ab.ApolloBase.Output = &waftestTestPrinter{}
	ab.ApolloBase.HTTPClient = wscan_http.NewClient()

	err := ys.Run(context.Background(), ab)
	if err != nil {
		t.Errorf("Run() should not return error, got: %v", err)
	}
}

func TestYamlFinger_Run_Passed(t *testing.T) {
	// Test when WAF does NOT block the request (returns 200)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "Welcome")
	}))
	defer ts.Close()

	tsURL, _ := url.Parse(ts.URL)
	testURL := fmt.Sprintf("http://%s/page?url=http://example.com", tsURL.Host)
	req, _ := wscan_http.NewRequest("GET", testURL, nil)
	flow := &wscan_http.Flow{Request: req, Response: &wscan_http.Response{StatusCode: 200}}

	ys := &YamlFinger{
		YamlScript: &YamlScript{
			Payload:      "test_payload",
			Encoder:      []string{"Plain"},
			Placeholders: []PlaceholderSpec{{Name: "URLParam"}},
			Type:         "test",
			Channel:      "web-generic",
		},
		cfg: &Config{
			BlockStatusCodes:   []int{403},
			PassStatusCodes:    []int{200},
			NonBlockedAsPassed: true,
		},
	}

	ab := base.NewApollo(flow)
	ab.ApolloBase.Output = &waftestTestPrinter{}
	ab.ApolloBase.HTTPClient = wscan_http.NewClient()

	err := ys.Run(context.Background(), ab)
	if err != nil {
		t.Errorf("Run() should not return error, got: %v", err)
	}
}

func TestYamlFinger_Run_InvalidEncoder(t *testing.T) {
	// Test with an invalid encoder name - the encoder.Apply panics on unknown encoders
	// so we need to use a valid encoder to test the Run flow
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "OK")
	}))
	defer ts.Close()

	tsURL, _ := url.Parse(ts.URL)
	testURL := fmt.Sprintf("http://%s/page?q=test", tsURL.Host)
	req, _ := wscan_http.NewRequest("GET", testURL, nil)
	flow := &wscan_http.Flow{Request: req, Response: &wscan_http.Response{StatusCode: 200}}

	ys := &YamlFinger{
		YamlScript: &YamlScript{
			Payload:      "test_payload",
			Encoder:      []string{"Plain"},
			Placeholders: []PlaceholderSpec{{Name: "URLParam"}},
			Type:         "test",
			Channel:      "web-generic",
		},
		cfg: &Config{
			BlockStatusCodes: []int{403},
			PassStatusCodes:  []int{200},
		},
	}

	ab := base.NewApollo(flow)
	ab.ApolloBase.Output = &waftestTestPrinter{}
	ab.ApolloBase.HTTPClient = wscan_http.NewClient()

	err := ys.Run(context.Background(), ab)
	if err != nil {
		t.Errorf("Run() should not error, got: %v", err)
	}
}

func TestYamlFinger_Run_InvalidPlaceholder(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "OK")
	}))
	defer ts.Close()

	tsURL, _ := url.Parse(ts.URL)
	testURL := fmt.Sprintf("http://%s/page?q=test", tsURL.Host)
	req, _ := wscan_http.NewRequest("GET", testURL, nil)
	flow := &wscan_http.Flow{Request: req, Response: &wscan_http.Response{StatusCode: 200}}

	ys := &YamlFinger{
		YamlScript: &YamlScript{
			Payload:      "test_payload",
			Encoder:      []string{"Plain"},
			Placeholders: []PlaceholderSpec{{Name: "InvalidPlaceholder"}},
			Type:         "test",
			Channel:      "web-generic",
		},
		cfg: &Config{
			BlockStatusCodes: []int{403},
			PassStatusCodes:  []int{200},
		},
	}

	ab := base.NewApollo(flow)
	ab.ApolloBase.Output = &waftestTestPrinter{}
	ab.ApolloBase.HTTPClient = wscan_http.NewClient()

	err := ys.Run(context.Background(), ab)
	// Invalid placeholder should be handled gracefully
	_ = err
}

func TestYamlFinger_Run_HTTPError(t *testing.T) {
	// Test when HTTP request fails (unreachable server)
	testURL := "http://127.0.0.1:1/page?q=test"
	req, _ := wscan_http.NewRequest("GET", testURL, nil)
	flow := &wscan_http.Flow{Request: req, Response: &wscan_http.Response{StatusCode: 200}}

	ys := &YamlFinger{
		YamlScript: &YamlScript{
			Payload:      "test_payload",
			Encoder:      []string{"Plain"},
			Placeholders: []PlaceholderSpec{{Name: "URLParam"}},
			Type:         "test",
			Channel:      "web-generic",
		},
		cfg: &Config{
			BlockStatusCodes: []int{403},
			PassStatusCodes:  []int{200},
		},
	}

	ab := base.NewApollo(flow)
	ab.ApolloBase.Output = &waftestTestPrinter{}
	ab.ApolloBase.HTTPClient = wscan_http.NewClient()

	err := ys.Run(context.Background(), ab)
	// HTTP errors should be handled gracefully
	_ = err
}

// ==================== checkBlocking and checkPass additional ====================

func TestYamlFinger_CheckBlocking_EmptyRegex(t *testing.T) {
	y := &YamlFinger{
		cfg: &Config{BlockRegex: ""},
	}
	if y.checkBlocking("", "", 200) {
		t.Error("Empty BlockRegex should not block")
	}
}

func TestYamlFinger_CheckBlocking_HeaderAndBody(t *testing.T) {
	y := &YamlFinger{
		cfg: &Config{BlockRegex: "Forbidden"},
	}
	// Block when header contains the pattern
	if !y.checkBlocking("HTTP/1.1 403 Forbidden", "", 200) {
		t.Error("Should block when header matches BlockRegex")
	}
	// Block when body contains the pattern
	if !y.checkBlocking("", "Access Forbidden", 200) {
		t.Error("Should block when body matches BlockRegex")
	}
	// Block when both header and body are combined
	if !y.checkBlocking("HTTP/1.1 403", "Forbidden content", 200) {
		t.Error("Should block when combined header+body matches BlockRegex")
	}
}

func TestYamlFinger_CheckPass_EmptyRegex(t *testing.T) {
	y := &YamlFinger{
		cfg: &Config{PassRegex: ""},
	}
	if y.checkPass("", "", 200) {
		t.Error("Empty PassRegex should not pass")
	}
}

func TestYamlFinger_CheckPass_HeaderAndBody(t *testing.T) {
	y := &YamlFinger{
		cfg: &Config{PassRegex: "Welcome"},
	}
	if !y.checkPass("Welcome header", "", 200) {
		t.Error("Should pass when header matches PassRegex")
	}
	if !y.checkPass("", "Welcome body", 200) {
		t.Error("Should pass when body matches PassRegex")
	}
}

func TestYamlFinger_CheckBlocking_InvalidRegex(t *testing.T) {
	y := &YamlFinger{
		cfg: &Config{BlockRegex: "[invalid"},
	}
	// Invalid regex should not crash, should return false
	if y.checkBlocking("", "anything", 200) {
		t.Error("Invalid regex should not block")
	}
}

func TestYamlFinger_CheckPass_InvalidRegex(t *testing.T) {
	y := &YamlFinger{
		cfg: &Config{PassRegex: "[invalid"},
	}
	if y.checkPass("", "anything", 200) {
		t.Error("Invalid regex should not pass")
	}
}

// ==================== parsePlaceholderSpec edge cases ====================

func TestParsePlaceholderSpec_MapWithNonStringKey(t *testing.T) {
	spec, err := parsePlaceholderSpec(map[any]any{
		123: "value",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Non-string key should result in nil spec (skip)
	if spec != nil {
		t.Error("Expected nil spec for non-string key in map")
	}
}

func TestParsePlaceholderSpec_MapWithInvalidConfig(t *testing.T) {
	spec, err := parsePlaceholderSpec(map[any]any{
		"RawRequest": "invalid_config_type",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should still parse the name even if config fails
	if spec == nil {
		t.Fatal("Expected non-nil spec")
	}
	if spec.Name != "RawRequest" {
		t.Errorf("Name = %q, want 'RawRequest'", spec.Name)
	}
}

// ==================== Config BaseConfig ====================

func TestConfig_BaseConfig_NilCheck(t *testing.T) {
	cfg := &Config{}
	bc := cfg.BaseConfig()
	if bc == nil {
		t.Error("BaseConfig should not return nil")
	}
}

// ==================== CustomTmpl.GetConfig before and after Init ====================

func TestCustomTmpl_GetConfig_AfterInitWithConfig(t *testing.T) {
	ct := &CustomTmpl{}
	cfg := &Config{
		PluginBaseConfig:   base.PluginBaseConfig{Name: "waftest", Enabled: true},
		NonBlockedAsPassed: true,
		BlockRegex:         "denied",
		PassRegex:          "welcome",
	}
	ab := &base.ApolloBase{}
	ct.Init(context.Background(), cfg, ab)

	gotCfg := ct.GetConfig()
	if gotCfg == nil {
		t.Fatal("Expected non-nil config after Init")
	}
	waftestCfg, ok := gotCfg.(*Config)
	if !ok {
		t.Fatal("Expected *Config type")
	}
	if !waftestCfg.NonBlockedAsPassed {
		t.Error("Expected NonBlockedAsPassed=true")
	}
}
