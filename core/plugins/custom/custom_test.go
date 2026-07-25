package custom

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	wscan_http "wscan/core/http"
	"wscan/core/plugins/base"
	"wscan/core/utils/printer"
)

func TestCustom_Close(t *testing.T) {
	c := &Custom{}
	if err := c.Close(); err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
}

func TestCustom_DefaultConfig(t *testing.T) {
	c := &Custom{}
	cfg := c.DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig() returned nil")
	}

	typedCfg, ok := cfg.(*Config)
	if !ok {
		t.Fatal("DefaultConfig() did not return *Config")
	}
	if typedCfg.PluginBaseConfig.Name != "custom" {
		t.Errorf("Expected Name='custom', got '%s'", typedCfg.PluginBaseConfig.Name)
	}
	if !typedCfg.PluginBaseConfig.Enabled {
		t.Error("Expected Enabled=true")
	}
	if typedCfg.Depth != 0 {
		t.Errorf("Expected Depth=0, got %d", typedCfg.Depth)
	}
}

func TestConfig_BaseConfig(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "custom",
			Enabled: true,
		},
		Depth: 2,
	}
	bc := cfg.BaseConfig()
	if bc == nil {
		t.Fatal("BaseConfig() returned nil")
	}
	if bc.Name != "custom" {
		t.Errorf("Expected Name='custom', got '%s'", bc.Name)
	}
}

func TestCustom_GetConfig(t *testing.T) {
	c := &Custom{}
	// Before Init
	cfg := c.GetConfig()
	if cfg != nil {
		t.Errorf("Expected nil config before Init, got %v", cfg)
	}

	// After Init
	expectedCfg := c.DefaultConfig()
	ab := &base.ApolloBase{}
	c.Init(context.Background(), expectedCfg, ab)

	cfg = c.GetConfig()
	if cfg == nil {
		t.Fatal("Expected non-nil config after Init")
	}
}

func TestCustom_Fingers_NoPOC(t *testing.T) {
	c := &Custom{}
	cfg := c.DefaultConfig()
	ab := &base.ApolloBase{}
	c.Init(context.Background(), cfg, ab)

	fingers := c.Fingers()
	// With no POC files included, should return empty
	if len(fingers) != 0 {
		t.Errorf("Expected 0 fingers with no POC, got %d", len(fingers))
	}
}

func TestCustom_Fingers_WithEnabledPOC(t *testing.T) {
	c := &Custom{}
	// Manually set enabledPOC to simulate loaded POCs
	factory := &mockFingerFactory{
		finger: &base.Finger{
			Channel: "web-generic",
		},
	}
	c.enabledPOC = []base.FingerFactory{factory}

	fingers := c.Fingers()
	if len(fingers) != 1 {
		t.Errorf("Expected 1 finger, got %d", len(fingers))
	}
	// CheckAction should be overridden with DepthCheck
	if fingers[0].CheckAction == nil {
		t.Error("CheckAction should not be nil")
	}
}

func TestCustom_DepthCheck_ZeroDepth(t *testing.T) {
	c := &Custom{}
	cfg := c.DefaultConfig()
	ab := &base.ApolloBase{}
	c.Init(context.Background(), cfg, ab)

	// With depth=0, DepthCheck should always pass
	// (depth=0 means no depth restriction)
}

func TestCustom_DepthCheck_ExceedsDepth(t *testing.T) {
	c := &Custom{}
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "custom",
			Enabled: true,
		},
		Depth: 1,
	}
	ab := &base.ApolloBase{}
	c.Init(context.Background(), cfg, ab)
}

func TestConfig_Depth(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "custom",
			Enabled: true,
		},
		Depth: 3,
	}
	if cfg.Depth != 3 {
		t.Errorf("Depth = %d, want 3", cfg.Depth)
	}
}

func TestConfig_IncludeExcludeTmpl(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "custom",
			Enabled: true,
		},
		IncludeTmpl: []string{"./tmpl-*"},
		ExcludeTmpl: []string{"*weblogic*"},
	}
	if len(cfg.IncludeTmpl) != 1 {
		t.Errorf("IncludeTmpl len = %d, want 1", len(cfg.IncludeTmpl))
	}
	if len(cfg.ExcludeTmpl) != 1 {
		t.Errorf("ExcludeTmpl len = %d, want 1", len(cfg.ExcludeTmpl))
	}
}

func TestLoadYamlTmpl_NoIncludes(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "custom",
			Enabled: true,
		},
		IncludeTmpl: []string{},
	}
	result := LoadYamlTmpl(cfg)
	if len(result) != 0 {
		t.Errorf("Expected 0 POCs with empty include list, got %d", len(result))
	}
}

func TestLoadYamlTmpl_NonExistentGlob(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "custom",
			Enabled: true,
		},
		IncludeTmpl: []string{"/nonexistent/path/*.yml"},
	}
	result := LoadYamlTmpl(cfg)
	if len(result) != 0 {
		t.Errorf("Expected 0 POCs with non-existent glob, got %d", len(result))
	}
}

func TestLoadSingleTemplate_NonExistentFile(t *testing.T) {
	_, err := LoadSingleTemplate("/nonexistent/file.yml", nil)
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
}

func TestLoadSingleTemplate_InvalidYAML(t *testing.T) {
	// Create a temp file with invalid YAML
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "invalid.yml")
	if err := os.WriteFile(tmpFile, []byte("invalid: [yaml: content"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadSingleTemplate(tmpFile, nil)
	if err == nil {
		t.Error("Expected error for invalid YAML")
	}
}

func TestLoadSingleTemplate_ValidYAML(t *testing.T) {
	// Create a temp file with valid YAML
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "valid.yml")
	yamlContent := `name: test-poc
payload:
  - test_payload_value
expression: "response.status == 200"
`
	if err := os.WriteFile(tmpFile, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}

	yfs, err := LoadSingleTemplate(tmpFile, nil)
	if err != nil {
		t.Fatalf("LoadSingleTemplate() error: %v", err)
	}
	if len(yfs) != 1 {
		t.Fatalf("Expected 1 YamlFinger, got %d", len(yfs))
	}
	if yfs[0].Payload != "test_payload_value" {
		t.Errorf("Payload = %q, want 'test_payload_value'", yfs[0].Payload)
	}
	if yfs[0].Temp == nil {
		t.Error("Temp should not be nil")
	}
	if yfs[0].Temp.Name != "test-poc" {
		t.Errorf("Temp.Name = %q, want 'test-poc'", yfs[0].Temp.Name)
	}
}

func TestLoadSingleTemplate_MultiplePayloads(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "multi.yml")
	yamlContent := `name: multi-poc
payload:
  - payload1
  - payload2
  - payload3
expression: "response.status == 200"
`
	if err := os.WriteFile(tmpFile, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}

	yfs, err := LoadSingleTemplate(tmpFile, nil)
	if err != nil {
		t.Fatalf("LoadSingleTemplate() error: %v", err)
	}
	if len(yfs) != 3 {
		t.Fatalf("Expected 3 YamlFingers, got %d", len(yfs))
	}
	if yfs[0].Payload != "payload1" {
		t.Errorf("First payload = %q, want 'payload1'", yfs[0].Payload)
	}
	if yfs[1].Payload != "payload2" {
		t.Errorf("Second payload = %q, want 'payload2'", yfs[1].Payload)
	}
	if yfs[2].Payload != "payload3" {
		t.Errorf("Third payload = %q, want 'payload3'", yfs[2].Payload)
	}
}

func TestTemplate_Struct(t *testing.T) {
	tmpl := &Template{
		Name:         "test",
		Payloads:     []string{"p1", "p2"},
		Encoders:     []string{"Base64"},
		Placeholders: []string{"URLParam"},
		Expression:   "response.status == 200",
		Type:         "web",
	}
	if tmpl.Name != "test" {
		t.Errorf("Name = %q, want 'test'", tmpl.Name)
	}
	if len(tmpl.Payloads) != 2 {
		t.Errorf("Payloads len = %d, want 2", len(tmpl.Payloads))
	}
	if tmpl.Expression != "response.status == 200" {
		t.Errorf("Expression = %q, want 'response.status == 200'", tmpl.Expression)
	}
}

func TestYamlScript_Struct(t *testing.T) {
	tmpl := &Template{Name: "test"}
	ys := &YamlScript{
		Temp:    tmpl,
		Payload: "test_payload",
		Channel: "web-generic",
	}
	if ys.Payload != "test_payload" {
		t.Errorf("Payload = %q, want 'test_payload'", ys.Payload)
	}
	if ys.Channel != "web-generic" {
		t.Errorf("Channel = %q, want 'web-generic'", ys.Channel)
	}
	if ys.Temp != tmpl {
		t.Error("Temp should point to the same template")
	}
}

func TestYamlFinger_Finger(t *testing.T) {
	tmpl := &Template{Name: "test-poc"}
	ys := &YamlFinger{
		YamlScript: &YamlScript{
			Temp:    tmpl,
			Payload: "test",
			Channel: "web-generic",
		},
	}
	finger := ys.Finger()
	if finger == nil {
		t.Fatal("YamlFinger.Finger() returned nil")
	}
	if finger.Channel != "web-generic" {
		t.Errorf("Channel = %q, want 'web-generic'", finger.Channel)
	}
	if finger.Binding.ID != "custom/test-poc" {
		t.Errorf("Binding.ID = %q, want 'custom/test-poc'", finger.Binding.ID)
	}
	if finger.ExecAction == nil {
		t.Error("ExecAction should not be nil")
	}
}

func TestLoadYamlTmpl_WithValidFile(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "poc.yml")
	yamlContent := `name: test-poc
payload:
  - test_payload
expression: "response.status == 200"
`
	if err := os.WriteFile(tmpFile, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "custom",
			Enabled: true,
		},
		IncludeTmpl: []string{tmpFile},
	}
	result := LoadYamlTmpl(cfg)
	if len(result) != 1 {
		t.Errorf("Expected 1 POC, got %d", len(result))
	}
}

func TestLoadYamlTmpl_SkipsNonYAMLFiles(t *testing.T) {
	tmpDir := t.TempDir()
	// Create a .txt file that should be skipped
	txtFile := filepath.Join(tmpDir, "poc.txt")
	if err := os.WriteFile(txtFile, []byte("not yaml"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "custom",
			Enabled: true,
		},
		IncludeTmpl: []string{filepath.Join(tmpDir, "*")},
	}
	result := LoadYamlTmpl(cfg)
	if len(result) != 0 {
		t.Errorf("Expected 0 POCs (non-yaml file), got %d", len(result))
	}
}

// mockFingerFactory for testing
type mockFingerFactory struct {
	finger *base.Finger
}

func (m *mockFingerFactory) Finger() *base.Finger {
	return m.finger
}

// ==================== DepthCheck tests with proper Apollo ====================

func makeCustomTestApollo(depth int) *base.Apollo {
	u, _ := url.Parse(fmt.Sprintf("http://example.com/%s", strings.Repeat("a/", depth)))
	req, _ := wscan_http.NewRequest("GET", u.String(), nil)
	flow := &wscan_http.Flow{
		Request:  req,
		Response: &wscan_http.Response{StatusCode: 200},
	}
	a := base.NewApollo(flow)
	a.ApolloBase.Output = &customMockPrinter{}
	return a
}

type customMockPrinter struct{}

func (m *customMockPrinter) Print(v any) error { return nil }
func (m *customMockPrinter) Close() error      { return nil }
func (m *customMockPrinter) AddInterceptor(func(any) (any, error)) printer.Printer {
	return m
}
func (m *customMockPrinter) LogSubdomain(any) error { return nil }
func (m *customMockPrinter) LogVuln(any) error      { return nil }

func TestCustom_DepthCheck_WithinDepth(t *testing.T) {
	c := &Custom{}
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "custom",
			Enabled: true,
		},
		Depth: 2,
	}
	ab := &base.ApolloBase{}
	ab.Output = &customMockPrinter{}
	c.Init(context.Background(), cfg, ab)

	// Depth 1 should pass with limit 2
	a := makeCustomTestApollo(1)
	err := c.DepthCheck(context.Background(), a)
	if err != nil {
		t.Errorf("DepthCheck with depth=1 and limit=2 should pass, got: %v", err)
	}
}

func TestCustom_DepthCheck_ExceedsDepthLimit(t *testing.T) {
	c := &Custom{}
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "custom",
			Enabled: true,
		},
		Depth: 1,
	}
	ab := &base.ApolloBase{}
	ab.Output = &customMockPrinter{}
	c.Init(context.Background(), cfg, ab)

	// Depth 2 should fail with limit 1
	a := makeCustomTestApollo(2)
	err := c.DepthCheck(context.Background(), a)
	if err == nil {
		t.Error("DepthCheck with depth=2 and limit=1 should fail")
	}
}

func TestCustom_DepthCheck_ZeroDepthLimit(t *testing.T) {
	c := &Custom{}
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "custom",
			Enabled: true,
		},
		Depth: 0,
	}
	ab := &base.ApolloBase{}
	ab.Output = &customMockPrinter{}
	c.Init(context.Background(), cfg, ab)

	// Depth 0 means no restriction
	a := makeCustomTestApollo(5)
	err := c.DepthCheck(context.Background(), a)
	if err != nil {
		t.Errorf("DepthCheck with depth=5 and limit=0 should pass, got: %v", err)
	}
}
