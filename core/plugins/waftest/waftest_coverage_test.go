package waftest

import (
	"testing"

	"wscan/core/plugins/base"
)

func TestCustomTmpl_DefaultConfig(t *testing.T) {
	ct := &CustomTmpl{}
	cfg := ct.DefaultConfig()
	if cfg == nil {
		t.Fatal("expected non-nil DefaultConfig")
	}
	bc := cfg.BaseConfig()
	if bc.Name != "waftest" {
		t.Errorf("expected Name 'waftest', got '%s'", bc.Name)
	}
	if !bc.Enabled {
		t.Error("expected Enabled=true")
	}
	waftestCfg, ok := cfg.(*Config)
	if !ok {
		t.Fatal("expected *Config type")
	}
	if waftestCfg.Depth != 0 {
		t.Errorf("expected Depth 0, got %d", waftestCfg.Depth)
	}
}

func TestCustomTmpl_Fingers_NoEnabledPOC(t *testing.T) {
	ct := &CustomTmpl{}
	fingers := ct.Fingers()
	if len(fingers) != 0 {
		t.Errorf("expected 0 fingers with no enabled POCs, got %d", len(fingers))
	}
}

func TestYamlFinger_CheckBlocking_BlockRegex(t *testing.T) {
	y := &YamlFinger{
		cfg: &Config{
			BlockRegex: "Access Denied|Forbidden",
		},
	}
	if !y.checkBlocking("", "Access Denied page", 200) {
		t.Error("expected blocking when body matches BlockRegex")
	}
	if !y.checkBlocking("HTTP/1.1 403 Forbidden\r\n", "normal", 200) {
		t.Error("expected blocking when header matches BlockRegex")
	}
	if y.checkBlocking("", "normal page", 200) {
		t.Error("expected no blocking when neither header nor body matches")
	}
}

func TestYamlFinger_CheckBlocking_BlockStatusCodes(t *testing.T) {
	y := &YamlFinger{
		cfg: &Config{
			BlockStatusCodes: []int{403, 401},
		},
	}
	if !y.checkBlocking("", "", 403) {
		t.Error("expected blocking for 403 status code")
	}
	if !y.checkBlocking("", "", 401) {
		t.Error("expected blocking for 401 status code")
	}
	if y.checkBlocking("", "", 200) {
		t.Error("expected no blocking for 200 status code")
	}
}

func TestYamlFinger_CheckBlocking_EmptyConfig(t *testing.T) {
	y := &YamlFinger{
		cfg: &Config{},
	}
	if y.checkBlocking("", "anything", 200) {
		t.Error("expected no blocking with empty config")
	}
}

func TestYamlFinger_CheckPass_PassRegex(t *testing.T) {
	y := &YamlFinger{
		cfg: &Config{
			PassRegex: "Welcome|OK",
		},
	}
	if !y.checkPass("", "Welcome to the site", 200) {
		t.Error("expected pass when body matches PassRegex")
	}
	if !y.checkPass("HTTP/1.1 200 OK\r\n", "normal", 200) {
		t.Error("expected pass when header matches PassRegex")
	}
	if y.checkPass("", "Access Denied", 200) {
		t.Error("expected no pass when neither matches")
	}
}

func TestYamlFinger_CheckPass_PassStatusCodes(t *testing.T) {
	y := &YamlFinger{
		cfg: &Config{
			PassStatusCodes: []int{200, 404},
		},
	}
	if !y.checkPass("", "", 200) {
		t.Error("expected pass for 200 status code")
	}
	if !y.checkPass("", "", 404) {
		t.Error("expected pass for 404 status code")
	}
	if y.checkPass("", "", 403) {
		t.Error("expected no pass for 403 status code")
	}
}

func TestYamlFinger_CheckPass_EmptyConfig(t *testing.T) {
	y := &YamlFinger{
		cfg: &Config{},
	}
	if y.checkPass("", "anything", 200) {
		t.Error("expected no pass with empty config")
	}
}

func TestYamlFinger_Finger(t *testing.T) {
	y := &YamlFinger{
		YamlScript: &YamlScript{
			Type:    "test-waf",
			Channel: "web-generic",
		},
		cfg: &Config{},
	}
	finger := y.Finger()
	if finger == nil {
		t.Fatal("expected non-nil finger")
	}
	if finger.Channel != "web-generic" {
		t.Errorf("expected Channel 'web-generic', got '%s'", finger.Channel)
	}
	if finger.Binding == nil {
		t.Fatal("expected non-nil Binding")
	}
	if finger.Binding.ID != "test-waf" {
		t.Errorf("expected Binding.ID 'test-waf', got '%s'", finger.Binding.ID)
	}
	if finger.ExecAction == nil {
		t.Error("expected non-nil ExecAction")
	}
}

func TestDetermineChannel(t *testing.T) {
	tests := []struct {
		placeholders []PlaceholderSpec
		expected     string
	}{
		{
			placeholders: []PlaceholderSpec{{Name: "URLParam"}},
			expected:     "web-generic",
		},
		{
			placeholders: []PlaceholderSpec{{Name: "URLPath"}},
			expected:     "web-directory",
		},
		{
			placeholders: []PlaceholderSpec{{Name: "NonCrudUrlPath"}},
			expected:     "web-directory",
		},
		{
			placeholders: []PlaceholderSpec{{Name: "URLPath"}, {Name: "URLParam"}},
			expected:     "web-directory",
		},
		{
			placeholders: []PlaceholderSpec{{Name: "Header"}},
			expected:     "web-generic",
		},
		{
			placeholders: []PlaceholderSpec{},
			expected:     "web-generic",
		},
	}
	for _, tt := range tests {
		result := determineChannel(tt.placeholders)
		if result != tt.expected {
			t.Errorf("determineChannel(%v) = '%s', expected '%s'", tt.placeholders, result, tt.expected)
		}
	}
}

func TestParsePlaceholderSpec_String(t *testing.T) {
	spec, err := parsePlaceholderSpec("URLParam")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spec == nil {
		t.Fatal("expected non-nil spec")
	}
	if spec.Name != "URLParam" {
		t.Errorf("expected Name 'URLParam', got '%s'", spec.Name)
	}
	if spec.Config != nil {
		t.Error("expected nil Config for simple string placeholder")
	}
}

func TestParsePlaceholderSpec_Map(t *testing.T) {
	spec, err := parsePlaceholderSpec(map[any]any{
		"RawRequest": map[any]any{
			"method": "POST",
			"path":   "/",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spec == nil {
		t.Fatal("expected non-nil spec")
	}
	if spec.Name != "RawRequest" {
		t.Errorf("expected Name 'RawRequest', got '%s'", spec.Name)
	}
}

func TestParsePlaceholderSpec_UnknownType(t *testing.T) {
	spec, err := parsePlaceholderSpec(12345)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spec != nil {
		t.Error("expected nil spec for unknown type")
	}
}

func TestParsePlaceholderSpec_Nil(t *testing.T) {
	spec, err := parsePlaceholderSpec(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spec != nil {
		t.Error("expected nil spec for nil input")
	}
}

func TestCustomTmpl_DefaultConfigValues(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{Name: "waftest", Enabled: true},
	}
	dc := (&CustomTmpl{}).DefaultConfig().(*Config)
	if dc.PassStatusCodes == nil || len(dc.PassStatusCodes) != 2 {
		t.Errorf("expected 2 default PassStatusCodes, got %v", dc.PassStatusCodes)
	}
	if dc.BlockStatusCodes == nil || len(dc.BlockStatusCodes) != 1 {
		t.Errorf("expected 1 default BlockStatusCodes, got %v", dc.BlockStatusCodes)
	}
	_ = cfg // suppress unused warning
}

func TestCustomTmpl_Fingers_WithEnabledPOC(t *testing.T) {
	ct := &CustomTmpl{}
	// Manually set an enabled POC
	yf := &YamlFinger{
		YamlScript: &YamlScript{
			Type:    "test-type",
			Channel: "web-generic",
		},
		cfg: &Config{},
	}
	ct.enabledPOC = []base.FingerFactory{yf}
	fingers := ct.Fingers()
	if len(fingers) != 1 {
		t.Fatalf("expected 1 finger, got %d", len(fingers))
	}
	if fingers[0].CheckAction == nil {
		t.Error("CheckAction should be set (DepthCheck)")
	}
	if fingers[0].Binding == nil || fingers[0].Binding.ID != "test-type" {
		t.Error("unexpected finger binding")
	}
}
