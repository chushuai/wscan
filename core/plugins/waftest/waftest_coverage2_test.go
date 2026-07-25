package waftest

import (
	"context"
	"testing"

	"wscan/core/plugins/base"
)

// ==================== CustomTmpl struct tests ====================

func TestCustomTmpl_DefaultConfig_Values(t *testing.T) {
	ct := &CustomTmpl{}
	cfg := ct.DefaultConfig().(*Config)
	if cfg.PluginBaseConfig.Name != "waftest" {
		t.Errorf("Expected Name='waftest', got '%s'", cfg.PluginBaseConfig.Name)
	}
	if !cfg.PluginBaseConfig.Enabled {
		t.Error("Expected Enabled=true")
	}
	if cfg.Depth != 0 {
		t.Errorf("Expected Depth=0, got %d", cfg.Depth)
	}
	if len(cfg.PassStatusCodes) != 2 {
		t.Errorf("Expected 2 PassStatusCodes, got %d", len(cfg.PassStatusCodes))
	}
	if len(cfg.BlockStatusCodes) != 1 {
		t.Errorf("Expected 1 BlockStatusCodes, got %d", len(cfg.BlockStatusCodes))
	}
}

func TestCustomTmpl_GetConfig_BeforeInit(t *testing.T) {
	ct := &CustomTmpl{}
	cfg := ct.GetConfig()
	if cfg != nil {
		t.Errorf("Expected nil config before Init, got %v", cfg)
	}
}

func TestCustomTmpl_GetConfig_AfterInit(t *testing.T) {
	ct := &CustomTmpl{}
	cfg := ct.DefaultConfig()
	ab := &base.ApolloBase{}
	ct.Init(context.Background(), cfg, ab)

	gotCfg := ct.GetConfig()
	if gotCfg == nil {
		t.Fatal("Expected non-nil config after Init")
	}
}

// ==================== Config tests ====================

func TestConfig_Fields(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig:   base.PluginBaseConfig{Name: "waftest", Enabled: true},
		Depth:              2,
		AutoLoadTmpl:       true,
		IncludeTmpl:        []string{"*.yml"},
		ExcludeTmpl:        []string{"*test*"},
		BlockStatusCodes:   []int{403, 401},
		PassStatusCodes:    []int{200, 404},
		BlockRegex:         "Access Denied",
		PassRegex:          "Welcome",
		NonBlockedAsPassed: true,
	}
	if cfg.Depth != 2 {
		t.Errorf("Expected Depth=2, got %d", cfg.Depth)
	}
	if !cfg.AutoLoadTmpl {
		t.Error("Expected AutoLoadTmpl=true")
	}
	if len(cfg.IncludeTmpl) != 1 {
		t.Errorf("Expected 1 IncludeTmpl, got %d", len(cfg.IncludeTmpl))
	}
	if !cfg.NonBlockedAsPassed {
		t.Error("Expected NonBlockedAsPassed=true")
	}
}

// ==================== PlaceholderSpec and Template tests ====================

func TestPlaceholderSpec(t *testing.T) {
	ps := PlaceholderSpec{Name: "URLParam", Config: nil}
	if ps.Name != "URLParam" {
		t.Errorf("Expected Name='URLParam', got '%s'", ps.Name)
	}
}

func TestTemplate_Struct(t *testing.T) {
	tmpl := Template{
		Payloads:     []string{"payload1", "payload2"},
		Encoders:     []string{"plain", "url"},
		Placeholders: []any{"URLParam"},
		Type:         "sqli",
	}
	if len(tmpl.Payloads) != 2 {
		t.Errorf("Expected 2 payloads, got %d", len(tmpl.Payloads))
	}
	if tmpl.Type != "sqli" {
		t.Errorf("Expected Type='sqli', got '%s'", tmpl.Type)
	}
}

func TestYamlScript_Struct(t *testing.T) {
	ys := YamlScript{
		Payload:      "test-payload",
		Encoder:      []string{"plain"},
		Placeholders: []PlaceholderSpec{{Name: "URLParam"}},
		Type:         "xss",
		Channel:      "web-generic",
	}
	if ys.Payload != "test-payload" {
		t.Errorf("Expected Payload='test-payload', got '%s'", ys.Payload)
	}
	if ys.Channel != "web-generic" {
		t.Errorf("Expected Channel='web-generic', got '%s'", ys.Channel)
	}
}

// ==================== DepthCheck test ====================

func TestCustomTmpl_DepthCheck(t *testing.T) {
	ct := &CustomTmpl{}
	ct.PluginMixinInitConfig.Config = &Config{
		PluginBaseConfig: base.PluginBaseConfig{Name: "waftest", Enabled: true},
		Depth:            0, // no depth limit
	}
	// Without an actual Apollo with a flow, this will panic on nil flow
	// So just verify the struct setup
	if ct.GetConfig() == nil {
		t.Error("Expected non-nil config after setting")
	}
}

// ==================== LoadSingleTemplate nil config test ====================

func TestLoadSingleTemplate_NilConfig(t *testing.T) {
	yss, err := LoadSingleTemplate("nonexistent.yml", nil)
	if err != nil {
		t.Errorf("Expected nil error for nil config, got: %v", err)
	}
	if yss != nil {
		t.Errorf("Expected nil result for nil config, got: %v", yss)
	}
}
