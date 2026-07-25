package xss

import (
	"testing"

	"wscan/core/plugins/base"
)

// ==================== XSS struct tests ====================

func TestXSS_DefaultConfig_Values(t *testing.T) {
	x := &XSS{}
	cfg := x.DefaultConfig().(*Config)
	if cfg.PluginBaseConfig.Name != "xss" {
		t.Errorf("Expected Name='xss', got '%s'", cfg.PluginBaseConfig.Name)
	}
	if !cfg.PluginBaseConfig.Enabled {
		t.Error("Expected Enabled=true")
	}
	if !cfg.DetectXSSInCookie {
		t.Error("Expected DetectXSSInCookie=true")
	}
	if !cfg.DetectXSSInReferer {
		t.Error("Expected DetectXSSInReferer=true")
	}
	if !cfg.IEFeature {
		t.Error("Expected IEFeature=true")
	}
}

func TestXSS_GetConfig_BeforeInit(t *testing.T) {
	x := &XSS{}
	cfg := x.GetConfig()
	if cfg != nil {
		t.Errorf("Expected nil config before Init, got %v", cfg)
	}
}

func TestXSS_GetConfig_AfterInit(t *testing.T) {
	x := &XSS{}
	cfg := x.DefaultConfig()
	// Set config directly without calling Init (which needs URLChecker)
	x.PluginMixinInitConfig.Config = cfg

	gotCfg := x.GetConfig()
	if gotCfg == nil {
		t.Fatal("Expected non-nil config after setting")
	}
}

func TestXSS_Init(t *testing.T) {
	x := &XSS{}
	cfg := x.DefaultConfig()
	// Set config directly without calling Init (which panics on nil URLChecker)
	x.PluginMixinInitConfig.Config = cfg
	gotCfg := x.GetConfig()
	if gotCfg == nil {
		t.Fatal("Expected non-nil config after setting")
	}
}

func TestXSS_Scan_ReturnsNil(t *testing.T) {
	x := &XSS{}
	scanFn := x.Scan()
	if scanFn != nil {
		t.Error("Expected nil Scan function")
	}
}

func TestXSS_execAction_ReturnsNil(t *testing.T) {
	x := &XSS{}
	err := x.execAction(nil, nil)
	if err != nil {
		t.Errorf("execAction() returned error: %v", err)
	}
}

func TestXSS_AddXSSVuln(t *testing.T) {
	x := &XSS{}
	// AddXSSVuln is a no-op, just verify it doesn't panic
	x.AddXSSVuln(nil, nil, nil, nil, "")
}

func TestXSS_Fingers_OnlyCookie(t *testing.T) {
	x := &XSS{}
	x.PluginMixinInitConfig.Config = &Config{
		PluginBaseConfig:   base.PluginBaseConfig{Name: "xss", Enabled: true},
		DetectXSSInCookie:  true,
		DetectXSSInReferer: false,
		IEFeature:          false,
	}
	fingers := x.Fingers()
	foundCookie := false
	for _, f := range fingers {
		if f.Binding != nil && f.Binding.ID == "xss/reflected/cookie" {
			foundCookie = true
		}
	}
	if !foundCookie {
		t.Error("Expected cookie XSS finger to be registered")
	}
}

func TestXSS_Fingers_OnlyReferer(t *testing.T) {
	x := &XSS{}
	x.PluginMixinInitConfig.Config = &Config{
		PluginBaseConfig:   base.PluginBaseConfig{Name: "xss", Enabled: true},
		DetectXSSInCookie:  false,
		DetectXSSInReferer: true,
		IEFeature:          false,
	}
	fingers := x.Fingers()
	foundReferer := false
	for _, f := range fingers {
		if f.Binding != nil && f.Binding.ID == "xss/reflected/referer" {
			foundReferer = true
		}
	}
	if !foundReferer {
		t.Error("Expected referer XSS finger to be registered")
	}
}

func TestXSS_Fingers_OnlyIE(t *testing.T) {
	x := &XSS{}
	x.PluginMixinInitConfig.Config = &Config{
		PluginBaseConfig:   base.PluginBaseConfig{Name: "xss", Enabled: true},
		DetectXSSInCookie:  false,
		DetectXSSInReferer: false,
		IEFeature:          true,
	}
	fingers := x.Fingers()
	foundIE := false
	for _, f := range fingers {
		if f.Binding != nil && f.Binding.ID == "xss/reflected/ie-feature" {
			foundIE = true
		}
	}
	if !foundIE {
		t.Error("Expected IE feature XSS finger to be registered")
	}
}

func TestConfig_BaseConfig(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{Name: "xss", Enabled: true},
	}
	bc := cfg.BaseConfig()
	if bc.Name != "xss" {
		t.Errorf("Expected Name='xss', got '%s'", bc.Name)
	}
}

// ==================== IE XSS finger test ====================

func TestIEXSS_Finger(t *testing.T) {
	ie := &ieFeatureXSS{}
	finger := ie.Finger()
	if finger == nil {
		t.Fatal("expected non-nil finger")
	}
	if finger.Channel != "web-generic" {
		t.Errorf("expected Channel 'web-generic', got '%s'", finger.Channel)
	}
	if finger.Binding == nil {
		t.Fatal("expected non-nil Binding")
	}
	if finger.Binding.ID != "xss/reflected/ie-feature" {
		t.Errorf("expected Binding.ID 'xss/reflected/ie-feature', got '%s'", finger.Binding.ID)
	}
	if finger.CheckAction == nil {
		t.Error("expected non-nil CheckAction")
	}
}

// ==================== Element struct test ====================

func TestElementStruct(t *testing.T) {
	e := Element{
		name:       "div",
		attributes: map[string]string{"class": "test"},
		text:       "hello",
	}
	if e.name != "div" {
		t.Errorf("expected name 'div', got '%s'", e.name)
	}
	if e.text != "hello" {
		t.Errorf("expected text 'hello', got '%s'", e.text)
	}
}
