package prometheus

import (
	"context"
	"testing"

	"wscan/core/plugins/base"
)

// ==================== Prometheus struct tests ====================

func TestPrometheus_Close(t *testing.T) {
	p := &Prometheus{}
	if err := p.Close(); err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
}

func TestPrometheus_DefaultConfig_Values(t *testing.T) {
	p := &Prometheus{}
	cfg := p.DefaultConfig().(*Config)
	if cfg.PluginBaseConfig.Name != "prometheus" {
		t.Errorf("Expected Name='prometheus', got '%s'", cfg.PluginBaseConfig.Name)
	}
	if !cfg.PluginBaseConfig.Enabled {
		t.Error("Expected Enabled=true")
	}
	if cfg.Depth != 1 {
		t.Errorf("Expected Depth=1, got %d", cfg.Depth)
	}
}

func TestPrometheus_GetConfig_BeforeInit(t *testing.T) {
	p := &Prometheus{}
	cfg := p.GetConfig()
	if cfg != nil {
		t.Errorf("Expected nil config before Init, got %v", cfg)
	}
}

func TestPrometheus_GetConfig_AfterInit(t *testing.T) {
	p := &Prometheus{}
	cfg := p.DefaultConfig()
	ab := &base.ApolloBase{}
	p.Init(context.Background(), cfg, ab)

	gotCfg := p.GetConfig()
	if gotCfg == nil {
		t.Fatal("Expected non-nil config after Init")
	}
	bc := gotCfg.BaseConfig()
	if bc.Name != "prometheus" {
		t.Errorf("Expected Name='prometheus', got '%s'", bc.Name)
	}
}

func TestPrometheus_Fingers(t *testing.T) {
	p := &Prometheus{}
	cfg := p.DefaultConfig()
	ab := &base.ApolloBase{}
	p.Init(context.Background(), cfg, ab)
	fingers := p.Fingers()
	// Just verify it doesn't panic
	_ = fingers
}

func TestPrometheus_Fingers_NoPOC(t *testing.T) {
	p := &Prometheus{}
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{Name: "prometheus", Enabled: true},
		Depth:            1,
		POC:              []string{},
		IncludePOC:       []string{},
		ExcludePOC:       []string{},
	}
	ab := &base.ApolloBase{}
	p.Init(context.Background(), cfg, ab)
	fingers := p.Fingers()
	_ = fingers
}

func TestPrometheus_Init(t *testing.T) {
	p := &Prometheus{}
	cfg := p.DefaultConfig()
	ab := &base.ApolloBase{}
	err := p.Init(context.Background(), cfg, ab)
	if err != nil {
		t.Errorf("Init() returned error: %v", err)
	}
}

// ==================== Config tests ====================

func TestConfig_BaseConfig(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{Name: "prometheus", Enabled: true},
		Depth:            2,
	}
	bc := cfg.BaseConfig()
	if bc.Name != "prometheus" {
		t.Errorf("Expected Name='prometheus', got '%s'", bc.Name)
	}
}

func TestConfig_Fields(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{Name: "prometheus", Enabled: true},
		Depth:            3,
		POC:              []string{"poc1", "poc2"},
		Exclusive:        false,
		AutoLoadPOC:      true,
		IncludePOC:       []string{"*weblogic*"},
		ExcludePOC:       []string{"*thinkphp*"},
	}
	if cfg.Depth != 3 {
		t.Errorf("Expected Depth=3, got %d", cfg.Depth)
	}
	if len(cfg.POC) != 2 {
		t.Errorf("Expected 2 POCs, got %d", len(cfg.POC))
	}
	if cfg.Exclusive {
		t.Error("Expected Exclusive=false")
	}
	if !cfg.AutoLoadPOC {
		t.Error("Expected AutoLoadPOC=true")
	}
}

// ==================== DepthCheck test ====================

func TestPrometheus_DepthCheck_StructSetup(t *testing.T) {
	p := &Prometheus{}
	p.PluginMixinInitConfig.Config = &Config{
		PluginBaseConfig: base.PluginBaseConfig{Name: "prometheus", Enabled: true},
		Depth:            0,
	}
	// Verify config is set properly
	cfg := p.GetConfig().(*Config)
	if cfg.Depth != 0 {
		t.Errorf("Expected Depth=0, got %d", cfg.Depth)
	}
}
