package thinkphp

import (
	"context"
	"testing"

	"wscan/core/plugins/base"
)

func TestDefaultConfig(t *testing.T) {
	p := &Thinkphp{}
	cfg := p.DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig() returned nil")
	}

	bc := cfg.BaseConfig()
	if bc == nil {
		t.Fatal("BaseConfig() returned nil")
	}
	if bc.Name != "thinkphp" {
		t.Errorf("Expected Name='thinkphp', got '%s'", bc.Name)
	}
	if !bc.Enabled {
		t.Error("Expected Enabled=true")
	}

	// Type assertion to check Config-specific fields
	thinkCfg, ok := cfg.(*Config)
	if !ok {
		t.Fatal("DefaultConfig() did not return *Config")
	}
	// By default, DetectThinkPHPSQLInjection should be false
	if thinkCfg.DetectThinkPHPSQLInjection {
		t.Error("Expected DetectThinkPHPSQLInjection=false by default")
	}
}

func TestClose(t *testing.T) {
	p := &Thinkphp{}
	if err := p.Close(); err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
}

func TestFingers_WithoutSQLi(t *testing.T) {
	p := &Thinkphp{}
	// Without Init, GetConfig returns nil, so the sqli detection branch is skipped
	fingers := p.Fingers()

	// Should have 4 fingers: InvokeRce, MethodRce, PregRce, V6FileWrite
	if len(fingers) != 4 {
		t.Errorf("Expected 4 fingers without sqli config, got %d", len(fingers))
	}

	// Verify the channels and bindings
	expectedIDs := []string{
		"thinkphp/rce/invoke",
		"thinkphp/rce/method",
		"thinkphp/rce/preg",
		"thinkphp/v6-file-write/default",
	}
	for i, id := range expectedIDs {
		if fingers[i].Binding.ID != id {
			t.Errorf("Finger[%d].Binding.ID: expected '%s', got '%s'", i, id, fingers[i].Binding.ID)
		}
	}
}

func TestFingers_WithSQLi(t *testing.T) {
	p := &Thinkphp{}
	// Initialize with config that has DetectThinkPHPSQLInjection enabled
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "thinkphp",
			Enabled: true,
		},
		DetectThinkPHPSQLInjection: true,
	}
	ab := &base.ApolloBase{}
	p.Init(context.Background(), cfg, ab)

	fingers := p.Fingers()

	// Should have 5 fingers: InvokeRce, MethodRce, PregRce, Sqli, V6FileWrite
	if len(fingers) != 5 {
		t.Errorf("Expected 5 fingers with sqli config, got %d", len(fingers))
	}

	sqliFound := false
	for _, f := range fingers {
		if f.Binding.ID == "thinkphp/sqli/default" {
			sqliFound = true
		}
	}
	if !sqliFound {
		t.Error("Expected sqli finger when DetectThinkPHPSQLInjection is true")
	}
}

func TestFingers_WithSQLiDisabled(t *testing.T) {
	p := &Thinkphp{}
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "thinkphp",
			Enabled: true,
		},
		DetectThinkPHPSQLInjection: false,
	}
	ab := &base.ApolloBase{}
	p.Init(context.Background(), cfg, ab)

	fingers := p.Fingers()
	// Should have 4 fingers (no sqli)
	if len(fingers) != 4 {
		t.Errorf("Expected 4 fingers with sqli disabled, got %d", len(fingers))
	}
}

func TestGetConfig(t *testing.T) {
	p := &Thinkphp{}
	// Before Init, config is nil
	cfg := p.GetConfig()
	if cfg != nil {
		t.Errorf("Expected nil config before Init, got %v", cfg)
	}

	// After Init
	expectedCfg := p.DefaultConfig()
	ab := &base.ApolloBase{}
	p.Init(context.Background(), expectedCfg, ab)

	cfg = p.GetConfig()
	if cfg == nil {
		t.Fatal("Expected non-nil config after Init")
	}
	bc := cfg.BaseConfig()
	if bc.Name != "thinkphp" {
		t.Errorf("Expected Name='thinkphp', got '%s'", bc.Name)
	}
}

func TestInit(t *testing.T) {
	p := &Thinkphp{}
	cfg := p.DefaultConfig()
	ab := &base.ApolloBase{}

	err := p.Init(context.Background(), cfg, ab)
	if err != nil {
		t.Errorf("Init() returned error: %v", err)
	}
}

func TestInvokeRceFinger(t *testing.T) {
	r := &InvokeRce{}
	f := r.Finger()
	if f == nil {
		t.Fatal("InvokeRce.Finger() returned nil")
	}
	if f.Channel != "website" {
		t.Errorf("Expected Channel='website', got '%s'", f.Channel)
	}
	if f.Binding.ID != "thinkphp/rce/invoke" {
		t.Errorf("Expected Binding.ID='thinkphp/rce/invoke', got '%s'", f.Binding.ID)
	}
	if f.CheckAction == nil {
		t.Error("CheckAction should not be nil")
	}
}

func TestMethodRceFinger(t *testing.T) {
	r := &MethodRce{}
	f := r.Finger()
	if f == nil {
		t.Fatal("MethodRce.Finger() returned nil")
	}
	if f.Channel != "website" {
		t.Errorf("Expected Channel='website', got '%s'", f.Channel)
	}
	if f.Binding.ID != "thinkphp/rce/method" {
		t.Errorf("Expected Binding.ID='thinkphp/rce/method', got '%s'", f.Binding.ID)
	}
	if f.CheckAction == nil {
		t.Error("CheckAction should not be nil")
	}
}

func TestPregRceFinger(t *testing.T) {
	r := &PregRce{}
	f := r.Finger()
	if f == nil {
		t.Fatal("PregRce.Finger() returned nil")
	}
	if f.Channel != "website" {
		t.Errorf("Expected Channel='website', got '%s'", f.Channel)
	}
	if f.Binding.ID != "thinkphp/rce/preg" {
		t.Errorf("Expected Binding.ID='thinkphp/rce/preg', got '%s'", f.Binding.ID)
	}
	if f.CheckAction == nil {
		t.Error("CheckAction should not be nil")
	}
}

func TestSqliFinger(t *testing.T) {
	s := &Sqli{}
	f := s.Finger()
	if f == nil {
		t.Fatal("Sqli.Finger() returned nil")
	}
	if f.Channel != "web-generic" {
		t.Errorf("Expected Channel='web-generic', got '%s'", f.Channel)
	}
	if f.Binding.ID != "thinkphp/sqli/default" {
		t.Errorf("Expected Binding.ID='thinkphp/sqli/default', got '%s'", f.Binding.ID)
	}
	if f.CheckAction == nil {
		t.Error("CheckAction should not be nil")
	}
}

func TestV6FileWriteFinger(t *testing.T) {
	v := &V6FileWrite{}
	f := v.Finger()
	if f == nil {
		t.Fatal("V6FileWrite.Finger() returned nil")
	}
	if f.Channel != "website" {
		t.Errorf("Expected Channel='website', got '%s'", f.Channel)
	}
	if f.Binding.ID != "thinkphp/v6-file-write/default" {
		t.Errorf("Expected Binding.ID='thinkphp/v6-file-write/default', got '%s'", f.Binding.ID)
	}
	if f.CheckAction == nil {
		t.Error("CheckAction should not be nil")
	}
}

func TestConfigBaseConfig(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "thinkphp",
			Enabled: true,
		},
		DetectThinkPHPSQLInjection: true,
	}
	bc := cfg.BaseConfig()
	if bc.Name != "thinkphp" {
		t.Errorf("Expected Name='thinkphp', got '%s'", bc.Name)
	}
	if !bc.Enabled {
		t.Error("Expected Enabled=true")
	}
}
