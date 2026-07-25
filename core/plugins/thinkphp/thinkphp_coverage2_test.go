package thinkphp

import (
	"context"
	"testing"

	"wscan/core/model"
	"wscan/core/plugins/base"
)

// ==================== Thinkphp struct tests ====================

func TestThinkphp_Close(t *testing.T) {
	p := &Thinkphp{}
	if err := p.Close(); err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
}

func TestThinkphp_DefaultConfig_Values(t *testing.T) {
	p := &Thinkphp{}
	cfg := p.DefaultConfig().(*Config)
	if cfg.PluginBaseConfig.Name != "thinkphp" {
		t.Errorf("Expected Name='thinkphp', got '%s'", cfg.PluginBaseConfig.Name)
	}
	if !cfg.PluginBaseConfig.Enabled {
		t.Error("Expected Enabled=true")
	}
	if cfg.DetectThinkPHPSQLInjection {
		t.Error("Expected DetectThinkPHPSQLInjection=false by default")
	}
}

func TestThinkphp_GetConfig_BeforeInit(t *testing.T) {
	p := &Thinkphp{}
	cfg := p.GetConfig()
	if cfg != nil {
		t.Errorf("Expected nil config before Init, got %v", cfg)
	}
}

func TestThinkphp_GetConfig_AfterInit(t *testing.T) {
	p := &Thinkphp{}
	cfg := p.DefaultConfig()
	ab := &base.ApolloBase{}
	p.Init(context.Background(), cfg, ab)

	gotCfg := p.GetConfig()
	if gotCfg == nil {
		t.Fatal("Expected non-nil config after Init")
	}
	bc := gotCfg.BaseConfig()
	if bc.Name != "thinkphp" {
		t.Errorf("Expected Name='thinkphp', got '%s'", bc.Name)
	}
}

func TestThinkphp_Init(t *testing.T) {
	p := &Thinkphp{}
	cfg := p.DefaultConfig()
	ab := &base.ApolloBase{}
	err := p.Init(context.Background(), cfg, ab)
	if err != nil {
		t.Errorf("Init() returned error: %v", err)
	}
}

func TestThinkphp_execAction(t *testing.T) {
	p := &Thinkphp{}
	err := p.execAction(context.Background(), nil)
	if err != nil {
		t.Errorf("execAction() returned error: %v", err)
	}
}

func TestConfig_BaseConfig(t *testing.T) {
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

// ==================== Finger detail tests ====================

func TestInvokeRce_Finger_Details(t *testing.T) {
	r := &InvokeRce{}
	f := r.Finger()
	if f.Channel != "website" {
		t.Errorf("Expected Channel='website', got '%s'", f.Channel)
	}
	if f.Binding.ID != "thinkphp/rce/invoke" {
		t.Errorf("Expected Binding.ID='thinkphp/rce/invoke', got '%s'", f.Binding.ID)
	}
	if f.Binding.Severity != model.SeverityCritical {
		t.Errorf("Expected SeverityCritical, got %v", f.Binding.Severity)
	}
	if f.CheckAction == nil {
		t.Error("Expected non-nil CheckAction")
	}
}

func TestMethodRce_Finger_Details(t *testing.T) {
	r := &MethodRce{}
	f := r.Finger()
	if f.Channel != "website" {
		t.Errorf("Expected Channel='website', got '%s'", f.Channel)
	}
	if f.Binding.ID != "thinkphp/rce/method" {
		t.Errorf("Expected Binding.ID='thinkphp/rce/method', got '%s'", f.Binding.ID)
	}
	if f.Binding.Severity != model.SeverityCritical {
		t.Errorf("Expected SeverityCritical, got %v", f.Binding.Severity)
	}
}

func TestPregRce_Finger_Details(t *testing.T) {
	r := &PregRce{}
	f := r.Finger()
	if f.Channel != "website" {
		t.Errorf("Expected Channel='website', got '%s'", f.Channel)
	}
	if f.Binding.ID != "thinkphp/rce/preg" {
		t.Errorf("Expected Binding.ID='thinkphp/rce/preg', got '%s'", f.Binding.ID)
	}
	if f.Binding.Severity != model.SeverityCritical {
		t.Errorf("Expected SeverityCritical, got %v", f.Binding.Severity)
	}
}

func TestSqli_Finger_Details(t *testing.T) {
	s := &Sqli{}
	f := s.Finger()
	if f.Channel != "web-generic" {
		t.Errorf("Expected Channel='web-generic', got '%s'", f.Channel)
	}
	if f.Binding.ID != "thinkphp/sqli/default" {
		t.Errorf("Expected Binding.ID='thinkphp/sqli/default', got '%s'", f.Binding.ID)
	}
	if f.Binding.Severity != model.SeverityHigh {
		t.Errorf("Expected SeverityHigh, got %v", f.Binding.Severity)
	}
}

func TestV6FileWrite_Finger_Details(t *testing.T) {
	v := &V6FileWrite{}
	f := v.Finger()
	if f.Channel != "website" {
		t.Errorf("Expected Channel='website', got '%s'", f.Channel)
	}
	if f.Binding.ID != "thinkphp/v6-file-write/default" {
		t.Errorf("Expected Binding.ID='thinkphp/v6-file-write/default', got '%s'", f.Binding.ID)
	}
	if f.Binding.Severity != model.SeverityHigh {
		t.Errorf("Expected SeverityHigh, got %v", f.Binding.Severity)
	}
}

// ==================== Sqli payload tests ====================

func TestSqliPayloads_Count(t *testing.T) {
	if len(sqliPayloads) != 3 {
		t.Errorf("Expected 3 sqli payloads, got %d", len(sqliPayloads))
	}
}

func TestSqliPayloads_Paths(t *testing.T) {
	for i, p := range sqliPayloads {
		if p.Path == "" {
			t.Errorf("sqliPayloads[%d].Path should not be empty", i)
		}
		if p.ParamKey == "" {
			t.Errorf("sqliPayloads[%d].ParamKey should not be empty", i)
		}
		if p.Payload == "" {
			t.Errorf("sqliPayloads[%d].Payload should not be empty", i)
		}
		if p.Check == nil {
			t.Errorf("sqliPayloads[%d].Check should not be nil", i)
		}
	}
}

// ==================== Utility function tests ====================

func TestExtractValueFromURL_Multiple(t *testing.T) {
	tests := []struct {
		input  string
		result string
		hasErr bool
	}{
		{"10*20", "200", false},
		{"100*5", "500", false},
		{"no match", "", true},
		{"", "", true},
	}
	for _, tt := range tests {
		result, err := extractValueFromURL(tt.input)
		if tt.hasErr && err == nil {
			t.Errorf("extractValueFromURL(%q): expected error, got nil", tt.input)
		}
		if !tt.hasErr && result != tt.result {
			t.Errorf("extractValueFromURL(%q) = %q, want %q", tt.input, result, tt.result)
		}
	}
}

func TestIsRandomPhp_Multiple(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"/123.php", true},
		{"/1.php", true},
		{"/0.php", true},
		{"/abc.php", false},
		{"/123.txt", false},
		{"/123.php4", false},
		{"/123.php?query=1", false},
		{"123.php", false},
	}
	for _, tt := range tests {
		got := isRandomPhp(tt.input)
		if got != tt.want {
			t.Errorf("isRandomPhp(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

// ==================== Thinkphp Fingers comprehensive tests ====================

func TestThinkphp_Fingers_WithSQLiConfig(t *testing.T) {
	p := &Thinkphp{}
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
	if len(fingers) != 5 {
		t.Errorf("Expected 5 fingers with sqli enabled, got %d", len(fingers))
	}

	// Verify each finger has proper binding
	expectedIDs := map[string]bool{
		"thinkphp/rce/invoke":            false,
		"thinkphp/rce/method":            false,
		"thinkphp/rce/preg":              false,
		"thinkphp/sqli/default":          false,
		"thinkphp/v6-file-write/default": false,
	}
	for _, f := range fingers {
		if _, ok := expectedIDs[f.Binding.ID]; ok {
			expectedIDs[f.Binding.ID] = true
		}
		if f.CheckAction == nil {
			t.Errorf("Finger %s should have CheckAction", f.Binding.ID)
		}
	}
	for id, found := range expectedIDs {
		if !found {
			t.Errorf("Expected finger with ID=%s not found", id)
		}
	}
}

func TestThinkphp_Fingers_WithNilConfig(t *testing.T) {
	p := &Thinkphp{}
	// Don't Init, so GetConfig returns nil
	fingers := p.Fingers()
	if len(fingers) != 4 {
		t.Errorf("Expected 4 fingers without sqli (nil config), got %d", len(fingers))
	}
}
