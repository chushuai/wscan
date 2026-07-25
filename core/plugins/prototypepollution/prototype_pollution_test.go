package prototypepollution

import (
	"context"
	"testing"

	"wscan/core/plugins/base"
)

func TestPrototypePollution_Close(t *testing.T) {
	p := &PrototypePollution{}
	if err := p.Close(); err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
}

func TestPrototypePollution_DefaultConfig(t *testing.T) {
	p := &PrototypePollution{}
	cfg := p.DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig() returned nil")
	}

	typedCfg, ok := cfg.(*Config)
	if !ok {
		t.Fatal("DefaultConfig() did not return *Config")
	}
	if typedCfg.PluginBaseConfig.Name != "prototype-pollution" {
		t.Errorf("Expected Name='prototype-pollution', got '%s'", typedCfg.PluginBaseConfig.Name)
	}
	if !typedCfg.PluginBaseConfig.Enabled {
		t.Error("Expected Enabled=true")
	}
}

func TestConfig_BaseConfig(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "prototype-pollution",
			Enabled: true,
		},
	}
	bc := cfg.BaseConfig()
	if bc == nil {
		t.Fatal("BaseConfig() returned nil")
	}
	if bc.Name != "prototype-pollution" {
		t.Errorf("Expected Name='prototype-pollution', got '%s'", bc.Name)
	}
}

func TestPrototypePollution_GetConfig(t *testing.T) {
	p := &PrototypePollution{}
	// Before Init
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
}

func TestPrototypePollution_Fingers(t *testing.T) {
	p := &PrototypePollution{}
	cfg := p.DefaultConfig()
	ab := &base.ApolloBase{}
	p.Init(context.Background(), cfg, ab)

	fingers := p.Fingers()
	if len(fingers) != 1 {
		t.Errorf("Expected 1 finger, got %d", len(fingers))
	}
	if fingers[0].Binding.ID != "prototype_pollution" {
		t.Errorf("Expected Binding.ID='prototype_pollution', got '%s'", fingers[0].Binding.ID)
	}
	if fingers[0].Channel != "web-generic" {
		t.Errorf("Expected Channel='web-generic', got '%s'", fingers[0].Channel)
	}
	if fingers[0].Binding.Severity != "high" {
		t.Errorf("Expected Severity='high', got '%s'", fingers[0].Binding.Severity)
	}
	if fingers[0].CheckAction == nil {
		t.Error("CheckAction should not be nil")
	}
	if fingers[0].ExecAction == nil {
		t.Error("ExecAction should not be nil")
	}
}

func TestSearchProtoPollutionError_PlainMatch(t *testing.T) {
	// Test exact match for plain error messages
	text := "TypeError: Cannot set property '__proto__' of null"
	result := searchProtoPollutionError(text)
	if result != "TypeError: Cannot set property '__proto__' of null" {
		t.Errorf("Expected match for plain error message, got: %s", result)
	}

	// Test match when error is embedded in larger text
	text2 := "Some response text\nTypeError: Cannot set property '__proto__' of null\nmore text"
	result2 := searchProtoPollutionError(text2)
	if result2 != "TypeError: Cannot set property '__proto__' of null" {
		t.Errorf("Expected match for embedded plain error message, got: %s", result2)
	}
}

func TestSearchProtoPollutionError_RegexMatch(t *testing.T) {
	// Test regex match for immutable prototype error
	text := "TypeError: Immutable prototype object '#<Object>' cannot have their prototype set"
	result := searchProtoPollutionError(text)
	if result == "" {
		t.Errorf("Expected match for regex error message, got empty string")
	}

	// Test regex match with different object description
	text2 := "TypeError: Immutable prototype object '[object Object]' cannot have their prototype set"
	result2 := searchProtoPollutionError(text2)
	if result2 == "" {
		t.Errorf("Expected match for regex error message with different object description, got empty string")
	}
}

func TestSearchProtoPollutionError_NoMatch(t *testing.T) {
	// Test no match for unrelated text
	text := "Normal response body without any errors"
	result := searchProtoPollutionError(text)
	if result != "" {
		t.Errorf("Expected no match for normal text, got: %s", result)
	}

	// Test no match for similar but different error
	text2 := "TypeError: Cannot set property 'name' of null"
	result2 := searchProtoPollutionError(text2)
	if result2 != "" {
		t.Errorf("Expected no match for different property error, got: %s", result2)
	}
}

func TestSearchProtoPollutionError_EmptyText(t *testing.T) {
	result := searchProtoPollutionError("")
	if result != "" {
		t.Errorf("Expected no match for empty text, got: %s", result)
	}
}
