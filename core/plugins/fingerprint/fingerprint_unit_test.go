package fingerprint

import (
	"testing"

	"wscan/core/plugins/base"
)

func TestDefaultConfig(t *testing.T) {
	p := &Fingerprint{}
	cfg := p.DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig() returned nil")
	}

	bc := cfg.BaseConfig()
	if bc == nil {
		t.Fatal("BaseConfig() returned nil")
	}
	if bc.Name != "fingerprint" {
		t.Errorf("Expected Name='fingerprint', got '%s'", bc.Name)
	}
	if !bc.Enabled {
		t.Error("Expected Enabled=true")
	}
	if !bc.IsAdvanced {
		t.Error("Expected IsAdvanced=true")
	}
}

func TestClose(t *testing.T) {
	p := &Fingerprint{}
	if err := p.Close(); err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
}

func TestFingers(t *testing.T) {
	p := &Fingerprint{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()
	fingers := p.Fingers()
	if len(fingers) == 0 {
		t.Error("Expected at least one finger")
	}

	for _, f := range fingers {
		if f.CheckAction == nil {
			t.Error("CheckAction should not be nil")
		}
		if f.Binding == nil {
			t.Error("Binding should not be nil")
		}
		if f.Channel != "web-generic" {
			t.Errorf("Expected Channel='web-generic', got '%s'", f.Channel)
		}
	}
}

func TestConfigBaseConfig(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:       "fingerprint",
			Enabled:    true,
			IsAdvanced: true,
		},
	}
	bc := cfg.BaseConfig()
	if bc.Name != "fingerprint" {
		t.Errorf("Expected Name='fingerprint', got '%s'", bc.Name)
	}
	if !bc.Enabled {
		t.Error("Expected Enabled=true")
	}
	if !bc.IsAdvanced {
		t.Error("Expected IsAdvanced=true")
	}
}

func TestGetConfig(t *testing.T) {
	p := &Fingerprint{}
	// Before Init
	cfg := p.GetConfig()
	if cfg != nil {
		t.Errorf("Expected nil config before Init, got %v", cfg)
	}

	// After Init
	expectedCfg := p.DefaultConfig()
	ab := &base.ApolloBase{}
	p.Init(nil, expectedCfg, ab)

	cfg = p.GetConfig()
	if cfg == nil {
		t.Fatal("Expected non-nil config after Init")
	}
	bc := cfg.BaseConfig()
	if bc.Name != "fingerprint" {
		t.Errorf("Expected Name='fingerprint', got '%s'", bc.Name)
	}
}

func TestFingerprintInfoYAML(t *testing.T) {
	info := FingerprintInfo{
		Name:   "WordPress",
		Author: "testauthor",
	}
	if info.Name != "WordPress" {
		t.Errorf("Expected Name='WordPress', got '%s'", info.Name)
	}
	if info.Author != "testauthor" {
		t.Errorf("Expected Author='testauthor', got '%s'", info.Author)
	}
}

func TestFingerprintRuleYAML(t *testing.T) {
	rule := FingerprintRule{
		Engine: "fingerprint",
		Info: FingerprintInfo{
			Name:   "Nginx",
			Author: "author1",
		},
		Pscan: FingerprintPscan{
			Path:        []string{"/", "/admin"},
			Expressions: []string{"response.status == 200"},
		},
	}
	if rule.Engine != "fingerprint" {
		t.Errorf("Expected Engine='fingerprint', got '%s'", rule.Engine)
	}
	if rule.Info.Name != "Nginx" {
		t.Errorf("Expected Info.Name='Nginx', got '%s'", rule.Info.Name)
	}
	if len(rule.Pscan.Path) != 2 {
		t.Errorf("Expected 2 paths, got %d", len(rule.Pscan.Path))
	}
	if len(rule.Pscan.Expressions) != 1 {
		t.Errorf("Expected 1 expression, got %d", len(rule.Pscan.Expressions))
	}
}

func TestFingerprintPscanFields(t *testing.T) {
	pscan := FingerprintPscan{
		Path:        []string{"/login"},
		Expressions: []string{"response.body.bcontains(b\"admin\")"},
	}
	if len(pscan.Path) != 1 || pscan.Path[0] != "/login" {
		t.Errorf("Path field incorrect: %v", pscan.Path)
	}
	if len(pscan.Expressions) != 1 || pscan.Expressions[0] != "response.body.bcontains(b\"admin\")" {
		t.Errorf("Expressions field incorrect: %v", pscan.Expressions)
	}
}

func TestLoadFingerprintRule(t *testing.T) {
	rule, err := LoadFingerprintRule("")
	// LoadFingerprintRule currently returns nil, nil
	if rule != nil {
		t.Errorf("Expected nil rule, got %v", rule)
	}
	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}
}

func TestFingerprintRulesLoaded(t *testing.T) {
	// The init() function should have loaded rules from embedded FS
	if len(fingerprintRules) == 0 {
		t.Error("Expected fingerprintRules to be loaded by init(), got empty list")
	}
	// Check that loaded rules have valid structure
	for i, rule := range fingerprintRules {
		if rule.Info.Name == "" {
			t.Errorf("Rule[%d] has empty Info.Name", i)
		}
		if rule.Engine == "" {
			t.Errorf("Rule[%d] has empty Engine", i)
		}
	}
}

func TestProcessFingerprint(t *testing.T) {
	// ProcessFingerprint currently does nothing, just verify it doesn't crash
	ProcessFingerprint(nil, nil)
}

func TestInit(t *testing.T) {
	p := &Fingerprint{}
	cfg := p.DefaultConfig()
	ab := &base.ApolloBase{}

	err := p.Init(nil, cfg, ab)
	if err != nil {
		t.Errorf("Init() returned error: %v", err)
	}
}
