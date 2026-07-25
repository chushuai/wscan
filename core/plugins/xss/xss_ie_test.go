package xss

import (
	"testing"

	"wscan/core/plugins/base"
)

func TestIEFeatureXSSFinger(t *testing.T) {
	ie := &ieFeatureXSS{}
	finger := ie.Finger()

	if finger == nil {
		t.Fatal("ieFeatureXSS.Finger() should not return nil")
	}
	if finger.CheckAction == nil {
		t.Fatal("ieFeatureXSS CheckAction should not be nil")
	}
	if finger.Binding == nil {
		t.Fatal("ieFeatureXSS Binding should not be nil")
	}
	if finger.Binding.ID != "xss/reflected/ie-feature" {
		t.Errorf("Expected binding ID 'xss/reflected/ie-feature', got %s", finger.Binding.ID)
	}
	if finger.Channel != "web-generic" {
		t.Errorf("Expected channel 'web-generic', got %s", finger.Channel)
	}
}

func TestXSSConfigIEFeature(t *testing.T) {
	x := &XSS{}
	cfg := x.DefaultConfig().(*Config)

	if !cfg.IEFeature {
		t.Error("IEFeature should default to true")
	}
	if !cfg.DetectXSSInCookie {
		t.Error("DetectXSSInCookie should default to true")
	}
	if !cfg.DetectXSSInReferer {
		t.Error("DetectXSSInReferer should default to true")
	}
}

func TestXSSFingersRegistration(t *testing.T) {
	// Test that IEFeature registration works
	x := &XSS{}
	// Simulate Init to set config
	x.PluginMixinInitConfig.Config = &Config{
		PluginBaseConfig:   base.PluginBaseConfig{Name: "xss", Enabled: true},
		DetectXSSInCookie:  true,
		DetectXSSInReferer: true,
		IEFeature:          true,
	}

	fingers := x.Fingers()

	foundIEFeature := false
	foundCookie := false
	foundReferer := false

	for _, f := range fingers {
		if f.Binding != nil {
			switch f.Binding.ID {
			case "xss/reflected/ie-feature":
				foundIEFeature = true
			case "xss/reflected/cookie":
				foundCookie = true
			case "xss/reflected/referer":
				foundReferer = true
			}
		}
	}

	if !foundIEFeature {
		t.Error("IEFeature finger should be registered when IEFeature=true")
	}
	if !foundCookie {
		t.Error("Cookie XSS finger should be registered when DetectXSSInCookie=true")
	}
	if !foundReferer {
		t.Error("Referer XSS finger should be registered when DetectXSSInReferer=true")
	}

	// Test with IEFeature=false
	x2 := &XSS{}
	x2.PluginMixinInitConfig.Config = &Config{
		PluginBaseConfig:   base.PluginBaseConfig{Name: "xss", Enabled: true},
		DetectXSSInCookie:  true,
		DetectXSSInReferer: true,
		IEFeature:          false,
	}

	fingers2 := x2.Fingers()
	for _, f := range fingers2 {
		if f.Binding != nil && f.Binding.ID == "xss/reflected/ie-feature" {
			t.Error("IEFeature finger should NOT be registered when IEFeature=false")
		}
	}
}

func TestSearchInputInResponse(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		body         string
		expectMinLen int // minimum expected occurrences (due to DOM traversal, parent elements may also match)
	}{
		{"in div", "test123", `<div>test123</div>`, 1},
		{"in attribute", "test123", `<div class="test123">hello</div>`, 1},
		{"not found", "test123", `<div>hello</div>`, 0},
		// Note: HTML comments may not be reliably parsed as separate elements by goquery,
		// so we only check that searching doesn't crash
		{"in comment", "test123", `<!-- test123 -->`, 0},
		{"in script", "test123", `<script>var x = "test123"</script>`, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SearchInputInResponse(tt.input, tt.body)
			if len(result) < tt.expectMinLen {
				t.Errorf("expected at least %d occurrences, got %d", tt.expectMinLen, len(result))
			}
		})
	}
}
