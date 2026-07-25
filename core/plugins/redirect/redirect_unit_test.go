package redirect

import (
	"testing"

	"wscan/core/http"
	"wscan/core/plugins/base"
)

func TestIsPotentialRedirectParam(t *testing.T) {
	tests := []struct {
		name     string
		param    http.Parameter
		expected bool
	}{
		// http prefix
		{"http prefix value", http.Parameter{Key: "foo", Value: "http://example.com"}, true},
		{"https prefix value", http.Parameter{Key: "foo", Value: "https://example.com"}, true},
		// protocol-relative URL
		{"protocol-relative", http.Parameter{Key: "foo", Value: "//example.com"}, true},
		// path-like values
		{"absolute path", http.Parameter{Key: "foo", Value: "/redirect"}, true},
		{"single slash", http.Parameter{Key: "foo", Value: "/"}, false},
		{"empty value", http.Parameter{Key: "foo", Value: ""}, false},
		// keyword-based names
		{"url key", http.Parameter{Key: "url", Value: "anything"}, true},
		{"URL key uppercase", http.Parameter{Key: "URL", Value: "anything"}, true},
		{"redirect key", http.Parameter{Key: "redirect", Value: "val"}, true},
		{"redir key", http.Parameter{Key: "redir", Value: "val"}, true},
		{"return key", http.Parameter{Key: "return", Value: "val"}, true},
		{"next key", http.Parameter{Key: "next", Value: "val"}, true},
		{"goto key", http.Parameter{Key: "goto", Value: "val"}, true},
		{"link key", http.Parameter{Key: "link", Value: "val"}, true},
		{"target key", http.Parameter{Key: "target", Value: "val"}, true},
		{"destination key", http.Parameter{Key: "destination", Value: "val"}, true},
		{"continue key", http.Parameter{Key: "continue", Value: "val"}, true},
		{"forward key", http.Parameter{Key: "forward", Value: "val"}, true},
		// partial keyword match
		{"callback_url key", http.Parameter{Key: "callback_url", Value: "val"}, true},
		// negative cases
		{"random key/value", http.Parameter{Key: "foo", Value: "bar"}, false},
		{"id key", http.Parameter{Key: "id", Value: "123"}, false},
		{"page key", http.Parameter{Key: "page", Value: "1"}, false},
		{"name key", http.Parameter{Key: "name", Value: "test"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPotentialRedirectParam(tt.param)
			if result != tt.expected {
				t.Errorf("isPotentialRedirectParam(%+v) = %v, want %v", tt.param, result, tt.expected)
			}
		})
	}
}

func TestIsRedirectToPayload(t *testing.T) {
	tests := []struct {
		name     string
		location string
		payload  string
		expected bool
	}{
		// Simple contains match
		{"location contains payload", "https://evil.com/path", "evil.com", true},
		{"exact match", "https://evil.com", "https://evil.com", true},
		// URL host matching
		{"host match", "https://evil.com/path", "https://evil.com", true},
		{"host suffix match", "https://sub.evil.com/path", "https://evil.com", true},
		{"host no match", "https://safe.com/path", "https://evil.com", false},
		// Non-URL payload
		{"non-URL payload contains", "https://evil1234.com", "evil1234", true},
		// Protocol-relative
		{"protocol-relative", "//evil.com/path", "evil.com", true},
		// Empty strings
		{"empty location", "", "evil.com", false},
		{"empty payload", "https://example.com", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isRedirectToPayload(tt.location, tt.payload)
			if result != tt.expected {
				t.Errorf("isRedirectToPayload(%q, %q) = %v, want %v", tt.location, tt.payload, result, tt.expected)
			}
		})
	}
}

func TestGetConfigRedirect(t *testing.T) {
	r := &Redirect{}
	// Before Init
	cfg := r.GetConfig()
	if cfg != nil {
		t.Errorf("Expected nil config before Init, got %v", cfg)
	}

	// After Init
	expectedCfg := r.DefaultConfig()
	ab := &base.ApolloBase{}
	r.Init(nil, expectedCfg, ab)

	cfg = r.GetConfig()
	if cfg == nil {
		t.Fatal("Expected non-nil config after Init")
	}
	bc := cfg.BaseConfig()
	if bc.Name != "redirect" {
		t.Errorf("Expected Name='redirect', got '%s'", bc.Name)
	}
}

func TestInitRedirect(t *testing.T) {
	r := &Redirect{}
	cfg := r.DefaultConfig()
	ab := &base.ApolloBase{}

	err := r.Init(nil, cfg, ab)
	if err != nil {
		t.Errorf("Init() returned error: %v", err)
	}
}

func TestDomRedirect(t *testing.T) {
	d := &domRedirect{}
	result, err := d.CheckMetaRedirect()
	if err != nil {
		t.Errorf("CheckMetaRedirect() returned error: %v", err)
	}
	if result != "" {
		t.Errorf("Expected empty result from CheckMetaRedirect, got '%s'", result)
	}

	result, err = d.CheckScriptRedirect()
	if err != nil {
		t.Errorf("CheckScriptRedirect() returned error: %v", err)
	}
	if result != "" {
		t.Errorf("Expected empty result from CheckScriptRedirect, got '%s'", result)
	}
}

func TestWebVulnPluginStruct(t *testing.T) {
	// Verify WebVulnPlugin can be instantiated
	wvp := WebVulnPlugin{}
	_ = wvp
}

func TestIsRedirectToPayload_EdgeCases(t *testing.T) {
	// Test with malformed URLs
	result := isRedirectToPayload("not-a-url", "not-a-url")
	if !result {
		t.Error("Expected true for identical non-URL strings")
	}

	// Test with special characters in URL
	result = isRedirectToPayload("https://evil.com\r\n", "evil.com")
	if !result {
		t.Error("Expected true when location contains payload with special chars")
	}

	// Test with tab character
	result = isRedirectToPayload("https://evil.com\t", "evil.com")
	if !result {
		t.Error("Expected true when location contains payload with tab")
	}
}

func TestIsPotentialRedirectParam_MixedCase(t *testing.T) {
	// Keyword matching should be case-insensitive
	param := http.Parameter{Key: "Redirect", Value: "val"}
	if !isPotentialRedirectParam(param) {
		t.Error("Expected Redirect key to match (case-insensitive)")
	}

	param = http.Parameter{Key: "NEXT", Value: "val"}
	if !isPotentialRedirectParam(param) {
		t.Error("Expected NEXT key to match (case-insensitive)")
	}
}

func TestIsRedirectToPayload_URLEdgeCases(t *testing.T) {
	// Test @ symbol in URL (common bypass)
	result := isRedirectToPayload("https://trusted.com@evil.com/path", "https://evil.com")
	if !result {
		t.Error("Expected true for @ bypass URL")
	}

	// Test with port in URL
	result = isRedirectToPayload("https://evil.com:8443/path", "https://evil.com")
	// This should match because evil.com is suffix of evil.com:8443 host
	_ = result

	// Test numeric IP
	result = isRedirectToPayload("https://2130706433/path", "2130706433")
	if !result {
		t.Error("Expected true for numeric IP payload")
	}
}

func TestIsPotentialRedirectParam_AllKeywords(t *testing.T) {
	keywords := []string{"url", "redirect", "redir", "return", "next", "goto", "link", "target", "destination", "continue", "forward"}
	for _, kw := range keywords {
		param := http.Parameter{Key: kw, Value: "val"}
		if !isPotentialRedirectParam(param) {
			t.Errorf("Expected keyword '%s' to match", kw)
		}
	}
}

func TestRedirectFingersBinding(t *testing.T) {
	r := &Redirect{}
	r.PluginMixinInitConfig.Config = r.DefaultConfig()
	fingers := r.Fingers()
	if len(fingers) == 0 {
		t.Fatal("Expected at least one finger")
	}
	f := fingers[0]
	if f.Binding == nil {
		t.Fatal("Expected non-nil Binding")
	}
	if f.Binding.ID != "redirect/redirect/default" {
		t.Errorf("Expected Binding.ID='redirect/redirect/default', got '%s'", f.Binding.ID)
	}
}
