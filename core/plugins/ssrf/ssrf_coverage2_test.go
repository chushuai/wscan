package ssrf

import (
	"context"
	"testing"

	wscan_http "wscan/core/http"
	"wscan/core/plugins/base"
)

// ==================== SSRF comprehensive Init/Close ====================

func TestSSRF_Init_WithContext(t *testing.T) {
	p := &SSRF{}
	cfg := p.DefaultConfig()
	ab := &base.ApolloBase{}

	err := p.Init(context.Background(), cfg, ab)
	if err != nil {
		t.Errorf("Init() error: %v", err)
	}
}

func TestSSRF_Init_WithNilContext(t *testing.T) {
	p := &SSRF{}
	cfg := p.DefaultConfig()
	ab := &base.ApolloBase{}

	err := p.Init(nil, cfg, ab)
	if err != nil {
		t.Errorf("Init() with nil context error: %v", err)
	}
}

func TestSSRF_MultipleClose_Coverage(t *testing.T) {
	p := &SSRF{}
	for i := 0; i < 3; i++ {
		if err := p.Close(); err != nil {
			t.Errorf("Close() call %d error: %v", i, err)
		}
	}
}

// ==================== SSRF Fingers comprehensive ====================

func TestSSRF_Fingers_DefaultConfig(t *testing.T) {
	p := &SSRF{}
	cfg := p.DefaultConfig()
	ab := &base.ApolloBase{}
	p.Init(context.Background(), cfg, ab)

	fingers := p.Fingers()
	if len(fingers) != 1 {
		t.Errorf("Expected 1 finger with default config, got %d", len(fingers))
	}
	// The default config has DetectInternalService=false
	f := fingers[0]
	if f.Channel != "web-generic" {
		t.Errorf("Channel = %q, want 'web-generic'", f.Channel)
	}
	if f.Binding.ID != "ssrf/default" {
		t.Errorf("Binding.ID = %q, want 'ssrf/default'", f.Binding.ID)
	}
}

// ==================== Config comprehensive ====================

func TestConfig_DetectInternalServiceTrue(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig:      base.PluginBaseConfig{Name: "ssrf", Enabled: true},
		DetectInternalService: true,
	}
	if !cfg.DetectInternalService {
		t.Error("DetectInternalService should be true")
	}
	bc := cfg.BaseConfig()
	if bc.Name != "ssrf" {
		t.Errorf("Name = %q, want 'ssrf'", bc.Name)
	}
}

// ==================== extractHostPort additional coverage ====================

func TestExtractHostPort_SchemeOnlyHTTP(t *testing.T) {
	result := extractHostPort("http://")
	if result != "" {
		t.Errorf("Expected empty for 'http://', got '%s'", result)
	}
}

func TestExtractHostPort_SchemeOnlyHTTPS(t *testing.T) {
	result := extractHostPort("https://")
	if result != "" {
		t.Errorf("Expected empty for 'https://', got '%s'", result)
	}
}

// ==================== ipToDecimal edge cases ====================

func TestIPToDecimal_255s(t *testing.T) {
	result := ipToDecimal("255.255.255.255")
	if result != "4294967295" {
		t.Errorf("Expected '4294967295', got '%s'", result)
	}
}

func TestIPToDecimal_AllOnes(t *testing.T) {
	result := ipToDecimal("1.1.1.1")
	if result != "16843009" {
		t.Errorf("Expected '16843009', got '%s'", result)
	}
}

// ==================== ipToOctal edge cases ====================

func TestIPToOctal_255s(t *testing.T) {
	result := ipToOctal("255.255.255.255")
	if result != "0377.0377.0377.0377" {
		t.Errorf("Expected '0377.0377.0377.0377', got '%s'", result)
	}
}

// ==================== ipToHex edge cases ====================

func TestIPToHex_255s(t *testing.T) {
	result := ipToHex("255.255.255.255")
	if result != "0xffffffff" {
		t.Errorf("Expected '0xffffffff', got '%s'", result)
	}
}

// ==================== ipShortened edge cases ====================

func TestIPShortened_10(t *testing.T) {
	result := ipShortened("10.0.0.1")
	if result != "10.1" {
		t.Errorf("Expected '10.1', got '%s'", result)
	}
}

// ==================== ipToHexGroups edge cases ====================

func TestIPToHexGroups_192(t *testing.T) {
	result := ipToHexGroups("192.168.1.1")
	if result != "192168:11" {
		t.Errorf("Expected '192168:11', got '%s'", result)
	}
}

// ==================== getSSRFPayloads comprehensive ====================

func TestGetSSRFPayloads_HTTPSURL(t *testing.T) {
	reverseURL := "https://127.0.0.1:8443/callback"
	payloads := getSSRFPayloads(reverseURL)

	if len(payloads) < 1 {
		t.Errorf("Expected at least 1 payload, got %d", len(payloads))
	}
	if payloads[0] != reverseURL {
		t.Errorf("First payload should be %q, got %q", reverseURL, payloads[0])
	}
}

func TestGetSSRFPayloads_NonHTTPURL(t *testing.T) {
	reverseURL := "ftp://server/callback"
	payloads := getSSRFPayloads(reverseURL)

	if len(payloads) < 1 {
		t.Errorf("Expected at least 1 payload, got %d", len(payloads))
	}
	if payloads[0] != reverseURL {
		t.Errorf("First payload should be %q, got %q", reverseURL, payloads[0])
	}
}

func TestGetSSRFPayloads_IPBypassAll(t *testing.T) {
	reverseURL := "http://127.0.0.1:8080/abc"
	payloads := getSSRFPayloads(reverseURL)

	// Check decimal bypass
	foundDecimal := false
	foundOctal := false
	foundHex := false
	foundShortened := false
	foundIPv6 := false
	for _, p := range payloads {
		if containsStrCov(p, "2130706433") {
			foundDecimal = true
		}
		if containsStrCov(p, "0177") {
			foundOctal = true
		}
		if containsStrCov(p, "0x7f") {
			foundHex = true
		}
		if containsStrCov(p, "127.1") {
			foundShortened = true
		}
		if containsStrCov(p, "::1") {
			foundIPv6 = true
		}
	}
	if !foundDecimal {
		t.Error("Expected decimal IP bypass")
	}
	if !foundOctal {
		t.Error("Expected octal IP bypass")
	}
	if !foundHex {
		t.Error("Expected hex IP bypass")
	}
	if !foundShortened {
		t.Error("Expected shortened IP bypass")
	}
	if !foundIPv6 {
		t.Error("Expected IPv6 loopback bypass")
	}
}

// ==================== isPotentialURLParam comprehensive ====================

func TestIsPotentialURLParam_AllKeywordsComplete_Coverage(t *testing.T) {
	keywords := []string{
		"url", "link", "redirect", "uri", "path", "src", "source",
		"href", "site", "web", "blog", "callback", "return", "next",
		"dest", "destination", "goto", "feed", "img", "image",
		"load", "proxy", "request", "navigate", "continue", "file",
		"reference", "domain", "query",
	}
	for _, kw := range keywords {
		param := wscan_http.Parameter{Key: kw, Value: "test"}
		if !isPotentialURLParam(param) {
			t.Errorf("Expected keyword '%s' to be a potential URL param", kw)
		}
	}
}

func TestIsPotentialURLParam_HttpValue(t *testing.T) {
	param := wscan_http.Parameter{Key: "anything", Value: "http://evil.com"}
	if !isPotentialURLParam(param) {
		t.Error("Expected http:// value to be a potential URL param")
	}
}

func TestIsPotentialURLParam_HttpsValue(t *testing.T) {
	param := wscan_http.Parameter{Key: "anything", Value: "https://evil.com"}
	if !isPotentialURLParam(param) {
		t.Error("Expected https:// value to be a potential URL param")
	}
}

func TestIsPotentialURLParam_NegativeCases_Coverage(t *testing.T) {
	negatives := []wscan_http.Parameter{
		{Key: "id", Value: "123"},
		{Key: "page", Value: "1"},
		{Key: "username", Value: "admin"},
		{Key: "password", Value: "secret"},
		{Key: "", Value: ""},
	}
	for _, param := range negatives {
		if isPotentialURLParam(param) {
			t.Errorf("Did not expect key '%s' to be a potential URL param", param.Key)
		}
	}
}

func TestIsPotentialURLParam_CaseInsensitive_Coverage(t *testing.T) {
	param := wscan_http.Parameter{Key: "URL", Value: "test"}
	if !isPotentialURLParam(param) {
		t.Error("Expected URL (uppercase) to be a potential URL param")
	}
}

func TestIsPotentialURLParam_SubstringKey(t *testing.T) {
	param := wscan_http.Parameter{Key: "my_redirect_url", Value: "test"}
	if !isPotentialURLParam(param) {
		t.Error("Expected 'my_redirect_url' (contains 'redirect') to be a potential URL param")
	}
}

// ==================== internalServices comprehensive ====================

func TestInternalServices_AllHaveAddress(t *testing.T) {
	for _, svc := range internalServices {
		if svc.Address == "" {
			t.Errorf("Service %s has empty Address", svc.Name)
		}
	}
}

func TestInternalServices_AllHavePattern(t *testing.T) {
	for _, svc := range internalServices {
		if svc.Pattern == "" {
			t.Errorf("Service %s has empty Pattern", svc.Name)
		}
	}
}

func TestInternalServices_AllHaveName(t *testing.T) {
	for _, svc := range internalServices {
		if svc.Name == "" {
			t.Error("Service has empty Name")
		}
	}
}

func TestInternalServices_SpecificServices(t *testing.T) {
	expectedServices := map[string]string{
		"SSH":                  "skip",
		"Redis":                "skip",
		"MySQL":                "skip",
		"PostgreSQL":           "skip",
		"MongoDB":              "skip",
		"Elasticsearch":        "http",
		"Cloud Metadata (AWS)": "http",
		"Cloud Metadata (GCP)": "http",
		"Kubernetes API":       "http",
		"Docker API":           "http",
	}

	for _, svc := range internalServices {
		if expectedProto, ok := expectedServices[svc.Name]; ok {
			if svc.Proto != expectedProto {
				t.Errorf("Service %s: Proto = %q, want %q", svc.Name, svc.Proto, expectedProto)
			}
		}
	}
}

// ==================== ssrfReflectFinger comprehensive ====================

func TestSSRFReflectFinger_AllFields(t *testing.T) {
	f := ssrfReflectFinger()
	if f.CheckAction == nil {
		t.Error("CheckAction should not be nil")
	}
	if f.Channel != "web-generic" {
		t.Errorf("Channel = %q, want 'web-generic'", f.Channel)
	}
	if !f.NeedReverse {
		t.Error("NeedReverse should be true")
	}
	if f.Binding == nil {
		t.Fatal("Binding should not be nil")
	}
	if f.Binding.ID != "ssrf/default" {
		t.Errorf("Binding.ID = %q, want 'ssrf/default'", f.Binding.ID)
	}
	if f.Binding.Plugin != "ssrf/reflected" {
		t.Errorf("Binding.Plugin = %q, want 'ssrf/reflected'", f.Binding.Plugin)
	}
	if f.Binding.Category != "ssrf" {
		t.Errorf("Binding.Category = %q, want 'ssrf'", f.Binding.Category)
	}
}

// ==================== internalServiceFinger comprehensive ====================

func TestInternalServiceFinger_AllFields(t *testing.T) {
	f := internalServiceFinger()
	if f.CheckAction == nil {
		t.Error("CheckAction should not be nil")
	}
	if f.Channel != "web-generic" {
		t.Errorf("Channel = %q, want 'web-generic'", f.Channel)
	}
	if f.Binding == nil {
		t.Fatal("Binding should not be nil")
	}
	if f.Binding.ID != "ssrf/internal-service" {
		t.Errorf("Binding.ID = %q, want 'ssrf/internal-service'", f.Binding.ID)
	}
	if f.Binding.Category != "ssrf" {
		t.Errorf("Binding.Category = %q, want 'ssrf'", f.Binding.Category)
	}
}

// ==================== Payload struct ====================

func TestPayload_AllFields(t *testing.T) {
	p := Payload{
		description: "test description",
		host:        "127.0.0.1",
	}
	if p.description != "test description" {
		t.Errorf("description = %q, want 'test description'", p.description)
	}
	if p.host != "127.0.0.1" {
		t.Errorf("host = %q, want '127.0.0.1'", p.host)
	}
}

// ==================== extractPath additional ====================

func TestExtractPath_Simple(t *testing.T) {
	result := extractPath("http://example.com/test/path")
	if result != "test/path" {
		t.Errorf("Expected 'test/path', got '%s'", result)
	}
}

func TestExtractPath_Root(t *testing.T) {
	result := extractPath("http://example.com/")
	if result != "" {
		t.Errorf("Expected empty for root, got '%s'", result)
	}
}

func TestExtractPath_NoPath(t *testing.T) {
	result := extractPath("http://example.com")
	if result != "" {
		t.Errorf("Expected empty for no path, got '%s'", result)
	}
}

// ==================== Helper ====================

func containsStrCov(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
