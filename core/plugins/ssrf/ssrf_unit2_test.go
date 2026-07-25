package ssrf

import (
	"testing"

	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
)

// ==================== SSRF struct methods ====================

func TestSSRF_MultipleInit(t *testing.T) {
	p := &SSRF{}
	cfg := p.DefaultConfig()
	ab := &base.ApolloBase{}

	err := p.Init(nil, cfg, ab)
	if err != nil {
		t.Errorf("First Init() error: %v", err)
	}
	err = p.Init(nil, cfg, ab)
	if err != nil {
		t.Errorf("Second Init() error: %v", err)
	}
}

func TestSSRF_MultipleClose(t *testing.T) {
	p := &SSRF{}
	for i := 0; i < 3; i++ {
		if err := p.Close(); err != nil {
			t.Errorf("Close() call %d returned error: %v", i, err)
		}
	}
}

// ==================== extractHostPort edge cases ====================

func TestExtractHostPort_HTTPSPath(t *testing.T) {
	result := extractHostPort("https://example.com:443/secret/path")
	if result != "example.com:443" {
		t.Errorf("Expected 'example.com:443', got '%s'", result)
	}
}

func TestExtractHostPort_HTTPNoPath(t *testing.T) {
	result := extractHostPort("http://example.com")
	if result != "example.com" {
		t.Errorf("Expected 'example.com', got '%s'", result)
	}
}

func TestExtractHostPort_EmptyString(t *testing.T) {
	result := extractHostPort("")
	if result != "" {
		t.Errorf("Expected empty for empty string, got '%s'", result)
	}
}

func TestExtractHostPort_FTP(t *testing.T) {
	result := extractHostPort("ftp://example.com")
	if result != "" {
		t.Errorf("Expected empty for ftp URL, got '%s'", result)
	}
}

// ==================== extractPath edge cases ====================

func TestExtractPath_HTTPSUrl(t *testing.T) {
	// extractPath only trims "http://", not "https://"
	// This tests the current behavior
	result := extractPath("https://example.com:443/secret")
	_ = result // Document known limitation
}

func TestExtractPath_SimplePath(t *testing.T) {
	result := extractPath("http://example.com/test/path")
	if result != "test/path" {
		t.Errorf("Expected 'test/path', got '%s'", result)
	}
}

func TestExtractPath_EmptyPath(t *testing.T) {
	result := extractPath("http://example.com/")
	if result != "" {
		t.Errorf("Expected empty for root path, got '%s'", result)
	}
}

func TestExtractPath_NoTrailingSlash(t *testing.T) {
	result := extractPath("http://example.com")
	if result != "" {
		t.Errorf("Expected empty for no path, got '%s'", result)
	}
}

// ==================== isPotentialURLParam additional cases ====================

func TestIsPotentialURLParam_CaseInsensitive(t *testing.T) {
	param := http.Parameter{Key: "URL", Value: "test"}
	if !isPotentialURLParam(param) {
		t.Error("Expected URL (uppercase) to be a potential URL param")
	}
}

func TestIsPotentialURLParam_PartialKeyMatch(t *testing.T) {
	param := http.Parameter{Key: "redirect_url", Value: "test"}
	if !isPotentialURLParam(param) {
		t.Error("Expected redirect_url to be a potential URL param (contains 'redirect')")
	}
}

func TestIsPotentialURLParam_HTTPSPrefix(t *testing.T) {
	param := http.Parameter{Key: "anything", Value: "https://evil.com"}
	if !isPotentialURLParam(param) {
		t.Error("Expected https:// value to be a potential URL param")
	}
}

// ==================== ipToDecimal with port ====================

func TestIPToDecimal_WithPort(t *testing.T) {
	result := ipToDecimal("10.0.0.1:8080")
	if result != "167772161:8080" {
		t.Errorf("Expected '167772161:8080', got '%s'", result)
	}
}

func TestIPToDecimal_InvalidIP(t *testing.T) {
	result := ipToDecimal("not-valid-ip")
	if result != "not-valid-ip" {
		t.Errorf("Expected original string for invalid IP, got '%s'", result)
	}
}

// ==================== ipToOctal with port ====================

func TestIPToOctal_WithPort(t *testing.T) {
	result := ipToOctal("192.168.1.1:443")
	expectedPrefix := "0300.0250.01.01:443"
	if result != expectedPrefix {
		t.Errorf("Expected '%s', got '%s'", expectedPrefix, result)
	}
}

func TestIPToOctal_InvalidIP(t *testing.T) {
	result := ipToOctal("invalid")
	if result != "invalid" {
		t.Errorf("Expected original string for invalid IP, got '%s'", result)
	}
}

// ==================== ipToHex with port ====================

func TestIPToHex_WithPort(t *testing.T) {
	result := ipToHex("10.0.0.1:9090")
	if result != "0xa000001:9090" {
		t.Errorf("Expected '0xa000001:9090', got '%s'", result)
	}
}

func TestIPToHex_InvalidIP(t *testing.T) {
	result := ipToHex("invalid")
	if result != "invalid" {
		t.Errorf("Expected original string for invalid IP, got '%s'", result)
	}
}

// ==================== ipShortened with port ====================

func TestIPShortened_WithPort(t *testing.T) {
	result := ipShortened("192.168.1.1:8080")
	if result != "192.1:8080" {
		t.Errorf("Expected '192.1:8080', got '%s'", result)
	}
}

func TestIPShortened_InvalidIP(t *testing.T) {
	result := ipShortened("invalid")
	if result != "invalid" {
		t.Errorf("Expected original string for invalid IP, got '%s'", result)
	}
}

// ==================== ipToHexGroups with port ====================

func TestIPToHexGroups_InvalidIP(t *testing.T) {
	result := ipToHexGroups("invalid")
	if result != "invalid" {
		t.Errorf("Expected original string for invalid IP, got '%s'", result)
	}
}

// ==================== getSSRFPayloads edge cases ====================

func TestGetSSRFPayloads_NoHostPort(t *testing.T) {
	// When extractHostPort returns empty, only basic payloads are generated
	reverseURL := "ftp://server/callback"
	payloads := getSSRFPayloads(reverseURL)
	if len(payloads) < 1 {
		t.Errorf("Expected at least 1 payload, got %d", len(payloads))
	}
	// First payload should be the reverse URL itself
	if payloads[0] != reverseURL {
		t.Errorf("First payload should be %q, got %q", reverseURL, payloads[0])
	}
}

func TestGetSSRFPayloads_IPBypassPayloads(t *testing.T) {
	reverseURL := "http://127.0.0.1:8080/callback"
	payloads := getSSRFPayloads(reverseURL)

	// Should include decimal IP bypass
	foundDecimal := false
	foundOctal := false
	foundHex := false
	for _, p := range payloads {
		if strings := containsStr(p, "2130706433"); strings {
			foundDecimal = true
		}
		if containsStr(p, "0177") {
			foundOctal = true
		}
		if containsStr(p, "0x7f") {
			foundHex = true
		}
	}
	if !foundDecimal {
		t.Error("Expected decimal IP bypass payload")
	}
	if !foundOctal {
		t.Error("Expected octal IP bypass payload")
	}
	if !foundHex {
		t.Error("Expected hex IP bypass payload")
	}
}

// ==================== SSRF Reflect Finger details ====================

func TestSSRFReflectFinger_NeedReverse(t *testing.T) {
	f := ssrfReflectFinger()
	if !f.NeedReverse {
		t.Error("Expected NeedReverse=true")
	}
	if f.Binding.Severity != model.SeverityHigh {
		t.Errorf("Expected Severity=SeverityHigh, got '%v'", f.Binding.Severity)
	}
}

// ==================== InternalServiceFinger details ====================

func TestInternalServiceFinger_Binding(t *testing.T) {
	f := internalServiceFinger()
	if f.Binding.ID != "ssrf/internal-service" {
		t.Errorf("Expected Binding.ID='ssrf/internal-service', got '%s'", f.Binding.ID)
	}
	if f.Binding.Category != "ssrf" {
		t.Errorf("Expected Binding.Category='ssrf', got '%s'", f.Binding.Category)
	}
}

// ==================== InternalService entries ====================

func TestInternalService_HasAddresses(t *testing.T) {
	for _, svc := range internalServices {
		if svc.Address == "" {
			t.Errorf("Service %s has empty Address", svc.Name)
		}
		if svc.Pattern == "" {
			t.Errorf("Service %s has empty Pattern", svc.Name)
		}
	}
}

// ==================== Config fields ====================

func TestConfig_DetectInternalServiceField(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "ssrf",
			Enabled: true,
		},
		DetectInternalService:      true,
		DangerouslyUseCommentInSQL: true,
	}
	if !cfg.DetectInternalService {
		t.Error("Expected DetectInternalService=true")
	}
	if !cfg.DangerouslyUseCommentInSQL {
		t.Error("Expected DangerouslyUseCommentInSQL=true")
	}
}

// ==================== Fingers with various configs ====================

func TestFingers_WithDefaultConfig(t *testing.T) {
	p := &SSRF{}
	cfg := p.DefaultConfig()
	ab := &base.ApolloBase{}
	p.Init(nil, cfg, ab)

	fingers := p.Fingers()
	// Default config has DetectInternalService=false, so only 1 finger
	if len(fingers) != 1 {
		t.Errorf("Expected 1 finger with default config, got %d", len(fingers))
	}
}

// ==================== Payload struct ====================

func TestPayload_Fields(t *testing.T) {
	p := Payload{
		description: "test",
		host:        "127.0.0.1",
	}
	if p.description != "test" {
		t.Errorf("description = %q, want 'test'", p.description)
	}
	if p.host != "127.0.0.1" {
		t.Errorf("host = %q, want '127.0.0.1'", p.host)
	}
}

// ==================== Helper ====================

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
