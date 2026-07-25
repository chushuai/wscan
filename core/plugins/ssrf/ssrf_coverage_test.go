package ssrf

import (
	"testing"
	"wscan/core/http"
	"wscan/core/plugins/base"
)

// ---- DefaultConfig / Close / Fingers ----

func TestDefaultConfig(t *testing.T) {
	p := &SSRF{}
	cfg := p.DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig() returned nil")
	}

	bc := cfg.BaseConfig()
	if bc == nil {
		t.Fatal("BaseConfig() returned nil")
	}
	if bc.Name != "ssrf" {
		t.Errorf("Expected Name='ssrf', got '%s'", bc.Name)
	}
	if !bc.Enabled {
		t.Error("Expected Enabled=true")
	}

	ssrfCfg, ok := cfg.(*Config)
	if !ok {
		t.Fatal("DefaultConfig() did not return *Config")
	}
	if ssrfCfg.DetectInternalService {
		t.Error("Expected DetectInternalService=false by default")
	}
}

func TestClose(t *testing.T) {
	p := &SSRF{}
	if err := p.Close(); err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
}

func TestFingers_WithoutInternalService(t *testing.T) {
	p := &SSRF{}
	fingers := p.Fingers()
	// Without Init, GetConfig returns nil, so only the reflect finger is added
	if len(fingers) < 1 {
		t.Errorf("Expected at least 1 finger, got %d", len(fingers))
	}
}

func TestFingers_WithInternalService(t *testing.T) {
	p := &SSRF{}
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "ssrf",
			Enabled: true,
		},
		DetectInternalService: true,
	}
	ab := &base.ApolloBase{}
	p.Init(nil, cfg, ab)

	fingers := p.Fingers()
	if len(fingers) != 2 {
		t.Errorf("Expected 2 fingers with internal service, got %d", len(fingers))
	}
}

func TestConfigBaseConfig(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "ssrf",
			Enabled: true,
		},
		DetectInternalService: true,
	}
	bc := cfg.BaseConfig()
	if bc.Name != "ssrf" {
		t.Errorf("Expected Name='ssrf', got '%s'", bc.Name)
	}
}

// ---- Pure logic function tests ----

func TestExtractHostPort(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"http://127.0.0.1:8080/callback", "127.0.0.1:8080"},
		{"http://example.com/path", "example.com"},
		{"http://10.0.0.1:9000/a/b/c", "10.0.0.1:9000"},
		{"http://localhost/", "localhost"},
		{"http://192.168.1.1", "192.168.1.1"},
		{"not-a-url", ""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := extractHostPort(tt.input)
			if result != tt.expected {
				t.Errorf("extractHostPort(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestExtractPath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"http://127.0.0.1:8080/callback/abc", "callback/abc"},
		{"http://example.com/path", "path"},
		{"http://10.0.0.1:9000/", ""},
		{"http://localhost/", ""},
		{"http://192.168.1.1", ""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := extractPath(tt.input)
			if result != tt.expected {
				t.Errorf("extractPath(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestIpToDecimal(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"127.0.0.1", "2130706433"},
		{"127.0.0.1:8080", "2130706433:8080"},
		{"10.0.0.1", "167772161"},
		{"192.168.1.1", "3232235777"},
		{"0.0.0.0", "0"},
		{"not-an-ip", "not-an-ip"}, // Not 4 octets
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := ipToDecimal(tt.input)
			if result != tt.expected {
				t.Errorf("ipToDecimal(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestIpToOctal(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"127.0.0.1", "0177.00.00.01"},
		{"127.0.0.1:8080", "0177.00.00.01:8080"},
		{"10.0.0.1", "012.00.00.01"},
		{"not-an-ip", "not-an-ip"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := ipToOctal(tt.input)
			if result != tt.expected {
				t.Errorf("ipToOctal(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestIpToHex(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"127.0.0.1", "0x7f000001"},
		{"127.0.0.1:8080", "0x7f000001:8080"},
		{"10.0.0.1", "0xa000001"},
		{"0.0.0.0", "0x0"},
		{"not-an-ip", "not-an-ip"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := ipToHex(tt.input)
			if result != tt.expected {
				t.Errorf("ipToHex(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestIpShortened(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"127.0.0.1", "127.1"},
		{"127.0.0.1:8080", "127.1:8080"},
		{"10.0.0.1", "10.1"},
		{"192.168.1.1", "192.1"},
		{"not-an-ip", "not-an-ip"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := ipShortened(tt.input)
			if result != tt.expected {
				t.Errorf("ipShortened(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestIpToHexGroups(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"127.0.0.1", "1270:01"},
		{"10.0.0.1", "100:01"},
		{"192.168.1.1", "192168:11"},
		{"not-an-ip", "not-an-ip"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := ipToHexGroups(tt.input)
			if result != tt.expected {
				t.Errorf("ipToHexGroups(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestGetSSRFPayloads(t *testing.T) {
	reverseURL := "http://127.0.0.1:8080/abc123"
	payloads := getSSRFPayloads(reverseURL)

	if len(payloads) < 3 {
		t.Errorf("Expected at least 3 payloads, got %d", len(payloads))
	}

	// First payload should be the reverse URL itself
	if payloads[0] != reverseURL {
		t.Errorf("First payload should be %q, got %q", reverseURL, payloads[0])
	}

	// Second payload should have URL encoding bypass
	if payloads[1] != "h%74tp://127.0.0.1:8080/abc123" {
		t.Errorf("Second payload URL encoding bypass incorrect, got %q", payloads[1])
	}

	// Third payload should have double URL encoding
	if payloads[2] != "h%2574tp://127.0.0.1:8080/abc123" {
		t.Errorf("Third payload double URL encoding bypass incorrect, got %q", payloads[2])
	}

	// Should include IP bypass payloads
	found := false
	for _, p := range payloads {
		if p == "http://2130706433:8080/abc123" {
			found = true
		}
	}
	if !found {
		t.Error("Expected decimal IP bypass payload")
	}
}

func TestGetSSRFPayloads_NoPort(t *testing.T) {
	reverseURL := "http://example.com/abc123"
	payloads := getSSRFPayloads(reverseURL)
	// Should still generate payloads, but without port-specific bypasses
	if len(payloads) < 3 {
		t.Errorf("Expected at least 3 payloads, got %d", len(payloads))
	}
}

func TestIsPotentialURLParam(t *testing.T) {
	tests := []struct {
		name     string
		param    http.Parameter
		expected bool
	}{
		{"url value", http.Parameter{Key: "foo", Value: "http://example.com"}, true},
		{"https value", http.Parameter{Key: "foo", Value: "https://example.com"}, true},
		{"url key", http.Parameter{Key: "url", Value: "anything"}, true},
		{"redirect key", http.Parameter{Key: "redirect", Value: "val"}, true},
		{"path key", http.Parameter{Key: "path", Value: "val"}, true},
		{"src key", http.Parameter{Key: "src", Value: "val"}, true},
		{"callback key", http.Parameter{Key: "callback", Value: "val"}, true},
		{"proxy key", http.Parameter{Key: "proxy", Value: "val"}, true},
		{"domain key", http.Parameter{Key: "domain", Value: "val"}, true},
		{"random key/value", http.Parameter{Key: "foo", Value: "bar"}, false},
		{"id key", http.Parameter{Key: "id", Value: "123"}, false},
		{"page key", http.Parameter{Key: "page", Value: "1"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPotentialURLParam(tt.param)
			if result != tt.expected {
				t.Errorf("isPotentialURLParam(%+v) = %v, want %v", tt.param, result, tt.expected)
			}
		})
	}
}

func TestInternalServicesList(t *testing.T) {
	if len(internalServices) == 0 {
		t.Error("internalServices list should not be empty")
	}
	// Check that known services are present
	foundSSH := false
	foundRedis := false
	foundDocker := false
	for _, svc := range internalServices {
		if svc.Name == "SSH" {
			foundSSH = true
			if svc.Proto != "skip" {
				t.Errorf("SSH should have Proto='skip', got '%s'", svc.Proto)
			}
		}
		if svc.Name == "Redis" {
			foundRedis = true
		}
		if svc.Name == "Docker API" {
			foundDocker = true
			if svc.Proto != "http" {
				t.Errorf("Docker API should have Proto='http', got '%s'", svc.Proto)
			}
		}
	}
	if !foundSSH {
		t.Error("Expected SSH in internalServices")
	}
	if !foundRedis {
		t.Error("Expected Redis in internalServices")
	}
	if !foundDocker {
		t.Error("Expected Docker API in internalServices")
	}
}

func TestSSRFReflectFinger(t *testing.T) {
	f := ssrfReflectFinger()
	if f == nil {
		t.Fatal("ssrfReflectFinger() returned nil")
	}
	if f.Channel != "web-generic" {
		t.Errorf("Expected Channel='web-generic', got '%s'", f.Channel)
	}
	if !f.NeedReverse {
		t.Error("Expected NeedReverse=true")
	}
	if f.Binding.ID != "ssrf/default" {
		t.Errorf("Expected Binding.ID='ssrf/default', got '%s'", f.Binding.ID)
	}
}

func TestInternalServiceFinger(t *testing.T) {
	f := internalServiceFinger()
	if f == nil {
		t.Fatal("internalServiceFinger() returned nil")
	}
	if f.Channel != "web-generic" {
		t.Errorf("Expected Channel='web-generic', got '%s'", f.Channel)
	}
	if f.Binding.ID != "ssrf/internal-service" {
		t.Errorf("Expected Binding.ID='ssrf/internal-service', got '%s'", f.Binding.ID)
	}
	if f.CheckAction == nil {
		t.Error("CheckAction should not be nil")
	}
}
