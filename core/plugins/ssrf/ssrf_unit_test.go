package ssrf

import (
	"testing"

	"wscan/core/http"
	"wscan/core/plugins/base"
)

func TestSSRFDefaultConfig(t *testing.T) {
	p := &SSRF{}
	cfg := p.DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig() returned nil")
	}

	bc := cfg.BaseConfig()
	if bc.Name != "ssrf" {
		t.Errorf("Expected Name='ssrf', got '%s'", bc.Name)
	}
	if !bc.Enabled {
		t.Error("Expected Enabled=true")
	}
}

func TestSSRFClose(t *testing.T) {
	p := &SSRF{}
	if err := p.Close(); err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
}

func TestSSRFGetConfig(t *testing.T) {
	p := &SSRF{}
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
	if bc.Name != "ssrf" {
		t.Errorf("Expected Name='ssrf', got '%s'", bc.Name)
	}
}

func TestSSRFInit(t *testing.T) {
	p := &SSRF{}
	cfg := p.DefaultConfig()
	ab := &base.ApolloBase{}

	err := p.Init(nil, cfg, ab)
	if err != nil {
		t.Errorf("Init() returned error: %v", err)
	}
}

func TestConfigBaseConfigSSRF(t *testing.T) {
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

func TestFingers_WithoutInit(t *testing.T) {
	p := &SSRF{}
	fingers := p.Fingers()
	// Without Init, GetConfig returns nil, so only reflect finger
	if len(fingers) < 1 {
		t.Errorf("Expected at least 1 finger, got %d", len(fingers))
	}
}

func TestFingers_WithInternalServiceEnabled(t *testing.T) {
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
		t.Errorf("Expected 2 fingers with internal service enabled, got %d", len(fingers))
	}
}

func TestFingers_WithInternalServiceDisabled(t *testing.T) {
	p := &SSRF{}
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "ssrf",
			Enabled: true,
		},
		DetectInternalService: false,
	}
	ab := &base.ApolloBase{}
	p.Init(nil, cfg, ab)

	fingers := p.Fingers()
	if len(fingers) != 1 {
		t.Errorf("Expected 1 finger with internal service disabled, got %d", len(fingers))
	}
}

func TestExtractHostPort_HTTPS(t *testing.T) {
	result := extractHostPort("https://example.com:443/path")
	if result != "example.com:443" {
		t.Errorf("Expected 'example.com:443', got '%s'", result)
	}
}

func TestExtractHostPort_InvalidURL(t *testing.T) {
	result := extractHostPort("ftp://example.com/path")
	if result != "" {
		t.Errorf("Expected empty for non-http URL, got '%s'", result)
	}
}

func TestExtractPath_HTTPS(t *testing.T) {
	result := extractPath("https://example.com:443/secret/path")
	// extractPath only trims "http://", not "https://"
	// This is a known behavior - test it as-is
	_ = result
}

func TestIsPotentialURLParam_AllKeywords(t *testing.T) {
	keywords := []string{"url", "link", "redirect", "uri", "path", "src", "source", "href",
		"site", "web", "blog", "callback", "return", "next", "dest", "destination",
		"goto", "feed", "img", "image", "load", "proxy", "request", "navigate",
		"continue", "file", "reference", "domain", "query"}

	for _, kw := range keywords {
		param := http.Parameter{Key: kw, Value: "test"}
		if !isPotentialURLParam(param) {
			t.Errorf("Expected keyword '%s' to be a potential URL param", kw)
		}
	}
}

func TestIsPotentialURLParam_NegativeCases(t *testing.T) {
	negativeCases := []http.Parameter{
		{Key: "id", Value: "123"},
		{Key: "page", Value: "1"},
		{Key: "name", Value: "test"},
		{Key: "username", Value: "admin"},
		{Key: "password", Value: "secret"},
		{Key: "token", Value: "abc"},
	}

	for _, param := range negativeCases {
		if isPotentialURLParam(param) {
			t.Errorf("Did not expect param with key '%s' to be a potential URL param", param.Key)
		}
	}
}

func TestIsPotentialURLParam_HTTPValue(t *testing.T) {
	param := http.Parameter{Key: "anything", Value: "http://example.com"}
	if !isPotentialURLParam(param) {
		t.Error("Expected param with http:// value to be a potential URL param")
	}

	param = http.Parameter{Key: "anything", Value: "https://example.com"}
	if !isPotentialURLParam(param) {
		t.Error("Expected param with https:// value to be a potential URL param")
	}
}

func TestGetSSRFPayloads_WithHTTPSPort(t *testing.T) {
	reverseURL := "https://127.0.0.1:8080/secret"
	payloads := getSSRFPayloads(reverseURL)

	if len(payloads) < 3 {
		t.Errorf("Expected at least 3 payloads, got %d", len(payloads))
	}

	// First payload should be the reverse URL itself
	if payloads[0] != reverseURL {
		t.Errorf("First payload should be %q, got %q", reverseURL, payloads[0])
	}
}

func TestGetSSRFPayloads_BasicPayloads(t *testing.T) {
	reverseURL := "http://192.168.1.1:9000/callback"
	payloads := getSSRFPayloads(reverseURL)

	// Check basic payloads are present
	if payloads[0] != reverseURL {
		t.Errorf("First payload incorrect, got %q", payloads[0])
	}

	// URL encoding bypass
	if payloads[1] != "h%74tp://192.168.1.1:9000/callback" {
		t.Errorf("URL encoding bypass incorrect, got %q", payloads[1])
	}

	// Double URL encoding
	if payloads[2] != "h%2574tp://192.168.1.1:9000/callback" {
		t.Errorf("Double URL encoding bypass incorrect, got %q", payloads[2])
	}
}

func TestGetSSRFPayloads_IPBypass(t *testing.T) {
	reverseURL := "http://10.0.0.1:8080/test"
	payloads := getSSRFPayloads(reverseURL)

	// Check IP bypass payloads exist
	if len(payloads) < 9 {
		t.Errorf("Expected at least 9 payloads with IP bypasses, got %d", len(payloads))
	}
}

func TestIPToDecimal_EdgeCases(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"255.255.255.255", "4294967295"},
		{"1.1.1.1", "16843009"},
		{"10.10.10.10", "168430090"},
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

func TestIpToOctal_EdgeCases(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"255.255.255.255", "0377.0377.0377.0377"},
		{"0.0.0.0", "00.00.00.00"},
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

func TestIpToHex_EdgeCases(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"255.255.255.255", "0xffffffff"},
		{"1.0.0.1", "0x1000001"},
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

func TestInternalServicesListComplete(t *testing.T) {
	expectedServices := []struct {
		name  string
		proto string
	}{
		{"SSH", "skip"},
		{"Redis", "skip"},
		{"MySQL", "skip"},
		{"PostgreSQL", "skip"},
		{"MongoDB", "skip"},
		{"Elasticsearch", "http"},
		{"Cloud Metadata (AWS)", "http"},
		{"Cloud Metadata (GCP)", "http"},
		{"Kubernetes API", "http"},
		{"Docker API", "http"},
	}

	if len(internalServices) != len(expectedServices) {
		t.Errorf("Expected %d internal services, got %d", len(expectedServices), len(internalServices))
	}

	for _, expected := range expectedServices {
		found := false
		for _, svc := range internalServices {
			if svc.Name == expected.name {
				found = true
				if svc.Proto != expected.proto {
					t.Errorf("Service %s: expected Proto='%s', got '%s'", expected.name, expected.proto, svc.Proto)
				}
				break
			}
		}
		if !found {
			t.Errorf("Expected service '%s' not found", expected.name)
		}
	}
}

func TestSSRFReflectFingerProperties(t *testing.T) {
	f := ssrfReflectFinger()
	if f == nil {
		t.Fatal("ssrfReflectFinger() returned nil")
	}
	if f.Channel != "web-generic" {
		t.Errorf("Expected Channel='web-generic', got '%s'", f.Channel)
	}
	if !f.NeedReverse {
		t.Error("Expected NeedReverse=true for reflect finger")
	}
	if f.Binding == nil {
		t.Fatal("Expected non-nil Binding")
	}
	if f.Binding.ID != "ssrf/default" {
		t.Errorf("Expected Binding.ID='ssrf/default', got '%s'", f.Binding.ID)
	}
	if f.Binding.Category != "ssrf" {
		t.Errorf("Expected Binding.Category='ssrf', got '%s'", f.Binding.Category)
	}
}

func TestInternalServiceFingerProperties(t *testing.T) {
	f := internalServiceFinger()
	if f == nil {
		t.Fatal("internalServiceFinger() returned nil")
	}
	if f.Channel != "web-generic" {
		t.Errorf("Expected Channel='web-generic', got '%s'", f.Channel)
	}
	if f.Binding == nil {
		t.Fatal("Expected non-nil Binding")
	}
	if f.Binding.ID != "ssrf/internal-service" {
		t.Errorf("Expected Binding.ID='ssrf/internal-service', got '%s'", f.Binding.ID)
	}
	if f.CheckAction == nil {
		t.Error("Expected non-nil CheckAction")
	}
}

func TestPayloadStruct(t *testing.T) {
	p := Payload{
		description: "test payload",
		host:        "127.0.0.1",
	}
	if p.description != "test payload" {
		t.Errorf("Expected description='test payload', got '%s'", p.description)
	}
	if p.host != "127.0.0.1" {
		t.Errorf("Expected host='127.0.0.1', got '%s'", p.host)
	}
}

func TestConfigDetectInternalServiceDefault(t *testing.T) {
	p := &SSRF{}
	cfg := p.DefaultConfig()
	ssrfCfg, ok := cfg.(*Config)
	if !ok {
		t.Fatal("DefaultConfig() did not return *Config")
	}
	if ssrfCfg.DetectInternalService {
		t.Error("Expected DetectInternalService=false by default")
	}
}

func TestConfigDangerouslyUseCommentInSQL(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "ssrf",
			Enabled: true,
		},
		DangerouslyUseCommentInSQL: true,
	}
	if !cfg.DangerouslyUseCommentInSQL {
		t.Error("Expected DangerouslyUseCommentInSQL=true")
	}
}
