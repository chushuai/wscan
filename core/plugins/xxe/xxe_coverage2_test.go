package xxe

import (
	"context"
	"testing"

	"wscan/core/model"
	"wscan/core/plugins/base"
)

// ==================== XXE struct tests ====================

func TestXXE_Init(t *testing.T) {
	p := &XXE{}
	cfg := p.DefaultConfig()
	ab := &base.ApolloBase{}
	err := p.Init(context.Background(), cfg, ab)
	if err != nil {
		t.Errorf("Init() returned error: %v", err)
	}
}

func TestXXE_GetConfig_AfterInit(t *testing.T) {
	p := &XXE{}
	cfg := p.DefaultConfig()
	ab := &base.ApolloBase{}
	p.Init(context.Background(), cfg, ab)

	gotCfg := p.GetConfig()
	if gotCfg == nil {
		t.Fatal("Expected non-nil config after Init")
	}
	bc := gotCfg.BaseConfig()
	if bc.Name != "xxe" {
		t.Errorf("Expected Name='xxe', got '%s'", bc.Name)
	}
}

func TestXXE_Fingers_Comprehensive(t *testing.T) {
	p := &XXE{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()
	fingers := p.Fingers()
	if len(fingers) != 1 {
		t.Fatalf("Expected 1 finger, got %d", len(fingers))
	}
	f := fingers[0]
	if f.CheckAction == nil {
		t.Error("CheckAction should not be nil")
	}
	if f.Binding == nil {
		t.Error("Binding should not be nil")
	}
	if f.Binding.ID != "xxe/dispatcher/default" {
		t.Errorf("Expected Binding.ID 'xxe/dispatcher/default', got '%s'", f.Binding.ID)
	}
	if !f.NeedReverse {
		t.Error("XXE finger should need reverse")
	}
	if f.Channel != "web-generic" {
		t.Errorf("Expected Channel 'web-generic', got '%s'", f.Channel)
	}
	if f.Binding.Severity != model.SeverityCritical {
		t.Errorf("Expected SeverityCritical, got %v", f.Binding.Severity)
	}
}

// ==================== CheckXXEEcho comprehensive tests ====================

func TestCheckXXEEcho_AllPatterns(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{"etc passwd", "root:x:0:0:root:/root:/bin/bash", true},
		{"etc shadow sha512", "root:$6$salt$hash:18000:0:99999:7:::", true},
		{"etc shadow sha256", "root:$5$salt$hash:18000:0:99999:7:::", true},
		{"etc shadow md5", "root:$1$salt$hash:18000:0:99999:7:::", true},
		{"linux user info", "uid=0(root) gid=0(root) groups=0(root)", true},
		{"windows dir", "Volume in drive C is Windows", true},
		{"windows dir D", "Volume in drive D is Data", true},
		{"normal text", "Hello World", false},
		{"empty", "", false},
		{"partial match", "root:x:0", false},
		{"similar but different", "user:x:0:0:user:/home/user:/bin/sh", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CheckXXEEcho(tt.body)
			if result != tt.expected {
				t.Errorf("CheckXXEEcho(%q) = %v, expected %v", tt.body, result, tt.expected)
			}
		})
	}
}

// ==================== isXMLContentType comprehensive tests ====================

func TestIsXMLContentType_AllCases(t *testing.T) {
	tests := []struct {
		ct       string
		expected bool
	}{
		{"application/xml", true},
		{"text/xml", true},
		{"application/soap+xml", true},
		{"application/xhtml+xml", true},
		{"text/html", false},
		{"application/json", false},
		{"", false},
		{"APPLICATION/XML", true},
		{"Text/Xml", true},
		{"Application/SOAP+XML", true},
		{"application/xml; charset=utf-8", true},
		{"text/xml; charset=iso-8859-1", true},
		{"image/svg+xml", true},
		{"multipart/form-data", false},
	}
	for _, tt := range tests {
		t.Run(tt.ct, func(t *testing.T) {
			result := isXMLContentType(tt.ct)
			if result != tt.expected {
				t.Errorf("isXMLContentType(%q) = %v, expected %v", tt.ct, result, tt.expected)
			}
		})
	}
}

// ==================== Payload generation tests ====================

func TestGetBlindXXEPayloads_WithCallback(t *testing.T) {
	callback := "http://callback.example.com"
	payloads := GetBlindXXEPayloads(callback)
	if len(payloads) != 2 {
		t.Fatalf("Expected 2 blind XXE payloads, got %d", len(payloads))
	}
	for i, p := range payloads {
		if p == "" {
			t.Errorf("payload[%d] should not be empty", i)
		}
	}
}

func TestGetSOAPXXEPayloads_WithCallback(t *testing.T) {
	callback := "http://callback.example.com"
	payloads := GetSOAPXXEPayloads(callback)
	if len(payloads) != 2 {
		t.Fatalf("Expected 2 SOAP XXE payloads, got %d", len(payloads))
	}
	for i, p := range payloads {
		if p == "" {
			t.Errorf("payload[%d] should not be empty", i)
		}
	}
}

func TestGetSOAPXXEPayloads_EmptyCallback(t *testing.T) {
	payloads := GetSOAPXXEPayloads("")
	if len(payloads) != 2 {
		t.Fatalf("Expected 2 payloads, got %d", len(payloads))
	}
}

func TestGetSVGXXEPayloads_WithCallback(t *testing.T) {
	callback := "http://callback.example.com"
	payloads := GetSVGXXEPayloads(callback)
	if len(payloads) != 1 {
		t.Fatalf("Expected 1 SVG XXE payload, got %d", len(payloads))
	}
	if payloads[0] == "" {
		t.Error("payload should not be empty")
	}
}

func TestGetXIncludeXXEPayloads_WithCallback(t *testing.T) {
	callback := "http://callback.example.com"
	payloads := GetXIncludeXXEPayloads(callback)
	if len(payloads) != 1 {
		t.Fatalf("Expected 1 XInclude XXE payload, got %d", len(payloads))
	}
	if payloads[0] == "" {
		t.Error("payload should not be empty")
	}
}

// ==================== Regex pattern tests ====================

func TestEtcPasswdRegex(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"root:x:0:0:root:/root:/bin/bash", true},
		{"root:x:0:0:", true},
		{"root:*:0:0:", true},
		{"root:x:65534:65534:", true},
		{"root:x:0", false},
		{"hello world", false},
	}
	for _, tt := range tests {
		got := etcPasswdRegex.MatchString(tt.input)
		if got != tt.want {
			t.Errorf("etcPasswdRegex.MatchString(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestEtcShadowRegex(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"root:$6$salt$hash:18000:0:99999:7:::", true},
		{"root:$5$salt$hash:", true},
		{"root:$1$salt$hash:", true},
		{"root:$2b$salt$hash:", false},
		{"root:x:0:0:", false},
	}
	for _, tt := range tests {
		got := etcShadowRegex.MatchString(tt.input)
		if got != tt.want {
			t.Errorf("etcShadowRegex.MatchString(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestLinuxUserInfoRegex(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"uid=0(root) gid=0(root) groups=0(root)", true},
		{"uid=1000(user) gid=1000(user)", true},
		{"uid=33(www-data) gid=33(www-data)", true},
		{"some other text", false},
	}
	for _, tt := range tests {
		got := linuxUserInfo.MatchString(tt.input)
		if got != tt.want {
			t.Errorf("linuxUserInfo.MatchString(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestWindowsDirRegex(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"Volume in drive C is Windows", true},
		{"Volume in drive D is Data", true},
		{"Volume in drive A is Floppy", true},
		{"some other text", false},
	}
	for _, tt := range tests {
		got := windowsDirRegex.MatchString(tt.input)
		if got != tt.want {
			t.Errorf("windowsDirRegex.MatchString(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}
