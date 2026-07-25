package xxe

import (
	"testing"

	"wscan/core/model"
	"wscan/core/plugins/base"
)

func TestCheckXXEEcho_EtcPasswd(t *testing.T) {
	if !CheckXXEEcho("root:x:0:0:root:/root:/bin/bash") {
		t.Error("expected true for /etc/passwd pattern")
	}
}

func TestCheckXXEEcho_EtcShadow(t *testing.T) {
	if !CheckXXEEcho("root:$6$salt$hash:18000:0:99999:7:::") {
		t.Error("expected true for /etc/shadow pattern with $6$")
	}
	if !CheckXXEEcho("root:$5$salt$hash:18000:0:99999:7:::") {
		t.Error("expected true for /etc/shadow pattern with $5$")
	}
	if !CheckXXEEcho("root:$1$salt$hash:18000:0:99999:7:::") {
		t.Error("expected true for /etc/shadow pattern with $1$")
	}
}

func TestCheckXXEEcho_LinuxUserInfo(t *testing.T) {
	if !CheckXXEEcho("uid=0(root) gid=0(root) groups=0(root)") {
		t.Error("expected true for Linux user info pattern")
	}
}

func TestCheckXXEEcho_WindowsDir(t *testing.T) {
	if !CheckXXEEcho("Volume in drive C is Windows") {
		t.Error("expected true for Windows dir pattern")
	}
}

func TestCheckXXEEcho_NoMatch(t *testing.T) {
	if CheckXXEEcho("Hello World") {
		t.Error("expected false for non-matching body")
	}
	if CheckXXEEcho("") {
		t.Error("expected false for empty body")
	}
}

func TestIsXMLContentType(t *testing.T) {
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
		{"APPLICATION/XML", true}, // case-insensitive
		{"Text/Xml", true},        // case-insensitive
	}
	for _, tt := range tests {
		result := isXMLContentType(tt.ct)
		if result != tt.expected {
			t.Errorf("isXMLContentType(%q) = %v, expected %v", tt.ct, result, tt.expected)
		}
	}
}

func TestGetBlindXXEPayloads(t *testing.T) {
	payloads := GetBlindXXEPayloads("http://callback.example.com")
	if len(payloads) != 2 {
		t.Fatalf("expected 2 blind XXE payloads, got %d", len(payloads))
	}
	for i, p := range payloads {
		if p == "" {
			t.Errorf("payload[%d] should not be empty", i)
		}
	}
}

func TestGetBlindXXEPayloads_EmptyCallback(t *testing.T) {
	payloads := GetBlindXXEPayloads("")
	if len(payloads) != 2 {
		t.Fatalf("expected 2 payloads, got %d", len(payloads))
	}
}

func TestGetSOAPXXEPayloads(t *testing.T) {
	payloads := GetSOAPXXEPayloads("http://callback.example.com")
	if len(payloads) != 2 {
		t.Fatalf("expected 2 SOAP XXE payloads, got %d", len(payloads))
	}
	for i, p := range payloads {
		if p == "" {
			t.Errorf("payload[%d] should not be empty", i)
		}
	}
}

func TestGetSVGXXEPayloads(t *testing.T) {
	payloads := GetSVGXXEPayloads("http://callback.example.com")
	if len(payloads) != 1 {
		t.Fatalf("expected 1 SVG XXE payload, got %d", len(payloads))
	}
	if payloads[0] == "" {
		t.Error("payload should not be empty")
	}
}

func TestGetXIncludeXXEPayloads(t *testing.T) {
	payloads := GetXIncludeXXEPayloads("http://callback.example.com")
	if len(payloads) != 1 {
		t.Fatalf("expected 1 XInclude XXE payload, got %d", len(payloads))
	}
	if payloads[0] == "" {
		t.Error("payload should not be empty")
	}
}

func TestXXE_DefaultConfig(t *testing.T) {
	p := &XXE{}
	cfg := p.DefaultConfig()
	if cfg == nil {
		t.Fatal("expected non-nil DefaultConfig")
	}
	bc := cfg.BaseConfig()
	if bc.Name != "xxe" {
		t.Errorf("expected Name 'xxe', got '%s'", bc.Name)
	}
	if !bc.Enabled {
		t.Error("expected Enabled=true")
	}
}

func TestXXE_Close(t *testing.T) {
	p := &XXE{}
	if err := p.Close(); err != nil {
		t.Errorf("expected nil error from Close, got %v", err)
	}
}

func TestXXE_Fingers(t *testing.T) {
	p := &XXE{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()
	fingers := p.Fingers()
	if len(fingers) != 1 {
		t.Fatalf("expected 1 finger, got %d", len(fingers))
	}
	f := fingers[0]
	if f.CheckAction == nil {
		t.Error("CheckAction should not be nil")
	}
	if f.Binding == nil {
		t.Error("Binding should not be nil")
	}
	if f.Binding.ID != "xxe/dispatcher/default" {
		t.Errorf("expected Binding.ID 'xxe/dispatcher/default', got '%s'", f.Binding.ID)
	}
	if !f.NeedReverse {
		t.Error("XXE finger should need reverse")
	}
	if f.Channel != "web-generic" {
		t.Errorf("expected Channel 'web-generic', got '%s'", f.Channel)
	}
}

func TestXXE_ConfigBaseConfig(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "xxe",
			Enabled: true,
		},
	}
	bc := cfg.BaseConfig()
	if bc.Name != "xxe" {
		t.Errorf("expected Name 'xxe', got '%s'", bc.Name)
	}
}

func TestXXE_GetConfig_BeforeInit(t *testing.T) {
	p := &XXE{}
	cfg := p.GetConfig()
	if cfg != nil {
		t.Errorf("expected nil config before Init, got %v", cfg)
	}
}

func TestXXE_Fingers_ChannelAndSeverity(t *testing.T) {
	p := &XXE{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()
	fingers := p.Fingers()
	if len(fingers) == 0 {
		t.Fatal("expected at least one finger")
	}
	f := fingers[0]
	if f.Channel != "web-generic" {
		t.Errorf("expected Channel 'web-generic', got '%s'", f.Channel)
	}
	if f.Binding.Severity != model.SeverityCritical {
		t.Errorf("expected SeverityCritical, got %v", f.Binding.Severity)
	}
}
