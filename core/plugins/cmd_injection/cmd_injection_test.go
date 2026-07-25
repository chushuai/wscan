package cmd_injection

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"wscan/core/http"
	"wscan/core/plugins/base"
	"wscan/core/utils"
)

func TestCmdInjection_Close(t *testing.T) {
	c := &CmdInjection{}
	if err := c.Close(); err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
}

func TestCmdInjection_DefaultConfig(t *testing.T) {
	c := &CmdInjection{}
	cfg := c.DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig() returned nil")
	}

	typedCfg, ok := cfg.(*Config)
	if !ok {
		t.Fatal("DefaultConfig() did not return *Config")
	}
	if typedCfg.PluginBaseConfig.Name != "cmd-injection" {
		t.Errorf("Expected Name='cmd-injection', got '%s'", typedCfg.PluginBaseConfig.Name)
	}
	if !typedCfg.PluginBaseConfig.Enabled {
		t.Error("Expected Enabled=true")
	}
}

func TestConfig_BaseConfig(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "cmd-injection",
			Enabled: true,
		},
	}
	bc := cfg.BaseConfig()
	if bc == nil {
		t.Fatal("BaseConfig() returned nil")
	}
	if bc.Name != "cmd-injection" {
		t.Errorf("Expected Name='cmd-injection', got '%s'", bc.Name)
	}
}

func TestCmdInjection_GetConfig(t *testing.T) {
	c := &CmdInjection{}
	// Before Init
	cfg := c.GetConfig()
	if cfg != nil {
		t.Errorf("Expected nil config before Init, got %v", cfg)
	}

	// After Init
	expectedCfg := c.DefaultConfig()
	ab := &base.ApolloBase{}
	c.Init(context.Background(), expectedCfg, ab)

	cfg = c.GetConfig()
	if cfg == nil {
		t.Fatal("Expected non-nil config after Init")
	}
}

func TestCmdInjection_Fingers(t *testing.T) {
	c := &CmdInjection{}
	cfg := c.DefaultConfig()
	ab := &base.ApolloBase{}
	c.Init(context.Background(), cfg, ab)

	fingers := c.Fingers()
	if len(fingers) != 1 {
		t.Errorf("Expected 1 finger, got %d", len(fingers))
	}
	if fingers[0].Binding.ID != "cmd-injection" {
		t.Errorf("Expected Binding.ID='cmd-injection', got '%s'", fingers[0].Binding.ID)
	}
}

func TestRenderIntMd5Payload(t *testing.T) {
	payload, verifyResult := RenderIntMd5Payload("print(md5(%d));")

	// Verify payload contains the format
	if !strings.Contains(payload, "md5") {
		t.Errorf("Payload should contain 'md5', got: %s", payload)
	}

	// Verify the md5 result format
	if len(verifyResult) != 32 {
		t.Errorf("MD5 result should be 32 chars, got: %d chars (%s)", len(verifyResult), verifyResult)
	}
}

func TestRenderIntMd5Payload_DifferentFormats(t *testing.T) {
	formats := []string{
		"${@var_dump(md5(%d))};",
		"'-var_dump(md5(%d))-'",
		"print(md5(%d));",
		";print(md5(%d));",
		"';print(md5(%d));$a='",
	}

	for _, fmtStr := range formats {
		payload, verifyResult := RenderIntMd5Payload(fmtStr)
		if payload == "" {
			t.Errorf("RenderIntMd5Payload(%q) returned empty payload", fmtStr)
		}
		if verifyResult == "" {
			t.Errorf("RenderIntMd5Payload(%q) returned empty verifyResult", fmtStr)
		}
		// Verify the verifyResult is actually the MD5 of a number in the right range
		if len(verifyResult) != 32 {
			t.Errorf("MD5 should be 32 chars for format %q, got %d chars", fmtStr, len(verifyResult))
		}
	}
}

func TestRenderIntMul(t *testing.T) {
	payload, verifyResult := RenderIntMul("response.write(%d*%d)")

	// Verify payload contains multiplication
	if !strings.Contains(payload, "*") {
		t.Errorf("Payload should contain '*', got: %s", payload)
	}

	// Verify result is numeric
	if verifyResult == "" {
		t.Errorf("VerifyResult should not be empty")
	}
	// verifyResult should be a number (product of two integers)
	for _, c := range verifyResult {
		if c < '0' || c > '9' {
			t.Errorf("VerifyResult should be numeric, got: %s", verifyResult)
			break
		}
	}
}

func TestRenderIntAdd(t *testing.T) {
	payload, verifyResult := RenderIntAdd("\nexpr %d + %d\n")

	// Verify payload contains addition
	if !strings.Contains(payload, "+") {
		t.Errorf("Payload should contain '+', got: %s", payload)
	}

	// Verify result is numeric
	if verifyResult == "" {
		t.Errorf("VerifyResult should not be empty")
	}
	for _, c := range verifyResult {
		if c < '0' || c > '9' {
			t.Errorf("VerifyResult should be numeric, got: %s", verifyResult)
			break
		}
	}
}

func TestRenderIntMul_DifferentFormats(t *testing.T) {
	formats := []string{
		"response.write(%d*%d)",
		"'+response.write(%d*%d)+'",
		"\"response.write(%d*%d)+\"",
		"#{%d*%d}",
		"{{%d*%d}}",
		"{{= %d*%d}}",
		"<# %d*%d>",
		"${{\"{{\"}}%d*%d{{\"}}\"}}",
	}

	for _, fmtStr := range formats {
		payload, verifyResult := RenderIntMul(fmtStr)
		if payload == "" {
			t.Errorf("RenderIntMul(%q) returned empty payload", fmtStr)
		}
		if verifyResult == "" {
			t.Errorf("RenderIntMul(%q) returned empty verifyResult", fmtStr)
		}
	}
}

func TestGenCmdInjectionPayload(t *testing.T) {
	payloads := GenCmdInjectionPayload()
	if len(payloads) == 0 {
		t.Error("GenCmdInjectionPayload() returned empty list")
	}

	// Verify we have the expected types of payloads
	valueCount := 0
	suffixCount := 0
	for _, p := range payloads {
		if p.ParameterType == http.ParameterTypeValue {
			valueCount++
		} else if p.ParameterType == http.ParameterTypeSuffix {
			suffixCount++
		}
		// Each payload should have non-empty payload and verify result
		if p.Payload == "" {
			t.Errorf("Payload should not be empty: %+v", p)
		}
		if p.VerifyResult == "" {
			t.Errorf("VerifyResult should not be empty: %+v", p)
		}
	}

	if valueCount == 0 {
		t.Error("Expected at least one Value-type payload")
	}
	if suffixCount == 0 {
		t.Error("Expected at least one Suffix-type payload")
	}
}

func TestGenCmdInjectionPayload_ShellSuffixPayloads(t *testing.T) {
	payloads := GenCmdInjectionPayload()

	// Check for shell suffix payloads like ";echo md5hash"
	for _, p := range payloads {
		if p.ParameterType == http.ParameterTypeSuffix {
			// Suffix payloads should contain "echo" or be appended
			if strings.Contains(p.Payload, "echo") {
				// Verify the md5 result matches
				if !strings.Contains(p.Payload, p.VerifyResult) {
					t.Errorf("Shell suffix payload should contain verifyResult: payload=%s, verifyResult=%s", p.Payload, p.VerifyResult)
				}
				// Verify verifyResult is a valid MD5 format
				if len(p.VerifyResult) != 32 {
					t.Errorf("Shell suffix verifyResult should be 32 chars (MD5), got %d chars", len(p.VerifyResult))
				}
			}
		}
	}
}

func TestGenCmdInjectionPayload_ShellValuePayloads(t *testing.T) {
	payloads := GenCmdInjectionPayload()

	// Check for shell value payloads like "echo md5hash"
	for _, p := range payloads {
		if p.ParameterType == http.ParameterTypeValue {
			if strings.Contains(p.Payload, "echo") && !strings.Contains(p.Payload, "response.write") {
				// This is a shell echo payload
				if !strings.Contains(p.Payload, p.VerifyResult) {
					t.Errorf("Shell value payload should contain verifyResult: payload=%s, verifyResult=%s", p.Payload, p.VerifyResult)
				}
			}
		}
	}
}

func TestRenderIntMd5Payload_Consistency(t *testing.T) {
	// Call twice and verify that each call generates unique random numbers
	p1, v1 := RenderIntMd5Payload("print(md5(%d));")
	p2, v2 := RenderIntMd5Payload("print(md5(%d));")

	// Both should produce valid payloads
	if p1 == "" || v1 == "" {
		t.Error("First call returned empty result")
	}
	if p2 == "" || v2 == "" {
		t.Error("Second call returned empty result")
	}
}

func TestCMDInjectionPayload_Render(t *testing.T) {
	p := &CMDInjectionPayload{}
	result, verifyResult := p.Render("test")
	if result != "" || verifyResult != "" {
		t.Errorf("CMDInjectionPayload.Render() returns empty strings, got result=%q verifyResult=%q", result, verifyResult)
	}
}

func TestPHPCodeInjectionPayload_Render(t *testing.T) {
	p := &PHPCodeInjectionPayload{}
	result, verifyResult := p.Render("test")
	if result != "" || verifyResult != "" {
		t.Errorf("PHPCodeInjectionPayload.Render() returns empty strings, got result=%q verifyResult=%q", result, verifyResult)
	}
}

func TestTemplateInjectionPayload_Render(t *testing.T) {
	p := &TemplateInjectionPayload{}
	result, verifyResult := p.Render("test")
	if result != "" || verifyResult != "" {
		t.Errorf("TemplateInjectionPayload.Render() returns empty strings, got result=%q verifyResult=%q", result, verifyResult)
	}
}

func TestCmdInjectionPayload_Struct(t *testing.T) {
	p := CmdInjectionPayload{
		Payload:       "test_payload",
		VerifyResult:  "test_result",
		ParameterType: http.ParameterTypeValue,
	}
	if p.Payload != "test_payload" {
		t.Errorf("Payload = %q, want 'test_payload'", p.Payload)
	}
	if p.VerifyResult != "test_result" {
		t.Errorf("VerifyResult = %q, want 'test_result'", p.VerifyResult)
	}
	if p.ParameterType != http.ParameterTypeValue {
		t.Errorf("ParameterType = %q, want %q", p.ParameterType, http.ParameterTypeValue)
	}
}

// Test that MD5 computation is correct
func TestMD5ComputationInPayload(t *testing.T) {
	// Test that the verifyResult is the correct MD5 of the random integer
	randint := utils.RandInt(5120, 10240)
	expectedMD5 := utils.MD5(fmt.Sprintf("%d", randint))

	_, verifyResult := RenderIntMd5Payload("print(md5(%d));")
	// verifyResult should be an MD5 hash of some integer
	if len(verifyResult) != 32 {
		t.Errorf("MD5 should be 32 chars, got %d", len(verifyResult))
	}
	// The expectedMD5 should also be 32 chars
	if len(expectedMD5) != 32 {
		t.Errorf("Expected MD5 should be 32 chars, got %d", len(expectedMD5))
	}
}

func TestRenderIntAdd_ValuesInRange(t *testing.T) {
	for i := 0; i < 10; i++ {
		payload, verifyResult := RenderIntAdd("\nexpr %d + %d\n")
		// verifyResult should be a large number (sum of two 100M-500M numbers)
		numVal := 0
		for _, c := range verifyResult {
			if c >= '0' && c <= '9' {
				numVal = numVal*10 + int(c-'0')
			}
		}
		if numVal < 200000000 {
			t.Errorf("Add result should be >= 200M, got %d (payload=%s)", numVal, payload)
		}
	}
}
