package elinject

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"wscan/core/plugins/base"
)

func TestELInject_Close(t *testing.T) {
	p := &ELInject{}
	if err := p.Close(); err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
}

func TestELInject_DefaultConfig(t *testing.T) {
	p := &ELInject{}
	cfg := p.DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig() returned nil")
	}

	typedCfg, ok := cfg.(*Config)
	if !ok {
		t.Fatal("DefaultConfig() did not return *Config")
	}
	if typedCfg.PluginBaseConfig.Name != "el-injection" {
		t.Errorf("Expected Name='el-injection', got '%s'", typedCfg.PluginBaseConfig.Name)
	}
	if !typedCfg.PluginBaseConfig.Enabled {
		t.Error("Expected Enabled=true")
	}
}

func TestConfig_BaseConfig(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "el-injection",
			Enabled: true,
		},
	}
	bc := cfg.BaseConfig()
	if bc == nil {
		t.Fatal("BaseConfig() returned nil")
	}
	if bc.Name != "el-injection" {
		t.Errorf("Expected Name='el-injection', got '%s'", bc.Name)
	}
}

func TestELInject_GetConfig(t *testing.T) {
	p := &ELInject{}
	// Before Init
	cfg := p.GetConfig()
	if cfg != nil {
		t.Errorf("Expected nil config before Init, got %v", cfg)
	}

	// After Init
	expectedCfg := p.DefaultConfig()
	ab := &base.ApolloBase{}
	p.Init(context.Background(), expectedCfg, ab)

	cfg = p.GetConfig()
	if cfg == nil {
		t.Fatal("Expected non-nil config after Init")
	}
}

func TestELInject_Fingers(t *testing.T) {
	p := &ELInject{}
	cfg := p.DefaultConfig()
	ab := &base.ApolloBase{}
	p.Init(context.Background(), cfg, ab)

	fingers := p.Fingers()
	if len(fingers) != 1 {
		t.Errorf("Expected 1 finger, got %d", len(fingers))
	}
	if fingers[0].Binding.ID != "el_injection" {
		t.Errorf("Expected Binding.ID='el_injection', got '%s'", fingers[0].Binding.ID)
	}
	if fingers[0].Channel != "web-generic" {
		t.Errorf("Expected Channel='web-generic', got '%s'", fingers[0].Channel)
	}
	if fingers[0].Binding.Severity != "critical" {
		t.Errorf("Expected Severity='critical', got '%s'", fingers[0].Binding.Severity)
	}
	if fingers[0].CheckAction == nil {
		t.Error("CheckAction should not be nil")
	}
	if fingers[0].ExecAction == nil {
		t.Error("ExecAction should not be nil")
	}
}

func TestGenELInjectionPayloads(t *testing.T) {
	addPayloads, subPayloads, antiFP := genELInjectionPayloads()

	// Should generate 2 add payloads (${} and #{})
	if len(addPayloads) != 2 {
		t.Errorf("Expected 2 add payloads, got %d", len(addPayloads))
	}
	// Should generate 2 sub payloads (${} and #{})
	if len(subPayloads) != 2 {
		t.Errorf("Expected 2 sub payloads, got %d", len(subPayloads))
	}

	// Verify add payloads contain correct syntax
	for i, p := range addPayloads {
		if i == 0 && !strings.HasPrefix(p.Payload, "${") {
			t.Errorf("First add payload should start with '${', got: %s", p.Payload)
		}
		if i == 1 && !strings.HasPrefix(p.Payload, "#{") {
			t.Errorf("Second add payload should start with '#{', got: %s", p.Payload)
		}
		if !strings.Contains(p.Payload, "+") {
			t.Errorf("Add payload should contain '+', got: %s", p.Payload)
		}
		if p.VerifyResult == "" {
			t.Errorf("VerifyResult should not be empty for payload: %s", p.Payload)
		}
		// VerifyResult should be numeric
		for _, c := range p.VerifyResult {
			if c < '0' || c > '9' {
				t.Errorf("Add VerifyResult should be numeric, got: %s", p.VerifyResult)
				break
			}
		}
	}

	// Verify sub payloads contain correct syntax
	for i, p := range subPayloads {
		if i == 0 && !strings.HasPrefix(p.Payload, "${") {
			t.Errorf("First sub payload should start with '${', got: %s", p.Payload)
		}
		if i == 1 && !strings.HasPrefix(p.Payload, "#{") {
			t.Errorf("Second sub payload should start with '#{', got: %s", p.Payload)
		}
		if !strings.Contains(p.Payload, "-") {
			t.Errorf("Sub payload should contain '-', got: %s", p.Payload)
		}
		if p.VerifyResult == "" {
			t.Errorf("VerifyResult should not be empty for payload: %s", p.Payload)
		}
	}

	// Verify anti-false-positive payload
	if antiFP.Payload != "${0+0}" {
		t.Errorf("AntiFP payload should be '${0+0}', got: %s", antiFP.Payload)
	}
}

func TestGenELInjectionPayloads_Arithmetic(t *testing.T) {
	// Verify the arithmetic is correct for multiple iterations
	for i := 0; i < 5; i++ {
		addPayloads, subPayloads, antiFP := genELInjectionPayloads()

		// Add: verifyResult should match the sum
		// Extract numbers from payload like "${9999123+9999456}"
		for _, p := range addPayloads {
			// The payload format is like ${num1+num2} or #{num1+num2}
			// Strip the prefix and suffix
			inner := p.Payload[2 : len(p.Payload)-1] // Remove ${ and }
			parts := strings.SplitN(inner, "+", 2)
			if len(parts) != 2 {
				t.Errorf("Could not parse add payload: %s", p.Payload)
				continue
			}
			num1, num2 := 0, 0
			fmt.Sscanf(parts[0], "%d", &num1)
			fmt.Sscanf(parts[1], "%d", &num2)
			expected := fmt.Sprintf("%d", num1+num2)
			if p.VerifyResult != expected {
				t.Errorf("Add arithmetic wrong: %d+%d=%s, but VerifyResult=%s", num1, num2, expected, p.VerifyResult)
			}
		}

		// Sub: verifyResult should match the difference
		for _, p := range subPayloads {
			inner := p.Payload[2 : len(p.Payload)-1]
			parts := strings.SplitN(inner, "-", 2)
			if len(parts) != 2 {
				t.Errorf("Could not parse sub payload: %s", p.Payload)
				continue
			}
			num1, num2 := 0, 0
			fmt.Sscanf(parts[0], "%d", &num1)
			fmt.Sscanf(parts[1], "%d", &num2)
			expected := fmt.Sprintf("%d", num1-num2)
			if p.VerifyResult != expected {
				t.Errorf("Sub arithmetic wrong: %d-%d=%s, but VerifyResult=%s", num1, num2, expected, p.VerifyResult)
			}
		}

		// AntiFP: verifyResult should not be "0"
		if antiFP.VerifyResult == "0" {
			t.Error("AntiFP VerifyResult should not be '0'")
		}
	}
}

func TestGenELInjectionPayloads_NumbersInRange(t *testing.T) {
	for i := 0; i < 5; i++ {
		addPayloads, _, _ := genELInjectionPayloads()
		for _, p := range addPayloads {
			inner := p.Payload[2 : len(p.Payload)-1]
			parts := strings.SplitN(inner, "+", 2)
			num1, num2 := 0, 0
			fmt.Sscanf(parts[0], "%d", &num1)
			fmt.Sscanf(parts[1], "%d", &num2)
			// Numbers should be in range 9999000-9999999 (approximately)
			if num1 < 9999000 || num1 > 9999999 {
				t.Errorf("num1 should be in range 9999000-9999999, got %d", num1)
			}
			if num2 < 9999000 || num2 > 9999999 {
				t.Errorf("num2 should be in range 9999000-9999999, got %d", num2)
			}
		}
	}
}

func TestELPayload_Struct(t *testing.T) {
	p := ELPayload{
		Payload:      "${9999123+9999456}",
		VerifyResult: "19998579",
	}
	if p.Payload != "${9999123+9999456}" {
		t.Errorf("Payload = %q, want '${9999123+9999456}'", p.Payload)
	}
	if p.VerifyResult != "19998579" {
		t.Errorf("VerifyResult = %q, want '19998579'", p.VerifyResult)
	}
}
