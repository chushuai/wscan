package xss

import (
	"testing"

	"wscan/core/plugins/base"
)

func TestXSS_DefaultConfig(t *testing.T) {
	x := &XSS{}
	cfg := x.DefaultConfig()
	if cfg == nil {
		t.Fatal("expected non-nil DefaultConfig")
	}
	bc := cfg.BaseConfig()
	if bc.Name != "xss" {
		t.Errorf("expected Name 'xss', got '%s'", bc.Name)
	}
	if !bc.Enabled {
		t.Error("expected Enabled=true")
	}
}

func TestXSS_Close(t *testing.T) {
	x := &XSS{}
	if err := x.Close(); err != nil {
		t.Errorf("expected nil error from Close, got %v", err)
	}
}

func TestXSS_Fingers_NoConfig(t *testing.T) {
	x := &XSS{}
	fingers := x.Fingers()
	// Without Init, only the main XSS finger is registered
	if len(fingers) < 1 {
		t.Error("expected at least one finger (main XSS)")
	}
}

func TestXSS_Fingers_AllEnabled(t *testing.T) {
	x := &XSS{}
	x.PluginMixinInitConfig.Config = &Config{
		PluginBaseConfig:   base.PluginBaseConfig{Name: "xss", Enabled: true},
		DetectXSSInCookie:  true,
		DetectXSSInReferer: true,
		IEFeature:          true,
	}
	fingers := x.Fingers()
	if len(fingers) < 4 {
		t.Errorf("expected at least 4 fingers (main + cookie + referer + ie), got %d", len(fingers))
	}
}

func TestXSS_Fingers_CookieOnly(t *testing.T) {
	x := &XSS{}
	x.PluginMixinInitConfig.Config = &Config{
		PluginBaseConfig:   base.PluginBaseConfig{Name: "xss", Enabled: true},
		DetectXSSInCookie:  true,
		DetectXSSInReferer: false,
		IEFeature:          false,
	}
	fingers := x.Fingers()
	foundCookie := false
	foundReferer := false
	foundIE := false
	for _, f := range fingers {
		if f.Binding != nil {
			switch f.Binding.ID {
			case "xss/reflected/cookie":
				foundCookie = true
			case "xss/reflected/referer":
				foundReferer = true
			case "xss/reflected/ie-feature":
				foundIE = true
			}
		}
	}
	if !foundCookie {
		t.Error("expected cookie XSS finger to be registered")
	}
	if foundReferer {
		t.Error("expected referer XSS finger NOT to be registered")
	}
	if foundIE {
		t.Error("expected IE feature XSS finger NOT to be registered")
	}
}

func TestXSS_ConfigBaseConfig(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{Name: "xss", Enabled: true},
	}
	bc := cfg.BaseConfig()
	if bc.Name != "xss" {
		t.Errorf("expected Name 'xss', got '%s'", bc.Name)
	}
}

func TestXSS_execAction(t *testing.T) {
	x := &XSS{}
	err := x.execAction(nil, nil)
	if err != nil {
		t.Errorf("expected nil error from execAction, got %v", err)
	}
}

func TestXSS_Scan(t *testing.T) {
	x := &XSS{}
	scanFn := x.Scan()
	if scanFn != nil {
		t.Error("expected nil Scan function")
	}
}

func TestSearchInputInResponse_Comprehensive(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		body         string
		expectMinLen int
	}{
		{"in div", "test123", `<div>test123</div>`, 1},
		{"in attribute value", "test123", `<div class="test123">hello</div>`, 1},
		{"not found", "test123", `<div>hello</div>`, 0},
		{"in script tag", "test123", `<script>var x = "test123"</script>`, 1},
		{"in attribute key", "test123", `<div test123="value">hello</div>`, 1},
		{"in style tag", "test123", `<style>.test123 { color: red; }</style>`, 1},
		{"exact tag match", "div", `<div>hello</div>`, 1},
		{"nested elements", "inner", `<div><span>inner</span></div>`, 1},
		{"empty body", "test", "", 0},
		{"html entity", "test", `<div>&amp;test</div>`, 0},
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

func TestSearchInputInResponse_OccurrenceTypes(t *testing.T) {
	// Test that occurrences have correct Type field
	tests := []struct {
		name         string
		input        string
		body         string
		expectedType string
	}{
		{"intag", "mytag", `<mytag>content</mytag>`, "intag"},
		{"html in div", "marker", `<div>marker</div>`, "html"},
		{"script", "marker", `<script>marker</script>`, "script"},
		{"attribute key", "marker", `<div marker="val">text</div>`, "attribute"},
		{"attribute value", "marker", `<div class="marker">text</div>`, "attribute"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SearchInputInResponse(tt.input, tt.body)
			found := false
			for _, occ := range result {
				if occ.Type == tt.expectedType {
					found = true
					break
				}
			}
			if !found {
				types := make([]string, len(result))
				for i, occ := range result {
					types[i] = occ.Type
				}
				t.Errorf("expected occurrence with type '%s', got types: %v", tt.expectedType, types)
			}
		})
	}
}

func TestCookieXSS_Finger(t *testing.T) {
	c := &cookieXSS{}
	finger := c.Finger()
	if finger == nil {
		t.Fatal("expected non-nil finger")
	}
	if finger.Channel != "web-generic" {
		t.Errorf("expected Channel 'web-generic', got '%s'", finger.Channel)
	}
	if finger.Binding == nil {
		t.Fatal("expected non-nil Binding")
	}
	if finger.Binding.ID != "xss/reflected/cookie" {
		t.Errorf("expected Binding.ID 'xss/reflected/cookie', got '%s'", finger.Binding.ID)
	}
	if finger.CheckAction == nil {
		t.Error("expected non-nil CheckAction")
	}
}

func TestRefererXSS_Finger(t *testing.T) {
	r := &refererXSS{}
	finger := r.Finger()
	if finger == nil {
		t.Fatal("expected non-nil finger")
	}
	if finger.Channel != "web-generic" {
		t.Errorf("expected Channel 'web-generic', got '%s'", finger.Channel)
	}
	if finger.Binding == nil {
		t.Fatal("expected non-nil Binding")
	}
	if finger.Binding.ID != "xss/reflected/referer" {
		t.Errorf("expected Binding.ID 'xss/reflected/referer', got '%s'", finger.Binding.ID)
	}
	if finger.CheckAction == nil {
		t.Error("expected non-nil CheckAction")
	}
}

func TestParseCookieHeader(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		expected int
	}{
		{"single cookie", "name=value", 1},
		{"multiple cookies", "name1=value1; name2=value2", 2},
		{"empty header", "", 0},
		{"cookie with spaces", "name1=value1;  name2=value2", 2},
		{"no value", "name", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pairs := parseCookieHeader(tt.header)
			if len(pairs) != tt.expected {
				t.Errorf("expected %d pairs, got %d", tt.expected, len(pairs))
			}
		})
	}
}

func TestParseCookieHeader_Keys(t *testing.T) {
	pairs := parseCookieHeader("session=abc123; user=john")
	if len(pairs) != 2 {
		t.Fatalf("expected 2 pairs, got %d", len(pairs))
	}
	if pairs[0].Key != "session" || pairs[0].Value != "abc123" {
		t.Errorf("expected first pair (session, abc123), got (%s, %s)", pairs[0].Key, pairs[0].Value)
	}
	if pairs[1].Key != "user" || pairs[1].Value != "john" {
		t.Errorf("expected second pair (user, john), got (%s, %s)", pairs[1].Key, pairs[1].Value)
	}
}

func TestReplaceCookieValue(t *testing.T) {
	result := replaceCookieValue("session=abc123; user=john", "session", "newvalue")
	if result != "session=newvalue;  user=john" {
		t.Errorf("expected 'session=newvalue;  user=john', got '%s'", result)
	}
}

func TestReplaceCookieValue_NotFound(t *testing.T) {
	result := replaceCookieValue("session=abc123; user=john", "nonexistent", "newvalue")
	// Should return header with separator normalization
	if result != "session=abc123;  user=john" {
		t.Errorf("expected 'session=abc123;  user=john', got '%s'", result)
	}
}

func TestReplaceCookieValue_SingleCookie(t *testing.T) {
	result := replaceCookieValue("session=abc123", "session", "newvalue")
	if result != "session=newvalue" {
		t.Errorf("expected 'session=newvalue', got '%s'", result)
	}
}

func TestIEPayloads(t *testing.T) {
	if len(iePayloads) == 0 {
		t.Fatal("expected at least one IE payload")
	}
	for i, p := range iePayloads {
		if p.Description == "" {
			t.Errorf("payload[%d]: Description should not be empty", i)
		}
		if p.Payload == "" {
			t.Errorf("payload[%d]: Payload should not be empty", i)
		}
		if p.Type == "" {
			t.Errorf("payload[%d]: Type should not be empty", i)
		}
	}
}

func TestOccurrenceStruct(t *testing.T) {
	occ := Occurrence{
		Type:     "html",
		Position: 0,
		Details:  map[string]any{"tagname": "div"},
	}
	if occ.Type != "html" {
		t.Errorf("expected Type 'html', got '%s'", occ.Type)
	}
}
