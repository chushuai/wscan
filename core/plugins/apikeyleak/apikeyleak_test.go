/**
* @Author: shaochuyu
* @Date: 6/16/2026
 */
package apikeyleak

import (
	"math"
	"strings"
	"testing"
)

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		input string
		min   float64
		max   float64
	}{
		{"", 0.0, 0.0},
		{"aaaa", 0.0, 0.01},
		{"1111", 0.0, 0.01},
		{"0101", 0.99, 1.01},
		{"AKIAIOSFODNN7EXAMPLE", 3.0, 5.0},
		{"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", 3.0, 6.0},
		{"hello world", 2.0, 4.0},
	}
	for _, tt := range tests {
		ent := shannonEntropy(tt.input)
		if ent < tt.min || ent > tt.max {
			t.Errorf("shannonEntropy(%q) = %f, want between %f and %f", tt.input, ent, tt.min, tt.max)
		}
	}
}

func TestShannonEntropyFormula(t *testing.T) {
	ent := shannonEntropy("ab")
	if math.Abs(ent-1.0) > 0.001 {
		t.Errorf("shannonEntropy(\"ab\") = %f, want 1.0", ent)
	}
	ent = shannonEntropy("abcd")
	if math.Abs(ent-2.0) > 0.001 {
		t.Errorf("shannonEntropy(\"abcd\") = %f, want 2.0", ent)
	}
}

func TestMaskValue(t *testing.T) {
	tests := []struct {
		input  string
		expect string
	}{
		{"AKIAIOSFODNN7EXAMPLE", "AKIA************MPLE"}, // len 20: first4 + 12stars + last4
		{"short", "*****"},         // len 5 <= 8: all stars
		{"12345678", "********"},   // len 8 <= 8: all stars
		{"123456789", "1234*6789"}, // len 9: first4 + 1star + last4
	}
	for _, tt := range tests {
		result := maskValue(tt.input)
		if result != tt.expect {
			t.Errorf("maskValue(%q) = %q, want %q", tt.input, result, tt.expect)
		}
	}
}

func TestBuildKeyPatterns(t *testing.T) {
	patterns := buildKeyPatterns()
	if len(patterns) < 35 {
		t.Errorf("buildKeyPatterns() returned %d patterns, want at least 35 (AWVS has 40+)", len(patterns))
	}
	for _, pat := range patterns {
		if pat.KeyRegex == "" {
			t.Errorf("pattern %q has empty KeyRegex", pat.Name)
		}
		if pat.ValueRegex == "" {
			t.Errorf("pattern %q has empty ValueRegex", pat.Name)
		}
		if pat.MinEntropy < 0 {
			t.Errorf("pattern %q has negative MinEntropy %f", pat.Name, pat.MinEntropy)
		}
	}
}

func TestGenerateRegexFromKeyNames(t *testing.T) {
	result := generateRegexFromKeyNames([]string{"aws_secret_access_key", "secret_key"})
	if !strings.Contains(result, "[\\_\\-\\.]?") {
		t.Errorf("generateRegexFromKeyNames should replace _ with [\\_\\-\\.]?, got: %s", result)
	}
	if !strings.Contains(result, "|") {
		t.Errorf("generateRegexFromKeyNames should join with |, got: %s", result)
	}
}

func TestLookForSecretKeyLeakage(t *testing.T) {
	patterns := buildKeyPatterns()

	// AWVS secret key values must have exact matching lengths per their regex
	// AWS Secret Key: [0-9a-zA-Z/+]{40} - must be exactly 40 chars
	awsSecretVal := "q5tvxhm4SmxKu0HPolyKQjIkn3u9MgD1wxV795KT" // 40 chars
	// AWS Access Key ID: (A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}
	awsAccessVal := "AKIAIOSFODNN7EXAMPLE" // AKIA + 16 = 20 chars

	tests := []struct {
		name      string
		body      string
		wantMatch bool
		matchName string
	}{
		{
			name:      "AWS Secret Key with = and double quotes",
			body:      "aws_secret_access_key = \"" + awsSecretVal + "\"\n",
			wantMatch: true,
			matchName: "Amazon AWS Secret Key",
		},
		{
			name:      "AWS Access Key ID with = and double quotes",
			body:      "aws_access_key_id = \"" + awsAccessVal + "\"\n",
			wantMatch: true,
			matchName: "Amazon AWS Access Key ID",
		},
		{
			name:      "AWS key in JSON format with colon separator",
			body:      "{\"aws_secret_access_key\": \"" + awsSecretVal + "\"}\n",
			wantMatch: true,
			matchName: "Amazon AWS Secret Key",
		},
		{
			name:      "AWS key in YAML format",
			body:      "aws_secret_access_key: " + awsSecretVal + "\n",
			wantMatch: true,
			matchName: "Amazon AWS Secret Key",
		},
		{
			name: "Stripe API Key live",
			// AWVS Stripe regex: ((?:r|s)k_live_[0-9a-zA-Z]{24}) = 32 chars total (sk_live_ = 8 + 24)
			body:      "stripe_api_key = \"sk_live_abc123def456ghi789jkl012\"\n",
			wantMatch: true,
			matchName: "Stripe API Key",
		},
		{
			name:      "No leak - plain text",
			body:      "This is just a normal HTML page with no secrets.\n",
			wantMatch: false,
		},
		{
			name:      "AWS key without key name (standalone) - should NOT match (AWVS requires key name)",
			body:      "config: " + awsSecretVal + "\n",
			wantMatch: false, // AWVS only does combined key+value, no standalone
		},
		{
			name:      "Mismatched quotes - should NOT match",
			body:      "aws_secret_access_key = \"" + awsSecretVal + "'\n",
			wantMatch: false, // AWVS backreference requires matching quotes
		},
		{
			name:      "Low entropy value should be filtered",
			body:      "aws_secret_access_key = \"aaaaaaaaaa1bbbbbbbbbb2cccccccccc3dddddddddd4\"\n",
			wantMatch: false, // entropy too low
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := lookForSecretKeyLeakage(tt.body, patterns, 3.0)
			if tt.wantMatch {
				found := false
				for _, f := range findings {
					if f.Name == tt.matchName {
						found = true
						break
					}
				}
				if !found {
					var names []string
					for _, f := range findings {
						names = append(names, f.Name)
					}
					t.Errorf("lookForSecretKeyLeakage() missing expected match %q in body %q (got findings: %v)", tt.matchName, tt.body, names)
				}
			} else {
				if len(findings) > 0 {
					var names []string
					for _, f := range findings {
						names = append(names, f.Name+": "+f.MaskedValue)
					}
					t.Errorf("lookForSecretKeyLeakage() found unexpected matches in body %q: %v", tt.body, names)
				}
			}
		})
	}
}

func TestExclusions(t *testing.T) {
	patterns := buildKeyPatterns()

	// connection_strings_exclusions should exclude test credentials in DB connection strings
	body := "db_url = \"postgresql://db_user:db_password@localhost:5432/testdb\"\n"
	findings := lookForSecretKeyLeakage(body, patterns, 3.0)
	for _, f := range findings {
		if f.Name == "Database Connection String" {
			t.Errorf("db_user/db_password should be excluded from Database Connection String, but got: %v", f)
		}
	}

	// Slack Webhook exclusions
	body = "webhook = \"https://hooks.slack.com/services/T12345678/B98765432/ABC123DEF456GHI789000XXX\"\n"
	findings = lookForSecretKeyLeakage(body, patterns, 3.0)
	for _, f := range findings {
		if f.Name == "Slack Webhook" {
			t.Errorf("Slack example webhook should be excluded, but got: %v", f)
		}
	}
}

func TestEntropyFiltering(t *testing.T) {
	patterns := buildKeyPatterns()
	body := "aws_secret_access_key = \"aaaaaaaaaa1bbbbbbbbbb2cccccccccc3dddddddddd4\"\n"
	findings := lookForSecretKeyLeakage(body, patterns, 3.0)
	for _, f := range findings {
		if f.Name == "Amazon AWS Secret Key" {
			t.Errorf("low-entropy value should have been filtered, but got finding: %+v", f)
		}
	}
}

func TestQuotePairing(t *testing.T) {
	patterns := buildKeyPatterns()
	awsSecretVal := "q5tvxhm4SmxKu0HPolyKQjIkn3u9MgD1wxV795KT"

	// Matching quotes should work
	body := "aws_secret_access_key = \"" + awsSecretVal + "\"\n"
	findings := lookForSecretKeyLeakage(body, patterns, 3.0)
	found := false
	for _, f := range findings {
		if f.Name == "Amazon AWS Secret Key" {
			found = true
		}
	}
	if !found {
		t.Errorf("Matching double quotes should produce a finding")
	}

	// Mismatched quotes should NOT match (AWVS backreference)
	body = "aws_secret_access_key = \"" + awsSecretVal + "'\n"
	findings = lookForSecretKeyLeakage(body, patterns, 3.0)
	for _, f := range findings {
		if f.Name == "Amazon AWS Secret Key" {
			t.Errorf("Mismatched quotes should not produce a finding (AWVS backreference), got: %+v", f)
		}
	}
}

func TestCommaSeparator(t *testing.T) {
	patterns := buildKeyPatterns()
	awsSecretVal := "q5tvxhm4SmxKu0HPolyKQjIkn3u9MgD1wxV795KT"
	// AWVS supports comma as separator [=:\s,]
	body := "aws_secret_access_key, " + awsSecretVal + "\n"
	findings := lookForSecretKeyLeakage(body, patterns, 3.0)
	found := false
	for _, f := range findings {
		if f.Name == "Amazon AWS Secret Key" {
			found = true
		}
	}
	if !found {
		t.Errorf("Comma separator should be supported (AWVS: [=:\\s,])")
	}
}
