package path_traversal

import (
	"regexp"
	"testing"

	"wscan/core/plugins/base"
)

func TestIsValueReplacePayload(t *testing.T) {
	tests := []struct {
		name     string
		vector   string
		expected bool
	}{
		{"php://filter", "php://filter/read=convert.base64-encode/resource=index.php", true},
		{"php://input", "php://input", true},
		{"file:/// with three slashes", "file:///etc/passwd", true},
		{"file:// with two slashes", "file://etc/passwd", true},
		{"regular path traversal", "../../etc/passwd", false},
		{"absolute path", "/etc/passwd", false},
		{"empty string", "", false},
		{"http URL", "http://example.com", false},
		{"null byte", "/etc/passwd%00", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValueReplacePayload(tt.vector)
			if result != tt.expected {
				t.Errorf("isValueReplacePayload(%q) = %v, want %v", tt.vector, result, tt.expected)
			}
		})
	}
}

func TestPathTraversalRulesLoaded(t *testing.T) {
	if len(pathTraversalRules) == 0 {
		t.Error("Expected pathTraversalRules to be loaded by init(), got empty list")
	}
}

func TestPathTraversalRulesHaveCompiledRegex(t *testing.T) {
	for i, rule := range pathTraversalRules {
		if rule.compiled == nil {
			t.Errorf("Rule[%d] has nil compiled regex", i)
		}
	}
}

func TestPathTraversalRulesHaveType(t *testing.T) {
	for i, rule := range pathTraversalRules {
		if rule.typ == "" {
			t.Errorf("Rule[%d] has empty type", i)
		}
		if rule.typ != "LFI" && rule.typ != "RFI" && rule.typ != "FI" {
			t.Errorf("Rule[%d] has unexpected type '%s'", i, rule.typ)
		}
	}
}

func TestPathTraversalRulesLFIMatch(t *testing.T) {
	for _, rule := range pathTraversalRules {
		if rule.Vector == "/etc/passwd" && rule.typ == "LFI" {
			if !rule.compiled.MatchString("root:x:0:0:root:/root:/bin/bash") {
				t.Errorf("LFI rule for /etc/passwd should match 'root:x:0:0:root:/root:/bin/bash'")
			}
			if rule.compiled.MatchString("nothing interesting here") {
				t.Errorf("LFI rule for /etc/passwd should not match 'nothing interesting here'")
			}
			return
		}
	}
}

func TestPathTraversalRulesBootIniMatch(t *testing.T) {
	for _, rule := range pathTraversalRules {
		if rule.Vector == "c:/boot.ini" {
			if !rule.compiled.MatchString("boot loader") {
				t.Errorf("Windows rule for c:/boot.ini should match 'boot loader'")
			}
			if rule.Windows != 1 {
				t.Errorf("Windows rule for c:/boot.ini should have Windows=1, got %d", rule.Windows)
			}
			return
		}
	}
}

func TestPathTraversalRulesPHPFilter(t *testing.T) {
	for _, rule := range pathTraversalRules {
		if rule.Vector == "php://filter/read=convert.base64-encode/resource=" {
			if rule.typ != "LFI" {
				t.Errorf("php://filter rule should be LFI type, got '%s'", rule.typ)
			}
			if rule.compiled == nil {
				t.Error("php://filter rule should have compiled regex")
			}
			return
		}
	}
}

func TestPathTraversalRulesFileProtocol(t *testing.T) {
	for _, rule := range pathTraversalRules {
		if rule.Vector == "file:///etc/passwd" {
			if rule.typ != "LFI" {
				t.Errorf("file:///etc/passwd rule should be LFI type, got '%s'", rule.typ)
			}
			if rule.compiled == nil {
				t.Error("file:///etc/passwd rule should have compiled regex")
			}
			return
		}
	}
}

func TestGetConfigPathTraversal(t *testing.T) {
	pt := &PathTraversal{}
	// Before Init
	cfg := pt.GetConfig()
	if cfg != nil {
		t.Errorf("Expected nil config before Init, got %v", cfg)
	}

	// After Init
	expectedCfg := pt.DefaultConfig()
	ab := &base.ApolloBase{}
	pt.Init(nil, expectedCfg, ab)

	cfg = pt.GetConfig()
	if cfg == nil {
		t.Fatal("Expected non-nil config after Init")
	}
	bc := cfg.BaseConfig()
	if bc.Name != "path_traversal" {
		t.Errorf("Expected Name='path_traversal', got '%s'", bc.Name)
	}
}

func TestInitPathTraversal(t *testing.T) {
	pt := &PathTraversal{}
	cfg := pt.DefaultConfig()
	ab := &base.ApolloBase{}

	err := pt.Init(nil, cfg, ab)
	if err != nil {
		t.Errorf("Init() returned error: %v", err)
	}
}

func TestRuleStructFields(t *testing.T) {
	r := Rule{
		Vector:  "/etc/passwd",
		Windows: 0,
		Linux:   1,
		Data:    "root:x:0:0:root:/root:/bin/bash",
	}
	if r.Vector != "/etc/passwd" {
		t.Errorf("Expected Vector='/etc/passwd', got '%s'", r.Vector)
	}
	if r.Windows != 0 {
		t.Errorf("Expected Windows=0, got %d", r.Windows)
	}
	if r.Linux != 1 {
		t.Errorf("Expected Linux=1, got %d", r.Linux)
	}
	if r.Data != "root:x:0:0:root:/root:/bin/bash" {
		t.Errorf("Expected Data to match, got '%s'", r.Data)
	}
}

func TestPathTraversalRulesRegexCompiles(t *testing.T) {
	for _, rule := range pathTraversalRules {
		// Just ensure it doesn't panic
		_ = rule.compiled.MatchString("")
		_ = rule.compiled.MatchString("some random response text")
		_ = rule.compiled.Match([]byte("some random response text"))
	}
}

func TestRuleCompiledType(t *testing.T) {
	var r Rule
	// Test that the compiled field starts as nil
	if r.compiled != nil {
		t.Error("Expected compiled to start as nil")
	}
	// Compile a regex and assign
	compiled, err := regexp.Compile("root:x:0:0")
	if err != nil {
		t.Fatalf("Failed to compile regex: %v", err)
	}
	r.compiled = compiled
	if r.compiled == nil {
		t.Error("Expected compiled to be non-nil after assignment")
	}
}

func TestPathTraversalRulesHaveVectors(t *testing.T) {
	for i, rule := range pathTraversalRules {
		if rule.Vector == "" && rule.typ != "FI" {
			t.Errorf("Rule[%d] has empty Vector", i)
		}
	}
}

func TestPathTraversalLFIRulesCount(t *testing.T) {
	lfiCount := 0
	for _, rule := range pathTraversalRules {
		if rule.typ == "LFI" {
			lfiCount++
		}
	}
	if lfiCount == 0 {
		t.Error("Expected at least one LFI rule")
	}
}

func TestPathTraversalLinuxRulesHaveLinuxFlag(t *testing.T) {
	for _, rule := range pathTraversalRules {
		if rule.Linux == 1 && rule.typ == "LFI" {
			// Good - Linux rules should have Linux=1
			return
		}
	}
	t.Error("Expected at least one LFI rule with Linux=1")
}

func TestPathTraversalRulesMatchEtcPasswd(t *testing.T) {
	// Test various /etc/passwd vectors
	foundEtcPasswd := false
	for _, rule := range pathTraversalRules {
		if rule.Vector == "../../../../../../../../../../../../../../../../../etc/passwd" {
			foundEtcPasswd = true
			if !rule.compiled.MatchString("root:x:0:0:root:/root:/bin/bash") {
				t.Error("Expected traversal rule to match /etc/passwd pattern")
			}
		}
	}
	if !foundEtcPasswd {
		t.Log("Note: Deep traversal /etc/passwd rule not found; skipping exact check")
	}
}

func TestPathTraversalRulesMatchShells(t *testing.T) {
	for _, rule := range pathTraversalRules {
		if rule.Vector == "../../../../../../../../../../../../../../etc/shells" {
			if !rule.compiled.MatchString("# /etc/shells") {
				t.Error("Expected shells rule to match /etc/shells pattern")
			}
			return
		}
	}
}

func TestPathTraversalRulesMatchAccessLog(t *testing.T) {
	for _, rule := range pathTraversalRules {
		if rule.Vector == "/var/log/apache2/access.log" {
			if !rule.compiled.MatchString(`"GET / HTTP/1.1" 200 1234`) {
				t.Error("Expected access log rule to match apache log pattern")
			}
			return
		}
	}
}

func TestPathTraversalRulesMatchProcEnviron(t *testing.T) {
	for _, rule := range pathTraversalRules {
		if rule.Vector == "/proc/self/environ" {
			if !rule.compiled.MatchString("XDG_SESSION_ID=123") {
				t.Error("Expected /proc/self/environ rule to match pattern")
			}
			return
		}
	}
}
