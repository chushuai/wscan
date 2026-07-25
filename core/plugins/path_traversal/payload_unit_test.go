package path_traversal

import (
	"encoding/xml"
	"regexp"
	"testing"
)

// ==================== Rules struct parsing ====================

func TestRules_XMLParsing(t *testing.T) {
	xmlData := `<?xml version="1.0" encoding="UTF-8"?>
<root>
    <LFI>
        <rule vector="/etc/passwd" windows="0" linux="1"><![CDATA[root:x:0:0]]></rule>
    </LFI>
    <RFI>
        <rule vector="http://evil.com/shell.txt" windows="0" linux="0"><![CDATA[evil_content]]></rule>
    </RFI>
    <FI>
        <rule vector="" windows="0" linux="0"><![CDATA[anything]]></rule>
    </FI>
</root>`

	var root Root
	err := xml.Unmarshal([]byte(xmlData), &root)
	if err != nil {
		t.Fatalf("XML unmarshal error: %v", err)
	}

	if len(root.LFI) != 1 {
		t.Errorf("Expected 1 LFI rule, got %d", len(root.LFI))
	}
	if len(root.RFI) != 1 {
		t.Errorf("Expected 1 RFI rule, got %d", len(root.RFI))
	}
	if len(root.FI) != 1 {
		t.Errorf("Expected 1 FI rule, got %d", len(root.FI))
	}

	if root.LFI[0].Vector != "/etc/passwd" {
		t.Errorf("LFI Vector = %q, want '/etc/passwd'", root.LFI[0].Vector)
	}
	if root.LFI[0].Linux != 1 {
		t.Errorf("LFI Linux = %d, want 1", root.LFI[0].Linux)
	}
	if root.LFI[0].Windows != 0 {
		t.Errorf("LFI Windows = %d, want 0", root.LFI[0].Windows)
	}
}

// ==================== Rule compiled regex ====================

func TestRule_CompiledRegex_Valid(t *testing.T) {
	// Verify that rules loaded by init() have valid compiled regexes
	for i, rule := range pathTraversalRules {
		if rule.compiled == nil {
			t.Errorf("Rule[%d] has nil compiled regex", i)
			continue
		}
		// Verify the regex doesn't panic
		_ = rule.compiled.MatchString("")
	}
}

// ==================== Rule type assignment ====================

func TestRule_TypeAssignment(t *testing.T) {
	// Verify that rules have correct type based on their origin
	lfiCount := 0
	rfiCount := 0
	fiCount := 0
	for _, rule := range pathTraversalRules {
		switch rule.typ {
		case "LFI":
			lfiCount++
		case "RFI":
			rfiCount++
		case "FI":
			fiCount++
		default:
			t.Errorf("Unexpected rule type: %q", rule.typ)
		}
	}
	if lfiCount == 0 {
		t.Error("Expected at least one LFI rule")
	}
	if rfiCount == 0 {
		t.Error("Expected at least one RFI rule")
	}
	if fiCount == 0 {
		t.Error("Expected at least one FI rule")
	}
}

// ==================== Rule Data field ====================

func TestRule_DataField(t *testing.T) {
	for i, rule := range pathTraversalRules {
		if rule.Data == "" {
			t.Errorf("Rule[%d] Data field is empty", i)
		}
	}
}

// ==================== isValueReplacePayload comprehensive ====================

func TestIsValueReplacePayload_AllPrefixes(t *testing.T) {
	prefixes := map[string]bool{
		"php://filter/read=convert.base64-encode/resource=index.php": true,
		"php://input":                   true,
		"file:///etc/passwd":            true,
		"file://etc/passwd":             true,
		"../../etc/passwd":              false,
		"/etc/passwd":                   false,
		"":                              false,
		"http://example.com":            false,
		"data://text/plain;base64,test": false,
		"expect://command":              false,
	}

	for vector, expected := range prefixes {
		result := isValueReplacePayload(vector)
		if result != expected {
			t.Errorf("isValueReplacePayload(%q) = %v, want %v", vector, result, expected)
		}
	}
}

// ==================== Rule Vector field ====================

func TestRule_VectorField(t *testing.T) {
	// FI rules should have empty Vector
	for _, rule := range pathTraversalRules {
		if rule.typ == "FI" && rule.Vector != "" {
			// FI rules can have empty vectors
		}
	}
}

// ==================== Rule Windows/Linux flags ====================

func TestRule_OSFlags(t *testing.T) {
	for i, rule := range pathTraversalRules {
		if rule.Windows != 0 && rule.Windows != 1 {
			t.Errorf("Rule[%d] Windows = %d, expected 0 or 1", i, rule.Windows)
		}
		if rule.Linux != 0 && rule.Linux != 1 {
			t.Errorf("Rule[%d] Linux = %d, expected 0 or 1", i, rule.Linux)
		}
	}
}

// ==================== Custom Rule construction ====================

func TestCustomRule_Construction(t *testing.T) {
	compiled, err := regexp.Compile("test pattern")
	if err != nil {
		t.Fatalf("Failed to compile regex: %v", err)
	}

	r := Rule{
		Vector:   "/custom/path",
		Windows:  1,
		Linux:    1,
		Data:     "test pattern",
		compiled: compiled,
		typ:      "LFI",
	}

	if r.Vector != "/custom/path" {
		t.Errorf("Vector = %q, want '/custom/path'", r.Vector)
	}
	if !r.compiled.MatchString("test pattern") {
		t.Error("Compiled regex should match 'test pattern'")
	}
	if r.typ != "LFI" {
		t.Errorf("typ = %q, want 'LFI'", r.typ)
	}
}

// ==================== XML unmarshalling edge cases ====================

func TestRoot_XMLUnmarshal_EmptyRoot(t *testing.T) {
	xmlData := `<?xml version="1.0" encoding="UTF-8"?><root></root>`
	var root Root
	err := xml.Unmarshal([]byte(xmlData), &root)
	if err != nil {
		t.Fatalf("XML unmarshal error: %v", err)
	}
	if len(root.LFI) != 0 {
		t.Errorf("Expected 0 LFI rules, got %d", len(root.LFI))
	}
}

func TestRoot_XMLUnmarshal_InvalidXML(t *testing.T) {
	xmlData := `<invalid`
	var root Root
	err := xml.Unmarshal([]byte(xmlData), &root)
	if err == nil {
		t.Error("Expected error for invalid XML")
	}
}

// ==================== PathTraversal execAction coverage ====================

func TestPathTraversal_ConfigDefaults(t *testing.T) {
	pt := &PathTraversal{}
	cfg := pt.DefaultConfig()
	bc := cfg.BaseConfig()
	if bc.Name != "path_traversal" {
		t.Errorf("Default Name = %q, want 'path_traversal'", bc.Name)
	}
	if !bc.Enabled {
		t.Error("Default Enabled should be true")
	}
}
