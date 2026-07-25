package entry

import (
	"os"
	"path/filepath"
	"testing"

	"wscan/core/output"
)

func TestConvertJSONToHTML_Basic(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a simple JSON file with one vuln per line
	jsonPath := filepath.Join(tmpDir, "vulns.json")
	jsonContent := `{"plugin":"xss","severity":"high","detail":{"addr":"http://example.com"}}
{"plugin":"sqli","severity":"critical","detail":{"addr":"http://example.com/login"}}
`
	err := os.WriteFile(jsonPath, []byte(jsonContent), 0644)
	if err != nil {
		t.Fatalf("failed to write JSON file: %v", err)
	}

	htmlPath := filepath.Join(tmpDir, "report.html")
	err = convertJSONToHTML(jsonPath, htmlPath)
	if err != nil {
		t.Fatalf("convertJSONToHTML returned error: %v", err)
	}

	data, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("failed to read HTML output: %v", err)
	}

	content := string(data)

	// Should contain the HTML template
	templateData := output.GetHTMLTemplate()
	if len(data) < len(templateData) {
		t.Errorf("HTML output too small: got %d bytes, template is %d bytes", len(data), len(templateData))
	}

	// Should contain web-vulns script tags
	if !containsStr(content, "<script class='web-vulns'>webVulns.push(") {
		t.Error("expected web-vulns script tag in HTML output")
	}

	// Should contain both vulns entries
	if !containsStr(content, `"plugin":"xss"`) {
		t.Error("expected xss vuln in HTML output")
	}
	if !containsStr(content, `"plugin":"sqli"`) {
		t.Error("expected sqli vuln in HTML output")
	}
}

func TestConvertJSONToHTML_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()

	jsonPath := filepath.Join(tmpDir, "empty.json")
	err := os.WriteFile(jsonPath, []byte(""), 0644)
	if err != nil {
		t.Fatalf("failed to write JSON file: %v", err)
	}

	htmlPath := filepath.Join(tmpDir, "report.html")
	err = convertJSONToHTML(jsonPath, htmlPath)
	if err != nil {
		t.Fatalf("convertJSONToHTML returned error for empty file: %v", err)
	}

	data, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("failed to read HTML output: %v", err)
	}

	// Should still contain the template
	templateData := output.GetHTMLTemplate()
	if len(data) < len(templateData) {
		t.Errorf("HTML output too small even for empty input")
	}
}

func TestConvertJSONToHTML_SkipsNonJSON(t *testing.T) {
	tmpDir := t.TempDir()

	jsonPath := filepath.Join(tmpDir, "mixed.json")
	jsonContent := `not a json line
{"plugin":"xss","severity":"high"}
another non-json
`
	err := os.WriteFile(jsonPath, []byte(jsonContent), 0644)
	if err != nil {
		t.Fatalf("failed to write JSON file: %v", err)
	}

	htmlPath := filepath.Join(tmpDir, "report.html")
	err = convertJSONToHTML(jsonPath, htmlPath)
	if err != nil {
		t.Fatalf("convertJSONToHTML returned error: %v", err)
	}

	data, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("failed to read HTML output: %v", err)
	}

	content := string(data)
	// Should only contain the valid JSON line
	if !containsStr(content, `"plugin":"xss"`) {
		t.Error("expected xss vuln in HTML output")
	}
	// Should NOT contain non-JSON lines
	if containsStr(content, "not a json line") {
		t.Error("non-JSON lines should be skipped")
	}
}

func TestConvertJSONToHTML_NonExistentJSON(t *testing.T) {
	tmpDir := t.TempDir()
	htmlPath := filepath.Join(tmpDir, "report.html")

	err := convertJSONToHTML("/nonexistent/file.json", htmlPath)
	if err == nil {
		t.Error("expected error for non-existent JSON file")
	}
}

func TestConvertJSONToHTML_NonExistentHTMLDir(t *testing.T) {
	tmpDir := t.TempDir()

	jsonPath := filepath.Join(tmpDir, "vulns.json")
	err := os.WriteFile(jsonPath, []byte(`{"plugin":"xss"}`), 0644)
	if err != nil {
		t.Fatalf("failed to write JSON file: %v", err)
	}

	err = convertJSONToHTML(jsonPath, "/nonexistent/dir/report.html")
	if err == nil {
		t.Error("expected error for non-existent HTML directory")
	}
}

func TestConvertHTMLToJSON_Basic(t *testing.T) {
	tmpDir := t.TempDir()

	// Create an HTML file with web-vulns script tags
	htmlPath := filepath.Join(tmpDir, "report.html")
	templateData := output.GetHTMLTemplate()
	htmlContent := string(templateData) + "\n" +
		`<script class='web-vulns'>webVulns.push({"plugin":"xss","severity":"high"})</script>` + "\n" +
		`<script class='web-vulns'>webVulns.push({"plugin":"sqli","severity":"critical"})</script>` + "\n"
	err := os.WriteFile(htmlPath, []byte(htmlContent), 0644)
	if err != nil {
		t.Fatalf("failed to write HTML file: %v", err)
	}

	jsonPath := filepath.Join(tmpDir, "vulns.json")
	err = convertHTMLToJSON(htmlPath, jsonPath)
	if err != nil {
		t.Fatalf("convertHTMLToJSON returned error: %v", err)
	}

	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("failed to read JSON output: %v", err)
	}

	content := string(data)
	if !containsStr(content, `"plugin":"xss"`) {
		t.Error("expected xss vuln in JSON output")
	}
	if !containsStr(content, `"plugin":"sqli"`) {
		t.Error("expected sqli vuln in JSON output")
	}
}

func TestConvertHTMLToJSON_NoVulns(t *testing.T) {
	tmpDir := t.TempDir()

	htmlPath := filepath.Join(tmpDir, "empty.html")
	templateData := output.GetHTMLTemplate()
	err := os.WriteFile(htmlPath, templateData, 0644)
	if err != nil {
		t.Fatalf("failed to write HTML file: %v", err)
	}

	jsonPath := filepath.Join(tmpDir, "vulns.json")
	err = convertHTMLToJSON(htmlPath, jsonPath)
	if err != nil {
		t.Fatalf("convertHTMLToJSON returned error: %v", err)
	}

	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("failed to read JSON output: %v", err)
	}

	if len(data) != 0 {
		t.Errorf("expected empty JSON output for HTML with no vulns, got %d bytes", len(data))
	}
}

func TestConvertHTMLToJSON_NonExistentHTML(t *testing.T) {
	tmpDir := t.TempDir()
	jsonPath := filepath.Join(tmpDir, "vulns.json")

	err := convertHTMLToJSON("/nonexistent/file.html", jsonPath)
	if err == nil {
		t.Error("expected error for non-existent HTML file")
	}
}

func TestConvertHTMLToJSON_RoundTrip(t *testing.T) {
	tmpDir := t.TempDir()

	// Start with JSON
	jsonPath := filepath.Join(tmpDir, "vulns.json")
	jsonContent := `{"plugin":"xss","severity":"high","detail":{"addr":"http://example.com"}}
`
	err := os.WriteFile(jsonPath, []byte(jsonContent), 0644)
	if err != nil {
		t.Fatalf("failed to write JSON file: %v", err)
	}

	// Convert JSON -> HTML
	htmlPath := filepath.Join(tmpDir, "report.html")
	err = convertJSONToHTML(jsonPath, htmlPath)
	if err != nil {
		t.Fatalf("convertJSONToHTML returned error: %v", err)
	}

	// Convert HTML -> JSON
	jsonPath2 := filepath.Join(tmpDir, "vulns2.json")
	err = convertHTMLToJSON(htmlPath, jsonPath2)
	if err != nil {
		t.Fatalf("convertHTMLToJSON returned error: %v", err)
	}

	// Verify the round-trip result
	data, err := os.ReadFile(jsonPath2)
	if err != nil {
		t.Fatalf("failed to read round-trip JSON: %v", err)
	}

	content := string(data)
	if !containsStr(content, `"plugin":"xss"`) {
		t.Error("expected xss vuln in round-trip JSON output")
	}
}

func TestConvertHTMLToJSON_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()

	// HTML with invalid JSON inside web-vulns tag should be skipped
	htmlPath := filepath.Join(tmpDir, "invalid.html")
	templateData := output.GetHTMLTemplate()
	htmlContent := string(templateData) + "\n" +
		`<script class='web-vulns'>webVulns.push({invalid json!!!})</script>` + "\n" +
		`<script class='web-vulns'>webVulns.push({"plugin":"xss","severity":"high"})</script>` + "\n"
	err := os.WriteFile(htmlPath, []byte(htmlContent), 0644)
	if err != nil {
		t.Fatalf("failed to write HTML file: %v", err)
	}

	jsonPath := filepath.Join(tmpDir, "vulns.json")
	err = convertHTMLToJSON(htmlPath, jsonPath)
	if err != nil {
		t.Fatalf("convertHTMLToJSON returned error: %v", err)
	}

	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("failed to read JSON output: %v", err)
	}

	content := string(data)
	// Invalid JSON should be skipped
	if containsStr(content, "invalid json!!!") {
		t.Error("invalid JSON should be skipped")
	}
	// Valid JSON should still be present
	if !containsStr(content, `"plugin":"xss"`) {
		t.Error("valid vuln should still be extracted")
	}
}

// containsStr is a simple substring check
func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
