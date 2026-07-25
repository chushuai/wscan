package output

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"wscan/core/model"
)

// ==================== NewHTMLFilePrinter coverage ====================

func TestCoverage_NewHTMLFilePrinter_OsCreateError(t *testing.T) {
	// Try creating a file in a non-existent directory to trigger os.Create error path
	filename := "/nonexistent/deeply/nested/dir/output.html"

	hfp := NewHTMLFilePrinter(filename)
	if hfp != nil {
		t.Error("expected nil when os.Create fails")
		// Cleanup if somehow it succeeded
		hfp.Close()
	}
}

func TestCoverage_NewHTMLFilePrinter_WritePrefix(t *testing.T) {
	tmpDir := t.TempDir()
	filename := filepath.Join(tmpDir, "prefix_test.html")

	hfp := NewHTMLFilePrinter(filename)
	if hfp == nil {
		t.Fatal("NewHTMLFilePrinter returned nil")
	}

	// writePrefix is a no-op but should be callable
	err := hfp.writePrefix()
	if err != nil {
		t.Errorf("writePrefix returned unexpected error: %v", err)
	}

	hfp.Close()
}

func TestCoverage_NewHTMLFilePrinter_VerifyWrittenContent(t *testing.T) {
	tmpDir := t.TempDir()
	filename := filepath.Join(tmpDir, "content_test.html")

	hfp := NewHTMLFilePrinter(filename)
	if hfp == nil {
		t.Fatal("NewHTMLFilePrinter returned nil")
	}

	// Write a vuln and then close
	vuln := &model.Vuln{
		Binding: &model.VulnBinding{
			Plugin:   "coverage-plugin",
			Category: "xss",
			ID:       "coverage-xss-01",
			Severity: model.SeverityHigh,
		},
		Extra:      map[string]any{"key": "value"},
		CreateTime: time.Now().Unix(),
	}
	vuln.SetTargetURL(mustParseURL("http://example.com/vuln"))

	hfp.Print(vuln)
	hfp.Print(&model.StatisticRecord{
		NumFoundUrls:        10,
		NumScannedUrls:      5,
		NumSentHTTPRequests: 50,
		AverageResponseTime: 25.5,
	})

	hfp.Close()

	// Verify the file contains both the template and the vuln script
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}
	content := string(data)

	// Template should be present
	templateData := GetHTMLTemplate()
	if len(data) < len(templateData) {
		t.Errorf("output file too small: got %d bytes, template is %d bytes", len(data), len(templateData))
	}

	// Vuln script should be present
	if !containsSubstring(content, "webVulns.push(") {
		t.Error("expected webVulns.push in output")
	}

	// Scan summary should be present
	if !containsSubstring(content, "scanSummary=") {
		t.Error("expected scanSummary in output")
	}
}

func TestCoverage_NewHTMLFilePrinter_MultipleVulnsAndStats(t *testing.T) {
	tmpDir := t.TempDir()
	filename := filepath.Join(tmpDir, "multi_test.html")

	hfp := NewHTMLFilePrinter(filename)
	if hfp == nil {
		t.Fatal("NewHTMLFilePrinter returned nil")
	}

	// Print multiple vulns
	for i := 0; i < 5; i++ {
		vuln := &model.Vuln{
			Binding: &model.VulnBinding{
				Plugin:   "test-plugin",
				Category: "sqli",
				ID:       "test-sqli",
				Severity: model.SeverityMedium,
			},
			Extra:      map[string]any{"i": i},
			CreateTime: time.Now().Unix(),
		}
		vuln.SetTargetURL(mustParseURL("http://example.com/page"))
		hfp.Print(vuln)
	}

	// Print multiple stats
	for i := 0; i < 3; i++ {
		hfp.Print(&model.StatisticRecord{
			NumFoundUrls:        int64(10 + i),
			NumScannedUrls:      int64(5 + i),
			NumSentHTTPRequests: int64(50 + i),
			AverageResponseTime: 25.5 + float32(i),
		})
	}

	if hfp.vulnCount != 5 {
		t.Errorf("expected vulnCount=5, got %d", hfp.vulnCount)
	}

	if hfp.lastStat == nil {
		t.Error("lastStat should not be nil after printing statistics")
	}
	if hfp.lastStat.NumFoundUrls != 12 {
		t.Errorf("expected last stat NumFoundUrls=12, got %d", hfp.lastStat.NumFoundUrls)
	}

	hfp.Close()

	// Verify the file contains all vulns
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}
	content := string(data)
	if !containsSubstring(content, "webVulns.push(") {
		t.Error("expected webVulns.push in output")
	}
}

func TestCoverage_NewHTMLFilePrinter_PrintNonMatchingType(t *testing.T) {
	tmpDir := t.TempDir()
	filename := filepath.Join(tmpDir, "nonmatch_test.html")

	hfp := NewHTMLFilePrinter(filename)
	if hfp == nil {
		t.Fatal("NewHTMLFilePrinter returned nil")
	}

	// Print various non-matching types - should all be ignored
	hfp.Print(42)
	hfp.Print("string")
	hfp.Print(nil)
	hfp.Print(&model.CrawlerResult{Url: "http://example.com"})

	// vulnCount should still be 0
	if hfp.vulnCount != 0 {
		t.Errorf("expected vulnCount=0, got %d", hfp.vulnCount)
	}
	// lastStat should be nil
	if hfp.lastStat != nil {
		t.Error("expected lastStat to be nil when no StatisticRecord printed")
	}

	hfp.Close()
}

func TestCoverage_NewHTMLFilePrinter_EmptyStatisticRecord(t *testing.T) {
	tmpDir := t.TempDir()
	filename := filepath.Join(tmpDir, "empty_stat_test.html")

	hfp := NewHTMLFilePrinter(filename)
	if hfp == nil {
		t.Fatal("NewHTMLFilePrinter returned nil")
	}

	// Print a nil stat - should go to default branch in Print
	hfp.Print(nil)

	hfp.Close()

	// Verify summary with nil stat - should use empty StatisticRecord
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}
	content := string(data)
	if !containsSubstring(content, "scanSummary=") {
		t.Error("expected scanSummary in output even with no stats")
	}
}

func TestCoverage_NewHTMLFilePrinter_StartTime(t *testing.T) {
	tmpDir := t.TempDir()
	filename := filepath.Join(tmpDir, "time_test.html")

	beforeCreate := time.Now()
	hfp := NewHTMLFilePrinter(filename)
	afterCreate := time.Now()

	if hfp == nil {
		t.Fatal("NewHTMLFilePrinter returned nil")
	}

	// Verify startTime is set between before and after
	if hfp.startTime.Before(beforeCreate) || hfp.startTime.After(afterCreate) {
		t.Errorf("startTime %v not between %v and %v", hfp.startTime, beforeCreate, afterCreate)
	}

	hfp.Close()
}
