package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
	"wscan/core/model"
)

// --- htmlFilePrinter tests ---

func TestNewHTMLFilePrinter(t *testing.T) {
	tmpDir := t.TempDir()
	filename := filepath.Join(tmpDir, "test_output.html")

	hfp := NewHTMLFilePrinter(filename)
	if hfp == nil {
		t.Fatal("NewHTMLFilePrinter returned nil")
	}
	if hfp.filename != filename {
		t.Errorf("expected filename %q, got %q", filename, hfp.filename)
	}
	if hfp.writer == nil {
		t.Error("writer should not be nil")
	}
	if hfp.startTime.IsZero() {
		t.Error("startTime should be set")
	}

	// Verify the file was created and contains the template prefix
	err := hfp.Close()
	if err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}
	templateData := GetHTMLTemplate()
	if len(data) < len(templateData) {
		t.Errorf("output file too small: got %d bytes, template is %d bytes", len(data), len(templateData))
	}
}

func TestHTMLFilePrinter_PrintVuln(t *testing.T) {
	tmpDir := t.TempDir()
	filename := filepath.Join(tmpDir, "vuln_test.html")

	hfp := NewHTMLFilePrinter(filename)
	defer hfp.Close()

	vuln := &model.Vuln{
		Binding: &model.VulnBinding{
			Plugin:   "test-plugin",
			Category: "xss",
			ID:       "test-xss-01",
			Severity: model.SeverityHigh,
		},
		Extra:      map[string]any{"key": "value"},
		CreateTime: time.Now().Unix(),
	}
	vuln.SetTargetURL(mustParseURL("http://example.com/page"))

	err := hfp.Print(vuln)
	if err != nil {
		t.Fatalf("Print returned error: %v", err)
	}
	if hfp.vulnCount != 1 {
		t.Errorf("expected vulnCount=1, got %d", hfp.vulnCount)
	}
}

func TestHTMLFilePrinter_PrintStatisticRecord(t *testing.T) {
	tmpDir := t.TempDir()
	filename := filepath.Join(tmpDir, "stat_test.html")

	hfp := NewHTMLFilePrinter(filename)
	defer hfp.Close()

	stat := &model.StatisticRecord{
		NumFoundUrls:            100,
		NumScannedUrls:          80,
		NumSentHTTPRequests:     500,
		AverageResponseTime:     45.5,
		RatioFailedHTTPRequests: 0.02,
	}

	err := hfp.Print(stat)
	if err != nil {
		t.Fatalf("Print returned error: %v", err)
	}
	if hfp.lastStat == nil {
		t.Error("lastStat should not be nil after printing StatisticRecord")
	}
	if hfp.lastStat.NumFoundUrls != 100 {
		t.Errorf("expected NumFoundUrls=100, got %d", hfp.lastStat.NumFoundUrls)
	}
}

func TestHTMLFilePrinter_PrintUnknownType(t *testing.T) {
	tmpDir := t.TempDir()
	filename := filepath.Join(tmpDir, "unknown_test.html")

	hfp := NewHTMLFilePrinter(filename)
	defer hfp.Close()

	// Printing a type that is not Vuln or StatisticRecord should not error
	err := hfp.Print("some random string")
	if err != nil {
		t.Fatalf("Print returned error for unknown type: %v", err)
	}
}

func TestHTMLFilePrinter_WriteScanSummary_WithStat(t *testing.T) {
	tmpDir := t.TempDir()
	filename := filepath.Join(tmpDir, "summary_test.html")

	hfp := NewHTMLFilePrinter(filename)

	stat := &model.StatisticRecord{
		NumFoundUrls:        200,
		NumScannedUrls:      150,
		NumSentHTTPRequests: 800,
		AverageResponseTime: 33.3,
	}
	hfp.Print(stat)
	hfp.vulnCount = 5

	err := hfp.Close()
	if err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}
	content := string(data)
	if !containsSubstring(content, "scan-summary") {
		t.Error("expected scan summary script tag in output")
	}
	if !containsSubstring(content, "scanSummary=") {
		t.Error("expected scanSummary assignment in output")
	}
}

func TestHTMLFilePrinter_WriteScanSummary_NilStat(t *testing.T) {
	tmpDir := t.TempDir()
	filename := filepath.Join(tmpDir, "nil_summary_test.html")

	hfp := NewHTMLFilePrinter(filename)
	// Don't set lastStat - should use empty StatisticRecord

	err := hfp.Close()
	if err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}
	content := string(data)
	if !containsSubstring(content, "scan-summary") {
		t.Error("expected scan summary script tag even with nil stat")
	}
}

func TestHTMLFilePrinter_AddInterceptor(t *testing.T) {
	tmpDir := t.TempDir()
	filename := filepath.Join(tmpDir, "interceptor_test.html")

	hfp := NewHTMLFilePrinter(filename)
	defer hfp.Close()

	// AddInterceptor always returns nil per implementation
	result := hfp.AddInterceptor(func(a any) (any, error) { return a, nil })
	if result != nil {
		t.Error("AddInterceptor should return nil for htmlFilePrinter")
	}
}

func TestHTMLFilePrinter_LogSubdomain(t *testing.T) {
	tmpDir := t.TempDir()
	filename := filepath.Join(tmpDir, "subdomain_test.html")

	hfp := NewHTMLFilePrinter(filename)
	defer hfp.Close()

	err := hfp.LogSubdomain("subdomain data")
	if err != nil {
		t.Fatalf("LogSubdomain returned error: %v", err)
	}
}

func TestHTMLFilePrinter_LogVuln(t *testing.T) {
	tmpDir := t.TempDir()
	filename := filepath.Join(tmpDir, "logvuln_test.html")

	hfp := NewHTMLFilePrinter(filename)
	defer hfp.Close()

	err := hfp.LogVuln("vuln data")
	if err != nil {
		t.Fatalf("LogVuln returned error: %v", err)
	}
}

func TestHTMLFilePrinter_MultipleVulns(t *testing.T) {
	tmpDir := t.TempDir()
	filename := filepath.Join(tmpDir, "multi_vuln_test.html")

	hfp := NewHTMLFilePrinter(filename)
	defer hfp.Close()

	for i := 0; i < 3; i++ {
		vuln := &model.Vuln{
			Binding: &model.VulnBinding{
				Plugin:   "test-plugin",
				Category: "sqli",
				ID:       "test-sqli-" + string(rune('0'+i)),
				Severity: model.SeverityMedium,
			},
			Extra:      map[string]any{"i": i},
			CreateTime: time.Now().Unix(),
		}
		vuln.SetTargetURL(mustParseURL("http://example.com/page"))
		hfp.Print(vuln)
	}

	if hfp.vulnCount != 3 {
		t.Errorf("expected vulnCount=3, got %d", hfp.vulnCount)
	}
}

func TestGetHTMLTemplate(t *testing.T) {
	data := GetHTMLTemplate()
	if len(data) == 0 {
		t.Error("GetHTMLTemplate returned empty data")
	}
}

// --- stdoutPrinter tests ---

func TestNewStdoutPrinter(t *testing.T) {
	p := NewStdoutPrinter()
	if p == nil {
		t.Fatal("NewStdoutPrinter returned nil")
	}
}

func TestStdoutPrinter_PrintVuln(t *testing.T) {
	p := NewStdoutPrinter()
	vuln := &model.Vuln{
		Binding: &model.VulnBinding{
			Plugin:   "test-plugin",
			Category: "xss",
			Severity: model.SeverityHigh,
		},
		Extra: map[string]any{},
	}
	vuln.SetTargetURL(mustParseURL("http://example.com/vuln"))

	err := p.Print(vuln)
	if err != nil {
		t.Fatalf("Print vuln returned error: %v", err)
	}
}

func TestStdoutPrinter_PrintStatisticRecord(t *testing.T) {
	p := NewStdoutPrinter()

	stat := &model.StatisticRecord{
		NumFoundUrls:            50,
		NumScannedUrls:          30,
		NumSentHTTPRequests:     200,
		AverageResponseTime:     100.5,
		RatioFailedHTTPRequests: 0.05,
	}

	err := p.Print(stat)
	if err != nil {
		t.Fatalf("Print stat returned error: %v", err)
	}

	// Verify lastStat is updated
	if p.lastStat == nil {
		t.Error("lastStat should not be nil after printing")
	}
	if p.lastStat.NumFoundUrls != 50 {
		t.Errorf("expected NumFoundUrls=50, got %d", p.lastStat.NumFoundUrls)
	}
}

func TestStdoutPrinter_PrintStatisticRecord_PendingBecomesZero(t *testing.T) {
	p := NewStdoutPrinter()

	// First stat with pending > 0
	p.Print(&model.StatisticRecord{
		NumFoundUrls:        10,
		NumScannedUrls:      5,
		NumSentHTTPRequests: 20,
	})

	// Second stat with pending == 0 (all scanned)
	p.Print(&model.StatisticRecord{
		NumFoundUrls:        10,
		NumScannedUrls:      10,
		NumSentHTTPRequests: 20,
	})

	if p.lastStat.NumScannedUrls != 10 {
		t.Errorf("expected lastStat.NumScannedUrls=10, got %d", p.lastStat.NumScannedUrls)
	}
}

func TestStdoutPrinter_PrintCrawlerResult(t *testing.T) {
	p := NewStdoutPrinter()
	cr := &model.CrawlerResult{Url: "http://example.com"}

	err := p.Print(cr)
	if err != nil {
		t.Fatalf("Print CrawlerResult returned error: %v", err)
	}
}

func TestStdoutPrinter_PrintDefault(t *testing.T) {
	p := NewStdoutPrinter()
	// Print an unrecognized type - should go to default branch
	err := p.Print(42)
	if err != nil {
		t.Fatalf("Print int returned error: %v", err)
	}
}

func TestStdoutPrinter_AddInterceptor(t *testing.T) {
	p := NewStdoutPrinter()
	result := p.AddInterceptor(func(a any) (any, error) { return a, nil })
	if result != nil {
		t.Error("AddInterceptor should return nil for stdoutPrinter")
	}
}

func TestStdoutPrinter_Close(t *testing.T) {
	p := NewStdoutPrinter()
	err := p.Close()
	if err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
}

// --- webHookPrinter tests ---

func TestNewWebHookPrinter(t *testing.T) {
	u := mustParseURL("http://localhost:9090/webhook")
	p := NewWebHookPrinter(u)
	if p == nil {
		t.Fatal("NewWebHookPrinter returned nil")
	}
	if p.url.String() != "http://localhost:9090/webhook" {
		t.Errorf("unexpected url: %s", p.url.String())
	}
}

func TestWebHookPrinter_AddInterceptor(t *testing.T) {
	u := mustParseURL("http://localhost:9090/webhook")
	p := NewWebHookPrinter(u)
	result := p.AddInterceptor(func(a any) (any, error) { return a, nil })
	if result != nil {
		t.Error("AddInterceptor should return nil for webHookPrinter")
	}
}

func TestWebHookPrinter_Close(t *testing.T) {
	u := mustParseURL("http://localhost:9090/webhook")
	p := NewWebHookPrinter(u)
	err := p.Close()
	if err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
}

func TestWebHookPrinter_LogSubdomain(t *testing.T) {
	u := mustParseURL("http://localhost:9090/webhook")
	p := NewWebHookPrinter(u)
	err := p.LogSubdomain(nil)
	if err != nil {
		t.Fatalf("LogSubdomain returned error: %v", err)
	}
}

func TestWebHookPrinter_PrintCrawlerResult(t *testing.T) {
	u := mustParseURL("http://localhost:9090/webhook")
	p := NewWebHookPrinter(u)
	cr := &model.CrawlerResult{Url: "http://example.com"}
	err := p.Print(cr)
	if err != nil {
		t.Fatalf("Print CrawlerResult returned error: %v", err)
	}
}

func TestWebHookPrinter_PrintDefault(t *testing.T) {
	u := mustParseURL("http://localhost:9090/webhook")
	p := NewWebHookPrinter(u)
	err := p.Print("random string")
	if err != nil {
		t.Fatalf("Print string returned error: %v", err)
	}
}

func TestWebHookPrinter_TruncResult(t *testing.T) {
	u := mustParseURL("http://localhost:9090/webhook")
	p := NewWebHookPrinter(u)
	result := p.truncResult([]byte("data"))
	if result != nil {
		t.Error("truncResult should return nil")
	}
}

func TestWebHookRequest_Marshal(t *testing.T) {
	req := WebHookRequest{
		Type: "web_vuln",
		Data: map[string]string{"key": "value"},
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	if !containsSubstring(string(data), `"type":"web_vuln"`) {
		t.Errorf("unexpected marshal output: %s", string(data))
	}
}

// Test webHookPrinter with httptest server
func TestWebHookPrinter_LogVuln_WithServer(t *testing.T) {
	var receivedBody []byte
	server := newTestServer(t, func(body []byte) {
		receivedBody = body
	})
	defer server.Close()

	u := mustParseURL(server.URL)
	p := NewWebHookPrinter(u)

	vuln := &model.Vuln{
		Binding: &model.VulnBinding{
			Plugin:   "test-plugin",
			Category: "xss",
			ID:       "xss-01",
			Severity: model.SeverityHigh,
		},
		Payload:    "<script>alert(1)</script>",
		Extra:      map[string]any{},
		CreateTime: time.Now().Unix(),
	}
	vuln.SetTargetURL(mustParseURL("http://target.com/page"))

	err := p.LogVuln(vuln)
	if err != nil {
		t.Fatalf("LogVuln returned error: %v", err)
	}

	if len(receivedBody) == 0 {
		t.Fatal("server did not receive any body")
	}

	var req WebHookRequest
	if err := json.Unmarshal(receivedBody, &req); err != nil {
		t.Fatalf("failed to unmarshal request body: %v", err)
	}
	if req.Type != "web_vuln" {
		t.Errorf("expected type 'web_vuln', got %q", req.Type)
	}
}

func TestWebHookPrinter_LogStats_WithServer(t *testing.T) {
	var receivedBody []byte
	server := newTestServer(t, func(body []byte) {
		receivedBody = body
	})
	defer server.Close()

	u := mustParseURL(server.URL)
	p := NewWebHookPrinter(u)

	stat := &model.StatisticRecord{
		NumFoundUrls:        100,
		NumScannedUrls:      80,
		NumSentHTTPRequests: 400,
		AverageResponseTime: 55.5,
	}

	err := p.LogStats(stat)
	if err != nil {
		t.Fatalf("LogStats returned error: %v", err)
	}

	if len(receivedBody) == 0 {
		t.Fatal("server did not receive any body")
	}

	var req WebHookRequest
	if err := json.Unmarshal(receivedBody, &req); err != nil {
		t.Fatalf("failed to unmarshal request body: %v", err)
	}
	if req.Type != "web_statistic" {
		t.Errorf("expected type 'web_statistic', got %q", req.Type)
	}
}

func TestWebHookPrinter_PrintVuln_WithServer(t *testing.T) {
	var receivedBody []byte
	server := newTestServer(t, func(body []byte) {
		receivedBody = body
	})
	defer server.Close()

	u := mustParseURL(server.URL)
	p := NewWebHookPrinter(u)

	vuln := &model.Vuln{
		Binding: &model.VulnBinding{
			Plugin:   "test-plugin",
			Category: "sqli",
			ID:       "sqli-01",
			Severity: model.SeverityCritical,
		},
		Payload:    "' OR 1=1 --",
		Extra:      map[string]any{},
		CreateTime: time.Now().Unix(),
	}
	vuln.SetTargetURL(mustParseURL("http://target.com/login"))

	err := p.Print(vuln)
	if err != nil {
		t.Fatalf("Print vuln returned error: %v", err)
	}

	if len(receivedBody) == 0 {
		t.Fatal("server did not receive any body")
	}
}

func TestWebHookPrinter_PrintStat_WithServer(t *testing.T) {
	var receivedBody []byte
	server := newTestServer(t, func(body []byte) {
		receivedBody = body
	})
	defer server.Close()

	u := mustParseURL(server.URL)
	p := NewWebHookPrinter(u)

	stat := &model.StatisticRecord{
		NumFoundUrls:        50,
		NumScannedUrls:      50,
		NumSentHTTPRequests: 300,
	}

	err := p.Print(stat)
	if err != nil {
		t.Fatalf("Print stat returned error: %v", err)
	}

	if len(receivedBody) == 0 {
		t.Fatal("server did not receive any body")
	}
}
