/**
* @Author: PostScan Mechanism
* @Date: 6/16/2026
 */
package base

import (
	"sync"
	"testing"
	"time"
	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/utils/printer"
)

func TestReflectionRecord(t *testing.T) {
	ab := &ApolloBase{}

	rec1 := &ReflectionRecord{
		URL:        "http://example.com/page?id=1",
		Method:     "GET",
		Parameter:  "id",
		Payload:    "<script>alert(1)</script>",
		PluginName: "xss",
		VulnType:   "xss",
		Timestamp:  time.Now(),
	}

	rec2 := &ReflectionRecord{
		URL:        "http://example.com/search?q=test",
		Method:     "POST",
		Parameter:  "q",
		Payload:    "' OR 1=1--",
		PluginName: "sqldet",
		VulnType:   "sqli",
		Timestamp:  time.Now(),
	}

	ab.RecordReflection(rec1)
	ab.RecordReflection(rec2)

	records := ab.GetReflectionRecords()
	if len(records) != 2 {
		t.Fatalf("expected 2 reflection records, got %d", len(records))
	}

	if records[0].URL != "http://example.com/page?id=1" {
		t.Errorf("expected URL %q, got %q", "http://example.com/page?id=1", records[0].URL)
	}
	if records[0].VulnType != "xss" {
		t.Errorf("expected VulnType %q, got %q", "xss", records[0].VulnType)
	}
	if records[1].VulnType != "sqli" {
		t.Errorf("expected VulnType %q, got %q", "sqli", records[1].VulnType)
	}
}

func TestReflectionRecordConcurrent(t *testing.T) {
	ab := &ApolloBase{}
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ab.RecordReflection(&ReflectionRecord{
				URL:        "http://example.com/page",
				Method:     "GET",
				Parameter:  "id",
				Payload:    "payload",
				PluginName: "test",
				VulnType:   "xss",
				Timestamp:  time.Now(),
			})
		}(i)
	}
	wg.Wait()

	records := ab.GetReflectionRecords()
	if len(records) != 100 {
		t.Fatalf("expected 100 reflection records, got %d", len(records))
	}
}

func TestGetReflectionRecordsSnapshot(t *testing.T) {
	ab := &ApolloBase{}

	ab.RecordReflection(&ReflectionRecord{
		URL:        "http://example.com/page",
		Method:     "GET",
		Parameter:  "id",
		Payload:    "payload1",
		PluginName: "test",
		VulnType:   "xss",
		Timestamp:  time.Now(),
	})

	records1 := ab.GetReflectionRecords()
	// Modify the returned slice should not affect the original
	records1[0].Payload = "modified"

	records2 := ab.GetReflectionRecords()
	if records2[0].Payload == "modified" {
		t.Error("GetReflectionRecords should return a snapshot, not a reference to the original slice elements")
	}
}

func TestStoredVulnVerifierReportStoredVuln(t *testing.T) {
	// Test that reportStoredVuln correctly creates a vulnerability with
	// stored=true in Extra and the correct severity
	rec := &ReflectionRecord{
		URL:        "http://example.com/page",
		Method:     "GET",
		Parameter:  "id",
		Payload:    "<script>alert(1)</script>",
		PluginName: "xss",
		VulnType:   "xss",
		Timestamp:  time.Now(),
	}

	// Create a mock output that captures what was printed
	var printedVuln *model.Vuln
	mockOutput := &mockPrinter{
		printFunc: func(v any) error {
			if vuln, ok := v.(*model.Vuln); ok {
				printedVuln = vuln
			}
			return nil
		},
	}

	ab := &ApolloBase{
		Output: mockOutput,
	}

	sv := NewStoredVulnVerifier(ab, 60*time.Second, 120*time.Second)

	// Test reporting a stored XSS
	sv.reportStoredVuln(rec, nil, "xss/stored/default", model.SeverityCritical,
		"Stored XSS confirmed: payload persisted across requests")

	if printedVuln == nil {
		t.Fatal("expected a vulnerability to be printed")
	}
	if printedVuln.Binding.ID != "xss/stored/default" {
		t.Errorf("expected vuln ID %q, got %q", "xss/stored/default", printedVuln.Binding.ID)
	}
	if printedVuln.Binding.Severity != model.SeverityCritical {
		t.Errorf("expected severity %v, got %v", model.SeverityCritical, printedVuln.Binding.Severity)
	}
	stored, ok := printedVuln.Extra["stored"]
	if !ok || stored != true {
		t.Error("expected stored=true in Extra")
	}
	if printedVuln.Payload != rec.Payload {
		t.Errorf("expected payload %q, got %q", rec.Payload, printedVuln.Payload)
	}
}

func TestStoredVulnVerifierReportStoredVulnWithResponse(t *testing.T) {
	rec := &ReflectionRecord{
		URL:        "http://example.com/search",
		Method:     "POST",
		Parameter:  "q",
		Payload:    "' OR 1=1--",
		PluginName: "sqldet",
		VulnType:   "sqli",
		Timestamp:  time.Now(),
	}

	var printedVuln *model.Vuln
	mockOutput := &mockPrinter{
		printFunc: func(v any) error {
			if vuln, ok := v.(*model.Vuln); ok {
				printedVuln = vuln
			}
			return nil
		},
	}

	ab := &ApolloBase{
		HTTPClient: http.NewClient(),
		Output:     mockOutput,
	}

	sv := NewStoredVulnVerifier(ab, 60*time.Second, 120*time.Second)

	// Create a response for the test
	res := &http.Response{
		StatusCode: 200,
		Text:       "SQL syntax error detected",
	}

	sv.reportStoredVuln(rec, res, "sqldet/stored/default", model.SeverityCritical,
		"Stored SQLi confirmed: SQL error pattern found on re-visit")

	if printedVuln == nil {
		t.Fatal("expected a vulnerability to be printed")
	}
	if printedVuln.Binding.ID != "sqldet/stored/default" {
		t.Errorf("expected vuln ID %q, got %q", "sqldet/stored/default", printedVuln.Binding.ID)
	}
	if printedVuln.Binding.Severity != model.SeverityCritical {
		t.Errorf("expected severity %v, got %v", model.SeverityCritical, printedVuln.Binding.Severity)
	}
}

// mockPrinter implements printer.Printer for testing
type mockPrinter struct {
	printFunc func(any) error
}

func (m *mockPrinter) Print(v any) error {
	if m.printFunc != nil {
		return m.printFunc(v)
	}
	return nil
}

func (m *mockPrinter) AddInterceptor(f func(any) (any, error)) printer.Printer {
	return nil
}

func (m *mockPrinter) Close() error {
	return nil
}
