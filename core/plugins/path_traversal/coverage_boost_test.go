package path_traversal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	whttp "wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/utils/printer"
)

// ==================== Helpers ====================

type ptCountingPrinter struct {
	count int
	mu    sync.Mutex
}

func (p *ptCountingPrinter) AddInterceptor(func(any) (any, error)) printer.Printer { return p }
func (p *ptCountingPrinter) Close() error                                          { return nil }
func (p *ptCountingPrinter) Print(v any) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.count++
	return nil
}
func (p *ptCountingPrinter) Count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.count
}

func ptMakeApollo(t *testing.T, flow *whttp.Flow, output printer.Printer) *base.Apollo {
	t.Helper()
	apollo := base.NewApollo(flow)
	apollo.ApolloBase = &base.ApolloBase{
		HTTPClient: whttp.NewClient(),
		Output:     output,
		VulnFilter: &model.VulnFilterConfig{},
	}
	return apollo
}

// ==================== execAction with Header params (should be skipped) ====================
// Line 72-73: Header/Cookie params should be skipped

func TestPT_ExecAction_HeaderParamsSkipped(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("root:x:0:0:root:/root:/bin/bash"))
	}))
	defer server.Close()

	req, _ := whttp.NewRequest("GET", server.URL+"/page", nil)
	req.Header.Set("X-Custom", "testvalue")
	client := whttp.NewClient()
	resp, err := client.Respond(context.Background(), req)
	if err != nil {
		t.Fatalf("Failed to get response: %v", err)
	}
	flow := &whttp.Flow{Request: req, Response: resp}

	cp := &ptCountingPrinter{}
	apollo := ptMakeApollo(t, flow, cp)

	p := &PathTraversal{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()
	fingers := p.Fingers()

	err = fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
}

// ==================== execAction with Cookie params (should be skipped) ====================
// Line 72-73: Cookie params should be skipped

func TestPT_ExecAction_CookieParamsSkipped(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("root:x:0:0:root:/root:/bin/bash"))
	}))
	defer server.Close()

	req, _ := whttp.NewRequest("GET", server.URL+"/page", nil)
	req.Header.Set("Cookie", "session=abc123")
	client := whttp.NewClient()
	resp, err := client.Respond(context.Background(), req)
	if err != nil {
		t.Fatalf("Failed to get response: %v", err)
	}
	flow := &whttp.Flow{Request: req, Response: resp}

	cp := &ptCountingPrinter{}
	apollo := ptMakeApollo(t, flow, cp)

	p := &PathTraversal{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()
	fingers := p.Fingers()

	err = fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
}

// ==================== execAction with LFI value-replace payloads ====================
// Line 79-81: php://filter and file:/// payloads use Value replace

func TestPT_ExecAction_LFIValueReplace(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("<html>normal</html>"))
	}))
	defer server.Close()

	req, _ := whttp.NewRequest("GET", server.URL+"/?file=test.txt", nil)
	client := whttp.NewClient()
	resp, err := client.Respond(context.Background(), req)
	if err != nil {
		t.Fatalf("Failed to get response: %v", err)
	}
	flow := &whttp.Flow{Request: req, Response: resp}

	cp := &ptCountingPrinter{}
	apollo := ptMakeApollo(t, flow, cp)

	p := &PathTraversal{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()
	fingers := p.Fingers()

	err = fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
}

// ==================== execAction with FI rules (empty vector) ====================
// Line 82-84: FI rules with empty vector don't modify the value

func TestPT_ExecAction_FIRules(t *testing.T) {
	// Server that returns PHP warning messages for FI detection
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fileParam := r.URL.Query().Get("file")
		if fileParam != "test.txt" {
			w.WriteHeader(200)
			w.Write([]byte("Warning: fopen(test.txt): failed to open stream: No such file or directory in /var/www/html/index.php on line 12"))
			return
		}
		w.WriteHeader(200)
		w.Write([]byte("<html>normal page</html>"))
	}))
	defer server.Close()

	req, _ := whttp.NewRequest("GET", server.URL+"/?file=test.txt", nil)
	client := whttp.NewClient()
	resp, err := client.Respond(context.Background(), req)
	if err != nil {
		t.Fatalf("Failed to get response: %v", err)
	}
	flow := &whttp.Flow{Request: req, Response: resp}

	cp := &ptCountingPrinter{}
	apollo := ptMakeApollo(t, flow, cp)

	p := &PathTraversal{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()
	fingers := p.Fingers()

	err = fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
}

// ==================== execAction with LFI echo detection ====================
// Tests that /etc/passwd echo detection works

func TestPT_ExecAction_LFIEchoDetection(t *testing.T) {
	// Server that returns /etc/passwd content for modified params
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fileParam := r.URL.Query().Get("file")
		if strings.Contains(fileParam, "etc/passwd") || strings.Contains(fileParam, "../") {
			w.WriteHeader(200)
			w.Write([]byte("root:x:0:0:root:/root:/bin/bash"))
			return
		}
		w.WriteHeader(200)
		w.Write([]byte("<html>normal page</html>"))
	}))
	defer server.Close()

	req, _ := whttp.NewRequest("GET", server.URL+"/?file=test.txt", nil)
	client := whttp.NewClient()
	resp, err := client.Respond(context.Background(), req)
	if err != nil {
		t.Fatalf("Failed to get response: %v", err)
	}
	flow := &whttp.Flow{Request: req, Response: resp}

	cp := &ptCountingPrinter{}
	apollo := ptMakeApollo(t, flow, cp)

	p := &PathTraversal{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()
	fingers := p.Fingers()

	err = fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
	if cp.Count() == 0 {
		t.Error("Expected at least one vuln from LFI echo detection")
	}
}

// ==================== execAction with baseline suppression ====================
// Line 98-101: If baseline also matches the rule, it's a false positive

func TestPT_ExecAction_BaselineSuppression(t *testing.T) {
	// Server that always returns /etc/passwd content (baseline should suppress it)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("root:x:0:0:root:/root:/bin/bash"))
	}))
	defer server.Close()

	req, _ := whttp.NewRequest("GET", server.URL+"/?file=test.txt", nil)
	client := whttp.NewClient()
	resp, err := client.Respond(context.Background(), req)
	if err != nil {
		t.Fatalf("Failed to get response: %v", err)
	}
	flow := &whttp.Flow{Request: req, Response: resp}

	cp := &ptCountingPrinter{}
	apollo := ptMakeApollo(t, flow, cp)

	p := &PathTraversal{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()
	fingers := p.Fingers()

	err = fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
	// Baseline should suppress all detections since the same pattern is in the baseline
}

// ==================== execAction with HTTP errors ====================
// Line 94-95: HTTP errors should be handled gracefully

func TestPT_ExecAction_HTTPError(t *testing.T) {
	p := &PathTraversal{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()

	req, _ := whttp.NewRequest("GET", "http://127.0.0.1:1/?file=test.txt", nil)
	flow := &whttp.Flow{
		Request: req,
		Response: &whttp.Response{
			Text:       "",
			StatusCode: 0,
		},
	}

	cp := &ptCountingPrinter{}
	apollo := ptMakeApollo(t, flow, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error (expected with unreachable host): %v", err)
	}
}

// ==================== execAction with RFI echo detection ====================

func TestPT_ExecAction_RFIEchoDetection(t *testing.T) {
	// Server that returns RFI content for modified params
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fileParam := r.URL.Query().Get("file")
		if strings.Contains(fileParam, "http://") {
			w.WriteHeader(200)
			w.Write([]byte("We suggest the following mirror site for your download"))
			return
		}
		w.WriteHeader(200)
		w.Write([]byte("<html>normal page</html>"))
	}))
	defer server.Close()

	req, _ := whttp.NewRequest("GET", server.URL+"/?file=test.txt", nil)
	client := whttp.NewClient()
	resp, err := client.Respond(context.Background(), req)
	if err != nil {
		t.Fatalf("Failed to get response: %v", err)
	}
	flow := &whttp.Flow{Request: req, Response: resp}

	cp := &ptCountingPrinter{}
	apollo := ptMakeApollo(t, flow, cp)

	p := &PathTraversal{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()
	fingers := p.Fingers()

	err = fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
	if cp.Count() == 0 {
		t.Error("Expected at least one vuln from RFI echo detection")
	}
}

// ==================== execAction with POST body params ====================

func TestPT_ExecAction_PostBodyParams(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("<html>normal page</html>"))
	}))
	defer server.Close()

	req, _ := whttp.NewRequest("POST", server.URL+"/page", strings.NewReader("file=test.txt"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := whttp.NewClient()
	resp, err := client.Respond(context.Background(), req)
	if err != nil {
		t.Fatalf("Failed to get response: %v", err)
	}
	flow := &whttp.Flow{Request: req, Response: resp}

	cp := &ptCountingPrinter{}
	apollo := ptMakeApollo(t, flow, cp)

	p := &PathTraversal{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()
	fingers := p.Fingers()

	err = fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
}

// ==================== execAction with no params ====================

func TestPT_ExecAction_NoParams(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("<html>normal page</html>"))
	}))
	defer server.Close()

	req, _ := whttp.NewRequest("GET", server.URL+"/page", nil)
	client := whttp.NewClient()
	resp, err := client.Respond(context.Background(), req)
	if err != nil {
		t.Fatalf("Failed to get response: %v", err)
	}
	flow := &whttp.Flow{Request: req, Response: resp}

	cp := &ptCountingPrinter{}
	apollo := ptMakeApollo(t, flow, cp)

	p := &PathTraversal{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()
	fingers := p.Fingers()

	err = fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Errorf("execAction with no params returned error: %v", err)
	}
}

// ==================== isValueReplacePayload additional tests ====================

func TestPT_IsValueReplacePayload_EdgeCases(t *testing.T) {
	tests := []struct {
		vector   string
		expected bool
	}{
		{"php://filter/read=convert.base64-encode/resource=index.php", true},
		{"php://input", true},
		{"php://filter", true},
		{"file:///etc/passwd", true},
		{"file://localhost/etc/passwd", true},
		{"file:///", true},
		{"file://", true},
		{"../../etc/passwd", false},
		{"/etc/passwd", false},
		{"", false},
		{"http://example.com", false},
		{"data://text/plain;base64,test", false},
		{"expect://command", false},
		{"PHP://filter", false},       // case-sensitive
		{"File:///etc/passwd", false}, // case-sensitive
	}

	for _, tt := range tests {
		t.Run(tt.vector, func(t *testing.T) {
			result := isValueReplacePayload(tt.vector)
			if result != tt.expected {
				t.Errorf("isValueReplacePayload(%q) = %v, want %v", tt.vector, result, tt.expected)
			}
		})
	}
}

// ==================== Rule matching tests ====================

func TestPT_RuleMatching_EtcPasswd(t *testing.T) {
	for _, rule := range pathTraversalRules {
		if rule.Vector == "/etc/passwd" && rule.typ == "LFI" {
			if !rule.compiled.MatchString("root:x:0:0:root:/root:/bin/bash") {
				t.Error("/etc/passwd rule should match /etc/passwd content")
			}
			if rule.compiled.MatchString("nothing here") {
				t.Error("/etc/passwd rule should not match random text")
			}
			return
		}
	}
	t.Error("Expected /etc/passwd LFI rule")
}

func TestPT_RuleMatching_BootIni(t *testing.T) {
	for _, rule := range pathTraversalRules {
		if rule.Vector == "c:/boot.ini" {
			if !rule.compiled.MatchString("boot loader") {
				t.Error("c:/boot.ini rule should match 'boot loader'")
			}
			if rule.Windows != 1 {
				t.Errorf("c:/boot.ini rule should have Windows=1, got %d", rule.Windows)
			}
			return
		}
	}
	t.Error("Expected c:/boot.ini rule")
}

func TestPT_RuleMatching_PHPFilter(t *testing.T) {
	for _, rule := range pathTraversalRules {
		if strings.HasPrefix(rule.Vector, "php://filter") && rule.typ == "LFI" {
			if !rule.compiled.MatchString("cm9vdDp4OjA6MDpyb290Oi9yb290Oi9ia") {
				t.Error("php://filter rule should match base64 encoded content")
			}
			return
		}
	}
	t.Error("Expected php://filter LFI rule")
}

func TestPT_RuleMatching_FileProtocol(t *testing.T) {
	for _, rule := range pathTraversalRules {
		if rule.Vector == "file:///etc/passwd" && rule.typ == "LFI" {
			if !rule.compiled.MatchString("root:x:0:0:root:/root:/bin/bash") {
				t.Error("file:///etc/passwd rule should match /etc/passwd content")
			}
			return
		}
	}
	t.Error("Expected file:///etc/passwd LFI rule")
}

func TestPT_RuleMatching_RFI(t *testing.T) {
	for _, rule := range pathTraversalRules {
		if rule.typ == "RFI" && strings.Contains(rule.Vector, "apache.org") {
			if !rule.compiled.MatchString("We suggest the following mirror site for your download") {
				t.Error("RFI rule should match Apache download page content")
			}
			return
		}
	}
	t.Error("Expected Apache RFI rule")
}

func TestPT_RuleMatching_FI(t *testing.T) {
	for _, rule := range pathTraversalRules {
		if rule.typ == "FI" && rule.Vector == "" {
			// FI rules should have compiled regexes
			if rule.compiled == nil {
				t.Error("FI rule should have compiled regex")
			}
			return
		}
	}
	t.Error("Expected at least one FI rule with empty vector")
}

// ==================== PathTraversal plugin interface tests ====================

func TestPT_Close(t *testing.T) {
	pt := &PathTraversal{}
	if err := pt.Close(); err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
}

func TestPT_DefaultConfig(t *testing.T) {
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

func TestPT_Fingers(t *testing.T) {
	pt := &PathTraversal{}
	pt.PluginMixinInitConfig.Config = pt.DefaultConfig()
	fingers := pt.Fingers()
	if len(fingers) != 1 {
		t.Fatalf("Expected 1 finger, got %d", len(fingers))
	}
	f := fingers[0]
	if f.CheckAction == nil {
		t.Error("CheckAction should not be nil")
	}
	if f.Binding == nil {
		t.Error("Binding should not be nil")
	}
	if f.Binding.ID != "path-traversal/path-traversal/default" {
		t.Errorf("Expected Binding.ID 'path-traversal/path-traversal/default', got '%s'", f.Binding.ID)
	}
	if f.Binding.Severity != model.SeverityMedium {
		t.Errorf("Expected SeverityMedium, got %v", f.Binding.Severity)
	}
	if f.Channel != "web-generic" {
		t.Errorf("Expected Channel 'web-generic', got '%s'", f.Channel)
	}
}

func TestPT_InitAndGetConfig(t *testing.T) {
	pt := &PathTraversal{}
	cfg := pt.DefaultConfig()
	ab := &base.ApolloBase{}
	err := pt.Init(context.Background(), cfg, ab)
	if err != nil {
		t.Errorf("Init() returned error: %v", err)
	}
	gotCfg := pt.GetConfig()
	if gotCfg == nil {
		t.Fatal("Expected non-nil config after Init")
	}
	bc := gotCfg.BaseConfig()
	if bc.Name != "path_traversal" {
		t.Errorf("Expected Name='path_traversal', got '%s'", bc.Name)
	}
}

// ==================== Rule struct construction tests ====================

func TestPT_RuleStructConstruction(t *testing.T) {
	r := Rule{
		Vector:  "../../etc/passwd",
		Windows: 1,
		Linux:   1,
		Data:    "root:x:0:0",
	}
	if r.Vector != "../../etc/passwd" {
		t.Error("Unexpected Vector")
	}
	if r.Windows != 1 {
		t.Error("Unexpected Windows")
	}
	if r.Linux != 1 {
		t.Error("Unexpected Linux")
	}
	if r.typ != "" {
		t.Error("Expected empty typ for new Rule")
	}
	if r.compiled != nil {
		t.Error("Expected nil compiled for new Rule")
	}
}

// ==================== Root struct tests ====================

func TestPT_RootStructConstruction(t *testing.T) {
	r := Root{}
	if len(r.LFI) != 0 {
		t.Error("Expected empty LFI")
	}
	if len(r.RFI) != 0 {
		t.Error("Expected empty RFI")
	}
	if len(r.FI) != 0 {
		t.Error("Expected empty FI")
	}
}

// ==================== Config struct tests ====================

func TestPT_ConfigBaseConfig(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "path_traversal",
			Enabled: true,
		},
	}
	bc := cfg.BaseConfig()
	if bc.Name != "path_traversal" {
		t.Errorf("Expected Name='path_traversal', got '%s'", bc.Name)
	}
	if !bc.Enabled {
		t.Error("Expected Enabled=true")
	}
}
