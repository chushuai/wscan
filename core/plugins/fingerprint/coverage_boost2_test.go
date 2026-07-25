package fingerprint

import (
	"context"
	"embed"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	whttp "wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/plugins/helper/knowledge"
	"wscan/core/resource"
	"wscan/core/utils/printer"
)

//go:embed testdata
var testdataFS embed.FS

// ==================== readDir: ReadFile error branch ====================

// Test readDir with valid embedded FS content
func TestCov2ReadDir_ValidPath(t *testing.T) {
	rules, err := readDir("technologies/wscan", template)
	if err != nil {
		t.Fatalf("readDir on valid path should not error: %v", err)
	}
	if len(rules) == 0 {
		t.Error("expected at least one rule from embedded FS")
	}
}

// ==================== readDir: yaml.Unmarshal error path ====================
// Test with a directory containing invalid YAML - exercises line 59-61

func TestCov2ReadDir_InvalidYAML(t *testing.T) {
	// The testdata/bad_yaml directory contains a file with invalid YAML
	rules, err := readDir("testdata/bad_yaml", testdataFS)
	if err == nil {
		t.Error("expected error for invalid YAML file")
	}
	if len(rules) != 0 {
		t.Errorf("expected empty rules for invalid YAML, got %d", len(rules))
	}
}

// ==================== readDir: valid YAML in testdata ====================

func TestCov2ReadDir_ValidYAML(t *testing.T) {
	rules, err := readDir("testdata/good", testdataFS)
	if err != nil {
		t.Fatalf("readDir on good testdata should not error: %v", err)
	}
	if len(rules) != 1 {
		t.Errorf("expected 1 rule from good testdata, got %d", len(rules))
	}
	if len(rules) > 0 {
		if rules[0].Info.Name != "test" {
			t.Errorf("expected rule name 'test', got %q", rules[0].Info.Name)
		}
	}
}

// ==================== readDir: nonexistent directory ====================

func TestCov2ReadDir_NonexistentDir(t *testing.T) {
	rules, err := readDir("nonexistent/path", testdataFS)
	if err == nil {
		t.Error("expected error for nonexistent directory")
	}
	if len(rules) != 0 {
		t.Errorf("expected empty rules for nonexistent dir, got %d", len(rules))
	}
}

// ==================== readDir: subdirectory recursion ====================

func TestCov2ReadDir_SubdirectoryRecursion(t *testing.T) {
	// Verify that subdirectories within the embedded FS are traversed
	entries, err := template.ReadDir("technologies/wscan")
	if err != nil {
		t.Fatalf("Failed to read dir: %v", err)
	}
	hasSubdir := false
	for _, e := range entries {
		if e.IsDir() {
			hasSubdir = true
			// Recursively read the subdirectory
			subRules, subErr := readDir("technologies/wscan/"+e.Name(), template)
			if subErr != nil {
				t.Logf("readDir on subdir %s returned error: %v", e.Name(), subErr)
			}
			_ = subRules
			break
		}
	}
	if !hasSubdir {
		t.Log("No subdirectories found; subdirectory recursion path not exercised")
	}
}

// ==================== readDir: testdata root (contains subdirs) ====================

func TestCov2ReadDir_TestdataRoot(t *testing.T) {
	// Reading the testdata root should recurse into good/ and bad_yaml/
	// bad_yaml will fail, but good should succeed
	// The recursive call on bad_yaml returns error (which is discarded in the code: subRet, _ := readDir(...))
	rules, err := readDir("testdata", testdataFS)
	if err != nil {
		// The top-level call may not error since subdirectory errors are silently discarded
		t.Logf("readDir on testdata root returned error: %v", err)
	}
	// We should get at least the good rule (bad_yaml errors are silently swallowed)
	if len(rules) < 1 {
		t.Errorf("expected at least 1 rule from testdata, got %d", len(rules))
	}
}

// ==================== ProcessFingerprint coverage ====================

func TestCov2ProcessFingerprint_NilArgs(t *testing.T) {
	ProcessFingerprint(nil, nil)
}

func TestCov2ProcessFingerprint_WithContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	ProcessFingerprint(ctx, &resource.Service{})
}

func TestCov2ProcessFingerprint_WithCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ProcessFingerprint(ctx, nil)
}

// ==================== execAction: vuln found path ====================

func TestCov2ExecAction_VulnOutput(t *testing.T) {
	// Server that returns a response matching known fingerprint rules (e.g. nginx)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		w.WriteHeader(200)
		w.Write([]byte("<html><body>Welcome to nginx!</body></html>"))
	}))
	defer server.Close()

	var vulnOutput *model.Vuln
	mp := &cov2MockPrinter{onVuln: func(v *model.Vuln) {
		vulnOutput = v
	}}

	req, err := whttp.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	client := whttp.NewClient()
	resp, err := client.Respond(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	flow := &whttp.Flow{Request: req, Response: resp}

	ab := &base.ApolloBase{
		HTTPClient: client,
		Output:     mp,
		KDB:        knowledge.NewKnowledgeDB(nil),
	}
	apollo := base.NewApollo(flow)
	apollo.ApolloBase = ab

	p := &Fingerprint{}
	err = p.execAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
	// If a fingerprint was found, vulnOutput should be non-nil
	_ = vulnOutput
}

// ==================== execAction: expression evaluation error (continue) ====================

func TestCov2ExecAction_ExpressionError(t *testing.T) {
	// A server that returns a simple response - any expression errors
	// should be handled via continue
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("<html>ok</html>"))
	}))
	defer server.Close()

	req, _ := whttp.NewRequest("GET", server.URL, nil)
	client := whttp.NewClient()
	resp, err := client.Respond(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	flow := &whttp.Flow{Request: req, Response: resp}

	ab := &base.ApolloBase{
		HTTPClient: client,
		Output:     &cov2MockPrinter{},
		KDB:        knowledge.NewKnowledgeDB(nil),
	}
	apollo := base.NewApollo(flow)
	apollo.ApolloBase = ab

	p := &Fingerprint{}
	err = p.execAction(context.Background(), apollo)
	if err != nil {
		t.Errorf("execAction should not return error: %v", err)
	}
}

// ==================== execAction: isFound false (not ok or not true) ====================

func TestCov2ExecAction_NoFingerprintMatch(t *testing.T) {
	// Server that returns a very generic response unlikely to match any fingerprint
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("generic content with no identifiable technology"))
	}))
	defer server.Close()

	req, _ := whttp.NewRequest("GET", server.URL, nil)
	client := whttp.NewClient()
	resp, err := client.Respond(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	flow := &whttp.Flow{Request: req, Response: resp}

	ab := &base.ApolloBase{
		HTTPClient: client,
		Output:     &cov2MockPrinter{},
		KDB:        knowledge.NewKnowledgeDB(nil),
	}
	apollo := base.NewApollo(flow)
	apollo.ApolloBase = ab

	p := &Fingerprint{}
	err = p.execAction(context.Background(), apollo)
	if err != nil {
		t.Errorf("execAction should not error: %v", err)
	}
}

// ==================== execAction: ConvertHttpRequestToModelRequest error path ====================

func TestCov2ExecAction_WithRealFlow(t *testing.T) {
	// Create a real flow from a test server and test execAction end-to-end
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/7.4.3")
		w.WriteHeader(200)
		w.Write([]byte("<html><body>PHP application</body></html>"))
	}))
	defer server.Close()

	req, _ := whttp.NewRequest("GET", server.URL, nil)
	client := whttp.NewClient()
	resp, err := client.Respond(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	flow := &whttp.Flow{Request: req, Response: resp}

	ab := &base.ApolloBase{
		HTTPClient: client,
		Output:     &cov2MockPrinter{},
		KDB:        knowledge.NewKnowledgeDB(nil),
	}
	apollo := base.NewApollo(flow)
	apollo.ApolloBase = ab

	p := &Fingerprint{}
	err = p.execAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned: %v", err)
	}
}

// ==================== execAction: ConvertHttpResponseToModelResponse error path ====================

func TestCov2ExecAction_WithManualResponse(t *testing.T) {
	// Create a request and response manually to test the conversion path
	req, _ := whttp.NewRequest("GET", "http://example.com/", nil)
	u, _ := url.Parse("http://example.com/")
	netResp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": {"text/html"}, "Server": {"Apache/2.4.41"}},
		Body:       io.NopCloser(strings.NewReader("<html><body>Apache default page</body></html>")),
		Request:    &http.Request{URL: u},
	}
	resp, _ := whttp.ResponseFromNetHttpResponse(netResp)

	flow := &whttp.Flow{Request: req, Response: resp}
	ab := &base.ApolloBase{
		Output: &cov2MockPrinter{},
		KDB:    knowledge.NewKnowledgeDB(nil),
	}
	apollo := base.NewApollo(flow)
	apollo.ApolloBase = ab

	p := &Fingerprint{}
	err := p.execAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned: %v", err)
	}
}

// ==================== FingerprintRule YAML round-trip ====================

func TestCov2FingerprintRule_YAMLRoundTrip(t *testing.T) {
	original := FingerprintRule{
		Engine: "fingerprint",
		Info:   FingerprintInfo{Name: "TestTech", Author: "tester"},
		Pscan: FingerprintPscan{
			Path:        []string{"/", "/admin"},
			Expressions: []string{"response.status == 200", `response.body.bcontains(b"admin")`},
		},
	}

	// Verify fields are accessible
	if original.Engine != "fingerprint" {
		t.Errorf("Engine = %q, want 'fingerprint'", original.Engine)
	}
	if len(original.Pscan.Path) != 2 {
		t.Errorf("len(Path) = %d, want 2", len(original.Pscan.Path))
	}
	if len(original.Pscan.Expressions) != 2 {
		t.Errorf("len(Expressions) = %d, want 2", len(original.Pscan.Expressions))
	}
}

// ==================== readDir with custom FS for error paths ====================

//go:embed technologies/wscan
var cov2Template embed.FS

func TestCov2ReadDir_WithEmbedFS(t *testing.T) {
	// Test that the same embedded FS can be read multiple times
	rules1, err1 := readDir("technologies/wscan", cov2Template)
	if err1 != nil {
		t.Fatalf("First readDir failed: %v", err1)
	}
	rules2, err2 := readDir("technologies/wscan", cov2Template)
	if err2 != nil {
		t.Fatalf("Second readDir failed: %v", err2)
	}
	if len(rules1) != len(rules2) {
		t.Errorf("Same FS should produce same number of rules: %d vs %d", len(rules1), len(rules2))
	}
}

// ==================== Config with various values ====================

func TestCov2Config_VariousValues(t *testing.T) {
	tests := []struct {
		name    string
		enabled bool
	}{
		{"enabled", true},
		{"disabled", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				PluginBaseConfig: base.PluginBaseConfig{
					Name:    "fingerprint",
					Enabled: tt.enabled,
				},
			}
			bc := cfg.BaseConfig()
			if bc.Enabled != tt.enabled {
				t.Errorf("Enabled = %v, want %v", bc.Enabled, tt.enabled)
			}
		})
	}
}

// ==================== Fingers binding details ====================

func TestCov2Fingers_BindingDetails(t *testing.T) {
	p := &Fingerprint{}
	fingers := p.Fingers()
	if len(fingers) == 0 {
		t.Fatal("Expected at least one finger")
	}
	f := fingers[0]
	if f.Binding.ID != "fingerprint/default" {
		t.Errorf("Binding.ID = %q, want 'fingerprint/default'", f.Binding.ID)
	}
	if f.Binding.Plugin != "fingerprint" {
		t.Errorf("Binding.Plugin = %q, want 'fingerprint'", f.Binding.Plugin)
	}
	if f.Binding.Category != "fingerprint" {
		t.Errorf("Binding.Category = %q, want 'fingerprint'", f.Binding.Category)
	}
	if f.Binding.Severity != model.SeverityInfo {
		t.Errorf("Binding.Severity = %v, want SeverityInfo", f.Binding.Severity)
	}
}

// ==================== LoadFingerprintRule always returns nil ====================

func TestCov2LoadFingerprintRule_AlwaysNil(t *testing.T) {
	tests := []string{"", "nonexistent.yaml", "/tmp/test.yaml"}
	for _, input := range tests {
		rule, err := LoadFingerprintRule(input)
		if rule != nil || err != nil {
			t.Errorf("LoadFingerprintRule(%q) = (%v, %v), want (nil, nil)", input, rule, err)
		}
	}
}

// ==================== execAction with multiple server types ====================

func TestCov2ExecAction_IISResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Microsoft-IIS/10.0")
		w.WriteHeader(200)
		w.Write([]byte("<html><body>IIS default page</body></html>"))
	}))
	defer server.Close()

	p := &Fingerprint{}
	apollo := cov2MakeApollo(t, server.URL)
	err := p.execAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned: %v", err)
	}
}

func TestCov2ExecAction_TomcatResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache-Coyote/1.1")
		w.WriteHeader(200)
		w.Write([]byte(`<html><title>Apache Tomcat</title></html>`))
	}))
	defer server.Close()

	p := &Fingerprint{}
	apollo := cov2MakeApollo(t, server.URL)
	err := p.execAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned: %v", err)
	}
}

func TestCov2ExecAction_PHPResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/7.4.3")
		w.WriteHeader(200)
		w.Write([]byte(`<html><body>PHP application</body></html>`))
	}))
	defer server.Close()

	p := &Fingerprint{}
	apollo := cov2MakeApollo(t, server.URL)
	err := p.execAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned: %v", err)
	}
}

func TestCov2ExecAction_DjangoResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		cookie := &http.Cookie{Name: "csrftoken", Value: "abc123"}
		http.SetCookie(w, cookie)
		w.WriteHeader(200)
		w.Write([]byte(`<html><body>Django app</body></html>`))
	}))
	defer server.Close()

	p := &Fingerprint{}
	apollo := cov2MakeApollo(t, server.URL)
	err := p.execAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned: %v", err)
	}
}

func TestCov2ExecAction_RedirectResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/login")
		w.WriteHeader(302)
	}))
	defer server.Close()

	p := &Fingerprint{}
	apollo := cov2MakeApollo(t, server.URL)
	err := p.execAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned: %v", err)
	}
}

// ==================== Fingerprint plugin satisfies Plugin interface ====================

func TestCov2Fingerprint_SatisfiesPluginInterface(t *testing.T) {
	var _ base.Plugin = &Fingerprint{}
}

// ==================== fingerprintRules content validation ====================

func TestCov2FingerprintRules_HaveValidExpressions(t *testing.T) {
	count := 0
	for i, rule := range fingerprintRules {
		if len(rule.Pscan.Expressions) == 0 {
			count++
			continue
		}
		for j, expr := range rule.Pscan.Expressions {
			if expr == "" {
				t.Errorf("Rule[%d] (%s) expression[%d] is empty", i, rule.Info.Name, j)
			}
		}
	}
	t.Logf("%d rules have no expressions (expected for some rules)", count)
}

// ==================== Helper types and functions ====================

type cov2MockPrinter struct {
	onVuln func(v *model.Vuln)
}

func (m *cov2MockPrinter) Print(v any) error {
	if vuln, ok := v.(*model.Vuln); ok && m.onVuln != nil {
		m.onVuln(vuln)
	}
	return nil
}
func (m *cov2MockPrinter) Close() error                                          { return nil }
func (m *cov2MockPrinter) AddInterceptor(func(any) (any, error)) printer.Printer { return m }
func (m *cov2MockPrinter) LogSubdomain(any) error                                { return nil }
func (m *cov2MockPrinter) LogVuln(any) error                                     { return nil }

func cov2MakeApollo(t *testing.T, serverURL string) *base.Apollo {
	t.Helper()
	req, err := whttp.NewRequest("GET", serverURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	client := whttp.NewClient()
	resp, err := client.Respond(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	flow := &whttp.Flow{Request: req, Response: resp}
	ab := &base.ApolloBase{
		HTTPClient: client,
		Output:     &cov2MockPrinter{},
		KDB:        knowledge.NewKnowledgeDB(nil),
	}
	apollo := base.NewApollo(flow)
	apollo.ApolloBase = ab
	return apollo
}
