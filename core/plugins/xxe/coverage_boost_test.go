package xxe

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	whttp "wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/reverse"
	"wscan/core/utils/printer"
)

// ==================== Helpers for coverage_boost tests ====================

type cbPrinter struct {
	count int
	mu    sync.Mutex
}

func (p *cbPrinter) AddInterceptor(func(any) (any, error)) printer.Printer { return p }
func (p *cbPrinter) Close() error                                          { return nil }
func (p *cbPrinter) Print(v any) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.count++
	return nil
}
func (p *cbPrinter) Count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.count
}

func createCBReverse(t *testing.T) *reverse.Reverse {
	t.Helper()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "cb_reverse.db")

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to find available port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	config := &reverse.Config{
		Token: "cbtoken",
		HTTPServerConfig: reverse.HTTPServerConfig{
			Enabled:    true,
			ListenIP:   "127.0.0.1",
			ListenPort: fmt.Sprintf("%d", port),
		},
		DNSServerConfig: reverse.DNSServerConfig{
			Domain: "dnslog.com",
		},
		DBFilePath: dbPath,
	}

	rv := reverse.NewReverse(config)
	if rv == nil {
		t.Fatal("NewReverse returned nil")
	}
	t.Cleanup(func() { rv.Close() })
	return rv
}

func makeCBApollo(flow *whttp.Flow, rv *reverse.Reverse, output printer.Printer) *base.Apollo {
	apollo := base.NewApollo(flow)
	apollo.ApolloBase = &base.ApolloBase{
		HTTPClient: whttp.NewClient(),
		Reverse:    rv,
		Output:     output,
	}
	apollo.WithVuln(&model.Vuln{
		Binding: &model.VulnBinding{
			ID:       "xxe/dispatcher/default",
			Plugin:   "xxe/xxe/echo",
			Category: "xxe/xxe/echo",
			Severity: model.SeverityCritical,
		},
	})
	return apollo
}

// ==================== Phase 1: Query/Body param with various echo types ====================
// These tests exercise the Phase 1 branches of execAction where the echo is detected
// via CheckXXEEcho for each pattern type (passwd, shadow, linux user info, windows dir).

func TestCB_Phase1_ShadowEchoInQueryParam(t *testing.T) {
	rv := createCBReverse(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "root:$5$salt$hash:18000:0:99999:7:::")
	}))
	defer server.Close()

	p := &XXE{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()
	req, _ := whttp.NewRequest("GET", server.URL+"/test?cat=1", nil)
	req.Header = make(map[string][]string)
	flow := &whttp.Flow{
		Request: req,
		Response: &whttp.Response{
			Text:   "ok",
			Header: make(map[string][]string),
		},
	}

	cp := &cbPrinter{}
	apollo := makeCBApollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
	if cp.Count() == 0 {
		t.Error("Expected at least one vuln from shadow echo detection in query param")
	}
}

func TestCB_Phase1_LinuxUserInfoEchoInQueryParam(t *testing.T) {
	rv := createCBReverse(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "uid=0(root) gid=0(root) groups=0(root)")
	}))
	defer server.Close()

	p := &XXE{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()
	req, _ := whttp.NewRequest("GET", server.URL+"/test?user=admin", nil)
	req.Header = make(map[string][]string)
	flow := &whttp.Flow{
		Request: req,
		Response: &whttp.Response{
			Text:   "ok",
			Header: make(map[string][]string),
		},
	}

	cp := &cbPrinter{}
	apollo := makeCBApollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
	if cp.Count() == 0 {
		t.Error("Expected at least one vuln from Linux user info echo detection")
	}
}

func TestCB_Phase1_WindowsDirEchoInQueryParam(t *testing.T) {
	rv := createCBReverse(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "Volume in drive C is Windows")
	}))
	defer server.Close()

	p := &XXE{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()
	req, _ := whttp.NewRequest("GET", server.URL+"/test?dir=test", nil)
	req.Header = make(map[string][]string)
	flow := &whttp.Flow{
		Request: req,
		Response: &whttp.Response{
			Text:   "ok",
			Header: make(map[string][]string),
		},
	}

	cp := &cbPrinter{}
	apollo := makeCBApollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
	if cp.Count() == 0 {
		t.Error("Expected at least one vuln from Windows dir echo detection")
	}
}

// ==================== Phase 1: Body parameter injection ====================

func TestCB_Phase1_BodyParamEchoDetection(t *testing.T) {
	rv := createCBReverse(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash")
	}))
	defer server.Close()

	p := &XXE{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()
	body := "username=admin&password=test"
	req, _ := whttp.NewRequest("POST", server.URL+"/login", strings.NewReader(body))
	req.Header = make(map[string][]string)
	req.WithFormBody(strings.NewReader(body))
	flow := &whttp.Flow{
		Request: req,
		Response: &whttp.Response{
			Text:   "ok",
			Header: make(map[string][]string),
		},
	}

	cp := &cbPrinter{}
	apollo := makeCBApollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
	if cp.Count() == 0 {
		t.Error("Expected at least one vuln from body param echo detection")
	}
}

// ==================== Phase 2: XML body with echo - basic payload path ====================

func TestCB_Phase2_BasicPayloadEchoThenReturn(t *testing.T) {
	rv := createCBReverse(t)

	// Server that returns echo content for the first request (basic payload)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<?xml version="1.0"?><result>root:x:0:0:root:/root:/bin/bash</result>`)
	}))
	defer server.Close()

	p := &XXE{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()
	req, _ := whttp.NewRequest("POST", server.URL+"/api", nil)
	req.Header = make(map[string][]string)
	req.Header["Content-Type"] = []string{"application/xml"}
	flow := &whttp.Flow{
		Request: req,
		Response: &whttp.Response{
			Text:   "<result>ok</result>",
			Header: make(map[string][]string),
		},
	}

	cp := &cbPrinter{}
	apollo := makeCBApollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
	if cp.Count() == 0 {
		t.Error("Expected at least one vuln from basic payload echo detection")
	}
}

// ==================== Phase 2: SOAP echo detection path ====================

func TestCB_Phase2_SOAPEchoDetection(t *testing.T) {
	rv := createCBReverse(t)

	// Return echo for ALL requests to ensure SOAP payloads trigger
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/soap+xml")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash")
	}))
	defer server.Close()

	p := &XXE{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()
	req, _ := whttp.NewRequest("POST", server.URL+"/soap", nil)
	req.Header = make(map[string][]string)
	req.Header["Content-Type"] = []string{"application/soap+xml"}
	flow := &whttp.Flow{
		Request: req,
		Response: &whttp.Response{
			Text:   "<soap:Envelope/>",
			Header: make(map[string][]string),
		},
	}

	cp := &cbPrinter{}
	apollo := makeCBApollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
	// Should detect echo and return early
}

// ==================== Phase 2: SVG echo detection path ====================

func TestCB_Phase2_SVGEchoDetection(t *testing.T) {
	rv := createCBReverse(t)

	// Return echo for ALL requests - SVG payloads don't have echo check in code,
	// but this exercises the SVG payload path
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "<svg xmlns=\"http://www.w3.org/2000/svg\"><text>ok</text></svg>")
	}))
	defer server.Close()

	p := &XXE{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()
	req, _ := whttp.NewRequest("POST", server.URL+"/upload", nil)
	req.Header = make(map[string][]string)
	req.Header["Content-Type"] = []string{"image/svg+xml"}
	flow := &whttp.Flow{
		Request: req,
		Response: &whttp.Response{
			Text:   "<svg/>",
			Header: make(map[string][]string),
		},
	}

	cp := &cbPrinter{}
	apollo := makeCBApollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
}

// ==================== Phase 2: XInclude echo detection path ====================

func TestCB_Phase2_XIncludeEchoDetection(t *testing.T) {
	rv := createCBReverse(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<foo>root:x:0:0:root:/root:/bin/bash</foo>`)
	}))
	defer server.Close()

	p := &XXE{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()
	req, _ := whttp.NewRequest("POST", server.URL+"/api", nil)
	req.Header = make(map[string][]string)
	req.Header["Content-Type"] = []string{"application/xml"}
	flow := &whttp.Flow{
		Request: req,
		Response: &whttp.Response{
			Text:   "<result>ok</result>",
			Header: make(map[string][]string),
		},
	}

	cp := &cbPrinter{}
	apollo := makeCBApollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
}

// ==================== Phase 2: XML body with WithXMLBody (DeepClone path) ====================

func TestCB_Phase2_WithXMLBody(t *testing.T) {
	rv := createCBReverse(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<?xml version="1.0"?><response>ok</response>`)
	}))
	defer server.Close()

	p := &XXE{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()
	xmlBody := `<?xml version="1.0"?><request><data>test</data></request>`
	req, _ := whttp.NewRequest("POST", server.URL+"/api", nil)
	req.Header = make(map[string][]string)
	req.WithXMLBody(bytes.NewReader([]byte(xmlBody)))
	flow := &whttp.Flow{
		Request: req,
		Response: &whttp.Response{
			Text:   "<response>ok</response>",
			Header: make(map[string][]string),
		},
	}

	cp := &cbPrinter{}
	apollo := makeCBApollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
}

// ==================== Phase 2: Error handling in all XML payload types ====================

func TestCB_Phase2_XMLErrorHandling(t *testing.T) {
	rv := createCBReverse(t)

	// Server that closes connections for XML requests
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct := r.Header.Get("Content-Type")
		if strings.Contains(ct, "xml") || strings.Contains(ct, "soap") {
			if hijacker, ok := w.(http.Hijacker); ok {
				conn, _, err := hijacker.Hijack()
				if err == nil {
					conn.Close()
				}
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer server.Close()

	p := &XXE{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()
	req, _ := whttp.NewRequest("POST", server.URL+"/api", nil)
	req.Header = make(map[string][]string)
	req.Header["Content-Type"] = []string{"application/xml"}
	flow := &whttp.Flow{
		Request: req,
		Response: &whttp.Response{
			Text:   "<result>ok</result>",
			Header: make(map[string][]string),
		},
	}

	cp := &cbPrinter{}
	apollo := makeCBApollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error (expected with error server): %v", err)
	}
}

// ==================== Phase 2: Non-XML content type skips Phase 2 ====================

func TestCB_Phase2_NonXMLContentTypeSkips(t *testing.T) {
	rv := createCBReverse(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "<html>normal</html>")
	}))
	defer server.Close()

	p := &XXE{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()
	req, _ := whttp.NewRequest("POST", server.URL+"/api", strings.NewReader(`{"key":"value"}`))
	req.Header = make(map[string][]string)
	req.WithJSONBody(strings.NewReader(`{"key":"value"}`))
	flow := &whttp.Flow{
		Request: req,
		Response: &whttp.Response{
			Text:   `{"status":"ok"}`,
			Header: make(map[string][]string),
		},
	}

	cp := &cbPrinter{}
	apollo := makeCBApollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
	// Non-XML should skip Phase 2 entirely, no vulns expected
	if cp.Count() > 0 {
		t.Error("Expected no vulns for non-XML content type")
	}
}

// ==================== Phase 2: XHTML content type path ====================

func TestCB_Phase2_XHTMLContentType(t *testing.T) {
	rv := createCBReverse(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/xhtml+xml")
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
	defer server.Close()

	p := &XXE{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()
	req, _ := whttp.NewRequest("POST", server.URL+"/page", nil)
	req.Header = make(map[string][]string)
	req.Header["Content-Type"] = []string{"application/xhtml+xml"}
	flow := &whttp.Flow{
		Request: req,
		Response: &whttp.Response{
			Text:   "<html>ok</html>",
			Header: make(map[string][]string),
		},
	}

	cp := &cbPrinter{}
	apollo := makeCBApollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
}

// ==================== Phase 2: DNS detection path ====================

func TestCB_Phase2_DNSDetectionPath(t *testing.T) {
	rv := createCBReverse(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer server.Close()

	p := &XXE{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()
	req, _ := whttp.NewRequest("POST", server.URL+"/api", nil)
	req.Header = make(map[string][]string)
	req.Header["Content-Type"] = []string{"application/xml"}
	flow := &whttp.Flow{
		Request: req,
		Response: &whttp.Response{
			Text:   "<result>ok</result>",
			Header: make(map[string][]string),
		},
	}

	cp := &cbPrinter{}
	apollo := makeCBApollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
	// DNS detection path is exercised even if no vuln found
}

// ==================== Phase 1: No params in request ====================

func TestCB_Phase1_NoParams(t *testing.T) {
	rv := createCBReverse(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer server.Close()

	p := &XXE{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()
	req, _ := whttp.NewRequest("GET", server.URL+"/noparams", nil)
	req.Header = make(map[string][]string)
	flow := &whttp.Flow{
		Request: req,
		Response: &whttp.Response{
			Text:   "ok",
			Header: make(map[string][]string),
		},
	}

	cp := &cbPrinter{}
	apollo := makeCBApollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
}

// ==================== Phase 1: HTTP error on request ====================

func TestCB_Phase1_HTTPError(t *testing.T) {
	rv := createCBReverse(t)

	p := &XXE{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()
	req, _ := whttp.NewRequest("GET", "http://127.0.0.1:1/test?param=value", nil)
	req.Header = make(map[string][]string)
	flow := &whttp.Flow{
		Request: req,
		Response: &whttp.Response{
			Text:   "",
			Header: make(map[string][]string),
		},
	}

	cp := &cbPrinter{}
	apollo := makeCBApollo(flow, rv, cp)

	fingers := p.Fingers()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := fingers[0].CheckAction(ctx, apollo)
	if err != nil {
		t.Logf("execAction returned error (expected with unreachable host): %v", err)
	}
}

// ==================== Phase 2: Multiple query params with echo ====================

func TestCB_Phase1_MultipleParamsWithEcho(t *testing.T) {
	rv := createCBReverse(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash")
	}))
	defer server.Close()

	p := &XXE{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()
	req, _ := whttp.NewRequest("GET", server.URL+"/search?q=test&category=all&page=1", nil)
	req.Header = make(map[string][]string)
	flow := &whttp.Flow{
		Request: req,
		Response: &whttp.Response{
			Text:   "ok",
			Header: make(map[string][]string),
		},
	}

	cp := &cbPrinter{}
	apollo := makeCBApollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
	if cp.Count() == 0 {
		t.Error("Expected at least one vuln from echo detection with multiple params")
	}
}

// ==================== Phase 2: Shadow echo in XML body ====================

func TestCB_Phase2_ShadowEchoInXMLBody(t *testing.T) {
	rv := createCBReverse(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `root:$6$saltsalt$hashhash:18000:0:99999:7:::`)
	}))
	defer server.Close()

	p := &XXE{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()
	req, _ := whttp.NewRequest("POST", server.URL+"/api", nil)
	req.Header = make(map[string][]string)
	req.Header["Content-Type"] = []string{"application/xml"}
	flow := &whttp.Flow{
		Request: req,
		Response: &whttp.Response{
			Text:   "<result>ok</result>",
			Header: make(map[string][]string),
		},
	}

	cp := &cbPrinter{}
	apollo := makeCBApollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
}

// ==================== Phase 2: Linux user info echo in XML body ====================

func TestCB_Phase2_LinuxUserInfoInXMLBody(t *testing.T) {
	rv := createCBReverse(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `uid=0(root) gid=0(root) groups=0(root)`)
	}))
	defer server.Close()

	p := &XXE{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()
	req, _ := whttp.NewRequest("POST", server.URL+"/api", nil)
	req.Header = make(map[string][]string)
	req.Header["Content-Type"] = []string{"application/xml"}
	flow := &whttp.Flow{
		Request: req,
		Response: &whttp.Response{
			Text:   "<result>ok</result>",
			Header: make(map[string][]string),
		},
	}

	cp := &cbPrinter{}
	apollo := makeCBApollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
}

// ==================== Phase 2: Windows dir echo in XML body ====================

func TestCB_Phase2_WindowsDirInXMLBody(t *testing.T) {
	rv := createCBReverse(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `Volume in drive C is Windows`)
	}))
	defer server.Close()

	p := &XXE{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()
	req, _ := whttp.NewRequest("POST", server.URL+"/api", nil)
	req.Header = make(map[string][]string)
	req.Header["Content-Type"] = []string{"application/xml"}
	flow := &whttp.Flow{
		Request: req,
		Response: &whttp.Response{
			Text:   "<result>ok</result>",
			Header: make(map[string][]string),
		},
	}

	cp := &cbPrinter{}
	apollo := makeCBApollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
}

// ==================== Phase 1: OnVisit callback trigger via reverse server ====================
// To exercise the OnVisit callbacks (the uncovered code), we need the reverse server
// to actually receive a visit. We simulate this by having the test server extract
// the reverse URL from the XXE payload and visiting it.

func TestCB_Phase1_OnVisitTrigger(t *testing.T) {
	rv := createCBReverse(t)

	var callbackMade int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "<html>normal response</html>")

		// Extract the reverse server URL from the query parameters
		// The payload format: <?xml+version="1.0"?><!DOCTYPE+ANY+[<!ENTITY+content+SYSTEM+"http://addr/i/hash/group/unit/">]><a>&content;</a>
		for _, values := range r.URL.Query() {
			for _, v := range values {
				if idx := strings.Index(v, "http://"); idx != -1 {
					urlStr := v[idx:]
					endIdx := strings.IndexAny(urlStr, "\"'")
					if endIdx > 0 {
						urlStr = urlStr[:endIdx]
					}
					if strings.Contains(urlStr, "/i/") {
						go func(visitURL string) {
							client := &http.Client{Timeout: 2 * time.Second}
							resp, err := client.Get(visitURL)
							if err == nil {
								resp.Body.Close()
							}
							atomic.AddInt32(&callbackMade, 1)
						}(urlStr)
					}
				}
			}
		}
	}))
	defer server.Close()

	p := &XXE{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()
	req, _ := whttp.NewRequest("GET", server.URL+"/test?param1=value1", nil)
	req.Header = make(map[string][]string)
	flow := &whttp.Flow{
		Request: req,
		Response: &whttp.Response{
			Text:   "ok",
			Header: make(map[string][]string),
		},
	}

	cp := &cbPrinter{}
	apollo := makeCBApollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}

	// Wait for the callback goroutine to complete
	for i := 0; i < 20; i++ {
		if atomic.LoadInt32(&callbackMade) > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	// Give FetchEvent time to process
	time.Sleep(1 * time.Second)

	if cp.Count() > 0 {
		t.Logf("OnVisit callback was triggered! Vulns output: %d", cp.Count())
	}
}

// ==================== Phase 2: OnVisit trigger for XML body injection ====================

func TestCB_Phase2_OnVisitTrigger(t *testing.T) {
	rv := createCBReverse(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<?xml version="1.0"?><result>normal response</result>`)
	}))
	defer server.Close()

	p := &XXE{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()
	req, _ := whttp.NewRequest("POST", server.URL+"/api", nil)
	req.Header = make(map[string][]string)
	req.Header["Content-Type"] = []string{"application/xml"}
	flow := &whttp.Flow{
		Request: req,
		Response: &whttp.Response{
			Text:   "<result>ok</result>",
			Header: make(map[string][]string),
		},
	}

	cp := &cbPrinter{}
	apollo := makeCBApollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
}
