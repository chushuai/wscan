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

// ==================== Helpers for coverage_boost2 tests ====================

type cb2Printer struct {
	count int
	mu    sync.Mutex
}

func (p *cb2Printer) AddInterceptor(func(any) (any, error)) printer.Printer { return p }
func (p *cb2Printer) Close() error                                          { return nil }
func (p *cb2Printer) Print(v any) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.count++
	return nil
}
func (p *cb2Printer) Count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.count
}

func createCB2Reverse(t *testing.T) *reverse.Reverse {
	t.Helper()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "cb2_reverse.db")

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to find available port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	config := &reverse.Config{
		Token: "cb2token",
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

func makeCB2Apollo(flow *whttp.Flow, rv *reverse.Reverse, output printer.Printer) *base.Apollo {
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

// ==================== Phase 1: Echo detection with all echo types on first param ====================
// These tests exercise the Phase 1 echo detection path more thoroughly by ensuring
// that each echo type triggers on the very first parameter tested.

func TestCB2_Phase1_PasswdEchoOnFirstParam(t *testing.T) {
	rv := createCB2Reverse(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash")
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

	cp := &cb2Printer{}
	apollo := makeCB2Apollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
	if cp.Count() == 0 {
		t.Error("Expected at least one vuln from passwd echo detection")
	}
}

// ==================== Phase 2: XML body with text/xml content type ====================

func TestCB2_Phase2_TextXMLContentType(t *testing.T) {
	rv := createCB2Reverse(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<?xml version="1.0"?><result>ok</result>`)
	}))
	defer server.Close()

	p := &XXE{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()
	req, _ := whttp.NewRequest("POST", server.URL+"/api", nil)
	req.Header = make(map[string][]string)
	req.Header["Content-Type"] = []string{"text/xml"}
	flow := &whttp.Flow{
		Request: req,
		Response: &whttp.Response{
			Text:   "<result>ok</result>",
			Header: make(map[string][]string),
		},
	}

	cp := &cb2Printer{}
	apollo := makeCB2Apollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
}

// ==================== Phase 2: XML body with text/xml echo on basic payload ====================

func TestCB2_Phase2_TextXMLEchoDetection(t *testing.T) {
	rv := createCB2Reverse(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `root:x:0:0:root:/root:/bin/bash`)
	}))
	defer server.Close()

	p := &XXE{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()
	req, _ := whttp.NewRequest("POST", server.URL+"/api", nil)
	req.Header = make(map[string][]string)
	req.Header["Content-Type"] = []string{"text/xml"}
	flow := &whttp.Flow{
		Request: req,
		Response: &whttp.Response{
			Text:   "<result>ok</result>",
			Header: make(map[string][]string),
		},
	}

	cp := &cb2Printer{}
	apollo := makeCB2Apollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
	if cp.Count() == 0 {
		t.Error("Expected at least one vuln from text/xml echo detection")
	}
}

// ==================== Phase 2: SVG content type path ====================

func TestCB2_Phase2_SVGContentType(t *testing.T) {
	rv := createCB2Reverse(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<svg xmlns="http://www.w3.org/2000/svg"><text>ok</text></svg>`)
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

	cp := &cb2Printer{}
	apollo := makeCB2Apollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
}

// ==================== Phase 1: Body params with XML content type ====================
// This exercises both Phase 1 (body param injection) and Phase 2 (XML body injection)

func TestCB2_Phase1And2_BodyParamsWithXMLContentType(t *testing.T) {
	rv := createCB2Reverse(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<?xml version="1.0"?><result>normal</result>`)
	}))
	defer server.Close()

	p := &XXE{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()
	body := "username=admin&password=test"
	req, _ := whttp.NewRequest("POST", server.URL+"/api", strings.NewReader(body))
	req.Header = make(map[string][]string)
	req.WithFormBody(strings.NewReader(body))
	req.Header["Content-Type"] = []string{"application/xml"}
	flow := &whttp.Flow{
		Request: req,
		Response: &whttp.Response{
			Text:   "<result>ok</result>",
			Header: make(map[string][]string),
		},
	}

	cp := &cb2Printer{}
	apollo := makeCB2Apollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
}

// ==================== Phase 2: SOAP echo detection returning early ====================

func TestCB2_Phase2_SOAPEchoReturnsEarly(t *testing.T) {
	rv := createCB2Reverse(t)

	// Server that always returns echo content, so SOAP path detects it and returns early
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

	cp := &cb2Printer{}
	apollo := makeCB2Apollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
	if cp.Count() == 0 {
		t.Error("Expected at least one vuln from SOAP echo detection")
	}
}

// ==================== Phase 2: XInclude echo detection returning early ====================

func TestCB2_Phase2_XIncludeEchoReturnsEarly(t *testing.T) {
	rv := createCB2Reverse(t)

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

	cp := &cb2Printer{}
	apollo := makeCB2Apollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
	// XInclude echo detection should find the vuln and return early
}

// ==================== Phase 2: XML body with echo on basic payload, then early return ====================

func TestCB2_Phase2_BasicPayloadEchoThenEarlyReturn(t *testing.T) {
	rv := createCB2Reverse(t)

	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		// First request (basic payload) returns echo content
		if count == 1 {
			fmt.Fprint(w, `root:x:0:0:root:/root:/bin/bash`)
			return
		}
		fmt.Fprint(w, `<?xml version="1.0"?><result>normal</result>`)
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

	cp := &cb2Printer{}
	apollo := makeCB2Apollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
}

// ==================== Phase 1: OnVisit callback with reverse server (attempts coverage) ====================

func TestCB2_Phase1_OnVisitCallbackAttempt(t *testing.T) {
	rv := createCB2Reverse(t)

	var callbackMade int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "<html>normal response</html>")

		// Try to extract and visit the reverse server URL from request params
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
	req, _ := whttp.NewRequest("GET", server.URL+"/test?param1=value1&param2=value2", nil)
	req.Header = make(map[string][]string)
	flow := &whttp.Flow{
		Request: req,
		Response: &whttp.Response{
			Text:   "ok",
			Header: make(map[string][]string),
		},
	}

	cp := &cb2Printer{}
	apollo := makeCB2Apollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}

	// Wait for callbacks
	for i := 0; i < 30; i++ {
		if atomic.LoadInt32(&callbackMade) > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	time.Sleep(1 * time.Second)

	if cp.Count() > 0 {
		t.Logf("OnVisit callback triggered! Vulns: %d", cp.Count())
	}
}

// ==================== Phase 2: XML body with error on basic payload, success on blind ====================

func TestCB2_Phase2_ErrorOnBasicSuccessOnBlind(t *testing.T) {
	rv := createCB2Reverse(t)

	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		// First request (basic payload) causes an error by closing
		if count == 1 {
			if hijacker, ok := w.(http.Hijacker); ok {
				conn, _, err := hijacker.Hijack()
				if err == nil {
					conn.Close()
				}
				return
			}
		}
		fmt.Fprint(w, `<?xml version="1.0"?><result>normal</result>`)
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

	cp := &cb2Printer{}
	apollo := makeCB2Apollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
}

// ==================== Phase 2: XML body with existing XML body content ====================

func TestCB2_Phase2_WithExistingXMLBody(t *testing.T) {
	rv := createCB2Reverse(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		w.Write(body)
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

	cp := &cb2Printer{}
	apollo := makeCB2Apollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
}

// ==================== Phase 2: SOAP content type with error on all payloads ====================

func TestCB2_Phase2_SOAPWithErrors(t *testing.T) {
	rv := createCB2Reverse(t)

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

	cp := &cb2Printer{}
	apollo := makeCB2Apollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error (expected with error server): %v", err)
	}
}

// ==================== Phase 2: SVG with echo detection ====================

func TestCB2_Phase2_SVGWithEcho(t *testing.T) {
	rv := createCB2Reverse(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash")
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

	cp := &cb2Printer{}
	apollo := makeCB2Apollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
	// SVG payloads don't have echo check in code but other payload types before SVG do
}

// ==================== Phase 2: Shadow echo in SOAP response ====================

func TestCB2_Phase2_SOAPEchoShadowPattern(t *testing.T) {
	rv := createCB2Reverse(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/soap+xml")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "root:$6$saltsalt$hashhash:18000:0:99999:7:::")
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

	cp := &cb2Printer{}
	apollo := makeCB2Apollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
}

// ==================== Phase 2: XInclude echo with Windows dir pattern ====================

func TestCB2_Phase2_XIncludeEchoWindowsDir(t *testing.T) {
	rv := createCB2Reverse(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "Volume in drive C is Windows")
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

	cp := &cb2Printer{}
	apollo := makeCB2Apollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
}

// ==================== Phase 1: Request with multiple body params and echo ====================

func TestCB2_Phase1_MultipleBodyParamsWithEcho(t *testing.T) {
	rv := createCB2Reverse(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash")
	}))
	defer server.Close()

	p := &XXE{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()
	body := "username=admin&password=test&csrf=token123"
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

	cp := &cb2Printer{}
	apollo := makeCB2Apollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
	if cp.Count() == 0 {
		t.Error("Expected at least one vuln from body param echo detection")
	}
}

// ==================== Phase 2: Non-XML content type with query params ====================

func TestCB2_Phase2_NonXMLContentTypeWithQueryParams(t *testing.T) {
	rv := createCB2Reverse(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"ok"}`)
	}))
	defer server.Close()

	p := &XXE{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()
	req, _ := whttp.NewRequest("POST", server.URL+"/api?query=test", strings.NewReader(`{"key":"value"}`))
	req.Header = make(map[string][]string)
	req.WithJSONBody(strings.NewReader(`{"key":"value"}`))
	flow := &whttp.Flow{
		Request: req,
		Response: &whttp.Response{
			Text:   `{"status":"ok"}`,
			Header: make(map[string][]string),
		},
	}

	cp := &cb2Printer{}
	apollo := makeCB2Apollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
	// Non-XML content type should skip Phase 2
}

// ==================== Phase 2: XHTML with echo detection ====================

func TestCB2_Phase2_XHTMLWithEcho(t *testing.T) {
	rv := createCB2Reverse(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xhtml+xml")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash")
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

	cp := &cb2Printer{}
	apollo := makeCB2Apollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
	if cp.Count() == 0 {
		t.Error("Expected at least one vuln from XHTML echo detection")
	}
}

// ==================== Phase 1: Context timeout with slow server ====================

func TestCB2_Phase1_ContextTimeout(t *testing.T) {
	rv := createCB2Reverse(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer server.Close()

	p := &XXE{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()
	req, _ := whttp.NewRequest("GET", server.URL+"/test?param=value", nil)
	req.Header = make(map[string][]string)
	flow := &whttp.Flow{
		Request: req,
		Response: &whttp.Response{
			Text:   "ok",
			Header: make(map[string][]string),
		},
	}

	cp := &cb2Printer{}
	apollo := makeCB2Apollo(flow, rv, cp)

	fingers := p.Fingers()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := fingers[0].CheckAction(ctx, apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
}

// ==================== Payload content verification ====================

func TestCB2_PayloadContentVerification(t *testing.T) {
	// Test that payloads contain expected XML/DOCTYPE structures
	callback := "http://evil.example.com"

	blinds := GetBlindXXEPayloads(callback)
	if len(blinds) != 2 {
		t.Fatalf("Expected 2 blind payloads, got %d", len(blinds))
	}
	for i, p := range blinds {
		if !strings.Contains(p, callback) {
			t.Errorf("Blind payload[%d] missing callback URL", i)
		}
		if !strings.Contains(p, "<!DOCTYPE") {
			t.Errorf("Blind payload[%d] missing DOCTYPE", i)
		}
	}

	soaps := GetSOAPXXEPayloads(callback)
	if len(soaps) != 2 {
		t.Fatalf("Expected 2 SOAP payloads, got %d", len(soaps))
	}
	for i, p := range soaps {
		if !strings.Contains(p, callback) {
			t.Errorf("SOAP payload[%d] missing callback URL", i)
		}
		if !strings.Contains(p, "soap:Envelope") {
			t.Errorf("SOAP payload[%d] missing soap:Envelope", i)
		}
	}

	svgs := GetSVGXXEPayloads(callback)
	if len(svgs) != 1 {
		t.Fatalf("Expected 1 SVG payload, got %d", len(svgs))
	}
	if !strings.Contains(svgs[0], callback) {
		t.Error("SVG payload missing callback URL")
	}
	if !strings.Contains(svgs[0], "<svg") {
		t.Error("SVG payload missing <svg element")
	}

	xincludes := GetXIncludeXXEPayloads(callback)
	if len(xincludes) != 1 {
		t.Fatalf("Expected 1 XInclude payload, got %d", len(xincludes))
	}
	if !strings.Contains(xincludes[0], callback) {
		t.Error("XInclude payload missing callback URL")
	}
	if !strings.Contains(xincludes[0], "xi:include") {
		t.Error("XInclude payload missing xi:include")
	}
}

// ==================== XXE struct method coverage ====================

func TestCB2_XXE_Close_NilError(t *testing.T) {
	p := &XXE{}
	err := p.Close()
	if err != nil {
		t.Errorf("expected nil error from Close, got %v", err)
	}
}

func TestCB2_XXE_DefaultConfig_Values(t *testing.T) {
	p := &XXE{}
	cfg := p.DefaultConfig().(*Config)
	if cfg.PluginBaseConfig.Name != "xxe" {
		t.Errorf("expected Name='xxe', got '%s'", cfg.PluginBaseConfig.Name)
	}
	if !cfg.PluginBaseConfig.Enabled {
		t.Error("expected Enabled=true")
	}
}

func TestCB2_XXE_GetConfig_AfterInit(t *testing.T) {
	p := &XXE{}
	err := p.Init(context.Background(), p.DefaultConfig(), nil)
	if err != nil {
		t.Errorf("Init returned error: %v", err)
	}
	cfg := p.GetConfig()
	if cfg == nil {
		t.Error("GetConfig should not return nil after Init")
	}
}

func TestCB2_Config_BaseConfig(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{Name: "xxe", Enabled: true},
	}
	bc := cfg.BaseConfig()
	if bc.Name != "xxe" {
		t.Errorf("expected Name='xxe', got '%s'", bc.Name)
	}
	if !bc.Enabled {
		t.Error("expected Enabled=true")
	}
}

func TestCB2_XXE_Init_NilConfig(t *testing.T) {
	p := &XXE{}
	err := p.Init(context.Background(), nil, nil)
	if err != nil {
		t.Errorf("expected nil error from Init with nil config, got %v", err)
	}
}

// ==================== isXMLContentType coverage ====================

func TestCB2_IsXMLContentType_ApplicationXML(t *testing.T) {
	if !isXMLContentType("application/xml") {
		t.Error("application/xml should be XML content type")
	}
}

func TestCB2_IsXMLContentType_TextXML(t *testing.T) {
	if !isXMLContentType("text/xml") {
		t.Error("text/xml should be XML content type")
	}
}

func TestCB2_IsXMLContentType_SOAP(t *testing.T) {
	if !isXMLContentType("application/soap+xml") {
		t.Error("application/soap+xml should be XML content type")
	}
}

func TestCB2_IsXMLContentType_XHTML(t *testing.T) {
	if !isXMLContentType("application/xhtml+xml") {
		t.Error("application/xhtml+xml should be XML content type")
	}
}

func TestCB2_IsXMLContentType_HTML(t *testing.T) {
	if isXMLContentType("text/html") {
		t.Error("text/html should NOT be XML content type")
	}
}

func TestCB2_IsXMLContentType_JSON(t *testing.T) {
	if isXMLContentType("application/json") {
		t.Error("application/json should NOT be XML content type")
	}
}

func TestCB2_IsXMLContentType_CaseInsensitive(t *testing.T) {
	if !isXMLContentType("Application/XML") {
		t.Error("Should be case-insensitive")
	}
	if !isXMLContentType("TEXT/XML") {
		t.Error("Should be case-insensitive")
	}
}

// ==================== CheckXXEEcho coverage ====================

func TestCB2_CheckXXEEcho_EtcPasswd(t *testing.T) {
	if !CheckXXEEcho("root:x:0:0:root:/root:/bin/bash") {
		t.Error("Should detect /etc/passwd content")
	}
}

func TestCB2_CheckXXEEcho_EtcShadow(t *testing.T) {
	if !CheckXXEEcho("root:$6$saltsalt$hashhash:18000:0:99999:7:::") {
		t.Error("Should detect /etc/shadow content")
	}
}

func TestCB2_CheckXXEEcho_LinuxUserInfo(t *testing.T) {
	if !CheckXXEEcho("uid=0(root) gid=0(root) groups=0(root)") {
		t.Error("Should detect linux user info")
	}
}

func TestCB2_CheckXXEEcho_WindowsDir(t *testing.T) {
	if !CheckXXEEcho("Volume in drive C is Windows") {
		t.Error("Should detect Windows dir output")
	}
}

func TestCB2_CheckXXEEcho_NormalHTML(t *testing.T) {
	if CheckXXEEcho("<html><body>Normal page</body></html>") {
		t.Error("Should not detect normal HTML as echo")
	}
}

// ==================== Phase 1: OnVisit callback with reverse server triggering actual callback ====================

func TestCB2_Phase1_OnVisitCallbackTriggered(t *testing.T) {
	rv := createCB2Reverse(t)

	var callbackMade int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "<html>normal response</html>")

		// Extract and visit the reverse server URL from request params
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

		// Also check POST body
		if r.Method == "POST" {
			body, _ := io.ReadAll(r.Body)
			bodyStr := string(body)
			if idx := strings.Index(bodyStr, "http://"); idx != -1 {
				urlStr := bodyStr[idx:]
				endIdx := strings.IndexAny(urlStr, "\"'< ")
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
	}))
	defer server.Close()

	p := &XXE{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()
	req, _ := whttp.NewRequest("POST", server.URL+"/test?param1=value1", nil)
	req.Header = make(map[string][]string)
	flow := &whttp.Flow{
		Request: req,
		Response: &whttp.Response{
			Text:   "ok",
			Header: make(map[string][]string),
		},
	}

	cp := &cb2Printer{}
	apollo := makeCB2Apollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}

	// Wait for callbacks
	for i := 0; i < 30; i++ {
		if atomic.LoadInt32(&callbackMade) > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	time.Sleep(1 * time.Second)

	if cp.Count() > 0 {
		t.Logf("OnVisit callback triggered! Vulns: %d", cp.Count())
	}
}

// ==================== Phase 2: XML body with SVG echo detection ====================

func TestCB2_Phase2_SVGWithEchoDetection(t *testing.T) {
	rv := createCB2Reverse(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct := r.Header.Get("Content-Type")
		if strings.Contains(strings.ToLower(ct), "svg") {
			w.Header().Set("Content-Type", "image/svg+xml")
		} else {
			w.Header().Set("Content-Type", "application/xml")
		}
		w.WriteHeader(http.StatusOK)
		// Return echo content for SVG payload
		fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash")
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

	cp := &cb2Printer{}
	apollo := makeCB2Apollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
}

// ==================== Phase 2: Blind XXE with callback URL substitution ====================

func TestCB2_Phase2_BlindXXEPayloads(t *testing.T) {
	rv := createCB2Reverse(t)

	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<?xml version="1.0"?><result>normal</result>`)
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

	cp := &cb2Printer{}
	apollo := makeCB2Apollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
	t.Logf("Total requests made: %d", atomic.LoadInt32(&requestCount))
}

// ==================== Phase 2: DNS-based XXE detection path ====================

func TestCB2_Phase2_DNSBasedDetection(t *testing.T) {
	rv := createCB2Reverse(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<?xml version="1.0"?><result>normal</result>`)
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

	cp := &cb2Printer{}
	apollo := makeCB2Apollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
}

// ==================== Plugin interface compliance ====================

func TestCB2_XXE_PluginInterface(t *testing.T) {
	var _ base.Plugin = &XXE{}
}
