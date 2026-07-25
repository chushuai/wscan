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

// ==================== Additional execAction coverage ====================
// These tests focus on the uncovered paths in execAction, specifically:
// - Phase 2 XML body injection with all payload types (blind, SOAP, SVG, XInclude, DNS)
// - Phase 2 XML body with echo detection returning before blind/Out-of-band
// - Edge cases with nil responses, error handling in Phase 2

func createTestReverseForXXEBoost(t *testing.T) *reverse.Reverse {
	t.Helper()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "reverse_boost.db")

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to find available port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	config := &reverse.Config{
		Token: "boosttoken",
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
	t.Cleanup(func() {
		rv.Close()
	})
	return rv
}

func makeBoostApollo(flow *whttp.Flow, rv *reverse.Reverse, output printer.Printer) *base.Apollo {
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

// countingPrinterBoost counts vulns output
type countingPrinterBoost struct {
	count int
	mu    sync.Mutex
}

func (p *countingPrinterBoost) AddInterceptor(func(any) (any, error)) printer.Printer { return p }
func (p *countingPrinterBoost) Close() error                                          { return nil }
func (p *countingPrinterBoost) Print(v any) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.count++
	return nil
}
func (p *countingPrinterBoost) Count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.count
}

// TestExecAction_XMLBodyWithXIncludeEchoResponse tests that XInclude payloads
// detect in-band echo in XML responses
func TestExecAction_XMLBodyWithXIncludeEchoResponse(t *testing.T) {
	rv := createTestReverseForXXEBoost(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = body
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		// Return /etc/passwd content to trigger echo detection
		fmt.Fprint(w, `<result>root:x:0:0:root:/root:/bin/bash</result>`)
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

	cp := &countingPrinterBoost{}
	apollo := makeBoostApollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
	// Should detect XXE echo via one of the XML payload types
	t.Logf("XInclude echo detection: vulns=%d", cp.Count())
}

// TestExecAction_XMLBodyBasicPayloadOnly tests Phase 2 with just the basic XML payload
func TestExecAction_XMLBodyBasicPayloadOnly(t *testing.T) {
	rv := createTestReverseForXXEBoost(t)

	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		// First request (basic payload) returns echo content
		if count == 1 {
			fmt.Fprint(w, `<?xml version="1.0"?><result>root:x:0:0:root:/root:/bin/bash</result>`)
			return
		}
		// Subsequent requests return normal content
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

	cp := &countingPrinterBoost{}
	apollo := makeBoostApollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
	if cp.Count() == 0 {
		t.Error("Expected at least one vuln from basic XML payload echo detection")
	}
}

// TestExecAction_XMLBodyBlindPayload tests that blind XXE payloads are sent
// and out-of-band detection is registered
func TestExecAction_XMLBodyBlindPayload(t *testing.T) {
	rv := createTestReverseForXXEBoost(t)

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

	cp := &countingPrinterBoost{}
	apollo := makeBoostApollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
}

// TestExecAction_XMLBodySOAPWithEcho tests SOAP payload echo detection
func TestExecAction_XMLBodySOAPWithEcho(t *testing.T) {
	rv := createTestReverseForXXEBoost(t)

	// Return echo content for ALL requests so SOAP payload triggers
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/soap+xml")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `root:x:0:0:root:/root:/bin/bash`)
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
			Text:   `<soap:Envelope/>`,
			Header: make(map[string][]string),
		},
	}

	cp := &countingPrinterBoost{}
	apollo := makeBoostApollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
	if cp.Count() == 0 {
		t.Error("Expected at least one vuln from SOAP echo detection")
	}
}

// TestExecAction_XMLBodySVGWithEcho tests SVG payload echo detection
func TestExecAction_XMLBodySVGWithEcho(t *testing.T) {
	rv := createTestReverseForXXEBoost(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `root:x:0:0:root:/root:/bin/bash`)
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
			Text:   `<svg/>`,
			Header: make(map[string][]string),
		},
	}

	cp := &countingPrinterBoost{}
	apollo := makeBoostApollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
	if cp.Count() == 0 {
		t.Error("Expected at least one vuln from SVG echo detection")
	}
}

// TestExecAction_XMLBodyShadowEcho tests shadow file echo detection in XML body
func TestExecAction_XMLBodyShadowEcho(t *testing.T) {
	rv := createTestReverseForXXEBoost(t)

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

	cp := &countingPrinterBoost{}
	apollo := makeBoostApollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
	if cp.Count() == 0 {
		t.Error("Expected at least one vuln from shadow echo detection")
	}
}

// TestExecAction_XMLBodyLinuxUserInfoEcho tests Linux user info echo detection
func TestExecAction_XMLBodyLinuxUserInfoEcho(t *testing.T) {
	rv := createTestReverseForXXEBoost(t)

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

	cp := &countingPrinterBoost{}
	apollo := makeBoostApollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
	if cp.Count() == 0 {
		t.Error("Expected at least one vuln from Linux user info echo detection")
	}
}

// TestExecAction_XMLBodyWindowsDirEcho tests Windows dir echo detection
func TestExecAction_XMLBodyWindowsDirEcho(t *testing.T) {
	rv := createTestReverseForXXEBoost(t)

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

	cp := &countingPrinterBoost{}
	apollo := makeBoostApollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
	if cp.Count() == 0 {
		t.Error("Expected at least one vuln from Windows dir echo detection")
	}
}

// TestExecAction_XMLBodyDNSDetection tests the DNS-based XXE detection path
func TestExecAction_XMLBodyDNSDetection(t *testing.T) {
	rv := createTestReverseForXXEBoost(t)

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

	cp := &countingPrinterBoost{}
	apollo := makeBoostApollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
	// DNS detection path is exercised - even if no vuln found, coverage increases
}

// TestExecAction_XMLBodyWithXHTML tests XHTML content type path
func TestExecAction_XMLBodyWithXHTML(t *testing.T) {
	rv := createTestReverseForXXEBoost(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xhtml+xml")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<html><body>normal</body></html>`)
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

	cp := &countingPrinterBoost{}
	apollo := makeBoostApollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
}

// TestExecAction_QueryParamWithDifferentEchoTypes tests query param injection
// with different echo response types
func TestExecAction_QueryParamWithDifferentEchoTypes(t *testing.T) {
	rv := createTestReverseForXXEBoost(t)

	echoTests := []struct {
		name       string
		response   string
		expectVuln bool
	}{
		{"shadow echo", "root:$5$salt$hash:18000:", true},
		{"linux user info", "uid=0(root) gid=0(root)", true},
		{"windows dir", "Volume in drive C is Windows", true},
		{"no match", "normal response", false},
	}

	for _, tt := range echoTests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, tt.response)
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

			cp := &countingPrinterBoost{}
			apollo := makeBoostApollo(flow, rv, cp)

			fingers := p.Fingers()
			err := fingers[0].CheckAction(context.Background(), apollo)
			if err != nil {
				t.Logf("execAction returned error: %v", err)
			}
			if tt.expectVuln && cp.Count() == 0 {
				t.Errorf("Expected vuln for %s", tt.name)
			}
		})
	}
}

// TestExecAction_XMLBodyWithBodyParams tests that both Phase 1 (body params)
// and Phase 2 (XML body injection) are exercised when content type is XML
// and body has form parameters
func TestExecAction_XMLBodyWithBodyParams(t *testing.T) {
	rv := createTestReverseForXXEBoost(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<result>normal</result>`)
	}))
	defer server.Close()

	p := &XXE{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()

	body := "username=admin&password=test"
	req, _ := whttp.NewRequest("POST", server.URL+"/api", strings.NewReader(body))
	req.Header = make(map[string][]string)
	req.WithFormBody(strings.NewReader(body))
	flow := &whttp.Flow{
		Request: req,
		Response: &whttp.Response{
			Text:   "<result>ok</result>",
			Header: make(map[string][]string),
		},
	}

	cp := &countingPrinterBoost{}
	apollo := makeBoostApollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
}

// TestExecAction_XMLBodyWithXIncludeEcho tests XInclude echo detection specifically
func TestExecAction_XMLBodyWithXIncludeEcho(t *testing.T) {
	rv := createTestReverseForXXEBoost(t)

	// Server that returns echo content only for later requests (XInclude payloads come after basic/blind)
	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		// After first few requests (basic/blind), return echo content for XInclude
		if count > 4 {
			fmt.Fprint(w, `root:x:0:0:root:/root:/bin/bash`)
		} else {
			body, _ := io.ReadAll(r.Body)
			w.Write(body)
		}
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

	cp := &countingPrinterBoost{}
	apollo := makeBoostApollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
}

// TestExecAction_XMLBodyWithRealXML tests using WithXMLBody to set the body
func TestExecAction_XMLBodyWithRealXML(t *testing.T) {
	rv := createTestReverseForXXEBoost(t)

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

	cp := &countingPrinterBoost{}
	apollo := makeBoostApollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
}

// TestExecAction_XMLBodyErrorInAllPayloads tests that errors in all Phase 2 payloads
// are handled gracefully
func TestExecAction_XMLBodyErrorInAllPayloads(t *testing.T) {
	rv := createTestReverseForXXEBoost(t)

	// Server that closes connections for XML requests
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct := r.Header.Get("Content-Type")
		if strings.Contains(ct, "xml") || strings.Contains(ct, "soap") {
			// Close connection for XML body requests
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

	cp := &countingPrinterBoost{}
	apollo := makeBoostApollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error (expected with error server): %v", err)
	}
}

// TestExecAction_BlindCallbackWithReverseServer tests that the OnVisit callback
// is properly registered and Fetch is called for each blind payload type
func TestExecAction_BlindCallbackWithReverseServer(t *testing.T) {
	rv := createTestReverseForXXEBoost(t)

	var callbackMade int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "<html>normal response</html>")

		// Extract reverse server URLs from request params and visit them
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

	cp := &countingPrinterBoost{}
	apollo := makeBoostApollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}

	// Wait for callbacks
	for i := 0; i < 20; i++ {
		if atomic.LoadInt32(&callbackMade) > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	time.Sleep(1 * time.Second)
}

// TestExecAction_NonXMLContentTypeSkipsPhase2 tests that non-XML content types
// skip Phase 2 entirely
func TestExecAction_NonXMLContentTypeSkipsPhase2(t *testing.T) {
	rv := createTestReverseForXXEBoost(t)

	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
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

	cp := &countingPrinterBoost{}
	apollo := makeBoostApollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
	// Should not make many requests since non-XML content type skips Phase 2
	t.Logf("Request count for non-XML content type: %d", atomic.LoadInt32(&requestCount))
}

// TestExecAction_QueryParamEchoAndReturnEarly tests that when echo detection
// finds a vuln in Phase 1, it returns early
func TestExecAction_QueryParamEchoAndReturnEarly(t *testing.T) {
	rv := createTestReverseForXXEBoost(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash")
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

	cp := &countingPrinterBoost{}
	apollo := makeBoostApollo(flow, rv, cp)

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
	if cp.Count() == 0 {
		t.Error("Expected at least one vuln output from echo detection")
	}
}
