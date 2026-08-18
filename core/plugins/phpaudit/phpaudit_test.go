/**
* @Author: shaochuyu
* @Date: 2026-07-28
*
* Verifies the TechGate helper (base.HasTech) and the phpaudit plugin's PHP
* gate: a PHP-served flow is detected as PHP, while a non-PHP flow is not.
 */
package phpaudit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	whttp "wscan/core/http"
	"wscan/core/plugins/base"
	"wscan/core/utils/printer"
)

// buildFlow builds a *whttp.Flow whose Response carries the given status,
// headers and body, so we can feed synthetic PHP / non-PHP responses into the
// gate without a live target.
func buildFlow(t *testing.T, target string, status int, header map[string]string, body string) *whttp.Flow {
	t.Helper()
	hdr := make(map[string][]string)
	for k, v := range header {
		hdr[k] = []string{v}
	}
	resp := &whttp.Response{
		Status:     "200 OK",
		StatusCode: status,
		Header:     hdr,
		Text:       body,
	}
	resp.ResetBody([]byte(body))
	req, err := whttp.NewRequest("GET", target, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	return &whttp.Flow{Request: req, Response: resp}
}

// TestHasTech_PHP detects a PHP response via the X-Powered-By header, the same
// signal wappalyzer uses for "PHP". A plain non-PHP response must not match.
func TestHasTech_PHP(t *testing.T) {
	php := buildFlow(t, "http://example.com/info.php", 200,
		map[string]string{"X-Powered-By": "PHP/7.4.3", "Content-Type": "text/html"},
		"<html><body>hello</body></html>")
	if !base.HasTech(nil, php, "PHP") {
		t.Fatal("expected HasTech(PHP) true for a PHP/7.4.3 response")
	}
	// case-insensitive tech name
	if !base.HasTech(nil, php, "php") {
		t.Fatal("HasTech should match the tech name case-insensitively")
	}

	plain := buildFlow(t, "http://example.com/", 200,
		map[string]string{"Server": "nginx", "Content-Type": "text/html"},
		"<html><body>static</body></html>")
	if base.HasTech(nil, plain, "PHP") {
		t.Fatal("expected HasTech(PHP) false for a plain nginx response")
	}
}

// TestHasTech_NilResponseDegrades ensures the gate never panics when a flow has
// no response (e.g. scan-only seeds): it just reports no tech.
func TestHasTech_NilResponseDegrades(t *testing.T) {
	req, _ := whttp.NewRequest("GET", "http://example.com/", nil)
	noResp := &whttp.Flow{Request: req, Response: nil}
	if base.HasTech(nil, noResp, "PHP") {
		t.Fatal("expected HasTech false for a flow with no response")
	}
}

// TestPHPAuditGate_PluginOnlyRunsOnPHP runs the phpaudit checkAction against a
// live test server that serves a fake phpinfo page, and asserts:
//  1. on a PHP target the plugin probes and reports the leak;
//  2. on a non-PHP target the plugin skips (gate holds) and reports nothing.
func TestPHPAuditGate_PluginOnlyRunsOnPHP(t *testing.T) {
	// --- a PHP target that exposes phpinfo() at /phpinfo.php ---
	phpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// any path returns the PHP header so the gate sees PHP on the
		// directory-probing base request; /phpinfo.php returns the info page.
		w.Header().Set("X-Powered-By", "PHP/8.1.0")
		w.Header().Set("Content-Type", "text/html")
		if strings.HasSuffix(r.URL.Path, "phpinfo.php") {
			_, _ = w.Write([]byte("<html><head><title>phpinfo</title></head><body>PHP Version 8.1.0</body></html>"))
			return
		}
		_, _ = w.Write([]byte("<html><body>ok</body></html>"))
	}))
	defer phpSrv.Close()

	// --- a non-PHP target that would otherwise match (same leak content) ---
	plainSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		w.Header().Set("Content-Type", "text/html")
		if strings.HasSuffix(r.URL.Path, "phpinfo.php") {
			_, _ = w.Write([]byte("<html><head><title>phpinfo</title></head><body>PHP Version 8.1.0</body></html>"))
			return
		}
		_, _ = w.Write([]byte("<html><body>ok</body></html>"))
	}))
	defer plainSrv.Close()

	for _, tc := range []struct {
		name        string
		base        string
		baseHeaders map[string]string
		wantHit     bool
	}{
		{"php target — gate opens, leak reported", phpSrv.URL + "/",
			map[string]string{"X-Powered-By": "PHP/8.1.0"}, true},
		{"non-php target — gate holds, nothing reported", plainSrv.URL + "/",
			map[string]string{"Server": "nginx"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &PHPAudit{}
			if err := p.Init(context.Background(), p.DefaultConfig(), nil); err != nil {
				t.Fatalf("Init: %v", err)
			}
			// capture printed vulns via a stub printer
			stub := &stubPrinter{}
			ab := base.NewApollo(nil).ApolloBase
			ab.Output = stub
			ab.HTTPClient = whttp.NewClient()

			// the directory-base flow the web-directory channel would deliver.
			// The gate reads PHP off THIS flow's response, so the base request
			// itself must carry the PHP header (mirrors a real crawl where the
			// directory page is served by PHP).
			flow := buildFlow(t, tc.base, 200, tc.baseHeaders, "<html><body>ok</body></html>")
			bi := base.NewApollo(flow)
			bi.ApolloBase = ab

			_ = p.Fingers()[0].CheckAction(context.Background(), bi)

			got := stub.capture() > 0
			if got != tc.wantHit {
				t.Fatalf("hit=%v want=%v (vulns=%d)", got, tc.wantHit, stub.capture())
			}
		})
	}
}

// withFlow returns an Apollo whose GetTargetFlow yields the given flow. We can't
// set the unexported target field directly, so we rely on the production path:
// NewApollo(target) wraps a resource.Resource. The flow IS a resource.Resource.
func withFlow(_ *base.Apollo, flow *whttp.Flow) *base.Apollo {
	return base.NewApollo(flow)
}

// stubPrinter collects vulns for assertions.
type stubPrinter struct {
	vulns []any
}

func (s *stubPrinter) Print(v any) error { s.vulns = append(s.vulns, v); return nil }
func (s *stubPrinter) AddInterceptor(func(any) (any, error)) printer.Printer {
	return s
}
func (s *stubPrinter) Close() error { return nil }

// capture returns the count of vulns printed so far.
func (s *stubPrinter) capture() int { return len(s.vulns) }
