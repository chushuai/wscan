package baseline

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	wscan_http "wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
)

// ==================== ParsePolicy coverage ====================

func TestParsePolicy_Empty(t *testing.T) {
	result := ParsePolicy("")
	if len(result) != 0 {
		t.Errorf("ParsePolicy('') = %v, want empty map", result)
	}
}

func TestParsePolicy_SingleDirective(t *testing.T) {
	result := ParsePolicy("script-src 'self'")
	if len(result) != 1 {
		t.Fatalf("ParsePolicy('script-src self') returned %d directives, want 1", len(result))
	}
	sources, ok := result["script-src"]
	if !ok {
		t.Fatal("Expected 'script-src' directive")
	}
	if len(sources) != 1 || sources[0] != "'self'" {
		t.Errorf("script-src sources = %v, want ['self']", sources)
	}
}

func TestParsePolicy_MultipleDirectives(t *testing.T) {
	result := ParsePolicy("script-src 'self'; style-src 'unsafe-inline'; img-src *")
	if len(result) != 3 {
		t.Fatalf("Expected 3 directives, got %d", len(result))
	}
	if _, ok := result["script-src"]; !ok {
		t.Error("Expected script-src directive")
	}
	if _, ok := result["style-src"]; !ok {
		t.Error("Expected style-src directive")
	}
	if _, ok := result["img-src"]; !ok {
		t.Error("Expected img-src directive")
	}
}

func TestParsePolicy_DirectiveWithMultipleValues(t *testing.T) {
	result := ParsePolicy("script-src 'self' 'unsafe-inline' 'unsafe-eval'")
	sources := result["script-src"]
	if len(sources) != 3 {
		t.Errorf("Expected 3 sources, got %d: %v", len(sources), sources)
	}
}

func TestParsePolicy_TrailingSemicolon(t *testing.T) {
	result := ParsePolicy("script-src 'self';")
	if len(result) != 1 {
		t.Errorf("Expected 1 directive with trailing semicolon, got %d", len(result))
	}
}

func TestParsePolicy_LeadingWhitespace(t *testing.T) {
	result := ParsePolicy("  script-src 'self'")
	if len(result) != 1 {
		t.Errorf("Expected 1 directive with leading whitespace, got %d", len(result))
	}
}

// ==================== isASCII coverage ====================

func TestIsASCII_ASCIIOnly(t *testing.T) {
	if !isASCII("hello world 123") {
		t.Error("Expected ASCII string to return true")
	}
}

func TestIsASCII_WithNonASCII(t *testing.T) {
	if isASCII("hello \xc0 world") {
		t.Error("Expected non-ASCII string to return false")
	}
}

func TestIsASCII_Empty(t *testing.T) {
	if !isASCII("") {
		t.Error("Expected empty string to return true")
	}
}

func TestIsASCII_BoundaryChar(t *testing.T) {
	if !isASCII(string(rune(127))) {
		t.Error("Char 127 is still ASCII")
	}
	if isASCII(string(rune(128))) {
		t.Error("Char 128 is not ASCII")
	}
}

// ==================== getAllowedWildcardSources coverage ====================

func TestGetAllowedWildcardSources_AllDirectives(t *testing.T) {
	csp := "script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-src 'self'; frame-ancestors 'self'; font-src 'self'; media-src 'self'; object-src 'self'; manifest-src 'self'; worker-src 'self'; prefetch-src 'self'; form-action 'self'"
	result := getAllowedWildcardSources(csp)
	if len(result) != 13 {
		t.Errorf("Expected 13 wildcard sources, got %d: %v", len(result), result)
	}
}

func TestGetAllowedWildcardSources_SomeDirectives(t *testing.T) {
	csp := "script-src 'self'; img-src 'self'"
	result := getAllowedWildcardSources(csp)
	if len(result) != 2 {
		t.Errorf("Expected 2 wildcard sources, got %d: %v", len(result), result)
	}
}

func TestGetAllowedWildcardSources_None(t *testing.T) {
	csp := "default-src 'self'"
	result := getAllowedWildcardSources(csp)
	if len(result) != 0 {
		t.Errorf("Expected 0 wildcard sources for default-src only, got %d: %v", len(result), result)
	}
}

func TestGetAllowedWildcardSources_Empty(t *testing.T) {
	result := getAllowedWildcardSources("")
	if len(result) != 0 {
		t.Errorf("Expected 0 wildcard sources for empty CSP, got %d", len(result))
	}
}

// ==================== ContentSecurityPolicyScanRule Finger CheckActions ====================

func TestCSPScanRule_XCSPHeader_Vuln(t *testing.T) {
	u, _ := url.Parse("http://example.com/")
	netResp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("<html><body>test</body></html>")),
		Request:    &http.Request{URL: u},
	}
	netResp.Header.Set("Content-Type", "text/html")
	netResp.Header.Set("X-Content-Security-Policy", "default-src 'self'")
	resp, _ := wscan_http.ResponseFromNetHttpResponse(netResp)

	req, _ := wscan_http.NewRequest("GET", "http://example.com/", nil)
	a := base.NewApollo(&wscan_http.Flow{Request: req, Response: resp})
	vulnFound := false
	a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) { vulnFound = true }}

	r := &ContentSecurityPolicyScanRule{}
	fingers := r.Finger()
	// First finger is baseline/csp/xcsp
	err := fingers[0].CheckAction(context.Background(), a)
	if err != nil {
		t.Errorf("CheckAction error: %v", err)
	}
	if !vulnFound {
		t.Error("Expected vuln for X-Content-Security-Policy header")
	}
}

func TestCSPScanRule_WebkitCSPHeader_Vuln(t *testing.T) {
	u, _ := url.Parse("http://example.com/")
	netResp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("<html><body>test</body></html>")),
		Request:    &http.Request{URL: u},
	}
	netResp.Header.Set("Content-Type", "text/html")
	netResp.Header.Set("X-WebKit-CSP", "default-src 'self'")
	resp, _ := wscan_http.ResponseFromNetHttpResponse(netResp)

	req, _ := wscan_http.NewRequest("GET", "http://example.com/", nil)
	a := base.NewApollo(&wscan_http.Flow{Request: req, Response: resp})
	vulnFound := false
	a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) { vulnFound = true }}

	r := &ContentSecurityPolicyScanRule{}
	fingers := r.Finger()
	err := fingers[1].CheckAction(context.Background(), a)
	if err != nil {
		t.Errorf("CheckAction error: %v", err)
	}
	if !vulnFound {
		t.Error("Expected vuln for X-WebKit-CSP header")
	}
}

func TestCSPScanRule_NotHTML_SkipsAll(t *testing.T) {
	u, _ := url.Parse("http://example.com/")
	netResp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("not html")),
		Request:    &http.Request{URL: u},
	}
	netResp.Header.Set("Content-Type", "application/json")
	netResp.Header.Set("Content-Security-Policy", "script-src 'unsafe-inline'")
	resp, _ := wscan_http.ResponseFromNetHttpResponse(netResp)

	req, _ := wscan_http.NewRequest("GET", "http://example.com/", nil)
	a := base.NewApollo(&wscan_http.Flow{Request: req, Response: resp})
	vulnFound := false
	a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) { vulnFound = true }}

	r := &ContentSecurityPolicyScanRule{}
	fingers := r.Finger()
	for i, f := range fingers {
		err := f.CheckAction(context.Background(), a)
		if err != nil {
			t.Errorf("Finger[%d] CheckAction error: %v", i, err)
		}
	}
	if vulnFound {
		t.Error("Should not detect vuln for non-HTML response")
	}
}

func TestCSPScanRule_NoCSPHeader_NoVuln(t *testing.T) {
	u, _ := url.Parse("http://example.com/")
	netResp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("<html><body>test</body></html>")),
		Request:    &http.Request{URL: u},
	}
	netResp.Header.Set("Content-Type", "text/html")
	resp, _ := wscan_http.ResponseFromNetHttpResponse(netResp)

	req, _ := wscan_http.NewRequest("GET", "http://example.com/", nil)
	a := base.NewApollo(&wscan_http.Flow{Request: req, Response: resp})
	vulnFound := false
	a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) { vulnFound = true }}

	r := &ContentSecurityPolicyScanRule{}
	fingers := r.Finger()
	// Test wildcard finger (index 3) with no CSP
	err := fingers[3].CheckAction(context.Background(), a)
	if err != nil {
		t.Errorf("CheckAction error: %v", err)
	}
	if vulnFound {
		t.Error("Should not detect vuln when no CSP header present")
	}
}

func TestCSPScanRule_AllFingersCount(t *testing.T) {
	r := &ContentSecurityPolicyScanRule{}
	fingers := r.Finger()
	// There are 12 fingers: xcsp, xwkcsp, notices, wildcard,
	// scriptsrc_unsafe, scriptsrc_unsafe_hashes, scriptsrc_unsafe_eval,
	// stylesrc_unsafe_hashes, stylesrc_unsafe_inline,
	// both, malformed, meta_bad_directive
	if len(fingers) != 12 {
		t.Errorf("Expected 12 CSP fingers, got %d", len(fingers))
	}
}
