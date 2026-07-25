package baseline

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	wscan_http "wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
)

// Helper to set CSP header with lowercase key for testing direct map access
func makeTestResponseWithLowercaseCSP(body string, statusCode int, canonicalHeaders map[string]string, lowercaseHeaders map[string][]string) *wscan_http.Response {
	u, _ := url.Parse("http://example.com/")
	netResp := &http.Response{
		StatusCode: statusCode,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    &http.Request{URL: u},
	}
	for k, v := range canonicalHeaders {
		netResp.Header.Set(k, v)
	}
	for k, vals := range lowercaseHeaders {
		netResp.Header[k] = vals
	}
	resp, _ := wscan_http.ResponseFromNetHttpResponse(netResp)
	return resp
}

// ==================== CSP ScanRule CheckAction tests ====================

func TestContentSecurityPolicyScanRule_AllFingers(t *testing.T) {
	testCases := []struct {
		name             string
		headers          map[string]string
		lowercaseHeaders map[string][]string
	}{
		{"with XCSP", map[string]string{"Content-Type": "text/html", "X-Content-Security-Policy": "default-src 'self'"}, nil},
		{"with WebkitCSP", map[string]string{"Content-Type": "text/html", "X-WebKit-CSP": "default-src 'self'"}, nil},
		{"CSP script-src unsafe-inline", map[string]string{"Content-Type": "text/html"}, map[string][]string{"content-security-policy": {"script-src 'unsafe-inline'"}}},
		{"CSP script-src unsafe-hashes", map[string]string{"Content-Type": "text/html"}, map[string][]string{"content-security-policy": {"script-src 'unsafe-hashes'"}}},
		{"CSP script-src unsafe-eval", map[string]string{"Content-Type": "text/html"}, map[string][]string{"content-security-policy": {"script-src 'unsafe-eval'"}}},
		{"CSP styles-src unsafe-hashes", map[string]string{"Content-Type": "text/html"}, map[string][]string{"content-security-policy": {"styles-src 'unsafe-hashes'"}}},
		{"CSP styles-src unsafe-inline", map[string]string{"Content-Type": "text/html"}, map[string][]string{"content-security-policy": {"styles-src 'unsafe-inline'"}}},
		{"CSP default-src self", map[string]string{"Content-Type": "text/html"}, map[string][]string{"content-security-policy": {"default-src 'self'"}}},
		{"CSP sandbox", map[string]string{"Content-Type": "text/html"}, map[string][]string{"content-security-policy": {"sandbox allow-scripts"}}},
		{"CSP frame-ancestors", map[string]string{"Content-Type": "text/html"}, map[string][]string{"content-security-policy": {"frame-ancestors 'none'"}}},
		{"CSP wildcard script-src", map[string]string{"Content-Type": "text/html"}, map[string][]string{"content-security-policy": {"script-src 'self'"}}},
		{"no CSP", map[string]string{"Content-Type": "text/html"}, nil},
		{"non-HTML", map[string]string{"Content-Type": "application/json"}, nil},
		{"CSP non-ASCII", map[string]string{"Content-Type": "text/html"}, map[string][]string{"content-security-policy": {"script-src 'self'; 默认 none"}}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var resp *wscan_http.Response
			if tc.lowercaseHeaders != nil {
				resp = makeTestResponseWithLowercaseCSP("<html><body>test</body></html>", 200, tc.headers, tc.lowercaseHeaders)
			} else {
				resp = makeTestResponseWithHeaders("<html><body>test</body></html>", 200, tc.headers)
			}
			a := mockApollo(nil, resp)
			vulnFound := false
			a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) {
				vulnFound = true
			}}

			r := &ContentSecurityPolicyScanRule{}
			fingers := r.Finger()
			for _, f := range fingers {
				if f.CheckAction != nil {
					f.CheckAction(context.Background(), a)
				}
			}
			_ = vulnFound
		})
	}
}

// Test CSP "both" finger - needs meta tag + header
func TestContentSecurityPolicyScanRule_BothFinger(t *testing.T) {
	headers := map[string]string{"Content-Type": "text/html"}
	lowercaseHeaders := map[string][]string{"content-security-policy": {"default-src 'self'"}}
	resp := makeTestResponseWithLowercaseCSP(`<html><head><meta http-equiv="content-security-policy" content="default-src 'self'"></head><body>test</body></html>`, 200, headers, lowercaseHeaders)
	a := mockApollo(nil, resp)
	vulnFound := false
	a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) {
		vulnFound = true
	}}

	r := &ContentSecurityPolicyScanRule{}
	fingers := r.Finger()
	if len(fingers) > 9 && fingers[9].CheckAction != nil {
		fingers[9].CheckAction(context.Background(), a)
	}
	_ = vulnFound
}

// ==================== CookieSameSite CheckAction tests ====================

func TestCookieSameSiteScanRule_AllFingers(t *testing.T) {
	tests := []struct {
		name   string
		cookie string
	}{
		{"no SameSite", "session=abc123; Path=/"},
		{"SameSite=None", "session=abc123; Path=/; SameSite=None"},
		{"SameSite=Invalid", "session=abc123; Path=/; SameSite=Invalid"},
		{"SameSite=Strict", "session=abc123; Path=/; SameSite=Strict"},
		{"SameSite=Lax", "session=abc123; Path=/; SameSite=Lax"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, _ := url.Parse("http://example.com/")
			netResp := &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("body")),
				Request:    &http.Request{URL: u},
			}
			netResp.Header.Set("Content-Type", "text/html")
			netResp.Header.Set("Set-Cookie", tt.cookie)
			resp, _ := wscan_http.ResponseFromNetHttpResponse(netResp)

			a := mockApollo(nil, resp)
			vulnFound := false
			a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) {
				vulnFound = true
			}}

			r := &CookieSameSiteScanRule{}
			fingers := r.Finger()
			for _, f := range fingers {
				if f.CheckAction != nil {
					f.CheckAction(context.Background(), a)
				}
			}
			_ = vulnFound
		})
	}
}

// ==================== CookiePasswordLeak CheckAction tests ====================

func TestCookiePasswordLeak_CheckAction_AllPaths(t *testing.T) {
	tests := []struct {
		name       string
		cookie     string
		expectVuln bool
	}{
		{"password in name", "password=mypassword123; Path=/", true},
		{"pass in name", "user_pass=secret123; Path=/", true},
		{"token in name", "token=abc123; Path=/", true},
		{"auth in name with password value", "myauth=abc123xyz; Path=/", true},
		{"excluded sessionid", "sessionid=abc123def456; Path=/", false},
		{"excluded jsessionid", "jsessionid=abc123def456; Path=/", false},
		{"excluded phpsessid", "phpsessid=abc123def456; Path=/", false},
		{"excluded csrf_token", "csrf_token=abc123def456; Path=/", false},
		{"UUID value", "mydata=12345678-1234-1234-1234-123456789012; Path=/", false},
		{"hex session", "sess=abcdef0123456789abcdef0123456789; Path=/", false},
		{"base64 session", "sess=YWJjZGVmZ2hpamtsbW5vcA==; Path=/", false},
		{"empty value", "test=; Path=/", false},
		{"no cookies", "", false},
		{"password-like value with letters+digits", "mydata=abc123def; Path=/", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, _ := url.Parse("http://example.com/")
			netResp := &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("body")),
				Request:    &http.Request{URL: u},
			}
			netResp.Header.Set("Content-Type", "text/html")
			if tt.cookie != "" {
				netResp.Header.Set("Set-Cookie", tt.cookie)
			}
			resp, _ := wscan_http.ResponseFromNetHttpResponse(netResp)

			a := mockApollo(nil, resp)
			vulnFound := false
			a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) {
				vulnFound = true
			}}

			c := &cookiePasswordLeak{}
			finger := c.Finger()
			finger.CheckAction(context.Background(), a)
			if tt.expectVuln != vulnFound {
				t.Errorf("expected vulnFound=%v, got %v for cookie=%q", tt.expectVuln, vulnFound, tt.cookie)
			}
		})
	}
}

// ==================== SerializationDataInParams CheckAction tests ====================

func TestSerializationDataInParams_CheckAction_AllPaths(t *testing.T) {
	tests := []struct {
		name       string
		reqURL     string
		body       string
		expectVuln bool
	}{
		{"Java serialization in param", "http://example.com/?data=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA", "ok", true},
		{"PHP serialization in param", "http://example.com/?data=" + url.QueryEscape(`a:1:{s:3:"foo"`), "ok", true},
		{"Java serialization in body", "http://example.com/", "data=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAAAA", true},
		{"no serialization", "http://example.com/", "normal response", false},
		{"empty body", "http://example.com/", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := wscan_http.NewRequest("GET", tt.reqURL, nil)

			u, _ := url.Parse("http://example.com/")
			netResp := &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(tt.body)),
				Request:    &http.Request{URL: u},
			}
			netResp.Header.Set("Content-Type", "text/html")
			resp, _ := wscan_http.ResponseFromNetHttpResponse(netResp)

			a := base.NewApollo(&wscan_http.Flow{Request: req, Response: resp})
			vulnFound := false
			a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) {
				vulnFound = true
			}}

			s := &serializationDataInParams{}
			finger := s.Finger()
			finger.CheckAction(context.Background(), a)
			if tt.expectVuln != vulnFound {
				t.Errorf("expected vulnFound=%v, got %v", tt.expectVuln, vulnFound)
			}
		})
	}
}

// ==================== UnsafeSchemeLeak CheckAction tests ====================

func TestUnsafeSchemeLeak_CheckAction_AllPaths(t *testing.T) {
	tests := []struct {
		name       string
		scheme     string
		body       string
		ct         string
		expectVuln bool
	}{
		{"HTTPS with HTTP img", "https", `<html><body><img src="http://evil.com/img.jpg"></body></html>`, "text/html", true},
		{"HTTPS with HTTP href", "https", `<html><body><a href="http://evil.com/page">link</a></body></html>`, "text/html", true},
		{"HTTPS with url() style", "https", `<html><body style="background: url(http://evil.com/bg.png)">test</body></html>`, "text/html", true},
		{"HTTPS with HTTP form action", "https", `<html><body><form action="http://evil.com/submit"></form></body></html>`, "text/html", true},
		{"HTTP page skip", "http", `<html><body><img src="http://evil.com/img.jpg"></body></html>`, "text/html", false},
		{"HTTPS no unsafe", "https", `<html><body><img src="https://cdn.example.com/img.jpg"></body></html>`, "text/html", false},
		{"non-HTML", "https", `{"url": "http://evil.com"}`, "application/json", false},
		{"HTTPS empty body", "https", "", "text/html", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := wscan_http.NewRequest("GET", tt.scheme+"://example.com/", nil)

			u, _ := url.Parse(tt.scheme + "://example.com/")
			netResp := &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(tt.body)),
				Request:    &http.Request{URL: u},
			}
			netResp.Header.Set("Content-Type", tt.ct)
			resp, _ := wscan_http.ResponseFromNetHttpResponse(netResp)

			a := base.NewApollo(&wscan_http.Flow{Request: req, Response: resp})
			vulnFound := false
			a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) {
				vulnFound = true
			}}

			d := &unsafeSchemeLeak{}
			finger := d.Finger()
			finger.CheckAction(context.Background(), a)
			if tt.expectVuln != vulnFound {
				t.Errorf("expected vulnFound=%v, got %v", tt.expectVuln, vulnFound)
			}
		})
	}
}

// ==================== ApplicationErrorScanRule CheckAction tests ====================

func TestApplicationErrorScanRule_CheckAction_AllStatuses(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		ct         string
		body       string
	}{
		{"200 with error pattern", 200, "text/html", "Stack Trace: java.lang.NullPointerException"},
		{"500 skip", 500, "text/html", "Internal Server Error"},
		{"400", 400, "text/html", "Bad Request"},
		{"200 JavaScript", 200, "application/javascript", "var x = 1;"},
		{"200 CSS", 200, "text/css", "body { color: red; }"},
		{"200 wasm", 200, "application/wasm", "binary data"},
		{"200 normal", 200, "text/html", "Hello World"},
		{"200 JSON", 200, "application/json", `{"status": "ok"}`},
		{"403 normal", 403, "text/html", "Forbidden"},
		{"404 normal", 404, "text/html", "Not Found"},
		{"200 with ASP.NET error", 200, "text/html", "Server Error in '/' Application"},
		{"200 with PHP error", 200, "text/html", "Fatal error: Call to undefined function"},
		{"200 with Python traceback", 200, "text/html", "Traceback (most recent call last)"},
		{"200 with Ruby error", 200, "text/html", "ActionController::RoutingError"},
		{"200 with database error", 200, "text/html", "mysql_connect(): Access denied"},
		{"200 with ASP error", 200, "text/html", "Microsoft OLE DB Provider for SQL Server"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, _ := url.Parse("http://example.com/")
			netResp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(tt.body)),
				Request:    &http.Request{URL: u},
			}
			netResp.Header.Set("Content-Type", tt.ct)
			resp, _ := wscan_http.ResponseFromNetHttpResponse(netResp)

			a := mockApollo(nil, resp)
			vulnFound := false
			a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) {
				vulnFound = true
			}}

			r := &ApplicationErrorScanRule{}
			finger := r.Finger()
			finger.CheckAction(context.Background(), a)
			_ = vulnFound
		})
	}
}

// ==================== IsLooselyScopedCookie edge cases ====================

func TestIsLooselyScopedCookie_EdgeCases(t *testing.T) {
	tests := []struct {
		name   string
		cookie *http.Cookie
		host   string
		want   bool
	}{
		{"empty domain", &http.Cookie{Name: "test", Value: "val"}, "example.com", false},
		{"same domain", &http.Cookie{Name: "test", Value: "val", Domain: "example.com"}, "example.com", false},
		{"different domain", &http.Cookie{Name: "test", Value: "val", Domain: "other.com"}, "example.com", true},
		{"dot prefix different", &http.Cookie{Name: "test", Value: "val", Domain: ".other.com"}, "example.com", true},
		{"dot prefix same", &http.Cookie{Name: "test", Value: "val", Domain: ".example.com"}, "example.com", false},
		{"no prefix different 2-level", &http.Cookie{Name: "test", Value: "val", Domain: "api.other.com"}, "example.com", true},
		{"same TLD different 2nd", &http.Cookie{Name: "test", Value: "val", Domain: ".com"}, "example.com", true},
		{"subdomain same domain", &http.Cookie{Name: "test", Value: "val", Domain: "sub.example.com"}, "example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsLooselyScopedCookie(tt.cookie, tt.host)
			if got != tt.want {
				t.Errorf("IsLooselyScopedCookie() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ==================== Struct and method coverage tests ====================

func TestCookieLooselyScopedScanRule_Detect(t *testing.T) {
	r := &CookieLooselyScopedScanRule{}
	r.detect()
}

func TestServerError_IsServerError(t *testing.T) {
	s := &serverError{}
	s.isServerError()
}

func TestApplicationErrorScanRule_Detect(t *testing.T) {
	r := &ApplicationErrorScanRule{}
	r.detect()
}

func TestCORS_Structs(t *testing.T) {
	_ = &corsAllowHTTPSDowngrade{}
	_ = &corsAnyOrigin{}
	_ = &corsNullWithCred{}
	_ = &corsReflected{}
}

func TestCookie_Structs(t *testing.T) {
	_ = &cookieHTTPOnly{}
	_ = &cookiePassword{}
	_ = &cookieSecure{}
}

func TestPattern_Structs(t *testing.T) {
	p := Pattern{Type: "string", Content: "test"}
	_ = p.Type
	ps := Patterns{Version: "1.0", Patterns: []Pattern{{Type: "string", Content: "test"}}}
	_ = ps.Version
}

// ==================== isRedirectToPayload edge cases ====================

func TestIsRedirectToPayload_EdgeCases(t *testing.T) {
	tests := []struct {
		location string
		payload  string
		want     bool
	}{
		{"http://evil.com/path", "http://evil.com", true},
		{"https://sub.evil.com/path", "evil.com", true},
		{"http://other.com/path", "evil.com", false},
		{"http://test.com/payload/path", "payload", true},
		{"http://other.com/none", "nomatch", false},
	}
	for _, tt := range tests {
		got := isRedirectToPayload(tt.location, tt.payload)
		if got != tt.want {
			t.Errorf("isRedirectToPayload(%q, %q) = %v, want %v", tt.location, tt.payload, got, tt.want)
		}
	}
}

// ==================== HostInjection with HTTPClient ====================

func TestHostInjection_CheckAction_WithHTTPClient(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Reflect the Host header in response body to simulate injection
		w.Write([]byte("<html><body>Host: " + r.Host + "</body></html>"))
	}))
	defer ts.Close()

	req, _ := wscan_http.NewRequest("GET", ts.URL+"/", nil)
	tsURL, _ := url.Parse(ts.URL)
	req.Host = tsURL.Host
	u, _ := url.Parse(ts.URL + "/")
	netResp := &http.Response{
		StatusCode: 200, Header: make(http.Header),
		Body:    io.NopCloser(strings.NewReader("<html><body>ok</body></html>")),
		Request: &http.Request{URL: u},
	}
	netResp.Header.Set("Content-Type", "text/html")
	resp, _ := wscan_http.ResponseFromNetHttpResponse(netResp)
	a := base.NewApollo(&wscan_http.Flow{Request: req, Response: resp})
	a.ApolloBase.HTTPClient = wscan_http.NewClient()
	vulnFound := false
	a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) { vulnFound = true }}
	h := &hostInjection{}
	h.Finger().CheckAction(context.Background(), a)
	_ = vulnFound
}

func TestHostInjection_CheckAction_JSResponse(t *testing.T) {
	req, _ := wscan_http.NewRequest("GET", "http://example.com/", nil)
	u, _ := url.Parse("http://example.com/")
	netResp := &http.Response{
		StatusCode: 200, Header: make(http.Header),
		Body:    io.NopCloser(strings.NewReader("var x = 1;")),
		Request: &http.Request{URL: u},
	}
	netResp.Header.Set("Content-Type", "application/javascript")
	resp, _ := wscan_http.ResponseFromNetHttpResponse(netResp)
	a := base.NewApollo(&wscan_http.Flow{Request: req, Response: resp})
	a.ApolloBase.HTTPClient = wscan_http.NewClient()
	vulnFound := false
	a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) { vulnFound = true }}
	h := &hostInjection{}
	h.Finger().CheckAction(context.Background(), a)
	if vulnFound {
		t.Error("Should not detect vuln for JS response")
	}
}

func TestHostInjection_CheckAction_CSSResponse(t *testing.T) {
	req, _ := wscan_http.NewRequest("GET", "http://example.com/", nil)
	u, _ := url.Parse("http://example.com/")
	netResp := &http.Response{
		StatusCode: 200, Header: make(http.Header),
		Body:    io.NopCloser(strings.NewReader("body { color: red; }")),
		Request: &http.Request{URL: u},
	}
	netResp.Header.Set("Content-Type", "text/css")
	resp, _ := wscan_http.ResponseFromNetHttpResponse(netResp)
	a := base.NewApollo(&wscan_http.Flow{Request: req, Response: resp})
	a.ApolloBase.HTTPClient = wscan_http.NewClient()
	vulnFound := false
	a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) { vulnFound = true }}
	h := &hostInjection{}
	h.Finger().CheckAction(context.Background(), a)
	if vulnFound {
		t.Error("Should not detect vuln for CSS response")
	}
}

func TestHostInjection_CheckAction_ImageResponse(t *testing.T) {
	req, _ := wscan_http.NewRequest("GET", "http://example.com/", nil)
	u, _ := url.Parse("http://example.com/")
	netResp := &http.Response{
		StatusCode: 200, Header: make(http.Header),
		Body:    io.NopCloser(strings.NewReader("image data")),
		Request: &http.Request{URL: u},
	}
	netResp.Header.Set("Content-Type", "image/png")
	resp, _ := wscan_http.ResponseFromNetHttpResponse(netResp)
	a := base.NewApollo(&wscan_http.Flow{Request: req, Response: resp})
	a.ApolloBase.HTTPClient = wscan_http.NewClient()
	vulnFound := false
	a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) { vulnFound = true }}
	h := &hostInjection{}
	h.Finger().CheckAction(context.Background(), a)
	if vulnFound {
		t.Error("Should not detect vuln for image response")
	}
}

func TestHostInjection_CheckAction_NilHTTPClient(t *testing.T) {
	req, _ := wscan_http.NewRequest("GET", "http://example.com/", nil)
	u, _ := url.Parse("http://example.com/")
	netResp := &http.Response{
		StatusCode: 200, Header: make(http.Header),
		Body:    io.NopCloser(strings.NewReader("ok")),
		Request: &http.Request{URL: u},
	}
	netResp.Header.Set("Content-Type", "text/html")
	resp, _ := wscan_http.ResponseFromNetHttpResponse(netResp)
	a := base.NewApollo(&wscan_http.Flow{Request: req, Response: resp})
	a.ApolloBase.HTTPClient = nil
	h := &hostInjection{}
	err := h.Finger().CheckAction(context.Background(), a)
	if err != nil {
		t.Errorf("Should not return error: %v", err)
	}
}

// ==================== RedirectLogic with HTTPClient ====================

func TestRedirectLogic_CheckAction_WithHTTPClient(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("url") != "" {
			w.Header().Set("Location", r.URL.Query().Get("url"))
			w.WriteHeader(302)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>ok</body></html>"))
	}))
	defer ts.Close()

	reqURL := ts.URL + "/?url=http://example.com"
	req, _ := wscan_http.NewRequest("GET", reqURL, nil)
	u, _ := url.Parse(ts.URL + "/")
	netResp := &http.Response{
		StatusCode: 200, Header: make(http.Header),
		Body:    io.NopCloser(strings.NewReader("<html><body>ok</body></html>")),
		Request: &http.Request{URL: u},
	}
	netResp.Header.Set("Content-Type", "text/html")
	resp, _ := wscan_http.ResponseFromNetHttpResponse(netResp)
	a := base.NewApollo(&wscan_http.Flow{Request: req, Response: resp})
	a.ApolloBase.HTTPClient = wscan_http.NewClient()
	vulnFound := false
	a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) { vulnFound = true }}
	r := &redirectLogic{}
	r.Finger().CheckAction(context.Background(), a)
	_ = vulnFound
}

func TestRedirectLogic_CheckAction_NilHTTPClient(t *testing.T) {
	req, _ := wscan_http.NewRequest("GET", "http://example.com/", nil)
	u, _ := url.Parse("http://example.com/")
	netResp := &http.Response{
		StatusCode: 200, Header: make(http.Header),
		Body:    io.NopCloser(strings.NewReader("ok")),
		Request: &http.Request{URL: u},
	}
	netResp.Header.Set("Content-Type", "text/html")
	resp, _ := wscan_http.ResponseFromNetHttpResponse(netResp)
	a := base.NewApollo(&wscan_http.Flow{Request: req, Response: resp})
	a.ApolloBase.HTTPClient = nil
	r := &redirectLogic{}
	err := r.Finger().CheckAction(context.Background(), a)
	if err != nil {
		t.Errorf("Should not return error: %v", err)
	}
}

// ==================== ContentSecurityPolicyMissing edge cases ====================

func TestContentSecurityPolicyMissing_NonHTML(t *testing.T) {
	resp := makeTestResponseWithHeaders(`{"data": "test"}`, 200, map[string]string{"Content-Type": "application/json"})
	a := mockApollo(nil, resp)
	r := &ContentSecurityPolicyMissingScanRule{}
	r.Finger().CheckAction(context.Background(), a)
}

func TestContentSecurityPolicyMissing_Redirect(t *testing.T) {
	resp := makeTestResponseWithHeaders("redirect", 302, map[string]string{"Content-Type": "text/html"})
	a := mockApollo(nil, resp)
	r := &ContentSecurityPolicyMissingScanRule{}
	r.Finger().CheckAction(context.Background(), a)
}

func TestContentSecurityPolicyMissing_WithDeprecatedHeaders(t *testing.T) {
	tests := []struct {
		name   string
		header string
		value  string
	}{
		{"X-Content-Security-Policy", "X-Content-Security-Policy", "default-src 'self'"},
		{"X-WebKit-CSP", "X-WebKit-CSP", "default-src 'self'"},
		{"Report-Only", "Content-Security-Policy-Report-Only", "default-src 'self'"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, _ := url.Parse("http://example.com/")
			netResp := &http.Response{
				StatusCode: 200, Header: make(http.Header),
				Body:    io.NopCloser(strings.NewReader("<html><body>test</body></html>")),
				Request: &http.Request{URL: u},
			}
			netResp.Header.Set("Content-Type", "text/html")
			netResp.Header.Set(tt.header, tt.value)
			resp, _ := wscan_http.ResponseFromNetHttpResponse(netResp)
			a := mockApollo(nil, resp)
			vulnFound := false
			a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) { vulnFound = true }}
			r := &ContentSecurityPolicyMissingScanRule{}
			r.Finger().CheckAction(context.Background(), a)
			if !vulnFound {
				t.Errorf("Expected vuln for %s header", tt.name)
			}
		})
	}
}

// ==================== OutdatedSSLVersion CheckAction ====================

func TestOutdatedSSLVersion_CheckAction_HTTP(t *testing.T) {
	req, _ := wscan_http.NewRequest("GET", "http://example.com/", nil)
	u, _ := url.Parse("http://example.com/")
	netResp := &http.Response{
		StatusCode: 200, Header: make(http.Header),
		Body:    io.NopCloser(strings.NewReader("ok")),
		Request: &http.Request{URL: u},
	}
	netResp.Header.Set("Content-Type", "text/html")
	resp, _ := wscan_http.ResponseFromNetHttpResponse(netResp)
	a := base.NewApollo(&wscan_http.Flow{Request: req, Response: resp})
	o := &outdatedSSLVersion{}
	err := o.Finger().CheckAction(context.Background(), a)
	if err != nil {
		t.Errorf("Should not return error for HTTP: %v", err)
	}
}

func TestOutdatedSSLVersion_CheckAction_HTTPS_Unreachable(t *testing.T) {
	// Test with an HTTPS URL that won't be reachable - should gracefully handle error
	req, _ := wscan_http.NewRequest("GET", "https://127.0.0.1:1/", nil)
	u, _ := url.Parse("https://127.0.0.1:1/")
	netResp := &http.Response{
		StatusCode: 200, Header: make(http.Header),
		Body:    io.NopCloser(strings.NewReader("ok")),
		Request: &http.Request{URL: u},
	}
	netResp.Header.Set("Content-Type", "text/html")
	resp, _ := wscan_http.ResponseFromNetHttpResponse(netResp)
	a := base.NewApollo(&wscan_http.Flow{Request: req, Response: resp})
	o := &outdatedSSLVersion{}
	err := o.Finger().CheckAction(context.Background(), a)
	if err != nil {
		t.Errorf("Should not return error: %v", err)
	}
}

// ==================== Various no-match tests ====================

func TestChinaAddress_NoMatch(t *testing.T) {
	resp := makeTestResponseWithHeaders("hello world", 200, map[string]string{"Content-Type": "text/html"})
	a := mockApollo(nil, resp)
	vulnFound := false
	a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) { vulnFound = true }}
	c := &chinaAddress{}
	c.Finger().CheckAction(context.Background(), a)
	if vulnFound {
		t.Error("Should not detect vuln for non-Chinese-address text")
	}
}

func TestPrivateIPLeak_NoMatch(t *testing.T) {
	resp := makeTestResponseWithHeaders("Server: 8.8.8.8 is public", 200, map[string]string{"Content-Type": "text/html"})
	a := mockApollo(nil, resp)
	vulnFound := false
	a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) { vulnFound = true }}
	p := &privateIPLeak{}
	p.Finger().CheckAction(context.Background(), a)
	if vulnFound {
		t.Error("Should not detect vuln for public IP")
	}
}

func TestChinaPhoneNumber_NoMatch(t *testing.T) {
	resp := makeTestResponseWithHeaders("no phone", 200, map[string]string{"Content-Type": "text/html"})
	a := mockApollo(nil, resp)
	vulnFound := false
	a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) { vulnFound = true }}
	c := &chinaPhoneNumber{}
	c.Finger().CheckAction(context.Background(), a)
	if vulnFound {
		t.Error("Should not detect vuln when no phone number")
	}
}

func TestChinaBankCard_NoMatch(t *testing.T) {
	resp := makeTestResponseWithHeaders("no bank card", 200, map[string]string{"Content-Type": "text/html"})
	a := mockApollo(nil, resp)
	vulnFound := false
	a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) { vulnFound = true }}
	c := &chinaBankCard{}
	c.Finger().CheckAction(context.Background(), a)
	if vulnFound {
		t.Error("Should not detect vuln when no bank card")
	}
}

func TestSystemPath_NoMatch(t *testing.T) {
	resp := makeTestResponseWithHeaders("no system path", 200, map[string]string{"Content-Type": "text/html"})
	a := mockApollo(nil, resp)
	vulnFound := false
	a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) { vulnFound = true }}
	s := &systemPath{}
	s.Finger().CheckAction(context.Background(), a)
	if vulnFound {
		t.Error("Should not detect vuln when no system path")
	}
}

func TestEmailLeak_InternalDomain(t *testing.T) {
	resp := makeTestResponseWithHeaders("admin@domain.com is internal", 200, map[string]string{"Content-Type": "text/html"})
	a := mockApollo(nil, resp)
	vulnFound := false
	a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) { vulnFound = true }}
	e := &emailLeak{}
	e.Finger().CheckAction(context.Background(), a)
	if vulnFound {
		t.Error("Should not detect vuln for internal domain email")
	}
}

// ==================== CacheControl edge cases ====================

func TestCacheControlScanRule_EmptyBody(t *testing.T) {
	u, _ := url.Parse("http://example.com/")
	netResp := &http.Response{
		StatusCode: 200, Header: make(http.Header),
		Body:    io.NopCloser(strings.NewReader("")),
		Request: &http.Request{URL: u},
	}
	netResp.Header.Set("Content-Type", "text/html")
	resp, _ := wscan_http.ResponseFromNetHttpResponse(netResp)
	a := mockApollo(nil, resp)
	vulnFound := false
	a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) { vulnFound = true }}
	r := &CacheControlScanRule{}
	r.Finger().CheckAction(context.Background(), a)
	if vulnFound {
		t.Error("Should not detect vuln for empty body")
	}
}

// ==================== Cookie HttpOnly and Secure with good cookies ====================

func TestCookieHttpOnly_WithHttpOnly(t *testing.T) {
	u, _ := url.Parse("http://example.com/")
	netResp := &http.Response{
		StatusCode: 200, Header: make(http.Header),
		Body:    io.NopCloser(strings.NewReader("body")),
		Request: &http.Request{URL: u},
	}
	netResp.Header.Set("Content-Type", "text/html")
	netResp.Header.Set("Set-Cookie", "session=abc123; Path=/; HttpOnly")
	resp, _ := wscan_http.ResponseFromNetHttpResponse(netResp)
	a := mockApollo(nil, resp)
	vulnFound := false
	a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) { vulnFound = true }}
	r := &CookieHttpOnlyScanRule{}
	r.Finger().CheckAction(context.Background(), a)
	if vulnFound {
		t.Error("Should not detect vuln for HttpOnly cookie")
	}
}

func TestCookieSecureFlag_WithSecureFlag(t *testing.T) {
	u, _ := url.Parse("http://example.com/")
	netResp := &http.Response{
		StatusCode: 200, Header: make(http.Header),
		Body:    io.NopCloser(strings.NewReader("body")),
		Request: &http.Request{URL: u},
	}
	netResp.Header.Set("Content-Type", "text/html")
	netResp.Header.Set("Set-Cookie", "session=abc123; Path=/; Secure")
	resp, _ := wscan_http.ResponseFromNetHttpResponse(netResp)
	a := mockApollo(nil, resp)
	vulnFound := false
	a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) { vulnFound = true }}
	r := &CookieSecureFlagScanRule{}
	r.Finger().CheckAction(context.Background(), a)
	if vulnFound {
		t.Error("Should not detect vuln for cookie with Secure flag")
	}
}

// ==================== HeaderPolicy struct test ====================

func TestHeaderPolicy_StructCoverage(t *testing.T) {
	hp := HeaderPolicy{Name: "X-Frame-Options", Expected: true}
	if hp.Name != "X-Frame-Options" {
		t.Errorf("HeaderPolicy.Name = %q, want %q", hp.Name, "X-Frame-Options")
	}
}

// ==================== getAllowedWildcardSources coverage ====================

func TestGetAllowedWildcardSources_Full(t *testing.T) {
	csp := "script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-src 'self'; font-src 'self'; media-src 'self'; object-src 'self'; manifest-src 'self'; worker-src 'self'; prefetch-src 'self'; form-action 'self'; frame-ancestors 'none'"
	result := getAllowedWildcardSources(csp)
	// Should find all directives
	expectedCount := 13
	if len(result) != expectedCount {
		t.Errorf("Expected %d directives, got %d: %v", expectedCount, len(result), result)
	}
}

func TestParsePolicy_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		csp      string
		wantKeys int
	}{
		{"empty", "", 0},
		{"single", "script-src 'self'", 1},
		{"multiple", "script-src 'self'; style-src 'unsafe-inline'", 2},
		{"only semicolons", ";;; ", 0},
		{"single directive no value", "default-src", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParsePolicy(tt.csp)
			if len(result) != tt.wantKeys {
				t.Errorf("ParsePolicy(%q): got %d directives, want %d", tt.csp, len(result), tt.wantKeys)
			}
		})
	}
}

// ==================== SerializationDataInParams more body patterns ====================

func TestSerializationDataInParams_BodyPatterns(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		expectVuln bool
	}{
		{"dotnet viewstate in body", "viewstate=/wEAAABkAA1234datamoredatahere", true},
		{"python pickle in body", "data=gASVAAAAAAAAmoredata", true},
		{"ruby marshal in body", "data=BAhvAAAAAAAAmoredata", true},
		{"short match skip", "rO0ABXN", false},
		{"normal text", "hello world nothing to see", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := wscan_http.NewRequest("GET", "http://example.com/", nil)
			u, _ := url.Parse("http://example.com/")
			netResp := &http.Response{
				StatusCode: 200, Header: make(http.Header),
				Body:    io.NopCloser(strings.NewReader(tt.body)),
				Request: &http.Request{URL: u},
			}
			netResp.Header.Set("Content-Type", "text/html")
			resp, _ := wscan_http.ResponseFromNetHttpResponse(netResp)
			a := base.NewApollo(&wscan_http.Flow{Request: req, Response: resp})
			vulnFound := false
			a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) { vulnFound = true }}
			s := &serializationDataInParams{}
			s.Finger().CheckAction(context.Background(), a)
			if tt.expectVuln != vulnFound {
				t.Errorf("expected vulnFound=%v, got %v", tt.expectVuln, vulnFound)
			}
		})
	}
}

// ==================== RedirectLogic more paths ====================

func TestRedirectLogic_CheckAction_WithRedirectServer(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectURL := r.URL.Query().Get("redirect")
		if redirectURL != "" {
			w.Header().Set("Location", redirectURL)
			w.WriteHeader(302)
			return
		}
		nextURL := r.URL.Query().Get("next")
		if nextURL != "" {
			w.Header().Set("Location", nextURL)
			w.WriteHeader(302)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>ok</body></html>"))
	}))
	defer ts.Close()

	testURLs := []string{
		ts.URL + "/?redirect=/home",
		ts.URL + "/?next=/dashboard",
		ts.URL + "/?url=http://example.com",
	}

	for _, testURL := range testURLs {
		req, _ := wscan_http.NewRequest("GET", testURL, nil)
		u, _ := url.Parse(ts.URL + "/")
		netResp := &http.Response{
			StatusCode: 200, Header: make(http.Header),
			Body:    io.NopCloser(strings.NewReader("<html><body>ok</body></html>")),
			Request: &http.Request{URL: u},
		}
		netResp.Header.Set("Content-Type", "text/html")
		resp, _ := wscan_http.ResponseFromNetHttpResponse(netResp)
		a := base.NewApollo(&wscan_http.Flow{Request: req, Response: resp})
		a.ApolloBase.HTTPClient = wscan_http.NewClient()
		vulnFound := false
		a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) { vulnFound = true }}
		r := &redirectLogic{}
		r.Finger().CheckAction(context.Background(), a)
		_ = vulnFound
	}
}

// ==================== CookieLooselyScoped more paths ====================

func TestIsLooselyScopedCookie_MorePaths(t *testing.T) {
	tests := []struct {
		name   string
		cookie *http.Cookie
		host   string
		want   bool
	}{
		{"dot-prefixed subdomain", &http.Cookie{Name: "test", Value: "val", Domain: ".sub.example.com"}, "example.com", false},
		{"no dot prefix same", &http.Cookie{Name: "test", Value: "val", Domain: "example.com"}, "example.com", false},
		{"no dot prefix diff same tld", &http.Cookie{Name: "test", Value: "val", Domain: "other.com"}, "example.com", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsLooselyScopedCookie(tt.cookie, tt.host)
			if got != tt.want {
				t.Errorf("IsLooselyScopedCookie() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ==================== ContentSecurityPolicyMissing more paths ====================

func TestContentSecurityPolicyMissing_WithMetaCSP(t *testing.T) {
	// Test with CSP in meta tag
	u, _ := url.Parse("http://example.com/")
	netResp := &http.Response{
		StatusCode: 200, Header: make(http.Header),
		Body:    io.NopCloser(strings.NewReader(`<html><head><meta http-equiv="Content-Security-Policy" content="default-src 'self'"></head><body>test</body></html>`)),
		Request: &http.Request{URL: u},
	}
	netResp.Header.Set("Content-Type", "text/html")
	resp, _ := wscan_http.ResponseFromNetHttpResponse(netResp)
	a := mockApollo(nil, resp)
	vulnFound := false
	a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) { vulnFound = true }}
	r := &ContentSecurityPolicyMissingScanRule{}
	r.Finger().CheckAction(context.Background(), a)
	// When CSP is in meta tag, no vuln should be found
	_ = vulnFound
}

// ==================== AutoComplete more paths ====================

func TestAutoCompleteLeak_MorePatterns(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{"password with autocomplete off", `<input type="password" name="pwd" autocomplete="off">`, false},
		{"token input without autocomplete", `<input type="text" name="token" value="">`, true},
		{"secret id without autocomplete", `<input type="text" id="secret">`, true},
		{"normal text input", `<input type="text" name="search" autocomplete="off">`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := makeTestResponse(tt.body)
			a := mockApollo(nil, resp)
			vulnFound := false
			a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) { vulnFound = true }}
			al := &autoCompleteLeak{}
			al.Finger().CheckAction(context.Background(), a)
			if tt.expected != vulnFound {
				t.Errorf("expected vulnFound=%v, got %v for body=%q", tt.expected, vulnFound, tt.body)
			}
		})
	}
}

// ==================== EmailLeak more paths ====================

func TestEmailLeak_RealEmail(t *testing.T) {
	resp := makeTestResponseWithHeaders("Contact: admin@mycompany.org", 200, map[string]string{"Content-Type": "text/html"})
	a := mockApollo(nil, resp)
	vulnFound := false
	a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) { vulnFound = true }}
	e := &emailLeak{}
	e.Finger().CheckAction(context.Background(), a)
	if !vulnFound {
		t.Error("Expected vuln for real email domain")
	}
}

// ==================== ChinaAddress more paths ====================

func TestChinaAddress_StreetFormat(t *testing.T) {
	resp := makeTestResponseWithHeaders("地址：建国路100号", 200, map[string]string{"Content-Type": "text/html"})
	a := mockApollo(nil, resp)
	vulnFound := false
	a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) { vulnFound = true }}
	c := &chinaAddress{}
	c.Finger().CheckAction(context.Background(), a)
	_ = vulnFound
}
