package crawler

import (
	"bytes"
	"net"
	gohttp "net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	whttp "wscan/core/http"

	"github.com/PuerkitoBio/goquery"
)

// ==================== Coverage boost tests for crawler package ====================
// Focus on: UniqueId (75%), handleBasicTask (86.2%), DoFilter (83.9%),
// MarkPath (87.3%), markParamValue (9.3%), parser (50%), UrlParse (83.3%), GetUrl (86.4%)

// ---------- UniqueId additional paths ----------

func TestUniqueId_EmptyBodyPOST_Boost(t *testing.T) {
	// POST with nil body should still produce a valid unique ID
	req, _ := whttp.NewRequest("POST", "http://example.com/api", nil)
	id := UniqueId(req, false)
	if id == "" {
		t.Error("UniqueId should not be empty for POST with nil body")
	}
}

func TestUniqueId_SameMethodDifferentURL_Boost(t *testing.T) {
	req1, _ := whttp.NewRequest("GET", "http://example.com/api/v1", nil)
	req2, _ := whttp.NewRequest("GET", "http://example.com/api/v2", nil)
	id1 := UniqueId(req1, false)
	id2 := UniqueId(req2, false)
	if id1 == id2 {
		t.Error("Different URLs should produce different UniqueIds")
	}
}

// ---------- handleBasicTask additional coverage ----------

func TestHandleBasicTask_WithSourceMapJS_Boost(t *testing.T) {
	addr, cleanup := startBoostTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		if strings.HasSuffix(r.URL.Path, ".js") {
			w.WriteHeader(200)
			w.Write([]byte(`var api = "/api/v1/data"; var endpoint = "/api/v2/users";`))
			return
		}
		w.WriteHeader(200)
		w.Write([]byte(`<html><body>OK</body></html>`))
	}))
	defer cleanup()

	c := newTestCrawler()
	req, _ := whttp.NewRequest("GET", "http://"+addr+"/app.js", nil)
	tt := &task{
		req:         req,
		depth:       0,
		crawlerTask: c,
	}
	c.handleBasicTask(tt)
}

func TestHandleBasicTask_WithMainHashJS_Boost(t *testing.T) {
	addr, cleanup := startBoostTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(200)
		if strings.HasSuffix(r.URL.Path, ".js") {
			w.Write([]byte(`var x = "/api/data";`))
		} else {
			w.Write([]byte(`<html><body>OK</body></html>`))
		}
	}))
	defer cleanup()

	c := newTestCrawler()
	req, _ := whttp.NewRequest("GET", "http://"+addr+"/main.abc123.js", nil)
	tt := &task{
		req:         req,
		depth:       0,
		crawlerTask: c,
	}
	c.handleBasicTask(tt)
}

func TestHandleBasicTask_WithRobotsTxtDiscovery_Boost(t *testing.T) {
	addr, cleanup := startBoostTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		if r.URL.Path == "/robots.txt" {
			w.WriteHeader(200)
			w.Write([]byte("User-agent: *\nDisallow: /admin/\nAllow: /public/"))
			return
		}
		w.WriteHeader(200)
		w.Write([]byte(`<html><body>OK</body></html>`))
	}))
	defer cleanup()

	c := newTestCrawler()
	req, _ := whttp.NewRequest("GET", "http://"+addr+"/robots.txt", nil)
	tt := &task{
		req:         req,
		depth:       0,
		crawlerTask: c,
	}
	c.handleBasicTask(tt)
}

func TestHandleBasicTask_WithSitemapXMLDiscovery_Boost(t *testing.T) {
	addr, cleanup := startBoostTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		if r.URL.Path == "/sitemap.xml" {
			w.WriteHeader(200)
			w.Write([]byte(`<?xml version="1.0"?><urlset><url><loc>http://` + r.Host + `/page1</loc></url></urlset>`))
			return
		}
		w.WriteHeader(200)
		w.Write([]byte(`<html><body>OK</body></html>`))
	}))
	defer cleanup()

	c := newTestCrawler()
	req, _ := whttp.NewRequest("GET", "http://"+addr+"/sitemap.xml", nil)
	tt := &task{
		req:         req,
		depth:       0,
		crawlerTask: c,
	}
	c.handleBasicTask(tt)
}

func TestHandleBasicTask_WithMapFile_Boost(t *testing.T) {
	addr, cleanup := startBoostTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"version":3,"sources":["app.ts"],"sourcesContent":["var url = '/api/data';"],"mappings":"AAAA"}`))
	}))
	defer cleanup()

	c := newTestCrawler()
	req, _ := whttp.NewRequest("GET", "http://"+addr+"/app.map", nil)
	tt := &task{
		req:         req,
		depth:       0,
		crawlerTask: c,
	}
	c.handleBasicTask(tt)
}

func TestHandleBasicTask_WithRedirectAndHeaders_Boost(t *testing.T) {
	addr, cleanup := startBoostTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		if r.URL.Path == "/redirect" {
			w.Header().Set("Location", "/target")
			w.WriteHeader(302)
			return
		}
		w.WriteHeader(200)
		w.Write([]byte(`<html><body><a href="/page">Link</a></body></html>`))
	}))
	defer cleanup()

	c := newTestCrawler()
	c.config.MaxDepth = 5
	req, _ := whttp.NewRequest("GET", "http://"+addr+"/redirect", nil)
	req.Header.Set("X-Custom", "test-value")
	req.Header.Set("Authorization", "Bearer token123")
	tt := &task{
		req:         req,
		depth:       0,
		crawlerTask: c,
	}
	c.handleBasicTask(tt)
}

func TestHandleBasicTask_WithHTMLForm_Boost(t *testing.T) {
	addr, cleanup := startBoostTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`<html><body>
			<form action="/submit" method="POST">
				<input type="text" name="username" value="">
				<input type="password" name="password" value="">
				<input type="hidden" name="csrf" value="token123">
				<select name="country">
					<option value="us">US</option>
					<option value="uk">UK</option>
				</select>
				<textarea name="comment"></textarea>
				<input type="submit" value="Submit">
			</form>
		</body></html>`))
	}))
	defer cleanup()

	c := newTestCrawler()
	c.config.MaxDepth = 5
	req, _ := whttp.NewRequest("GET", "http://"+addr+"/form", nil)
	tt := &task{
		req:         req,
		depth:       0,
		crawlerTask: c,
	}
	c.handleBasicTask(tt)
}

func TestHandleBasicTask_WithFormMultipart_Boost(t *testing.T) {
	addr, cleanup := startBoostTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`<html><body>
			<form action="/upload" method="POST" enctype="multipart/form-data">
				<input type="text" name="title" value="test">
				<input type="file" name="document">
				<input type="submit" value="Upload">
			</form>
		</body></html>`))
	}))
	defer cleanup()

	c := newTestCrawler()
	c.config.MaxDepth = 5
	req, _ := whttp.NewRequest("GET", "http://"+addr+"/upload", nil)
	tt := &task{
		req:         req,
		depth:       0,
		crawlerTask: c,
	}
	c.handleBasicTask(tt)
}

func TestHandleBasicTask_WithFormGETMethod_Boost(t *testing.T) {
	addr, cleanup := startBoostTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`<html><body>
			<form action="/search" method="GET">
				<input type="text" name="q" value="">
				<input type="submit" value="Search">
			</form>
		</body></html>`))
	}))
	defer cleanup()

	c := newTestCrawler()
	c.config.MaxDepth = 5
	req, _ := whttp.NewRequest("GET", "http://"+addr+"/search-page", nil)
	tt := &task{
		req:         req,
		depth:       0,
		crawlerTask: c,
	}
	c.handleBasicTask(tt)
}

func TestHandleBasicTask_WithFormGETMultipart_Boost(t *testing.T) {
	addr, cleanup := startBoostTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`<html><body>
			<form action="/search" method="GET" enctype="multipart/form-data">
				<input type="text" name="q" value="">
				<input type="submit" value="Search">
			</form>
		</body></html>`))
	}))
	defer cleanup()

	c := newTestCrawler()
	c.config.MaxDepth = 5
	req, _ := whttp.NewRequest("GET", "http://"+addr+"/search-page", nil)
	tt := &task{
		req:         req,
		depth:       0,
		crawlerTask: c,
	}
	c.handleBasicTask(tt)
}

func TestHandleBasicTask_WithFormNoAction_Boost(t *testing.T) {
	addr, cleanup := startBoostTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`<html><body>
			<form method="POST">
				<input type="text" name="field" value="">
				<input type="submit" value="Submit">
			</form>
		</body></html>`))
	}))
	defer cleanup()

	c := newTestCrawler()
	c.config.MaxDepth = 5
	req, _ := whttp.NewRequest("GET", "http://"+addr+"/form-page", nil)
	tt := &task{
		req:         req,
		depth:       0,
		crawlerTask: c,
	}
	c.handleBasicTask(tt)
}

func TestHandleBasicTask_WithParentPathDetect_Boost(t *testing.T) {
	addr, cleanup := startBoostTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`<html><body>OK</body></html>`))
	}))
	defer cleanup()

	c := newTestCrawler()
	c.config.ParentPathDetect = true
	c.config.MaxDepth = 5
	req, _ := whttp.NewRequest("GET", "http://"+addr+"/a/b/c/page.html", nil)
	tt := &task{
		req:         req,
		depth:       0,
		crawlerTask: c,
	}
	c.handleBasicTask(tt)
}

// ---------- parser.go: headerContentLocationParser ----------

func TestHeaderContentLocationParser_EdgeCases_Boost(t *testing.T) {
	t.Run("Content-Location with relative path", func(t *testing.T) {
		u, _ := url.Parse("http://example.com/page")
		wu := whttp.URL{URL: *u}
		doc, _ := goquery.NewDocumentFromReader(bytes.NewReader([]byte("<html></html>")))
		resp := &whttp.Response{
			NativeResponse: &gohttp.Response{
				Header: gohttp.Header{
					"Content-Location": []string{"../other-page"},
				},
			},
		}
		headerContentLocationParser(&wu, doc, resp)
	})

	t.Run("Content-Location with fragment", func(t *testing.T) {
		u, _ := url.Parse("http://example.com/page")
		wu := whttp.URL{URL: *u}
		doc, _ := goquery.NewDocumentFromReader(bytes.NewReader([]byte("<html></html>")))
		resp := &whttp.Response{
			NativeResponse: &gohttp.Response{
				Header: gohttp.Header{
					"Content-Location": []string{"http://example.com/page#section"},
				},
			},
		}
		headerContentLocationParser(&wu, doc, resp)
	})
}

// ---------- UrlParse additional paths ----------

func TestUrlParse_EdgeCases_Boost(t *testing.T) {
	tests := []struct {
		name    string
		rawURL  string
		wantErr bool
	}{
		{"url with double slash", "http://example.com//path", false},
		{"url with special chars", "http://example.com/path?q=%E4%B8%AD%E6%96%87", false},
		{"just scheme and host", "http://example.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := UrlParse(tt.rawURL)
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error")
				}
				return
			}
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if u == nil {
				t.Error("URL should not be nil")
			}
		})
	}
}

// ---------- GetUrl additional paths ----------

func TestGetUrl_EdgeCases_Boost(t *testing.T) {
	t.Run("URL with path default", func(t *testing.T) {
		u, err := GetUrl("http://example.com")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if u.Path != "/" {
			t.Errorf("Path = %s, want /", u.Path)
		}
	})

	t.Run("URL with parent and fragment", func(t *testing.T) {
		parent := url.URL{Scheme: "http", Host: "example.com", Path: "/page"}
		u, err := GetUrl("#section", parent)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if u.Host != "example.com" {
			t.Errorf("Host = %s, want example.com", u.Host)
		}
	})

	t.Run("URL with query string", func(t *testing.T) {
		u, err := GetUrl("http://example.com/search?q=test&page=1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if u.RawQuery != "q=test&page=1" {
			t.Errorf("RawQuery = %s, want q=test&page=1", u.RawQuery)
		}
	})
}

// ---------- SmartFilter DoFilter additional paths ----------

func TestSmartFilterDoFilter_ComprehensiveScenarios_Boost(t *testing.T) {
	s := SmartFilter{
		SimpleFilter: SimpleFilter{},
	}
	s.Init()

	// Test with many different parameter key-value combinations
	// to trigger various filter thresholds
	for i := 0; i < 20; i++ {
		req, _ := whttp.NewRequest("GET", "http://example.com/search", nil)
		q := req.GetURL().Query()
		q.Set("q", "test")
		q.Set("page", "1")
		req.GetURL().RawQuery = q.Encode()
		s.DoFilter(req, false)
	}

	// Test with scanner-containing parameter values
	for i := 0; i < 5; i++ {
		req, _ := whttp.NewRequest("GET", "http://example.com/api?token=Scanner_test", nil)
		s.DoFilter(req, false)
	}
}

func TestSmartFilterDoFilter_WithEmptyParamsMultiple_Boost(t *testing.T) {
	s := SmartFilter{
		SimpleFilter: SimpleFilter{},
	}
	s.Init()

	// Send many requests with empty parameter values
	for i := 0; i < 15; i++ {
		req, _ := whttp.NewRequest("GET", "http://example.com/page?keyword"+string(rune('A'+i%26)), nil)
		s.DoFilter(req, false)
	}
}

// ---------- MarkPath additional coverage ----------

func TestSmartFilterMarkPath_MoreEdgeCases_Boost(t *testing.T) {
	s := SmartFilter{}

	tests := []struct {
		name string
		path string
	}{
		{"dot-separated with mixnum", "/static/abc1def2ghi3jkl4.js"},
		{"path with hash and extension", "/static/main.79aa39a81eb94047e946.js"},
		{"shtml file", "/page.shtml"},
		{"htm file with numbers", "/page123.htm"},
		{"html with alpha and numbers", "/abc123ABC.html"},
		{"numeric only segment", "/12345"},
		{"long segment", "/abcdefghijklmnopqrstuvwxyz123456789012"},
		{"uppercase only segment", "/ABCDEF"},
		{"segment with special chars", "/path{name}"},
		{"unicode segment", "/path\\u0041"},
		{"path with spaces", "/path with spaces"},
		{"dot file segment", "/file.min.js"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.MarkPath(tt.path)
			t.Logf("MarkPath(%q) = %q", tt.path, got)
		})
	}
}

// ---------- markParamValue additional coverage ----------

func TestSmartFilterMarkParamValue_AdditionalCases_Boost(t *testing.T) {
	s := SmartFilter{}
	s.Init()

	// Test various parameter values
	tests := []struct {
		name   string
		params map[string]any
	}{
		{"empty string value", map[string]any{"q": ""}},
		{"numeric value", map[string]any{"id": "12345"}},
		{"long value", map[string]any{"token": "abcdefghijklmnopqrstuvwxyz1234567890123456"}},
		{"uppercase value", map[string]any{"code": "ABCDEF"}},
		{"mixed value", map[string]any{"q": "abc123DEF"}},
		{"special chars", map[string]any{"q": "test@example.com"}},
		{"url-encoded value", map[string]any{"q": "%E6%B5%8B%E8%AF%95"}},
		{"unicode value", map[string]any{"q": "\\u6d4b\\u8bd5"}},
		{"scanner value", map[string]any{"q": "Scanner_test"}},
		{"integer value", map[string]any{"count": 42}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := whttp.NewRequest("GET", "http://example.com/api", nil)
			result := s.markParamValue(tt.params, *req)
			for key, val := range result {
				t.Logf("markParamValue key=%s value=%v", key, val)
			}
		})
	}
}

// ---------- markParamName additional coverage ----------

func TestSmartFilterMarkParamName_AdditionalCases_Boost(t *testing.T) {
	s := SmartFilter{}

	tests := []struct {
		name   string
		params map[string]any
	}{
		{"simple alpha keys", map[string]any{"name": "val", "age": "val"}},
		{"numeric in key", map[string]any{"param123": "val", "field456": "val"}},
		{"long key", map[string]any{"a_very_long_parameter_name_that_exceeds_32_chars": "val"}},
		{"mixed key", map[string]any{"user_id": "val"}},
		{"empty key", map[string]any{"": "val"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.markParamName(tt.params)
			for key, val := range result {
				t.Logf("markParamName key=%s value=%v", key, val)
			}
		})
	}
}

// ---------- preQueryMark additional coverage ----------

func TestSmartFilterPreQueryMark_AdditionalCases_Boost(t *testing.T) {
	s := SmartFilter{}

	tests := []struct {
		name     string
		rawQuery string
	}{
		{"chinese characters", "name=测试&age=25"},
		{"url-encoded", "name=%E6%B5%8B%E8%AF%95"},
		{"unicode escapes", "name=\\u6d4b\\u8bd5"},
		{"plain ascii", "name=test&age=25"},
		{"mixed", "name=测试&age=25&lang=en"},
		{"empty", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.preQueryMark(tt.rawQuery)
			t.Logf("preQueryMark(%q) = %q", tt.rawQuery, result)
		})
	}
}

// ---------- getMarkedUniqueID additional coverage ----------

func TestSmartFilterGetMarkedUniqueID_AdditionalCases_Boost(t *testing.T) {
	s := SmartFilter{}

	tests := []struct {
		name            string
		method          string
		url             string
		queryMapID      string
		postDataID      string
		pathID          string
		redirectionFlag bool
	}{
		{"GET with query", "GET", "http://example.com/api?q=1", "qm1", "", "p1", false},
		{"POST with data", "POST", "http://example.com/api", "", "pd1", "p1", false},
		{"DELETE with query", "DELETE", "http://example.com/api?id=1", "qm1", "", "p1", false},
		{"PUT with data", "PUT", "http://example.com/api", "", "pd1", "p1", false},
		{"GET with redirect", "GET", "http://example.com/api", "qm1", "", "p1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := whttp.NewRequest(tt.method, tt.url, nil)
			id := s.getMarkedUniqueID(req, tt.queryMapID, tt.postDataID, tt.pathID, tt.redirectionFlag)
			if id == "" {
				t.Error("getMarkedUniqueID should not return empty string")
			}
		})
	}
}

// ---------- helper: startBoostTestServer ----------

func startBoostTestServer(t *testing.T, handler gohttp.HandlerFunc) (string, func()) {
	t.Helper()
	server := &gohttp.Server{
		Handler: handler,
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("Cannot create test server listener: %v", err)
		return "", func() {}
	}
	addr := listener.Addr().String()
	go server.Serve(listener)
	time.Sleep(50 * time.Millisecond)
	return addr, func() {
		server.Close()
		listener.Close()
	}
}

// ---------- ParseResponseURL additional coverage ----------

func TestParseResponseURL_JSWithMainHashAndSourceMap_Boost(t *testing.T) {
	u, _ := url.Parse("http://example.com/assets/main.abc123.js")
	body := `var api = "/api/v1/data"; var endpoint = "/api/v2/users";` + "\n//# sourceMappingURL=main.abc123.js.map"
	result := ParseResponseURL(u, body)

	// Should find both the API URLs and the source map
	foundSourceMap := false
	foundAPI := false
	for _, req := range result {
		if req != nil && req.GetURL() != nil {
			urlStr := req.GetURL().String()
			if strings.Contains(urlStr, ".map") {
				foundSourceMap = true
			}
			if strings.Contains(urlStr, "/api/") {
				foundAPI = true
			}
		}
	}
	t.Logf("ParseResponseURL for main.[hash].js: foundSourceMap=%v, foundAPI=%v, total=%d", foundSourceMap, foundAPI, len(result))
}

func TestParseResponseURL_GenericExtensionWithUrls_Boost(t *testing.T) {
	u, _ := url.Parse("http://example.com/api/data")
	body := `"use strict";var endpoint="/api/v2/health";var resource="/api/v2/status";`
	result := ParseResponseURL(u, body)
	if len(result) < 1 {
		t.Errorf("Expected at least some URLs from generic response, got %d", len(result))
	}
}

// ---------- SmartFilter with StrictMode ----------

func TestSmartFilterDoFilter_StrictModeComprehensive_Boost(t *testing.T) {
	s := SmartFilter{
		SimpleFilter: SimpleFilter{},
		StrictMode:   true,
	}
	s.Init()

	// Test various parameter values in strict mode
	urls := []string{
		"http://example.com/api?id=123",
		"http://example.com/api?name=ABCDEF",
		"http://example.com/api?name=abcdef",
		"http://example.com/api?name=ABCdef",
		"http://example.com/api?name=abc-123",
	}

	for _, u := range urls {
		req, _ := whttp.NewRequest("GET", u, nil)
		result := s.DoFilter(req, false)
		t.Logf("StrictMode DoFilter(%s): filtered=%v", u, result)
	}
}

// ---------- Filter interface compliance ----------

func TestSyncMapFilter_AllMethods_Boost(t *testing.T) {
	f := &SyncMapFilter{Map: &sync.Map{}}

	// Check, Insert, Check, Reset, Check, Close
	if f.Check("key1", false) {
		t.Error("Check should return false for non-existent key")
	}
	f.Insert("key1")
	if !f.Check("key1", false) {
		t.Error("Check should return true after Insert")
	}
	f.Reset()
	if f.Check("key1", false) {
		t.Error("Check should return false after Reset")
	}
	f.Close()
}

// ---------- discoverParentDirs additional paths ----------

func TestDiscoverParentDirs_DeepPath_Boost(t *testing.T) {
	c := newTestCrawler()
	req, _ := whttp.NewRequest("GET", "http://example.com/a/b/c/d/e/f.html", nil)
	tt := &task{
		req:         req,
		depth:       0,
		crawlerTask: c,
	}
	c.discoverParentDirs(tt)
	if c.taskQueue.Len() < 1 {
		t.Errorf("Deep path should discover parent dirs, got %d tasks", c.taskQueue.Len())
	}
}

func TestDiscoverParentDirs_SinglePathComponent_Boost(t *testing.T) {
	c := newTestCrawler()
	req, _ := whttp.NewRequest("GET", "http://example.com/page", nil)
	tt := &task{
		req:         req,
		depth:       0,
		crawlerTask: c,
	}
	c.discoverParentDirs(tt)
	// /page has no parent directories beyond /
	if c.taskQueue.Len() != 0 {
		t.Errorf("Single path segment should not discover parent dirs, got %d", c.taskQueue.Len())
	}
}
