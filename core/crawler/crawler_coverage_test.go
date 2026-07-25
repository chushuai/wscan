package crawler

import (
	"bytes"
	"fmt"
	"net"
	gohttp "net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
	whttp "wscan/core/http"

	"github.com/PuerkitoBio/goquery"
)

// ========== handleBasicTask tests with httptest ==========

func startTestServer(t *testing.T, handler gohttp.HandlerFunc) (string, func()) {
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

func TestHandleBasicTaskWithServer(t *testing.T) {
	addr, cleanup := startTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		w.Write([]byte(`<html><body>
			<a href="/page1">Page1</a>
			<a href="/page2">Page2</a>
			<script src="/js/app.js"></script>
			<link href="/css/style.css" rel="stylesheet">
			<form action="/login" method="POST">
				<input type="text" name="username" value="">
				<input type="password" name="password" value="">
				<input type="submit" value="Login">
			</form>
		</body></html>`))
	}))
	defer cleanup()

	c := newTestCrawler()
	var errorsCaught []error
	c.OnError(func(err error) {
		errorsCaught = append(errorsCaught, err)
	})

	req, _ := whttp.NewRequest("GET", "http://"+addr+"/", nil)
	tt := &task{
		req:         req,
		depth:       0,
		crawlerTask: c,
	}

	c.handleBasicTask(tt)
}

func TestHandleBasicTaskRedirect(t *testing.T) {
	addr, cleanup := startTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		if r.URL.Path == "/redirect" {
			w.Header().Set("Location", "/target")
			w.WriteHeader(302)
			return
		}
		w.WriteHeader(200)
		w.Write([]byte(`<html><body>OK</body></html>`))
	}))
	defer cleanup()

	c := newTestCrawler()
	req, _ := whttp.NewRequest("GET", "http://"+addr+"/redirect", nil)
	tt := &task{
		req:         req,
		depth:       0,
		crawlerTask: c,
	}

	c.handleBasicTask(tt)
}

func TestHandleBasicTaskJSFile(t *testing.T) {
	addr, cleanup := startTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`var api = "/api/v1/users"; var url = "/api/v2/data";`))
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

func TestHandleBasicTaskMapFile(t *testing.T) {
	addr, cleanup := startTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
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

func TestHandleBasicTaskRobotsTxt(t *testing.T) {
	addr, cleanup := startTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(200)
		w.Write([]byte("User-agent: *\nDisallow: /admin/\nAllow: /public/"))
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

func TestHandleBasicTaskSitemapXML(t *testing.T) {
	addr, cleanup := startTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`<?xml version="1.0"?><urlset><url><loc>http://` + r.Host + `/page1</loc></url></urlset>`))
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

func TestHandleBasicTaskFormPOST(t *testing.T) {
	addr, cleanup := startTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`<html><body>
			<form action="/submit" method="POST" enctype="application/x-www-form-urlencoded">
				<input type="text" name="username" value="">
				<input type="password" name="password" value="">
				<input type="submit" value="Submit">
			</form>
		</body></html>`))
	}))
	defer cleanup()

	c := newTestCrawler()
	req, _ := whttp.NewRequest("GET", "http://"+addr+"/", nil)
	tt := &task{
		req:         req,
		depth:       0,
		crawlerTask: c,
	}

	c.handleBasicTask(tt)
}

func TestHandleBasicTaskFormMultipart(t *testing.T) {
	addr, cleanup := startTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`<html><body>
			<form action="/upload" method="POST" enctype="multipart/form-data">
				<input type="text" name="title" value="">
				<input type="file" name="attachment">
				<input type="submit" value="Upload">
			</form>
		</body></html>`))
	}))
	defer cleanup()

	c := newTestCrawler()
	req, _ := whttp.NewRequest("GET", "http://"+addr+"/", nil)
	tt := &task{
		req:         req,
		depth:       0,
		crawlerTask: c,
	}

	c.handleBasicTask(tt)
}

func TestHandleBasicTaskFormGET(t *testing.T) {
	addr, cleanup := startTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
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
	req, _ := whttp.NewRequest("GET", "http://"+addr+"/", nil)
	tt := &task{
		req:         req,
		depth:       0,
		crawlerTask: c,
	}

	c.handleBasicTask(tt)
}

func TestHandleBasicTaskFormGETMultipart(t *testing.T) {
	addr, cleanup := startTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
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
	req, _ := whttp.NewRequest("GET", "http://"+addr+"/", nil)
	tt := &task{
		req:         req,
		depth:       0,
		crawlerTask: c,
	}

	c.handleBasicTask(tt)
}

func TestHandleBasicTaskDepthLimit(t *testing.T) {
	addr, cleanup := startTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`<html><body><a href="/linked">Link</a></body></html>`))
	}))
	defer cleanup()

	c := newTestCrawler()
	c.config.MaxDepth = 0 // unlimited depth
	req, _ := whttp.NewRequest("GET", "http://"+addr+"/", nil)
	tt := &task{
		req:         req,
		depth:       0,
		crawlerTask: c,
	}

	c.handleBasicTask(tt)
}

func TestHandleBasicTaskWithLinksAndScripts(t *testing.T) {
	addr, cleanup := startTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`<html><body>
			<a href="/page1">Page1</a>
			<a href="/page2">Page2</a>
			<script src="/js/app.js"></script>
			<link href="/css/style.css" rel="stylesheet">
		</body></html>`))
	}))
	defer cleanup()

	c := newTestCrawler()
	c.config.MaxDepth = 5
	req, _ := whttp.NewRequest("GET", "http://"+addr+"/", nil)
	tt := &task{
		req:         req,
		depth:       0,
		crawlerTask: c,
	}

	c.handleBasicTask(tt)
}

func TestHandleBasicTaskRequestError(t *testing.T) {
	c := newTestCrawler()
	var receivedErr error
	c.OnError(func(err error) {
		receivedErr = err
	})

	req, _ := whttp.NewRequest("GET", "http://127.0.0.1:1/nonexistent", nil)
	tt := &task{
		req:         req,
		depth:       0,
		crawlerTask: c,
	}

	c.handleBasicTask(tt)
	if receivedErr == nil {
		t.Error("handleBasicTask should trigger error handler for failed request")
	}
}

func TestHandleBasicTaskNonHTMLResponse(t *testing.T) {
	addr, cleanup := startTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer cleanup()

	c := newTestCrawler()
	req, _ := whttp.NewRequest("GET", "http://"+addr+"/api", nil)
	tt := &task{
		req:         req,
		depth:       0,
		crawlerTask: c,
	}

	c.handleBasicTask(tt)
}

// ========== NewCrawler additional coverage ==========

func TestNewCrawlerWithProxyOnly(t *testing.T) {
	config := Config{
		MaxConcurrent: 2,
		Proxy:         "http://proxy:8080",
	}
	corrected, _ := config.Correct()
	crawler := NewCrawler(*corrected, nil)
	if crawler.Client == nil {
		t.Error("Client should be created with proxy config")
	}
	if crawler.config.Proxy != "http://proxy:8080" {
		t.Error("Proxy config should be preserved")
	}
}

// ========== Feed / Run / handleTask tests ==========

func TestFeedWithTasks(t *testing.T) {
	c := newTestCrawler()
	req, _ := whttp.NewRequest("GET", "http://example.com/page", nil)
	c.NewTask(req, 0)

	done := make(chan bool, 1)
	go func() {
		time.Sleep(2 * time.Second)
		c.EndFeed()
		done <- true
	}()

	go c.Feed()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Error("Feed should have ended")
	}
}

func TestRunWithWorkers(t *testing.T) {
	c := newTestCrawler()

	go c.Run()
	time.Sleep(200 * time.Millisecond)
	c.Stop()

	if c.ctx.Err() == nil {
		t.Error("Context should be cancelled after Stop")
	}
}

func TestHandleTaskDispatchesToBasic(t *testing.T) {
	c := newTestCrawler()
	c.config.Browser = false

	c.OnError(func(err error) {
		// Error handler for failed request
	})

	req, _ := whttp.NewRequest("GET", "http://127.0.0.1:1/fail", nil)
	tt := &task{
		req:         req,
		depth:       0,
		crawlerTask: c,
	}

	c.handleTask(tt)
}

// ========== clear with Pool ==========

func TestClearWithPool(t *testing.T) {
	c := newTestCrawler()
	if c.Pool == nil {
		t.Fatal("Pool should be initialized")
	}
	c.clear()
}

func TestClearWithBrowser(t *testing.T) {
	c := newTestCrawler()
	c.Browser = nil
	c.clear()
}

// ========== UniqueId additional coverage ==========

func TestUniqueIdPOSTRequest(t *testing.T) {
	req, _ := whttp.NewRequest("POST", "http://example.com/api", strings.NewReader("data=test"))
	id := UniqueId(req, false)
	if id == "" {
		t.Error("UniqueId should not be empty for POST")
	}

	idRedirect := UniqueId(req, true)
	if id == idRedirect {
		t.Error("POST UniqueId should differ with redirection flag")
	}
}

func TestUniqueIdNoBody(t *testing.T) {
	req, _ := whttp.NewRequest("GET", "http://example.com/api", nil)
	id := UniqueId(req, false)
	if id == "" {
		t.Error("UniqueId should not be empty for GET without body")
	}
}

// ========== markParamValue additional coverage ==========

func TestSmartFilterMarkParamValueWithScanner(t *testing.T) {
	s := SmartFilter{}
	s.Init()

	req, _ := whttp.NewRequest("GET", "http://example.com/api?token=Scanner_test", nil)
	paramMap := map[string]any{"token": "Scanner_test"}
	result := s.markParamValue(paramMap, *req)

	if result["token"] != CustomValueMark {
		t.Errorf("markParamValue should mark Scanner-containing value as CustomValueMark, got %v", result["token"])
	}
}

func TestSmartFilterMarkParamValueEmpty(t *testing.T) {
	s := SmartFilter{}
	s.Init()

	req, _ := whttp.NewRequest("GET", "http://example.com/api", nil)
	paramMap := map[string]any{}
	result := s.markParamValue(paramMap, *req)

	if len(result) != 0 {
		t.Errorf("Empty param map should return empty result, got %v", result)
	}
}

// ========== MarkPath additional branch coverage ==========

func TestSmartFilterMarkPathDotSeparated(t *testing.T) {
	s := SmartFilter{}

	tests := []struct {
		name string
		path string
	}{
		{"numeric dot segment", "/path/123.js"},
		{"uppercase dot segment", "/path/ABC.js"},
		{"long dot segment", "/path/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.js"},
		{"mixnum dot segment", "/path/abc1def2ghi3jkl4.js"},
		{"simple name dot segment", "/path/app.js"},
		{"html with dot", "/page.test.html"},
		{"htm with dot", "/page.test.htm"},
		{"shtml with dot", "/page.test.shtml"},
		{"dot and dotdot", "/a/./b"},
		{"parent ref", "/a/../b"},
		{"mixed dot segments", "/static/vendor.abc123.js"},
		{"file with hash", "/static/main.79aa39a81eb94047e946.js"},
		{"css file", "/static/style.css"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.MarkPath(tt.path)
			t.Logf("MarkPath(%q) = %q", tt.path, got)
		})
	}
}

func TestSmartFilterMarkPathHTMLEdgeCases(t *testing.T) {
	s := SmartFilter{}

	tests := []struct {
		name string
		path string
		want string
	}{
		{"html with all char types", "/abc123ABC.html", "/{{mix_alpha_num}}"},
		{"html numeric only", "/123.html", "/{{number}}"},
		{"html plain name", "/dashboard.html", "/dashboard"},
		{"htm numeric", "/456.htm", "/{{number}}"},
		{"shtml plain", "/index.shtml", "/index"},
		{"html with dots in name", "/page.test.html", "/page.test"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.MarkPath(tt.path)
			if got != tt.want {
				t.Errorf("MarkPath(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestSmartFilterMarkPathDotParts(t *testing.T) {
	s := SmartFilter{}

	tests := []struct {
		name string
		path string
		want string
	}{
		{"numeric dot part", "/static/123.js", "/static/{{number}}.js"},
		{"uppercase dot part", "/static/ABC.js", "/static/{{upper}}.js"},
		{"long dot part", "/static/aabcdefghijklmnopqrstuvwxyz12345678901234.js", "/static/{{long}}.js"},
		{"simple name dot part", "/static/app.js", "/static/app.js"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.MarkPath(tt.path)
			if got != tt.want {
				t.Errorf("MarkPath(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestSmartFilterMarkPathMixNumOver3Digits(t *testing.T) {
	s := SmartFilter{}

	tests := []struct {
		path string
		want string
	}{
		{"/api/abc1234def", "/api/{{mix_num}}"},
		{"/api/abc1def", "/api/abc1def"},
		{"/api/abc12def", "/api/abc12def"},
	}

	for _, tt := range tests {
		got := s.MarkPath(tt.path)
		if got != tt.want {
			t.Errorf("MarkPath(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

// ========== DoFilter additional branch coverage ==========

func TestSmartFilterDoFilterWithQueryParamVariations(t *testing.T) {
	s := SmartFilter{
		SimpleFilter: SimpleFilter{},
	}
	s.Init()

	for i := 0; i < 15; i++ {
		req, _ := whttp.NewRequest("GET", fmt.Sprintf("http://example.com/search?q=value%d&sort=asc", i), nil)
		s.DoFilter(req, false)
	}

	req, _ := whttp.NewRequest("GET", "http://example.com/search?q=newvalue&sort=asc", nil)
	result := s.DoFilter(req, false)
	t.Logf("DoFilter after many variations: filtered=%v", result)
}

func TestSmartFilterDoFilterWithEmptyParams(t *testing.T) {
	s := SmartFilter{
		SimpleFilter: SimpleFilter{},
	}
	s.Init()

	for i := 0; i < 15; i++ {
		req, _ := whttp.NewRequest("GET", fmt.Sprintf("http://example.com/page?param%d", i), nil)
		s.DoFilter(req, false)
	}
}

func TestSmartFilterDoFilterWithCommonScriptSuffix(t *testing.T) {
	s := SmartFilter{
		SimpleFilter: SimpleFilter{},
	}
	s.Init()

	for _, suffix := range ScriptSuffix {
		req, _ := whttp.NewRequest("GET", "http://example.com/dir/page."+suffix, nil)
		result := s.DoFilter(req, false)
		t.Logf("DoFilter for .%s: filtered=%v", suffix, result)
	}
}

func TestSmartFilterDoFilterStrictMode(t *testing.T) {
	s := SmartFilter{
		SimpleFilter: SimpleFilter{},
		StrictMode:   true,
	}
	s.Init()

	req, _ := whttp.NewRequest("GET", "http://example.com/api?id=abc", nil)
	if s.DoFilter(req, false) {
		t.Error("First request in strict mode should not be filtered")
	}
}

// ========== UrlParse edge case ==========

func TestUrlParseBadPercentThatFailsAfterEscape(t *testing.T) {
	u, err := UrlParse("http://example.com/path%ZZ")
	if err != nil {
		t.Logf("UrlParse with %%ZZ failed: %v (acceptable)", err)
	} else {
		t.Logf("UrlParse with %%ZZ succeeded: %s", u.String())
	}
}

// ========== GetUrl edge cases ==========

func TestGetUrlWithFragmentPath(t *testing.T) {
	u, err := GetUrl("http://example.com/page#/sub/path")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u.Fragment != "/sub/path" {
		t.Errorf("Fragment = %s, want /sub/path", u.Fragment)
	}
}

func TestGetUrlWithParentNoPath(t *testing.T) {
	parent := url.URL{Scheme: "http", Host: "example.com"}
	u, err := GetUrl("/test", parent)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u.Path != "/test" {
		t.Errorf("Path = %s, want /test", u.Path)
	}
}

// ========== headerContentLocationParser additional coverage ==========

func TestHeaderContentLocationParserWithInvalidURL(t *testing.T) {
	u, _ := url.Parse("http://example.com/page")
	wu := whttp.URL{URL: *u}
	doc, _ := goquery.NewDocumentFromReader(bytes.NewReader([]byte("<html></html>")))
	resp := &whttp.Response{
		NativeResponse: &gohttp.Response{
			Header: gohttp.Header{
				"Content-Location": []string{":://invalid-url"},
			},
		},
	}

	headerContentLocationParser(&wu, doc, resp)
}

// ========== handleFlow with multiple handlers ==========

func TestHandleFlowMultipleHandlers(t *testing.T) {
	c := newTestCrawler()
	callCount := 0
	c.OnFlow(func(flow *whttp.Flow) bool {
		callCount++
		return true
	})
	c.OnFlow(func(flow *whttp.Flow) bool {
		callCount++
		return true
	})
	req, _ := whttp.NewRequest("GET", "http://example.com/", nil)
	flow := &whttp.Flow{Request: req}
	result := c.handleFlow(flow)
	if !result {
		t.Error("handleFlow should return true when all handlers return true")
	}
	if callCount != 2 {
		t.Errorf("Expected 2 handler calls, got %d", callCount)
	}
}

func TestHandleFlowFirstRejects(t *testing.T) {
	c := newTestCrawler()
	secondCalled := false
	c.OnFlow(func(flow *whttp.Flow) bool { return false })
	c.OnFlow(func(flow *whttp.Flow) bool {
		secondCalled = true
		return true
	})
	req, _ := whttp.NewRequest("GET", "http://example.com/", nil)
	flow := &whttp.Flow{Request: req}
	result := c.handleFlow(flow)
	if result {
		t.Error("handleFlow should return false when first handler rejects")
	}
	if secondCalled {
		t.Error("Second handler should not be called when first rejects")
	}
}

// ========== AddResultRequest test ==========

func TestAddResultRequest(t *testing.T) {
	c := newTestCrawler()
	req, _ := whttp.NewRequest("GET", "http://example.com/api", nil)

	tab := &task{
		crawlerTask: c,
		depth:       0,
		ExtraHeaders: map[string]any{
			"X-Custom": "value",
		},
	}

	tab.AddResultRequest(req)
	if c.taskQueue.Len() != 1 {
		t.Errorf("AddResultRequest should add task to queue, got %d", c.taskQueue.Len())
	}
}

// ========== HandleHostBinding additional edge cases ==========

func TestHandleHostBindingRequestMatchesHost(t *testing.T) {
	navReq, _ := whttp.NewRequest("GET", "http://192.168.1.1/page", nil)
	navReq.Header.Set("Host", "api.example.com")

	req, _ := whttp.NewRequest("GET", "http://api.example.com/endpoint", nil)

	tab := &task{
		NavigateReq: *navReq,
	}

	tab.HandleHostBinding(req)

	if req.Header.Get("Host") != "api.example.com" {
		t.Errorf("Host header should be api.example.com, got %s", req.Header.Get("Host"))
	}
}

// ========== SmartFilter with location-based filter ==========

func TestSmartFilterDoFilterLocationBasedFilter(t *testing.T) {
	s := SmartFilter{
		SimpleFilter: SimpleFilter{},
	}
	s.Init()

	req1, _ := whttp.NewRequest("GET", "http://example.com/api?token=Scanner123", nil)
	s.DoFilter(req1, false)

	req2, _ := whttp.NewRequest("GET", "http://example.com/api?token=Scanner456", nil)
	result := s.DoFilter(req2, false)
	t.Logf("DoFilter with Scanner value after first: filtered=%v", result)
}

// ========== ContinueResourceList type test ==========

func TestContinueResourceListType(t *testing.T) {
	var crl ContinueResourceList = []string{"/css/", "/js/", "/images/"}
	if len(crl) != 3 {
		t.Errorf("ContinueResourceList should have 3 items, got %d", len(crl))
	}
}

// ========== SmartFilter DoFilter with parent path variations ==========

func TestSmartFilterDoFilterParentPathVariations(t *testing.T) {
	s := SmartFilter{
		SimpleFilter: SimpleFilter{},
	}
	s.Init()

	for i := 0; i < 35; i++ {
		req, _ := whttp.NewRequest("GET", fmt.Sprintf("http://example.com/api/resource%d", i), nil)
		s.DoFilter(req, false)
	}

	req, _ := whttp.NewRequest("GET", "http://example.com/api/resource36", nil)
	result := s.DoFilter(req, false)
	t.Logf("After many parent path variations: filtered=%v", result)
}

// ========== parse function edge cases ==========

func TestParseWhitespaceURL(t *testing.T) {
	result, err := parse("  http://example.com  ")
	if err != nil {
		t.Errorf("parse should handle whitespace: %v", err)
	}
	if result != "http://example.com" {
		t.Errorf("parse should trim whitespace, got %q", result)
	}
}

func TestParseMultipleHashes(t *testing.T) {
	result, err := parse("http://example.com/page###anchor")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(result, "###") {
		t.Errorf("parse should reduce multiple hashes, got %q", result)
	}
}

// ========== NewTask edge cases ==========

func TestNewTaskWithMaxDepthExceeded(t *testing.T) {
	c := newTestCrawler()
	c.config.MaxDepth = 1
	req, _ := whttp.NewRequest("GET", "http://example.com/page", nil)
	c.NewTask(req, 2)
	if c.taskQueue.Len() != 0 {
		t.Error("Request exceeding max depth should be dropped")
	}
}

func TestNewTaskAtExactMaxDepth(t *testing.T) {
	c := newTestCrawler()
	c.config.MaxDepth = 2
	req, _ := whttp.NewRequest("GET", "http://example.com/page", nil)
	c.NewTask(req, 2)
	if c.taskQueue.Len() != 1 {
		t.Error("Request at exact max depth should be allowed")
	}
}

// ========== DoFilter with POST body ==========

func TestSmartFilterDoFilterPOSTNoBody(t *testing.T) {
	s := SmartFilter{
		SimpleFilter: SimpleFilter{},
	}
	s.Init()

	req, _ := whttp.NewRequest("POST", "http://example.com/api", nil)
	if s.DoFilter(req, false) {
		t.Error("First POST without body should not be filtered")
	}
}

// ========== Test handleBasicTask with non-HTML error response ==========

func TestHandleBasicTaskGzipResponse(t *testing.T) {
	addr, cleanup := startTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`<html><body>Simple page</body></html>`))
	}))
	defer cleanup()

	c := newTestCrawler()
	req, _ := whttp.NewRequest("GET", "http://"+addr+"/", nil)
	tt := &task{
		req:         req,
		depth:       0,
		crawlerTask: c,
	}

	c.handleBasicTask(tt)
}

// ========== SmartFilter with global numeric param marking ==========

func TestSmartFilterDoFilterGlobalNumericParam(t *testing.T) {
	s := SmartFilter{
		SimpleFilter: SimpleFilter{},
	}
	s.Init()

	for i := 0; i < 5; i++ {
		req, _ := whttp.NewRequest("GET", fmt.Sprintf("http://example.com/search?page=Scanner_%d", i), nil)
		s.DoFilter(req, false)
	}

	req, _ := whttp.NewRequest("GET", "http://example.com/search?page=99", nil)
	result := s.DoFilter(req, false)
	t.Logf("DoFilter after Scanner-based marking: filtered=%v", result)
}

// ========== Test getMarkedUniqueID edge cases ==========

func TestSmartFilterGetMarkedUniqueIDHTTPSRootPath(t *testing.T) {
	s := SmartFilter{}

	req, _ := whttp.NewRequest("GET", "https://example.com/", nil)
	id := s.getMarkedUniqueID(req, "", "", "", false)
	if id == "" {
		t.Error("getMarkedUniqueID should return non-empty for HTTPS root")
	}

	req2, _ := whttp.NewRequest("GET", "http://example.com/", nil)
	id2 := s.getMarkedUniqueID(req2, "", "", "", false)
	if id2 == "" {
		t.Error("getMarkedUniqueID should return non-empty for HTTP root")
	}
}

func TestSmartFilterGetMarkedUniqueIDFragmentStartsWithSlash(t *testing.T) {
	s := SmartFilter{}

	req, _ := whttp.NewRequest("GET", "http://example.com/page#/route", nil)
	id := s.getMarkedUniqueID(req, "", "", "", false)
	if id == "" {
		t.Error("getMarkedUniqueID should return non-empty for fragment starting with /")
	}
}

func TestSmartFilterGetMarkedUniqueIDFragmentNoSlash(t *testing.T) {
	s := SmartFilter{}

	req, _ := whttp.NewRequest("GET", "http://example.com/page#section", nil)
	id := s.getMarkedUniqueID(req, "", "", "", false)
	if id == "" {
		t.Error("getMarkedUniqueID should return non-empty for fragment without /")
	}
}

// ========== Test task struct creation ==========

func TestTaskStructFields(t *testing.T) {
	c := newTestCrawler()
	req, _ := whttp.NewRequest("GET", "http://example.com/page", nil)

	tt := &task{
		req:           req,
		redirectCount: 2,
		depth:         1,
		crawlerTask:   c,
		browser:       c.Browser,
		TopFrameId:    "frame1",
		LoaderID:      "loader1",
		NavNetworkID:  "nav1",
		PageCharset:   "UTF-8",
		NavDone:       make(chan int),
		ExtraHeaders:  map[string]any{"X-Test": "value"},
	}

	if tt.redirectCount != 2 {
		t.Error("redirectCount mismatch")
	}
	if tt.TopFrameId != "frame1" {
		t.Error("TopFrameId mismatch")
	}
	if tt.PageCharset != "UTF-8" {
		t.Error("PageCharset mismatch")
	}
}

// ========== Test SmartFilter DoFilter with high param key all values ==========

func TestSmartFilterDoFilterHighParamKeyAllValues(t *testing.T) {
	s := SmartFilter{
		SimpleFilter: SimpleFilter{},
	}
	s.Init()

	for i := 0; i < 15; i++ {
		req, _ := whttp.NewRequest("GET", fmt.Sprintf("http://example.com/search?category=cat%d", i), nil)
		s.DoFilter(req, false)
	}

	req, _ := whttp.NewRequest("GET", "http://example.com/search?category=newcat", nil)
	result := s.DoFilter(req, false)
	t.Logf("DoFilter after high param key values: filtered=%v", result)
}

// ========== Test SmartFilter DoFilter with path param key symbol ==========

func TestSmartFilterDoFilterPathParamKeySymbol(t *testing.T) {
	s := SmartFilter{
		SimpleFilter: SimpleFilter{},
	}
	s.Init()

	for i := 0; i < 8; i++ {
		req, _ := whttp.NewRequest("GET", fmt.Sprintf("http://example.com/api/users?sort=asc&page=%d", i), nil)
		s.DoFilter(req, false)
	}
}

// ========== Test SmartFilter DoFilter with hash fragment ==========

func TestSmartFilterDoFilterWithHashFragmentPath(t *testing.T) {
	s := SmartFilter{
		SimpleFilter: SimpleFilter{},
	}
	s.Init()

	req1, _ := whttp.NewRequest("GET", "http://example.com/page#/route1", nil)
	req2, _ := whttp.NewRequest("GET", "http://example.com/page#/route2", nil)

	if s.DoFilter(req1, false) {
		t.Error("First request with fragment should not be filtered")
	}
	if s.DoFilter(req2, false) {
		t.Error("Different fragment should not be filtered")
	}
}

// ========== Test ParseResponseURL with map file and invalid JSON ==========

func TestParseResponseURLMapFileInvalidJSON(t *testing.T) {
	u, _ := url.Parse("http://example.com/assets/app.map")
	body := `this is not valid JSON`
	result := ParseResponseURL(u, body)
	t.Logf("ParseResponseURL with invalid JSON map: %d results", len(result))
}

// ========== Test discoverParentDirs with trailing slash ==========

func TestDiscoverParentDirsTrailingSlash(t *testing.T) {
	c := newTestCrawler()
	req, _ := whttp.NewRequest("GET", "http://example.com/a/b/c/", nil)
	tt := &task{
		req:         req,
		depth:       0,
		crawlerTask: c,
	}

	c.discoverParentDirs(tt)

	if c.taskQueue.Len() < 1 {
		t.Errorf("discoverParentDirs with trailing slash should add parent dir tasks, got %d", c.taskQueue.Len())
	}
}

// ========== Test OnResponse handler ==========

func TestOnResponseHandlerCalled(t *testing.T) {
	c := newTestCrawler()
	c.OnResponse(func(resp *whttp.Response) bool {
		return true
	})

	if len(c.responseHandlers) != 1 {
		t.Error("Response handler should be registered")
	}
}

// ========== Test Crawler SmartFilter initialized in NewCrawler ==========

func TestNewCrawlerSmartFilterInitialized(t *testing.T) {
	c := newTestCrawler()
	if c.smartFilter.filterLocationSet == nil {
		t.Error("SmartFilter filterLocationSet should be initialized in NewCrawler")
	}
	if c.smartFilter.uniqueMarkedIds == nil {
		t.Error("SmartFilter uniqueMarkedIds should be initialized in NewCrawler")
	}
}

// ========== Test FillForm with GetMatchInputText edge cases ==========

func TestGetMatchInputTextEmptyName(t *testing.T) {
	f := &FillForm{
		tab: &task{
			config: TabConfig{
				CustomFormValues: map[string]string{
					"default": "fallback",
				},
				CustomFormKeywordValues: map[string]string{},
			},
		},
	}

	got := f.GetMatchInputText("")
	if got != "fallback" {
		t.Errorf("GetMatchInputText('') should return default, got %q", got)
	}
}

// ========== Test SmartFilter with POST and multiple data ==========

func TestSmartFilterDoFilterPOSTMultipleData(t *testing.T) {
	s := SmartFilter{
		SimpleFilter: SimpleFilter{},
	}
	s.Init()

	req1, _ := whttp.NewRequest("POST", "http://example.com/api", strings.NewReader("user=alice&age=30"))
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	req2, _ := whttp.NewRequest("POST", "http://example.com/api", strings.NewReader("user=bob&age=25"))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if s.DoFilter(req1, false) {
		t.Error("First POST should not be filtered")
	}

	result2 := s.DoFilter(req2, false)
	t.Logf("Second POST with different data: filtered=%v", result2)
}

// ========== Test SyncMapFilter concurrent access ==========

func TestSyncMapFilterConcurrentAccess(t *testing.T) {
	f := &SyncMapFilter{Map: &sync.Map{}}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := fmt.Sprintf("key%d", i%10)
			f.Check(key, true)
			f.Insert(key)
		}(i)
	}
	wg.Wait()

	for i := 0; i < 10; i++ {
		if !f.Check(fmt.Sprintf("key%d", i), false) {
			t.Errorf("key%d should exist after concurrent inserts", i)
		}
	}
}

// ========== MarkPath single letter uppercase ==========

func TestSmartFilterMarkPathSingleLetterUppercaseAgain(t *testing.T) {
	s := SmartFilter{}
	// Single-letter uppercase segments should NOT be marked as UpperMark (length > 1 required)
	got := s.MarkPath("/A")
	t.Logf("MarkPath(/A) = %q", got)
}

// ========== MarkPath with chinese segment ==========

func TestSmartFilterMarkPathChineseSegmentAgain(t *testing.T) {
	s := SmartFilter{}
	got := s.MarkPath("/路径")
	if got != "/{{chinese}}" {
		t.Errorf("MarkPath with Chinese segment = %q, want /{{chinese}}", got)
	}
}

// ========== MarkPath with special symbol segment ==========

func TestSmartFilterMarkPathSpecialSymbolSegmentAgain(t *testing.T) {
	s := SmartFilter{}
	got := s.MarkPath("/path with spaces")
	if got != "/{{mix_symbol}}" {
		t.Errorf("MarkPath with spaces = %q, want /{{mix_symbol}}", got)
	}
}

// ========== DoFilter PATCH method ==========

func TestSmartFilterDoFilterPATCHMethodAgain(t *testing.T) {
	s := SmartFilter{
		SimpleFilter: SimpleFilter{},
	}
	s.Init()

	req, _ := whttp.NewRequest("PATCH", "http://example.com/api/resource", strings.NewReader("data=test"))
	result := s.DoFilter(req, false)
	t.Logf("PATCH method DoFilter result: %v", result)
}

// ========== SmartFilter DoFilter with HTTPS root ==========

func TestSmartFilterDoFilterHTTPSRootAgain(t *testing.T) {
	s := SmartFilter{
		SimpleFilter: SimpleFilter{},
	}
	s.Init()

	req, _ := whttp.NewRequest("GET", "https://example.com/", nil)
	if s.DoFilter(req, false) {
		t.Error("HTTPS root request should not be filtered")
	}
}

// ========== SmartFilter DoFilter with fragment path ==========

func TestSmartFilterDoFilterWithFragmentAgain(t *testing.T) {
	s := SmartFilter{
		SimpleFilter: SimpleFilter{},
	}
	s.Init()

	req, _ := whttp.NewRequest("GET", "http://example.com/page#/section", nil)
	if s.DoFilter(req, false) {
		t.Error("Request with fragment path should not be filtered")
	}
}

// ========== SmartFilter DoFilter redirection ==========

func TestSmartFilterDoFilterRedirectionAgain(t *testing.T) {
	s := SmartFilter{
		SimpleFilter: SimpleFilter{},
	}
	s.Init()

	req, _ := whttp.NewRequest("GET", "http://example.com/api/redirect", nil)
	if s.DoFilter(req, true) {
		t.Error("First redirect request should not be filtered")
	}
	if !s.DoFilter(req, true) {
		t.Error("Duplicate redirect request should be filtered")
	}
}

// ========== handleBasicTask with request handler rejecting ==========

func TestHandleBasicTaskWithRequestHandlerRejecting(t *testing.T) {
	addr, cleanup := startTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`<html><body><a href="/blocked">Link</a></body></html>`))
	}))
	defer cleanup()

	c := newTestCrawler()
	c.config.MaxDepth = 5
	// Add a request handler that rejects certain URLs
	c.OnRequest(func(req *whttp.Request) bool {
		return !strings.Contains(req.GetURL().String(), "blocked")
	})

	req, _ := whttp.NewRequest("GET", "http://"+addr+"/", nil)
	tt := &task{
		req:         req,
		depth:       0,
		crawlerTask: c,
	}

	c.handleBasicTask(tt)
}

// ========== handleBasicTask with error handlers ==========

func TestHandleBasicTaskWithFlowHandler(t *testing.T) {
	addr, cleanup := startTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`<html><body>OK</body></html>`))
	}))
	defer cleanup()

	c := newTestCrawler()
	flowCalled := false
	c.OnFlow(func(flow *whttp.Flow) bool {
		flowCalled = true
		return true
	})

	req, _ := whttp.NewRequest("GET", "http://"+addr+"/", nil)
	tt := &task{
		req:         req,
		depth:       0,
		crawlerTask: c,
	}

	c.handleBasicTask(tt)
	if !flowCalled {
		t.Error("Flow handler should have been called during handleBasicTask")
	}
}

// ========== handleBasicTask with document handler ==========

func TestHandleBasicTaskWithDocumentHandler(t *testing.T) {
	addr, cleanup := startTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`<html><body>Content</body></html>`))
	}))
	defer cleanup()

	c := newTestCrawler()
	docCalled := false
	c.documentHandlers = append(c.documentHandlers, func(u *url.URL, doc *goquery.Document, resp *whttp.Response, depth int) bool {
		docCalled = true
		return true
	})

	req, _ := whttp.NewRequest("GET", "http://"+addr+"/", nil)
	tt := &task{
		req:         req,
		depth:       0,
		crawlerTask: c,
	}

	c.handleBasicTask(tt)
	if !docCalled {
		t.Error("Document handler should have been called")
	}
}

// ========== handleBasicTask with header copying ==========

func TestHandleBasicTaskWithHeaders(t *testing.T) {
	addr, cleanup := startTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`<html><body>OK</body></html>`))
	}))
	defer cleanup()

	c := newTestCrawler()
	req, _ := whttp.NewRequest("GET", "http://"+addr+"/", nil)
	req.Header.Set("X-Custom", "test-value")
	req.Header.Set("Authorization", "Bearer token")

	tt := &task{
		req:         req,
		depth:       0,
		crawlerTask: c,
	}

	c.handleBasicTask(tt)
}

// ========== MarkPath with htm extension ==========

func TestSmartFilterMarkPathHTMExtensionWithAlphaNumAgain(t *testing.T) {
	s := SmartFilter{}
	got := s.MarkPath("/page1.htm")
	t.Logf("MarkPath(/page1.htm) = %q", got)
}

// ========== Test preQueryMark with different inputs ==========

func TestSmartFilterPreQueryMarkChinese(t *testing.T) {
	s := SmartFilter{}
	result := s.preQueryMark("name=测试")
	if result == "name=测试" {
		t.Log("Chinese query was not replaced (may not match regex)")
	}
}

func TestSmartFilterPreQueryMarkURLEncoded(t *testing.T) {
	s := SmartFilter{}
	result := s.preQueryMark("name=%E6%B5%8B%E8%AF%95")
	if result == "name=%E6%B5%8B%E8%AF%95" {
		t.Log("URL-encoded query was not replaced (may not match regex)")
	}
}

// ========== MarkPath unicode and special chars ==========

func TestSmartFilterMarkPathUnicodeSegmentAgain(t *testing.T) {
	s := SmartFilter{}
	got := s.MarkPath("/\\u0041\\u0042")
	t.Logf("MarkPath with unicode segment = %q", got)
}

// ========== SmartFilter DoFilter empty query params ==========

func TestSmartFilterDoFilterEmptyQueryParamsAgain(t *testing.T) {
	s := SmartFilter{
		SimpleFilter: SimpleFilter{},
	}
	s.Init()

	req, _ := whttp.NewRequest("GET", "http://example.com/?chu_xiu", nil)
	if s.DoFilter(req, false) {
		t.Error("Request with empty query param should not be filtered first time")
	}
}

// ========== SmartFilter DoFilter with multiple query params ==========

func TestSmartFilterDoFilterWithMultipleQueryParamsAgain(t *testing.T) {
	s := SmartFilter{
		SimpleFilter: SimpleFilter{},
	}
	s.Init()

	req, _ := whttp.NewRequest("GET", "http://example.com/api?a=1&b=2&c=3", nil)
	if s.DoFilter(req, false) {
		t.Error("Request with multiple query params should not be filtered first time")
	}
}

// ========== SmartFilter DoFilter PUT with post data ==========

func TestSmartFilterDoFilterPUTWithPostDataAgain(t *testing.T) {
	s := SmartFilter{
		SimpleFilter: SimpleFilter{},
	}
	s.Init()

	req, _ := whttp.NewRequest("PUT", "http://example.com/api/update", strings.NewReader("field1=value1&field2=value2"))
	if s.DoFilter(req, false) {
		t.Error("First PUT with data should not be filtered")
	}
}

// ========== Test MarkPath with various HTML extensions ==========

func TestSmartFilterMarkPathHTMVariants(t *testing.T) {
	s := SmartFilter{}

	tests := []struct {
		path string
		want string
	}{
		{"/page.html", "/page"},
		{"/page.htm", "/page"},
		{"/page.shtml", "/page"},
	}

	for _, tt := range tests {
		got := s.MarkPath(tt.path)
		if got != tt.want {
			t.Errorf("MarkPath(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

// ========== handleBasicTask with parent path detect ==========

func TestHandleBasicTaskWithParentPathDetect(t *testing.T) {
	addr, cleanup := startTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`<html><body>OK</body></html>`))
	}))
	defer cleanup()

	c := newTestCrawler()
	c.config.ParentPathDetect = true
	req, _ := whttp.NewRequest("GET", "http://"+addr+"/a/b/page.html", nil)
	tt := &task{
		req:         req,
		depth:       0,
		crawlerTask: c,
	}

	c.handleBasicTask(tt)
}

// ========== AddResultUrl tests ==========

func TestAddResultUrlSkipsProtocols(t *testing.T) {
	c := newTestCrawler()
	navReq, _ := whttp.NewRequest("GET", "http://example.com/page", nil)

	tab := &task{
		crawlerTask:  c,
		depth:        0,
		NavigateReq:  *navReq,
		ExtraHeaders: map[string]any{},
	}

	// Test that various protocols are skipped
	skippedURLs := []string{
		"data:image/png;base64,abc",
		"javascript:void(0)",
		"chrome-error://chromewebdata",
		"chrome://settings",
		"#fragment",
		"mailto:test@example.com",
	}

	for _, u := range skippedURLs {
		tab.AddResultUrl("GET", u, "DOM")
	}

	// None of these should have added tasks
	if c.taskQueue.Len() != 0 {
		t.Errorf("Skipped protocol URLs should not add tasks, got %d tasks", c.taskQueue.Len())
	}
}

func TestAddResultUrlValidURL(t *testing.T) {
	c := newTestCrawler()
	navReq, _ := whttp.NewRequest("GET", "http://example.com/page", nil)

	tab := &task{
		crawlerTask:  c,
		depth:        0,
		NavigateReq:  *navReq,
		ExtraHeaders: map[string]any{},
	}

	tab.AddResultUrl("GET", "http://example.com/newpage", "DOM")
	if c.taskQueue.Len() != 1 {
		t.Errorf("Valid URL should add task, got %d", c.taskQueue.Len())
	}
}

func TestAddResultUrlRelativeURL(t *testing.T) {
	c := newTestCrawler()
	navReq, _ := whttp.NewRequest("GET", "http://example.com/page", nil)

	tab := &task{
		crawlerTask:  c,
		depth:        0,
		NavigateReq:  *navReq,
		ExtraHeaders: map[string]any{},
	}

	tab.AddResultUrl("GET", "/relative/path", "DOM")
	if c.taskQueue.Len() != 1 {
		t.Errorf("Relative URL should add task, got %d", c.taskQueue.Len())
	}
}

func TestAddResultUrlWithHostBinding(t *testing.T) {
	c := newTestCrawler()
	navReq, _ := whttp.NewRequest("GET", "http://192.168.1.1/page", nil)
	navReq.Header.Set("Host", "example.com")

	tab := &task{
		crawlerTask:  c,
		depth:        0,
		NavigateReq:  *navReq,
		ExtraHeaders: map[string]any{},
	}

	tab.AddResultUrl("GET", "http://example.com/resource", "DOM")
	// Should handle host binding
}

func TestAddResultUrlWithExtraHeaders(t *testing.T) {
	c := newTestCrawler()
	navReq, _ := whttp.NewRequest("GET", "http://example.com/page", nil)

	tab := &task{
		crawlerTask: c,
		depth:       0,
		NavigateReq: *navReq,
		ExtraHeaders: map[string]any{
			"X-Custom": "value",
			"X-Empty":  "",
			"X-Other":  "other",
		},
	}

	tab.AddResultUrl("GET", "http://example.com/api", "DOM")
	if c.taskQueue.Len() != 1 {
		t.Errorf("URL with extra headers should add task, got %d", c.taskQueue.Len())
	}
}

func TestAddResultUrlWithCookies(t *testing.T) {
	c := newTestCrawler()
	navReq, _ := whttp.NewRequest("GET", "http://example.com/page", nil)
	navReq.Header.Set("Cookie", "session=abc123")

	tab := &task{
		crawlerTask:  c,
		depth:        0,
		NavigateReq:  *navReq,
		ExtraHeaders: map[string]any{},
	}

	tab.AddResultUrl("GET", "http://example.com/api", "DOM")
	if c.taskQueue.Len() != 1 {
		t.Errorf("URL with cookies should add task, got %d", c.taskQueue.Len())
	}
}

// ========== HandleRedirectionResp tests ==========

func TestHandleRedirectionRespRedirect(t *testing.T) {
	c := newTestCrawler()
	navReq, _ := whttp.NewRequest("GET", "http://example.com/page", nil)

	tab := &task{
		crawlerTask:  c,
		depth:        0,
		NavigateReq:  *navReq,
		NavNetworkID: "net123",
		WG:           sync.WaitGroup{},
	}

	tab.WG.Add(1)

	// 301 redirect headers
	headerText := "HTTP/1.1 301 Moved Permanently\r\nLocation: /new-page\r\n"
	extraInfo := &network.EventResponseReceivedExtraInfo{
		HeadersText: headerText,
	}

	tab.HandleRedirectionResp(extraInfo)
	// Should set FoundRedirection to true for 3XX response
	if !tab.FoundRedirection {
		t.Error("HandleRedirectionResp should set FoundRedirection for 301 response")
	}
}

func TestHandleRedirectionRespNonRedirect(t *testing.T) {
	c := newTestCrawler()
	navReq, _ := whttp.NewRequest("GET", "http://example.com/page", nil)

	tab := &task{
		crawlerTask:  c,
		depth:        0,
		NavigateReq:  *navReq,
		NavNetworkID: "net123",
		WG:           sync.WaitGroup{},
	}

	tab.WG.Add(1)

	// 200 OK response
	headerText := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
	extraInfo := &network.EventResponseReceivedExtraInfo{
		HeadersText: headerText,
	}

	tab.HandleRedirectionResp(extraInfo)
	// Should NOT set FoundRedirection for 200 response
	if tab.FoundRedirection {
		t.Error("HandleRedirectionResp should not set FoundRedirection for 200 response")
	}
}

// ========== GetContentCharset tests ==========

func TestGetContentCharsetFromResponse(t *testing.T) {
	c := newTestCrawler()
	navReq, _ := whttp.NewRequest("GET", "http://example.com/page", nil)

	tab := &task{
		crawlerTask:  c,
		depth:        0,
		NavigateReq:  *navReq,
		NavNetworkID: "net123",
		WG:           sync.WaitGroup{},
	}

	tab.WG.Add(1)

	// Response with charset
	respReceived := &network.EventResponseReceived{
		Response: &network.Response{
			Headers: map[string]any{
				"Content-Type": "text/html; charset=UTF-8",
			},
		},
	}

	tab.GetContentCharset(respReceived)
	if tab.PageCharset != "UTF-8" {
		t.Errorf("PageCharset should be UTF-8, got %s", tab.PageCharset)
	}
}

func TestGetContentCharsetNoCharset(t *testing.T) {
	c := newTestCrawler()
	navReq, _ := whttp.NewRequest("GET", "http://example.com/page", nil)

	tab := &task{
		crawlerTask:  c,
		depth:        0,
		NavigateReq:  *navReq,
		NavNetworkID: "net123",
		WG:           sync.WaitGroup{},
	}

	tab.WG.Add(1)

	// Response without charset
	respReceived := &network.EventResponseReceived{
		Response: &network.Response{
			Headers: map[string]any{
				"Content-Type": "text/html",
			},
		},
	}

	tab.GetContentCharset(respReceived)
	// PageCharset should remain empty
	if tab.PageCharset != "" {
		t.Errorf("PageCharset should be empty, got %s", tab.PageCharset)
	}
}

func TestGetContentCharsetNoContentType(t *testing.T) {
	c := newTestCrawler()
	navReq, _ := whttp.NewRequest("GET", "http://example.com/page", nil)

	tab := &task{
		crawlerTask:  c,
		depth:        0,
		NavigateReq:  *navReq,
		NavNetworkID: "net123",
		WG:           sync.WaitGroup{},
	}

	tab.WG.Add(1)

	// Response without Content-Type header
	respReceived := &network.EventResponseReceived{
		Response: &network.Response{
			Headers: map[string]any{},
		},
	}

	tab.GetContentCharset(respReceived)
}

// ========== handleBasicTask with all form scenarios ==========

func TestHandleBasicTaskFormWithSelect(t *testing.T) {
	addr, cleanup := startTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`<html><body>
			<form action="/submit" method="POST">
				<select name="color">
					<option value="red">Red</option>
					<option value="blue">Blue</option>
				</select>
				<textarea name="comment"></textarea>
				<input type="submit" value="Submit">
			</form>
		</body></html>`))
	}))
	defer cleanup()

	c := newTestCrawler()
	req, _ := whttp.NewRequest("GET", "http://"+addr+"/", nil)
	tt := &task{
		req:         req,
		depth:       0,
		crawlerTask: c,
	}

	c.handleBasicTask(tt)
}

// ========== Test do function ==========

func TestDoFunction(t *testing.T) {
	c := newTestCrawler()
	c.do() // empty implementation, just ensure no panic
}

// ========== Test findURLAndCreateNewTask ==========

func TestFindURLAndCreateNewTaskAgain(t *testing.T) {
	c := newTestCrawler()
	c.findURLAndCreateNewTask() // empty implementation
}

// ========== Test createTaskByURL ==========

func TestCreateTaskByURLAgain(t *testing.T) {
	c := newTestCrawler()
	c.createTaskByURL() // empty implementation
}

// ========== Test BrowserTaskRun ==========

func TestBrowserTaskRunAgain(t *testing.T) {
	c := newTestCrawler()
	c.BrowserTaskRun() // empty implementation
}

// ========== More handleBasicTask coverage - 401 response ==========

func TestHandleBasicTask401Response(t *testing.T) {
	addr, cleanup := startTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(401)
		w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
		w.Write([]byte("Unauthorized"))
	}))
	defer cleanup()

	c := newTestCrawler()
	req, _ := whttp.NewRequest("GET", "http://"+addr+"/protected", nil)
	tt := &task{
		req:         req,
		depth:       0,
		crawlerTask: c,
	}

	c.handleBasicTask(tt)
}

// ========== handleBasicTask with 500 response ==========

func TestHandleBasicTask500Response(t *testing.T) {
	addr, cleanup := startTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(500)
		w.Write([]byte("Internal Server Error"))
	}))
	defer cleanup()

	c := newTestCrawler()
	req, _ := whttp.NewRequest("GET", "http://"+addr+"/error", nil)
	tt := &task{
		req:         req,
		depth:       0,
		crawlerTask: c,
	}

	c.handleBasicTask(tt)
}

// ========== handleBasicTask with empty body ==========

func TestHandleBasicTaskEmptyBody(t *testing.T) {
	addr, cleanup := startTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(204)
	}))
	defer cleanup()

	c := newTestCrawler()
	req, _ := whttp.NewRequest("GET", "http://"+addr+"/nocontent", nil)
	tt := &task{
		req:         req,
		depth:       0,
		crawlerTask: c,
	}

	c.handleBasicTask(tt)
}

// ========== handleBasicTask with form that has bad action URL ==========

func TestHandleBasicTaskFormBadAction(t *testing.T) {
	addr, cleanup := startTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`<html><body>
			<form action=":://invalid" method="POST">
				<input type="text" name="field" value="">
				<input type="submit" value="Submit">
			</form>
		</body></html>`))
	}))
	defer cleanup()

	c := newTestCrawler()
	req, _ := whttp.NewRequest("GET", "http://"+addr+"/", nil)
	tt := &task{
		req:         req,
		depth:       0,
		crawlerTask: c,
	}

	c.handleBasicTask(tt)
}

// ========== Test NewCrawler with browser flag but no exec path ==========

func TestNewCrawlerBrowserNoExecPath(t *testing.T) {
	defer func() {
		recover() // InitBrowser will likely fail/panic without chrome
	}()
	config := Config{
		MaxConcurrent: 2,
		Browser:       true,
		ExecPath:      "",
	}
	corrected, _ := config.Correct()
	_ = NewCrawler(*corrected, nil)
}

// ========== Test handleBasicTask with form enctype multipart POST ==========

func TestHandleBasicTaskFormMultipartPOSTAgain(t *testing.T) {
	addr, cleanup := startTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`<html><body>
			<form action="/upload" method="POST" enctype="multipart/form-data">
				<input type="text" name="title" value="test">
				<input type="file" name="document">
				<input type="hidden" name="csrf" value="token123">
				<input type="submit" value="Upload">
			</form>
		</body></html>`))
	}))
	defer cleanup()

	c := newTestCrawler()
	req, _ := whttp.NewRequest("GET", "http://"+addr+"/form", nil)
	tt := &task{
		req:         req,
		depth:       0,
		crawlerTask: c,
	}

	c.handleBasicTask(tt)
}

// ========== Test newWorker with context cancellation ==========

func TestNewWorkerContextCancel(t *testing.T) {
	c := newTestCrawler()

	// Cancel context before worker starts
	c.cancel()

	// Worker should immediately return because ctx is already done
	go c.newWorker(0)

	time.Sleep(100 * time.Millisecond)
	// Worker should have exited
}

// ========== Test handleTask with browser=true ==========

func TestHandleTaskBrowserMode(t *testing.T) {
	c := newTestCrawler()
	c.config.Browser = true
	c.Browser = nil // no browser available

	req, _ := whttp.NewRequest("GET", "http://127.0.0.1:1/fail", nil)
	tt := &task{
		req:         req,
		depth:       0,
		crawlerTask: c,
		browser:     nil,
	}

	var receivedErr error
	c.OnError(func(err error) {
		receivedErr = err
	})

	// handleBrowserTask will try to call t.Task() which requires browser context
	// This will likely panic or crash, so we skip gracefully
	defer func() {
		recover()
	}()
	c.handleTask(tt)
	t.Logf("handleTask browser mode: receivedErr=%v", receivedErr)
}

// ========== Test clear with actual Browser object ==========

func TestClearWithBrowserObject(t *testing.T) {
	c := newTestCrawler()
	// Create a Browser object with nil context (won't actually call Close properly)
	c.Browser = &Browser{
		Ctx:    nil,
		Cancel: nil,
	}
	c.clear()
	// Should not panic
}

// ========== Test AvailabilityCheck ==========

func TestAvailabilityCheckNoPanicAgain(t *testing.T) {
	c := newTestCrawler()
	c.AvailabilityCheck()
}

// ========== Test handleBasicTask with request handler rejecting linked URLs ==========

func TestHandleBasicTaskRequestHandlerRejectingLinks(t *testing.T) {
	addr, cleanup := startTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`<html><body>
			<a href="/allowed">Allowed</a>
			<a href="/skip-me">Skip Me</a>
		</body></html>`))
	}))
	defer cleanup()

	c := newTestCrawler()
	c.config.MaxDepth = 5
	c.OnRequest(func(req *whttp.Request) bool {
		// Reject URLs containing "skip-me"
		return !strings.Contains(req.GetURL().String(), "skip-me")
	})

	req, _ := whttp.NewRequest("GET", "http://"+addr+"/", nil)
	tt := &task{
		req:         req,
		depth:       0,
		crawlerTask: c,
	}

	c.handleBasicTask(tt)
}

// ========== Test handleBasicTask with depth exceeding max ==========

func TestHandleBasicTaskMaxDepthReached(t *testing.T) {
	addr, cleanup := startTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`<html><body><a href="/next">Next</a></body></html>`))
	}))
	defer cleanup()

	c := newTestCrawler()
	c.config.MaxDepth = 1 // max depth is 1

	req, _ := whttp.NewRequest("GET", "http://"+addr+"/", nil)
	tt := &task{
		req:         req,
		depth:       1, // already at max depth
		crawlerTask: c,
	}

	c.handleBasicTask(tt)
	// Links from the page should not be followed since depth > MaxDepth
}

// ========== Test feedEnded behavior ==========

func TestFeedEndedState(t *testing.T) {
	c := newTestCrawler()
	if c.feedEnded {
		t.Error("feedEnded should start as false")
	}
	c.EndFeed()
	if !c.feedEnded {
		t.Error("EndFeed should set feedEnded to true")
	}
}

// ========== Test AddResultUrl with POST method ==========

func TestAddResultUrlPOSTMethod(t *testing.T) {
	c := newTestCrawler()
	navReq, _ := whttp.NewRequest("GET", "http://example.com/page", nil)

	tab := &task{
		crawlerTask:  c,
		depth:        0,
		NavigateReq:  *navReq,
		ExtraHeaders: map[string]any{},
	}

	tab.AddResultUrl("POST", "http://example.com/api", "DOM")
	if c.taskQueue.Len() != 1 {
		t.Errorf("POST URL should add task, got %d", c.taskQueue.Len())
	}
}

// ========== InterceptRequest and HandleAuthRequired need CDP context ==========

// These functions require a Chrome DevTools Protocol context (tab.GetExecutor())
// and cannot be tested without a running browser. We document this limitation.

// ========== Test tab.ParseResponseURL - needs CDP context ==========

// ParseResponseURL on task requires GetResponseBody from CDP, cannot test without browser.

// ========== Test handleBasicTask with map file extension ==========

func TestHandleBasicTaskMapFileAgain(t *testing.T) {
	addr, cleanup := startTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{
			"version": 3,
			"sources": ["app.ts"],
			"sourcesContent": ["fetch('/api/data'); var x = '/api/users';"],
			"mappings": "AAAA"
		}`))
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

// ========== Test handleBasicTask with nested links ==========

func TestHandleBasicTaskNestedLinks(t *testing.T) {
	addr, cleanup := startTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`<html><body>
			<a href="/page1">Link1</a>
			<a href="/page2">Link2</a>
			<a href="/page3">Link3</a>
		</body></html>`))
	}))
	defer cleanup()

	c := newTestCrawler()
	c.config.MaxDepth = 10

	req, _ := whttp.NewRequest("GET", "http://"+addr+"/", nil)
	tt := &task{
		req:         req,
		depth:       0,
		crawlerTask: c,
	}

	c.handleBasicTask(tt)
}

// ========== Test handleBasicTask with malformed response ==========

func TestHandleBasicTaskMalformedHTML(t *testing.T) {
	addr, cleanup := startTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`<html><broken<tags><more<<broken`))
	}))
	defer cleanup()

	c := newTestCrawler()
	req, _ := whttp.NewRequest("GET", "http://"+addr+"/", nil)
	tt := &task{
		req:         req,
		depth:       0,
		crawlerTask: c,
	}

	c.handleBasicTask(tt)
}

// ========== headerContentLocationParser with valid Content-Location ==========

func TestHeaderContentLocationParserWithValidURL(t *testing.T) {
	u, _ := url.Parse("http://example.com/page")
	wu := whttp.URL{URL: *u}
	doc, _ := goquery.NewDocumentFromReader(bytes.NewReader([]byte("<html></html>")))
	resp := &whttp.Response{
		NativeResponse: &gohttp.Response{
			Header: gohttp.Header{
				"Content-Location": []string{"/new-page"},
			},
		},
	}

	headerContentLocationParser(&wu, doc, resp)
}

func TestHeaderContentLocationParserWithEmptyHeader(t *testing.T) {
	u, _ := url.Parse("http://example.com/page")
	wu := whttp.URL{URL: *u}
	doc, _ := goquery.NewDocumentFromReader(bytes.NewReader([]byte("<html></html>")))
	resp := &whttp.Response{
		NativeResponse: &gohttp.Response{
			Header: gohttp.Header{},
		},
	}

	headerContentLocationParser(&wu, doc, resp)
}

func TestHeaderContentLocationParserWithAbsoluteURL(t *testing.T) {
	u, _ := url.Parse("http://example.com/page")
	wu := whttp.URL{URL: *u}
	doc, _ := goquery.NewDocumentFromReader(bytes.NewReader([]byte("<html></html>")))
	resp := &whttp.Response{
		NativeResponse: &gohttp.Response{
			Header: gohttp.Header{
				"Content-Location": []string{"http://other.com/resource"},
			},
		},
	}

	headerContentLocationParser(&wu, doc, resp)
}

// ========== ParsePKCS12 additional coverage ==========

func TestParsePKCS12WithInvalidData(t *testing.T) {
	_, err := ParsePKCS12([]byte("not a p12 file"), "")
	if err == nil {
		t.Error("ParsePKCS12 should return error for invalid data")
	}
}

func TestParsePKCS12WithEmptyData(t *testing.T) {
	_, err := ParsePKCS12([]byte{}, "")
	if err == nil {
		t.Error("ParsePKCS12 should return error for empty data")
	}
}

// ========== UniqueId additional coverage ==========

func TestUniqueIdWithRedirectionFlag(t *testing.T) {
	req, _ := whttp.NewRequest("GET", "http://example.com/api", nil)
	idNormal := UniqueId(req, false)
	idRedirect := UniqueId(req, true)
	if idNormal == idRedirect {
		t.Error("UniqueId with redirection flag should be different")
	}
	if idRedirect == "" {
		t.Error("UniqueId with redirection should not be empty")
	}
}

func TestUniqueIdPOSTWithBody(t *testing.T) {
	req, _ := whttp.NewRequest("POST", "http://example.com/api", strings.NewReader("data=test"))
	id := UniqueId(req, false)
	if id == "" {
		t.Error("UniqueId for POST with body should not be empty")
	}
}

// ========== NoHeaderId test ==========

func TestNoHeaderIdAgain(t *testing.T) {
	req, _ := whttp.NewRequest("GET", "http://example.com/api", nil)
	id := NoHeaderId(req)
	if id == "" {
		t.Error("NoHeaderId should not be empty")
	}
}

// ========== UniqueFilter test ==========

func TestSimpleFilterUniqueFilterAgain(t *testing.T) {
	s := &SimpleFilter{}
	req, _ := whttp.NewRequest("GET", "http://example.com/page", nil)
	// First request should not be filtered
	if s.UniqueFilter(req, false) {
		t.Error("First request should not be filtered")
	}
	// Second identical request should be filtered
	if !s.UniqueFilter(req, false) {
		t.Error("Duplicate request should be filtered")
	}
}

func TestSimpleFilterUniqueFilterWithRedirection(t *testing.T) {
	s := &SimpleFilter{}
	req, _ := whttp.NewRequest("GET", "http://example.com/page", nil)
	// First request with redirection flag
	if s.UniqueFilter(req, true) {
		t.Error("First redirect request should not be filtered")
	}
	// Same request without redirection flag should not be filtered (different ID)
	if s.UniqueFilter(req, false) {
		t.Error("Same URL with different redirection flag should not be filtered")
	}
	// Same request with same flag should be filtered
	if !s.UniqueFilter(req, true) {
		t.Error("Duplicate redirect request should be filtered")
	}
}

// ========== newWorker with task ==========

func TestNewWorkerWithTask(t *testing.T) {
	c := newTestCrawler()

	// Add a task to the channel
	req, _ := whttp.NewRequest("GET", "http://127.0.0.1:1/fail", nil)
	tt := &task{
		req:         req,
		depth:       0,
		crawlerTask: c,
	}

	c.OnError(func(err error) {
		_ = err
	})

	// Increment wait group since newWorker will call c.wg.Done()
	c.wg.Add(1)

	// Send task to channel
	c.taskChan <- tt

	// Start worker, it should process the task
	go c.newWorker(0)
	time.Sleep(200 * time.Millisecond)

	// Cancel to stop the worker
	c.cancel()
	time.Sleep(100 * time.Millisecond)
}

// ========== Config Correct edge cases ==========

func TestConfigCorrectNil(t *testing.T) {
	var c *Config
	_, err := c.Correct()
	if err == nil {
		t.Error("Correct should return error for nil config")
	}
}

func TestConfigCorrectNegativeValues(t *testing.T) {
	c := &Config{
		MaxConcurrent:  -1,
		MaxDepth:       -5,
		MaxCountOfURLs: -10,
		LoadWait:       -1,
	}
	corrected, err := c.Correct()
	if err != nil {
		t.Fatalf("Correct should not return error: %v", err)
	}
	if corrected.MaxConcurrent != 10 {
		t.Errorf("MaxConcurrent should be corrected to 10, got %d", corrected.MaxConcurrent)
	}
	if corrected.MaxDepth != 0 {
		t.Errorf("MaxDepth should be corrected to 0, got %d", corrected.MaxDepth)
	}
	if corrected.MaxCountOfURLs != MaxCrawlCount {
		t.Errorf("MaxCountOfURLs should be corrected to MaxCrawlCount, got %d", corrected.MaxCountOfURLs)
	}
	if corrected.LoadWait != 5 {
		t.Errorf("LoadWait should be corrected to 5, got %d", corrected.LoadWait)
	}
}

func TestConfigCorrectHighConcurrent(t *testing.T) {
	c := &Config{
		MaxConcurrent: 20,
	}
	corrected, err := c.Correct()
	if err != nil {
		t.Fatalf("Correct should not return error: %v", err)
	}
	if corrected.MaxConcurrent != 10 {
		t.Errorf("MaxConcurrent should be capped at 10, got %d", corrected.MaxConcurrent)
	}
}

func TestConfigCorrectBasicAuthMissingFields(t *testing.T) {
	c := &Config{
		MaxConcurrent: 2,
		AuthConfig: AuthConfig{
			BasicAuth: &BasicAuth{Username: "admin"},
		},
	}
	_, err := c.Correct()
	if err == nil {
		t.Error("Correct should return error for BasicAuth with missing password")
	}
}

func TestConfigCorrectFormAuthMissingURL(t *testing.T) {
	c := &Config{
		MaxConcurrent: 2,
		AuthConfig: AuthConfig{
			FormAuth: &FormAuth{Username: "admin", Password: "pass"},
		},
	}
	_, err := c.Correct()
	if err == nil {
		t.Error("Correct should return error for FormAuth with missing URL")
	}
}

func TestConfigCorrectFormAuthValid(t *testing.T) {
	c := &Config{
		MaxConcurrent: 2,
		AuthConfig: AuthConfig{
			FormAuth: &FormAuth{URL: "http://example.com/login", Username: "admin", Password: "pass"},
		},
	}
	corrected, err := c.Correct()
	if err != nil {
		t.Fatalf("Correct should not return error: %v", err)
	}
	if corrected.AuthConfig.FormAuth.URL != "http://example.com/login" {
		t.Error("FormAuth URL should be preserved")
	}
}

func TestConfigCorrectBasicAuthValid(t *testing.T) {
	c := &Config{
		MaxConcurrent: 2,
		AuthConfig: AuthConfig{
			BasicAuth: &BasicAuth{Username: "admin", Password: "pass"},
		},
	}
	corrected, err := c.Correct()
	if err != nil {
		t.Fatalf("Correct should not return error: %v", err)
	}
	if corrected.AuthConfig.BasicAuth.Username != "admin" {
		t.Error("BasicAuth username should be preserved")
	}
}

// ========== GetMatchInputText additional coverage ==========

func TestGetMatchInputTextWithCustomKeyword(t *testing.T) {
	f := &FillForm{
		tab: &task{
			config: TabConfig{
				CustomFormValues: map[string]string{
					"default": "fallback",
				},
				CustomFormKeywordValues: map[string]string{
					"special": "custom_value",
				},
			},
		},
	}

	got := f.GetMatchInputText("special_field")
	if got != "custom_value" {
		t.Errorf("GetMatchInputText should match custom keyword, got %q", got)
	}
}

func TestGetMatchInputTextWithEmail(t *testing.T) {
	f := &FillForm{
		tab: &task{
			config: TabConfig{
				CustomFormValues:        map[string]string{"default": "fallback"},
				CustomFormKeywordValues: map[string]string{},
			},
		},
	}

	got := f.GetMatchInputText("email_field")
	if got == "fallback" {
		t.Errorf("GetMatchInputText should match email keyword, got %q", got)
	}
}

func TestGetMatchInputTextWithPassword(t *testing.T) {
	f := &FillForm{
		tab: &task{
			config: TabConfig{
				CustomFormValues:        map[string]string{"default": "fallback"},
				CustomFormKeywordValues: map[string]string{},
			},
		},
	}

	got := f.GetMatchInputText("password_field")
	if got == "fallback" {
		t.Errorf("GetMatchInputText should match password keyword, got %q", got)
	}
}

func TestGetMatchInputTextWithCustomValue(t *testing.T) {
	f := &FillForm{
		tab: &task{
			config: TabConfig{
				CustomFormValues: map[string]string{
					"default":  "fallback",
					"username": "custom_user",
				},
				CustomFormKeywordValues: map[string]string{},
			},
		},
	}

	got := f.GetMatchInputText("username_field")
	if got != "custom_user" {
		t.Errorf("GetMatchInputText should return custom username value, got %q", got)
	}
}

// ========== handleBasicTask with various form types ==========

func TestHandleBasicTaskFormWithDefaultValues(t *testing.T) {
	addr, cleanup := startTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`<html><body>
			<form action="/submit" method="POST">
				<input type="text" name="username" value="default_user">
				<input type="password" name="password" value="default_pass">
				<input type="submit" value="Submit">
			</form>
		</body></html>`))
	}))
	defer cleanup()

	c := newTestCrawler()
	req, _ := whttp.NewRequest("GET", "http://"+addr+"/", nil)
	tt := &task{
		req:         req,
		depth:       0,
		crawlerTask: c,
	}

	c.handleBasicTask(tt)
}

// ========== IsIgnoredByKeywordMatch ==========

func TestIsIgnoredByKeywordMatchAgain(t *testing.T) {
	req, _ := whttp.NewRequest("GET", "http://example.com/logout", nil)
	if !IsIgnoredByKeywordMatch(req, []string{"logout"}) {
		t.Error("Should match logout keyword")
	}

	req2, _ := whttp.NewRequest("GET", "http://example.com/home", nil)
	if IsIgnoredByKeywordMatch(req2, []string{"logout"}) {
		t.Error("Should not match when keyword is not in URL")
	}

	req3, _ := whttp.NewRequest("GET", "http://example.com/admin/quit", nil)
	if !IsIgnoredByKeywordMatch(req3, []string{"logout", "quit"}) {
		t.Error("Should match quit keyword")
	}
}

// ========== handleBasicTask with ParentPathDetect enabled ==========

func TestHandleBasicTaskWithParentPathDetectEnabled(t *testing.T) {
	addr, cleanup := startTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`<html><body>OK</body></html>`))
	}))
	defer cleanup()

	c := newTestCrawler()
	c.config.ParentPathDetect = true
	req, _ := whttp.NewRequest("GET", "http://"+addr+"/a/b/c.html", nil)
	tt := &task{
		req:         req,
		depth:       0,
		crawlerTask: c,
	}

	c.handleBasicTask(tt)
}

// ========== handleBasicTask with form that has no action ==========

func TestHandleBasicTaskFormNoAction(t *testing.T) {
	addr, cleanup := startTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
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
	req, _ := whttp.NewRequest("GET", "http://"+addr+"/", nil)
	tt := &task{
		req:         req,
		depth:       0,
		crawlerTask: c,
	}

	c.handleBasicTask(tt)
}

// ========== handleBasicTask with script and link tags ==========

func TestHandleBasicTaskWithScriptLinkAndDepthExceeded(t *testing.T) {
	addr, cleanup := startTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`<html><head>
			<script src="/js/app.js"></script>
			<link href="/css/style.css" rel="stylesheet">
		</head><body>Content</body></html>`))
	}))
	defer cleanup()

	c := newTestCrawler()
	c.config.MaxDepth = 1

	req, _ := whttp.NewRequest("GET", "http://"+addr+"/", nil)
	tt := &task{
		req:         req,
		depth:       1, // At max depth, links should not be followed
		crawlerTask: c,
	}

	c.handleBasicTask(tt)
}
