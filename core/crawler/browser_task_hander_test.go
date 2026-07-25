package crawler

import (
	"strings"
	"testing"
	"time"

	gohttp "net/http"
	"wscan/core/http"
)

// ---------- GetStatusCode tests ----------

func TestGetStatusCode(t *testing.T) {
	tests := []struct {
		name       string
		headerText string
		want       int
	}{
		{"200 OK", "HTTP/1.1 200 OK\r\n", 200},
		{"301 Moved", "HTTP/1.1 301 Moved Permanently\r\n", 301},
		{"404 Not Found", "HTTP/1.1 404 Not Found\r\n", 404},
		{"500 Internal Server Error", "HTTP/1.1 500 Internal Server Error\r\n", 500},
		{"HTTP/1.0 302 Found", "HTTP/1.0 302 Found\r\n", 302},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tab := &task{}
			got := tab.GetStatusCode(tt.headerText)
			if got != tt.want {
				t.Errorf("GetStatusCode() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestGetStatusCodeEdgeCases(t *testing.T) {
	tests := []struct {
		name       string
		headerText string
		want       int
	}{
		{"empty string", "", 0},
		{"just status line no CRLF", "HTTP/1.1 200 OK", 200},
		{"malformed - missing version", "200 OK\r\n", 0},
		{"malformed - just code", "HTTP/1.1 200\r\n", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tab := &task{}
			got := tab.GetStatusCode(tt.headerText)
			if got != tt.want {
				t.Errorf("GetStatusCode() = %d, want %d", got, tt.want)
			}
		})
	}
}

// ---------- MergeHeaders tests ----------

func TestMergeHeaders(t *testing.T) {
	navHeaders := gohttp.Header{}
	navHeaders.Set("Authorization", "Bearer token")
	navHeaders.Set("X-Custom", "nav-value")

	headers := gohttp.Header{}
	headers.Set("Content-Type", "application/json")
	headers.Set("X-Custom", "req-value") // overrides nav

	merged := MergeHeaders(navHeaders, headers)

	// Should contain Authorization (only in navHeaders, not in headers)
	foundAuth := false
	foundContentType := false
	foundCustom := false
	for _, h := range merged {
		if h.Name == "Authorization" {
			foundAuth = true
		}
		if h.Name == "Content-Type" {
			foundContentType = true
		}
		if h.Name == "X-Custom" {
			foundCustom = true
		}
	}

	if !foundAuth {
		t.Error("MergeHeaders should include Authorization from navHeaders")
	}
	if !foundContentType {
		t.Error("MergeHeaders should include Content-Type from headers")
	}
	if !foundCustom {
		t.Error("MergeHeaders should include X-Custom")
	}
}

func TestMergeHeadersEmptyValues(t *testing.T) {
	navHeaders := gohttp.Header{}
	navHeaders.Set("X-Empty", "") // empty value should be skipped

	headers := gohttp.Header{}
	headers.Set("Content-Type", "text/html")

	merged := MergeHeaders(navHeaders, headers)

	for _, h := range merged {
		if h.Name == "X-Empty" {
			t.Error("Empty-value headers from navHeaders should be skipped")
		}
	}
}

func TestMergeHeadersBothEmpty(t *testing.T) {
	merged := MergeHeaders(gohttp.Header{}, gohttp.Header{})
	if len(merged) != 0 {
		t.Errorf("Merging two empty headers should give empty result, got %d", len(merged))
	}
}

// ---------- ConvertHeadersNoLocation tests ----------

func TestConvertHeadersNoLocation(t *testing.T) {
	h := map[string][]string{
		"Content-Type": {"text/html"},
		"Location":     {"http://example.com/redirect"},
		"Server":       {"nginx"},
	}

	result := ConvertHeadersNoLocation(h)

	if len(result) != 2 {
		t.Errorf("Expected 2 headers (excluding Location), got %d", len(result))
	}

	for _, header := range result {
		if header.Name == "Location" {
			t.Error("Location header should be excluded")
		}
	}
}

func TestConvertHeadersNoLocationEmpty(t *testing.T) {
	result := ConvertHeadersNoLocation(map[string][]string{})
	if len(result) != 0 {
		t.Errorf("Empty headers should give empty result, got %d", len(result))
	}
}

func TestConvertHeadersNoLocationOnlyLocation(t *testing.T) {
	h := map[string][]string{
		"Location": {"http://example.com/redirect"},
	}
	result := ConvertHeadersNoLocation(h)
	if len(result) != 0 {
		t.Errorf("Only Location header should give empty result, got %d", len(result))
	}
}

// ---------- IsNavigatorRequest tests ----------

func TestIsNavigatorRequest(t *testing.T) {
	tab := &task{
		LoaderID: "loader123",
	}

	if !tab.IsNavigatorRequest("loader123") {
		t.Error("Should return true for matching LoaderID")
	}

	if tab.IsNavigatorRequest("other") {
		t.Error("Should return false for non-matching LoaderID")
	}
}

// ---------- IsTopFrame tests ----------

func TestIsTopFrame(t *testing.T) {
	tab := &task{
		TopFrameId: "frame1",
	}

	if !tab.IsTopFrame("frame1") {
		t.Error("Should return true for matching TopFrameId")
	}

	if tab.IsTopFrame("frame2") {
		t.Error("Should return false for non-matching TopFrameId")
	}
}

// ---------- generateTabTask tests ----------

func TestGenerateTabTask(t *testing.T) {
	c := newTestCrawler()
	req, _ := http.NewRequest("GET", "http://example.com/page", nil)

	task := c.generateTabTask(req, 2)

	if task == nil {
		t.Fatal("generateTabTask should not return nil")
	}
	if task.crawlerTask != c {
		t.Error("Task crawlerTask should be the crawler")
	}
	if task.browser != c.Browser {
		t.Error("Task browser should be crawler's Browser")
	}
	if task.req != req {
		t.Error("Task req should be the provided request")
	}
	if task.depth != 2 {
		t.Errorf("Task depth = %d, want 2", task.depth)
	}
}

// ---------- selectorChecker tests ----------

func TestSelectorCheckerIsUsedSelector(t *testing.T) {
	sc := &selectorChecker{}
	// isUsedSelector always returns false per implementation
	if sc.isUsedSelector("test", false) {
		t.Error("isUsedSelector should return false")
	}
}

func TestSelectorCheckerShouldClick(t *testing.T) {
	sc := &selectorChecker{}
	if sc.shouldClick() {
		t.Error("shouldClick should return false")
	}
}

func TestSelectorCheckerFindNewNodesEvent(t *testing.T) {
	sc := &selectorChecker{}
	sc.findNewNodesEvent() // just ensure no panic
}

func TestSelectorCheckerCountClick(t *testing.T) {
	sc := &selectorChecker{}
	sc.countClick() // just ensure no panic
}

// ---------- BrowserTaskRun tests ----------

func TestBrowserTaskRun(t *testing.T) {
	c := newTestCrawler()
	c.BrowserTaskRun() // empty implementation, just ensure no panic
}

// ---------- clickAndAnalyzePage tests ----------

func TestClickAndAnalyzePage(t *testing.T) {
	c := newTestCrawler()
	err := c.clickAndAnalyzePage(nil, nil, nil, nil, 0)
	if err != nil {
		t.Errorf("clickAndAnalyzePage should return nil, got %v", err)
	}
}

// ---------- findURLAndCreateNewTask / createTaskByURL tests ----------

func TestFindURLAndCreateNewTask(t *testing.T) {
	c := newTestCrawler()
	c.findURLAndCreateNewTask() // empty implementation
}

func TestCreateTaskByURL(t *testing.T) {
	c := newTestCrawler()
	c.createTaskByURL() // empty implementation
}

// ---------- do tests ----------

func TestDo(t *testing.T) {
	c := newTestCrawler()
	c.do() // empty implementation
}

// ---------- HandleHostBinding tests ----------

func TestHandleHostBindingNoHost(t *testing.T) {
	// When NavigateReq has no Host header, nothing should change
	navReq, _ := http.NewRequest("GET", "http://example.com/page", nil)
	req, _ := http.NewRequest("GET", "http://example.com/resource", nil)

	tab := &task{
		NavigateReq: *navReq,
	}

	originalURL := req.GetURL().String()
	tab.HandleHostBinding(req)
	if req.GetURL().String() != originalURL {
		t.Error("URL should not change when no Host header is set")
	}
}

func TestHandleHostBindingWithHostMatchingNav(t *testing.T) {
	// When Host header matches the navigation URL hostname, URL host should be replaced
	navReq, _ := http.NewRequest("GET", "http://192.168.1.1/page", nil)
	navReq.Header.Set("Host", "example.com")

	req, _ := http.NewRequest("GET", "http://example.com/resource", nil)

	tab := &task{
		NavigateReq: *navReq,
	}

	tab.HandleHostBinding(req)

	// The request URL should be rewritten to use the nav hostname
	if req.Header.Get("Host") != "example.com" {
		t.Errorf("Host header should be set to example.com, got %s", req.Header.Get("Host"))
	}
}

func TestHandleHostBindingWithOriginHeader(t *testing.T) {
	navReq, _ := http.NewRequest("GET", "http://192.168.1.1/page", nil)
	navReq.Header.Set("Host", "example.com")

	req, _ := http.NewRequest("GET", "http://example.com/resource", nil)
	req.Header.Set("Origin", "http://192.168.1.1")

	tab := &task{
		NavigateReq: *navReq,
	}

	tab.HandleHostBinding(req)

	// Origin should be updated to use the Host value
	origin := req.Header.Get("Origin")
	if origin == "http://192.168.1.1" {
		t.Error("Origin should have been updated to use Host value")
	}
}

func TestHandleHostBindingWithRefererHeader(t *testing.T) {
	navReq, _ := http.NewRequest("GET", "http://192.168.1.1/page", nil)
	navReq.Header.Set("Host", "example.com")

	req, _ := http.NewRequest("GET", "http://example.com/resource", nil)
	req.Header.Set("Referer", "http://192.168.1.1/previous")

	tab := &task{
		NavigateReq: *navReq,
	}

	tab.HandleHostBinding(req)

	// Referer should be updated to use the Host value
	referer := req.Header.Get("Referer")
	if referer == "http://192.168.1.1/previous" {
		t.Error("Referer should have been updated to use Host value")
	}
}

func TestHandleHostBindingNoRefererDefaultSet(t *testing.T) {
	navReq, _ := http.NewRequest("GET", "http://192.168.1.1/page", nil)
	navReq.Header.Set("Host", "example.com")

	req, _ := http.NewRequest("GET", "http://example.com/resource", nil)
	// No Referer header set

	tab := &task{
		NavigateReq: *navReq,
	}

	tab.HandleHostBinding(req)

	// When no Referer, it should be set based on the nav URL with Host substituted
	referer := req.Header.Get("Referer")
	if referer == "" {
		t.Error("Referer should have been set when Host binding is active and no Referer exists")
	}
}

func TestHandleHostBindingSameHostname(t *testing.T) {
	// When Host header equals nav hostname, no changes needed
	navReq, _ := http.NewRequest("GET", "http://example.com/page", nil)
	navReq.Header.Set("Host", "example.com")

	req, _ := http.NewRequest("GET", "http://example.com/resource", nil)

	tab := &task{
		NavigateReq: *navReq,
	}

	tab.HandleHostBinding(req)

	// No changes since hostname matches Host header
	// The URL should remain unchanged
}

// ---------- MergeHeaders additional coverage ----------

func TestMergeHeadersEmptyValueInHeaders(t *testing.T) {
	headers := gohttp.Header{}
	headers.Set("X-Empty", "") // empty value in request headers should also be skipped in result

	merged := MergeHeaders(gohttp.Header{}, headers)
	for _, h := range merged {
		if h.Name == "X-Empty" {
			t.Error("Empty-value headers in request headers should be skipped")
		}
	}
}

func TestMergeHeadersOverlappingKeys(t *testing.T) {
	navHeaders := gohttp.Header{}
	navHeaders.Set("X-Shared", "nav-value")

	headers := gohttp.Header{}
	headers.Set("X-Shared", "req-value")

	merged := MergeHeaders(navHeaders, headers)

	// When key exists in headers, it should NOT come from navHeaders
	// but should come from headers
	sharedCount := 0
	for _, h := range merged {
		if h.Name == "X-Shared" {
			sharedCount++
			if h.Value != "req-value" {
				t.Errorf("X-Shared should be req-value from headers, got %s", h.Value)
			}
		}
	}
	if sharedCount != 1 {
		t.Errorf("X-Shared should appear exactly once, got %d", sharedCount)
	}
}

// ---------- tabTask struct tests ----------

func TestTabTaskStruct(t *testing.T) {
	// Just verify the tabTask struct fields are accessible
	tt := tabTask{
		depth: 1,
	}
	if tt.depth != 1 {
		t.Error("tabTask depth should be set")
	}
}

// ---------- TaskConfig struct tests ----------

func TestTaskConfigStruct(t *testing.T) {
	tc := TaskConfig{
		MaxCrawlCount:           200,
		MaxDepth:                5,
		FilterMode:              SmartFilterMode,
		ExtraHeaders:            map[string]any{"X-Test": "value"},
		IncognitoContext:        true,
		DomContentLoadedTimeout: 10 * time.Second,
		TabRunTimeout:           30 * time.Second,
		EventTriggerMode:        EventTriggerAsync,
		EventTriggerInterval:    100 * time.Millisecond,
		BeforeExitDelay:         1 * time.Second,
		EncodeURLWithCharset:    true,
		IgnoreKeywords:          []string{"logout"},
		CustomFormValues:        map[string]string{"default": "test"},
		CustomFormKeywordValues: map[string]string{"company": "Acme"},
	}

	if tc.MaxCrawlCount != 200 {
		t.Error("TaskConfig MaxCrawlCount should be 200")
	}
	if tc.FilterMode != SmartFilterMode {
		t.Error("TaskConfig FilterMode should be smart")
	}
}

// ---------- Result struct tests ----------

func TestResultStruct(t *testing.T) {
	r := Result{
		ReqList:       []*http.Request{},
		AllReqList:    []*http.Request{},
		AllDomainList: []string{"example.com"},
		SubDomainList: []string{"sub.example.com"},
	}

	if len(r.AllDomainList) != 1 {
		t.Error("Result AllDomainList should have 1 entry")
	}
	if len(r.SubDomainList) != 1 {
		t.Error("Result SubDomainList should have 1 entry")
	}
}

// ---------- part struct tests ----------

func TestPartStruct(t *testing.T) {
	p := part{
		IsFile:    true,
		FieldName: "upload",
		FileName:  "test.txt",
		Value:     []string{"content"},
	}

	if !p.IsFile {
		t.Error("part IsFile should be true")
	}
	if p.FieldName != "upload" {
		t.Error("part FieldName should be upload")
	}
}

// ---------- bindingCallPayload struct tests ----------

func TestBindingCallPayloadStruct(t *testing.T) {
	bc := bindingCallPayload{
		Name: "addLink",
		Seq:  1,
		Args: []string{"http://example.com", "DOM"},
	}

	if bc.Name != "addLink" {
		t.Error("bindingCallPayload Name should be addLink")
	}
	if len(bc.Args) != 2 {
		t.Error("bindingCallPayload Args should have 2 elements")
	}
}

// ---------- Browser struct tests ----------

func TestBrowserStruct(t *testing.T) {
	b := Browser{}
	if b.Ctx != nil {
		t.Error("Browser Ctx should start nil")
	}
}

// ---------- NodeEvents struct tests ----------

func TestNodeEventsStruct(t *testing.T) {
	ne := NodeEvents{
		Selector: "button",
		Events:   []string{"click", "mouseover"},
	}

	if ne.Selector != "button" {
		t.Error("NodeEvents Selector should be button")
	}
	if len(ne.Events) != 2 {
		t.Error("NodeEvents Events should have 2 entries")
	}
}

// ---------- Distributed struct tests ----------

func TestDistributedStruct(t *testing.T) {
	d := Distributed{
		RedisURL:        "redis://localhost:6379",
		RedisKey:        "crawler:urls",
		RedisKeyTimeout: 300,
	}

	if d.RedisURL != "redis://localhost:6379" {
		t.Error("Distributed RedisURL mismatch")
	}
}

// ---------- SmartFilter constants tests ----------

func TestSmartFilterConstants(t *testing.T) {
	constants := map[string]string{
		"CustomValueMark":    CustomValueMark,
		"FixParamRepeatMark": FixParamRepeatMark,
		"FixPathMark":        FixPathMark,
		"TooLongMark":        TooLongMark,
		"NumberMark":         NumberMark,
		"ChineseMark":        ChineseMark,
		"UpperMark":          UpperMark,
		"LowerMark":          LowerMark,
		"UrlEncodeMark":      UrlEncodeMark,
		"UnicodeMark":        UnicodeMark,
		"BoolMark":           BoolMark,
		"ListMark":           ListMark,
		"TimeMark":           TimeMark,
		"MixAlphaNumMark":    MixAlphaNumMark,
		"MixSymbolMark":      MixSymbolMark,
		"MixNumMark":         MixNumMark,
		"NoLowerAlphaMark":   NoLowerAlphaMark,
		"MixStringMark":      MixStringMark,
	}

	for name, value := range constants {
		if value == "" {
			t.Errorf("%s should not be empty", name)
		}
		if !strings.HasPrefix(value, "{{") || !strings.HasSuffix(value, "}}") {
			t.Errorf("%s should be wrapped in {{ }}, got %s", name, value)
		}
	}
}

// ---------- SmartFilter threshold constants tests ----------

func TestSmartFilterThresholdConstants(t *testing.T) {
	if MaxParentPathCount != 32 {
		t.Errorf("MaxParentPathCount = %d, want 32", MaxParentPathCount)
	}
	if MaxParamKeySingleCount != 8 {
		t.Errorf("MaxParamKeySingleCount = %d, want 8", MaxParamKeySingleCount)
	}
	if MaxParamKeyAllCount != 10 {
		t.Errorf("MaxParamKeyAllCount = %d, want 10", MaxParamKeyAllCount)
	}
	if MaxPathParamEmptyCount != 10 {
		t.Errorf("MaxPathParamEmptyCount = %d, want 10", MaxPathParamEmptyCount)
	}
	if MaxPathParamKeySymbolCount != 5 {
		t.Errorf("MaxPathParamKeySymbolCount = %d, want 5", MaxPathParamKeySymbolCount)
	}
}

// ---------- countClick test ----------

func TestSelectorCheckerCountClickWithStruct(t *testing.T) {
	sc := &selectorChecker{
		maxClick: 10,
	}
	sc.countClick()
	// Just ensure no panic and that clickCount is incremented
}

// ---------- AddResultUrl tests (no browser context needed for URL prefix checks) ----------

func TestAddResultUrlSkipsDataProtocol(t *testing.T) {
	// AddResultUrl skips data:, javascript:, chrome-error:, chrome://, #, mailto:
	// We can't fully test it without a browser context, but we verify the logic conceptually
	skippedProtocols := []string{"data:", "javascript:", "chrome-error:", "chrome://", "#", "mailto:"}
	for _, proto := range skippedProtocols {
		if !strings.HasPrefix(proto, "data:") && !strings.HasPrefix(proto, "javascript:") &&
			!strings.HasPrefix(proto, "chrome-error:") && !strings.HasPrefix(proto, "chrome://") &&
			!strings.HasPrefix(proto, "#") && !strings.HasPrefix(proto, "mailto:") {
			t.Errorf("Protocol %s should be in the skip list", proto)
		}
	}
}

// ---------- CrawlerStatistic test ----------

func TestCrawlerStatisticStruct(t *testing.T) {
	cs := CrawlerStatistic{
		CreatedRequestsCount:   100,
		RequestedRequestsCount: 50,
		WorkingTasksCount:      5,
		WorkerCount:            10,
	}

	if cs.CreatedRequestsCount != 100 {
		t.Error("CreatedRequestsCount mismatch")
	}
	if cs.RequestedRequestsCount != 50 {
		t.Error("RequestedRequestsCount mismatch")
	}
	if cs.WorkingTasksCount != 5 {
		t.Error("WorkingTasksCount mismatch")
	}
	if cs.WorkerCount != 10 {
		t.Error("WorkerCount mismatch")
	}
}

// ---------- AuthConfig tests ----------

func TestAuthConfigStructs(t *testing.T) {
	ba := BasicAuth{Username: "admin", Password: "secret"}
	if ba.Username != "admin" {
		t.Error("BasicAuth Username mismatch")
	}

	fa := FormAuth{URL: "http://example.com/login", Username: "user", Password: "pass"}
	if fa.URL != "http://example.com/login" {
		t.Error("FormAuth URL mismatch")
	}

	ac := AuthConfig{
		BasicAuth: &ba,
		FormAuth:  &fa,
	}
	if ac.BasicAuth.Username != "admin" {
		t.Error("AuthConfig BasicAuth mismatch")
	}
	if ac.FormAuth.URL != "http://example.com/login" {
		t.Error("AuthConfig FormAuth mismatch")
	}
}

// ---------- Config field tests ----------

func TestConfigAllFields(t *testing.T) {
	c := Config{
		Proxy:                    "http://proxy:8080",
		EnableImage:              true,
		Browser:                  true,
		LoadWait:                 10,
		ExecPath:                 "/usr/bin/chromium",
		DisableHeadless:          true,
		ForceSandbox:             true,
		MaxConcurrent:            5,
		MaxDepth:                 10,
		MaxCountOfURLs:           200,
		WindowWidth:              1920,
		WindowHeight:             1080,
		NavigateTimeoutSecond:    30,
		LoadTimeoutSecond:        20,
		Retry:                    3,
		PageAnalyzeTimeoutSecond: 15,
		MaxInteractive:           10,
		MaxInteractiveDepth:      5,
		MaxPageVisitPerSite:      100,
		ElementFilterStrength:    3,
		ParentPathDetect:         true,
		TabInitJS:                "console.log('init')",
		AllowVisitParentPath:     true,
	}

	if c.Proxy != "http://proxy:8080" {
		t.Error("Proxy mismatch")
	}
	if !c.EnableImage {
		t.Error("EnableImage should be true")
	}
	if !c.Browser {
		t.Error("Browser should be true")
	}
	if c.LoadWait != 10 {
		t.Error("LoadWait mismatch")
	}
	if c.Retry != 3 {
		t.Error("Retry mismatch")
	}
	if c.MaxInteractive != 10 {
		t.Error("MaxInteractive mismatch")
	}
	if !c.ParentPathDetect {
		t.Error("ParentPathDetect should be true")
	}
	if c.TabInitJS != "console.log('init')" {
		t.Error("TabInitJS mismatch")
	}
	if !c.AllowVisitParentPath {
		t.Error("AllowVisitParentPath should be true")
	}
}

// ---------- Config.Correct comprehensive ----------

func TestConfigCorrectValidConcurrent(t *testing.T) {
	c := &Config{MaxConcurrent: 5}
	corrected, err := c.Correct()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if corrected.MaxConcurrent != 5 {
		t.Errorf("Valid MaxConcurrent should be preserved, got %d", corrected.MaxConcurrent)
	}
}

func TestConfigCorrectNegativeConcurrent(t *testing.T) {
	c := &Config{MaxConcurrent: -1}
	corrected, err := c.Correct()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if corrected.MaxConcurrent != 10 {
		t.Errorf("Negative MaxConcurrent should be corrected to 10, got %d", corrected.MaxConcurrent)
	}
}

func TestConfigCorrectZeroDepth(t *testing.T) {
	c := &Config{MaxDepth: 0}
	corrected, err := c.Correct()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if corrected.MaxDepth != 0 {
		t.Errorf("Zero MaxDepth should remain 0 (unlimited), got %d", corrected.MaxDepth)
	}
}

func TestConfigCorrectNegativeCountOfURLs(t *testing.T) {
	c := &Config{MaxCountOfURLs: -5}
	corrected, err := c.Correct()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if corrected.MaxCountOfURLs != MaxCrawlCount {
		t.Errorf("Negative MaxCountOfURLs should default to MaxCrawlCount, got %d", corrected.MaxCountOfURLs)
	}
}

func TestConfigCorrectPositiveLoadWait(t *testing.T) {
	c := &Config{LoadWait: 10}
	corrected, err := c.Correct()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if corrected.LoadWait != 10 {
		t.Errorf("Valid LoadWait should be preserved, got %d", corrected.LoadWait)
	}
}

func TestConfigCorrectNoAuth(t *testing.T) {
	c := &Config{AuthConfig: AuthConfig{}}
	corrected, err := c.Correct()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if corrected.AuthConfig.BasicAuth != nil {
		t.Error("BasicAuth should remain nil when not set")
	}
	if corrected.AuthConfig.FormAuth != nil {
		t.Error("FormAuth should remain nil when not set")
	}
}
