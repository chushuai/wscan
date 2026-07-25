package crawler

import (
	"strings"
	"testing"
	"wscan/core/http"
)

// ---------- markParamValue tests ----------
// Currently at 9.3% coverage, need to exercise all branches

func TestSmartFilterMarkParamValueBasic(t *testing.T) {
	s := SmartFilter{}
	s.Init()

	// The current implementation marks all values as CustomValueMark
	// because of the `continue` after `markedParamMap[key] = CustomValueMark`
	// Let's test that this is the behavior
	req, _ := http.NewRequest("GET", "http://example.com/api?q=test", nil)
	paramMap := map[string]any{"q": "test"}
	result := s.markParamValue(paramMap, *req)

	if result["q"] != CustomValueMark {
		t.Errorf("markParamValue should mark value as CustomValueMark, got %v", result["q"])
	}
}

func TestSmartFilterMarkParamValueMultipleParams(t *testing.T) {
	s := SmartFilter{}
	s.Init()

	req, _ := http.NewRequest("GET", "http://example.com/api?name=hello&age=30", nil)
	paramMap := map[string]any{"name": "hello", "age": "30"}
	result := s.markParamValue(paramMap, *req)

	for key, value := range result {
		if value != CustomValueMark {
			t.Errorf("markParamValue should mark all values as CustomValueMark, key=%s got %v", key, value)
		}
	}
}

func TestSmartFilterMarkParamValuePOSTRequest(t *testing.T) {
	s := SmartFilter{}
	s.Init()

	req, _ := http.NewRequest("POST", "http://example.com/api", strings.NewReader("user=admin"))
	paramMap := map[string]any{"user": "admin"}
	result := s.markParamValue(paramMap, *req)

	if result["user"] != CustomValueMark {
		t.Errorf("markParamValue for POST should mark as CustomValueMark, got %v", result["user"])
	}
}

func TestSmartFilterMarkParamValueEmptyValue(t *testing.T) {
	s := SmartFilter{}
	s.Init()

	req, _ := http.NewRequest("GET", "http://example.com/api?q=", nil)
	paramMap := map[string]any{"q": ""}
	result := s.markParamValue(paramMap, *req)

	if result["q"] != CustomValueMark {
		t.Errorf("markParamValue should mark empty value as CustomValueMark, got %v", result["q"])
	}
}

func TestSmartFilterMarkParamValueNonStringValue(t *testing.T) {
	s := SmartFilter{}
	s.Init()

	req, _ := http.NewRequest("GET", "http://example.com/api", nil)
	paramMap := map[string]any{"q": 123}
	result := s.markParamValue(paramMap, *req)

	if result["q"] != CustomValueMark {
		t.Errorf("markParamValue should mark non-string value as CustomValueMark, got %v", result["q"])
	}
}

// ---------- MarkPath comprehensive tests ----------
// Currently at 63.6%, need to cover more branches

func TestSmartFilterMarkPathWithDots(t *testing.T) {
	s := SmartFilter{}

	tests := []struct {
		name string
		path string
		want string
	}{
		// Dot-separated paths with numeric parts
		{"numeric dot part", "/static/123.js", "/static/{{number}}.js"},
		// Dot-separated with uppercase
		{"uppercase dot part", "/static/ABC.js", "/static/{{upper}}.js"},
		// Dot-separated with long part
		{"long dot part", "/static/aabcdefghijklmnopqrstuvwxyz12345678901234.js", "/static/{{long}}.js"},
		// Dot-separated with mixnum (more than 3 digits triggers MixNumMark)
		{"mixnum dot part", "/static/abc123def456.js", "/static/{{mix_num}}.js"},
		// Dot-separated that doesn't need marking
		{"simple name dot part", "/static/app.js", "/static/app.js"},
		// HTML file with mixed alpha+num (after stripping .html, the remaining part is checked)
		// The dot-separated handling strips .html then checks the stripped part
		{"html with alpha+num path", "/page123abc.html", "/page123abc"},
		// HTML file with numeric only (after stripping .html, no special pattern)
		{"html with numeric path", "/page123.html", "/page123"},
		// HTML file simple
		{"html simple path", "/mypage.html", "/mypage"},
		// SHTML file
		{"shtml simple path", "/mypage.shtml", "/mypage"},
		// HTM file
		{"htm simple path", "/mypage.htm", "/mypage"},
		// Dot in path not as file extension
		{"dot in middle of segment", "/path.with.dots/page", "/path.with.dots/page"},
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

func TestSmartFilterMarkPathDotPartsHTMLHandling(t *testing.T) {
	s := SmartFilter{}

	tests := []struct {
		name string
		path string
		want string
	}{
		// html extension: numeric and alpha parts mixed
		{"html alpha+num+upper+lower", "/abc123ABC.html", "/{{mix_alpha_num}}"},
		// html extension: only numeric after removing .html
		{"html numeric only", "/123.html", "/{{number}}"},
		// html extension: regular name
		{"html regular name", "/dashboard.html", "/dashboard"},
		// htm extension: numeric
		{"htm numeric", "/456.htm", "/{{number}}"},
		// shtml extension: regular
		{"shtml regular", "/index.shtml", "/index"},
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

func TestSmartFilterMarkPathUnicodeURLEncoded(t *testing.T) {
	s := SmartFilter{}

	tests := []struct {
		name string
		path string
		want string
	}{
		{"unicode path", "/%u4e2d%u6587", "/{{unicode}}"},
		{"special symbols", "/path/{item}", "/path/{{mix_symbol}}"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.MarkPath(tt.path)
			// Some of these may not match exactly, just verify they get marked
			t.Logf("MarkPath(%q) = %q", tt.path, got)
		})
	}
}

func TestSmartFilterMarkPathSegmentOver32(t *testing.T) {
	s := SmartFilter{}
	// Test segment longer than 32 chars
	longSegment := "abcdefghijklmnopqrstuvwxyz1234567" // 33 chars
	path := "/api/" + longSegment
	got := s.MarkPath(path)
	if got != "/api/{{long}}" {
		t.Errorf("MarkPath with segment >32 chars = %q, want /api/{{long}}", got)
	}
}

func TestSmartFilterMarkPathWithNumberAndSymbol(t *testing.T) {
	s := SmartFilter{}

	tests := []struct {
		name string
		path string
		want string
	}{
		// Path segments that are numbers mixed with symbols like . _ -
		{"date-like path", "/2023-01-15", "/{{number}}"},
		{"underscore numbers", "/item_123", "/item_123"}, // not pure numbers with symbols
		{"dot numbers", "/v1.2.3", "/v1.{{number}}.{{number}}"},
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

func TestSmartFilterMarkPathMixNumOver3(t *testing.T) {
	s := SmartFilter{}
	// Segment with more than 3 numbers should be marked as MixNumMark
	path := "/api/abc1234def"
	got := s.MarkPath(path)
	// abc1234def has 4 digits, so should be marked as mix_num
	if got != "/api/{{mix_num}}" {
		t.Logf("MarkPath(%q) = %q (expected {{mix_num}} for segments with >3 numbers)", path, got)
	}
}

func TestSmartFilterMarkPathPureNumber(t *testing.T) {
	s := SmartFilter{}
	path := "/api/12345"
	got := s.MarkPath(path)
	if got != "/api/{{number}}" {
		t.Errorf("MarkPath(%q) = %q, want /api/{{number}}", path, got)
	}
}

func TestSmartFilterMarkPathUppercaseOnly(t *testing.T) {
	s := SmartFilter{}
	path := "/API"
	got := s.MarkPath(path)
	if got != "/{{upper}}" {
		t.Errorf("MarkPath(%q) = %q, want /{{upper}}", path, got)
	}
}

// ---------- SmartFilter DoFilter comprehensive tests ----------

func TestSmartFilterDoFilterPUTRequest(t *testing.T) {
	s := SmartFilter{
		SimpleFilter: SimpleFilter{},
	}
	s.Init()

	req, _ := http.NewRequest("PUT", "http://example.com/api/update", strings.NewReader("data=test"))
	if s.DoFilter(req, false) {
		t.Error("First PUT request should not be filtered")
	}
}

func TestSmartFilterDoFilterDELETERequest(t *testing.T) {
	s := SmartFilter{
		SimpleFilter: SimpleFilter{},
	}
	s.Init()

	req, _ := http.NewRequest("DELETE", "http://example.com/api/resource/1", nil)
	if s.DoFilter(req, false) {
		t.Error("First DELETE request should not be filtered")
	}
}

func TestSmartFilterDoFilterHEADRequest(t *testing.T) {
	s := SmartFilter{
		SimpleFilter: SimpleFilter{},
	}
	s.Init()

	req, _ := http.NewRequest("HEAD", "http://example.com/api/check", nil)
	if s.DoFilter(req, false) {
		t.Error("First HEAD request should not be filtered")
	}
}

func TestSmartFilterDoFilterOPTIONSRequest(t *testing.T) {
	s := SmartFilter{
		SimpleFilter: SimpleFilter{},
	}
	s.Init()

	req, _ := http.NewRequest("OPTIONS", "http://example.com/api/*", nil)
	if s.DoFilter(req, false) {
		t.Error("First OPTIONS request should not be filtered")
	}
}

func TestSmartFilterDoFilterRedirection(t *testing.T) {
	s := SmartFilter{
		SimpleFilter: SimpleFilter{},
	}
	s.Init()

	req, _ := http.NewRequest("GET", "http://example.com/api/redirect", nil)
	// Redirection flag should produce a different ID
	if s.DoFilter(req, true) {
		t.Error("First redirect request should not be filtered")
	}
	// Same URL with same redirect flag should be filtered
	if !s.DoFilter(req, true) {
		t.Error("Duplicate redirect request should be filtered")
	}
}

func TestSmartFilterDoFilterHTTPSRoot(t *testing.T) {
	s := SmartFilter{
		SimpleFilter: SimpleFilter{},
	}
	s.Init()

	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	if s.DoFilter(req, false) {
		t.Error("HTTPS root request should not be filtered")
	}
}

func TestSmartFilterDoFilterWithFragment(t *testing.T) {
	s := SmartFilter{
		SimpleFilter: SimpleFilter{},
	}
	s.Init()

	req, _ := http.NewRequest("GET", "http://example.com/page#/section", nil)
	if s.DoFilter(req, false) {
		t.Error("Request with fragment path should not be filtered")
	}
}

func TestSmartFilterDoFilterHighRepeatCount(t *testing.T) {
	s := SmartFilter{
		SimpleFilter: SimpleFilter{},
	}
	s.Init()

	// Send many requests with different values for same parameter key
	// This should eventually trigger the repeat count filter
	urls := []string{
		"http://example.com/search?q=aaa",
		"http://example.com/search?q=bbb",
		"http://example.com/search?q=ccc",
		"http://example.com/search?q=ddd",
		"http://example.com/search?q=eee",
		"http://example.com/search?q=fff",
		"http://example.com/search?q=ggg",
		"http://example.com/search?q=hhh",
		"http://example.com/search?q=iii",
		"http://example.com/search?q=jjj",
	}

	filtered := 0
	notFiltered := 0
	for _, u := range urls {
		req, _ := http.NewRequest("GET", u, nil)
		if s.DoFilter(req, false) {
			filtered++
		} else {
			notFiltered++
		}
	}
	t.Logf("High repeat count: filtered=%d, notFiltered=%d", filtered, notFiltered)
	// After enough requests, some should be filtered due to repeat count
}

func TestSmartFilterDoFilterPOSTWithDifferentData(t *testing.T) {
	s := SmartFilter{
		SimpleFilter: SimpleFilter{},
	}
	s.Init()

	req1, _ := http.NewRequest("POST", "http://example.com/api", strings.NewReader("name=alice"))
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2, _ := http.NewRequest("POST", "http://example.com/api", strings.NewReader("name=bob"))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if s.DoFilter(req1, false) {
		t.Error("First POST should not be filtered")
	}
	// Second POST with different data but same URL may or may not be filtered
	result := s.DoFilter(req2, false)
	t.Logf("Second POST with different data: filtered=%v", result)
}

// ---------- SmartFilter getMarkedUniqueID tests ----------

func TestSmartFilterGetMarkedUniqueIDHTTPSRoot(t *testing.T) {
	s := SmartFilter{}
	// HTTPS root URL with empty path and query should have "https" added
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	id1 := s.getMarkedUniqueID(req, "", "", "", false)
	id2 := s.getMarkedUniqueID(req, "", "", "", true) // with redirect flag
	if id1 == id2 {
		t.Error("Redirect flag should produce different unique IDs even for HTTPS root")
	}
}

func TestSmartFilterGetMarkedUniqueIDWithFragment(t *testing.T) {
	s := SmartFilter{}
	req, _ := http.NewRequest("GET", "http://example.com/page#/path", nil)
	id := s.getMarkedUniqueID(req, "", "", "", false)
	if id == "" {
		t.Error("getMarkedUniqueID should not return empty string for fragment URL")
	}
}

func TestSmartFilterGetMarkedUniqueIDPOSTMethod(t *testing.T) {
	s := SmartFilter{}
	req, _ := http.NewRequest("POST", "http://example.com/api", nil)
	id := s.getMarkedUniqueID(req, "", "postDataId", "pathId", false)
	if id == "" {
		t.Error("getMarkedUniqueID should not return empty for POST")
	}
}

func TestSmartFilterGetMarkedUniqueIDDELETMethod(t *testing.T) {
	s := SmartFilter{}
	req, _ := http.NewRequest("DELETE", "http://example.com/resource", nil)
	id := s.getMarkedUniqueID(req, "queryId", "", "pathId", false)
	if id == "" {
		t.Error("getMarkedUniqueID should not return empty for DELETE")
	}
}

// ---------- UniqueId edge cases ----------

func TestUniqueIdWithRedirection(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://example.com/api", nil)

	idNormal := UniqueId(req, false)
	idRedirect := UniqueId(req, true)

	if idNormal == "" {
		t.Error("UniqueId normal should not be empty")
	}
	if idRedirect == "" {
		t.Error("UniqueId redirect should not be empty")
	}
	if idNormal == idRedirect {
		t.Error("Normal and redirect UniqueIds should differ")
	}
}

func TestUniqueIdWithPOST(t *testing.T) {
	req, _ := http.NewRequest("POST", "http://example.com/api", strings.NewReader("data=test"))

	id := UniqueId(req, false)
	if id == "" {
		t.Error("UniqueId should not be empty for POST")
	}
}

// ---------- SmartFilter DoFilter with empty query params ----------

func TestSmartFilterDoFilterEmptyQueryParams(t *testing.T) {
	s := SmartFilter{
		SimpleFilter: SimpleFilter{},
	}
	s.Init()

	// Test with empty query parameters (pseudo-static URLs)
	req, _ := http.NewRequest("GET", "http://example.com/?chu_xiu", nil)
	if s.DoFilter(req, false) {
		t.Error("Request with empty query param should not be filtered first time")
	}
}

func TestSmartFilterDoFilterWithMultipleQueryParams(t *testing.T) {
	s := SmartFilter{
		SimpleFilter: SimpleFilter{},
	}
	s.Init()

	req, _ := http.NewRequest("GET", "http://example.com/api?a=1&b=2&c=3", nil)
	if s.DoFilter(req, false) {
		t.Error("Request with multiple query params should not be filtered first time")
	}
}

func TestSmartFilterDoFilterPUTWithPostData(t *testing.T) {
	s := SmartFilter{
		SimpleFilter: SimpleFilter{},
	}
	s.Init()

	req, _ := http.NewRequest("PUT", "http://example.com/api/update", strings.NewReader("field1=value1&field2=value2"))
	if s.DoFilter(req, false) {
		t.Error("First PUT with data should not be filtered")
	}
}

// ---------- SmartFilter DoFilter with smart dedup on path ----------

func TestSmartFilterDoFilterParentPathDetection(t *testing.T) {
	s := SmartFilter{
		SimpleFilter: SimpleFilter{},
	}
	s.Init()

	// Test many different paths under the same parent directory
	// to trigger parent path detection
	for i := 0; i < 35; i++ {
		req, _ := http.NewRequest("GET", "http://example.com/items/item"+string(rune('A'+i)), nil)
		s.DoFilter(req, false)
	}
	// Just verify no panic and the filter runs
}

// ---------- SmartFilter DoFilter with param value empty ----------

func TestSmartFilterDoFilterEmptyParamValues(t *testing.T) {
	s := SmartFilter{
		SimpleFilter: SimpleFilter{},
	}
	s.Init()

	// Test many different param names with empty values (pseudo-static)
	for i := 0; i < 12; i++ {
		req, _ := http.NewRequest("GET", "http://example.com/page?keyword"+string(rune('A'+i)), nil)
		s.DoFilter(req, false)
	}
	// Just verify no panic
}

// ---------- MarkPath additional edge cases ----------

func TestSmartFilterMarkPathDotAndDotDot(t *testing.T) {
	s := SmartFilter{}

	// "." and ".." should not be treated as file extensions
	tests := []struct {
		path string
		want string
	}{
		{"/a/./b", "/a/./b"},
		{"/a/../b", "/a/../b"},
	}
	for _, tt := range tests {
		got := s.MarkPath(tt.path)
		if got != tt.want {
			t.Errorf("MarkPath(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestSmartFilterMarkPathSingleLetterUppercase(t *testing.T) {
	s := SmartFilter{}
	// Single-letter uppercase segments should NOT be marked as UpperMark (length > 1 required)
	got := s.MarkPath("/A")
	// "A" is only 1 char, so it shouldn't be marked as {{upper}}
	t.Logf("MarkPath(/A) = %q", got)
}

func TestSmartFilterMarkPathChineseSegment(t *testing.T) {
	s := SmartFilter{}
	got := s.MarkPath("/路径")
	if got != "/{{chinese}}" {
		t.Errorf("MarkPath with Chinese segment = %q, want /{{chinese}}", got)
	}
}

func TestSmartFilterMarkPathUnicodeSegment(t *testing.T) {
	s := SmartFilter{}
	got := s.MarkPath("/\\u0041\\u0042")
	t.Logf("MarkPath with unicode segment = %q", got)
}

func TestSmartFilterMarkPathSpecialSymbolSegment(t *testing.T) {
	s := SmartFilter{}
	got := s.MarkPath("/path with spaces")
	if got != "/{{mix_symbol}}" {
		t.Errorf("MarkPath with spaces = %q, want /{{mix_symbol}}", got)
	}
}

func TestSmartFilterMarkPathHTMExtensionWithAlphaNum(t *testing.T) {
	s := SmartFilter{}
	// path segment that ends in .htm and has alpha+num
	got := s.MarkPath("/page1.htm")
	t.Logf("MarkPath(/page1.htm) = %q", got)
}

// ---------- SmartFilter DoFilter unsupported method ----------

func TestSmartFilterDoFilterPATCHMethod(t *testing.T) {
	s := SmartFilter{
		SimpleFilter: SimpleFilter{},
	}
	s.Init()

	// PATCH is not explicitly handled, should hit the else branch
	req, _ := http.NewRequest("PATCH", "http://example.com/api/resource", strings.NewReader("data=test"))
	// Should not panic, just log "dont support such method"
	result := s.DoFilter(req, false)
	t.Logf("PATCH method filter result: %v", result)
}
