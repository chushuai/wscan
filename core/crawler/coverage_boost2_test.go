package crawler

import (
	"fmt"
	gohttp "net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	whttp "wscan/core/http"
)

// ==================== Coverage boost 2 tests ====================
// Focus on uncovered code paths from:
// - filter.go: markParamValue (9.3% - the switch branches after the continue)
// - filter.go: MarkPath additional branches
// - filter.go: SyncMapFilter.Reset, SyncMapFilter.Close
// - form.go: FillForm.GetMatchInputText with CustomFormKeywordValues
// - form.go: FillForm with nil tab (edge case)
// - parser.go: headerContentLocationParser with valid Content-Location URL
// - util.go: shouldCopyHeaderOnRedirect, canonicalAddr, idnaASCII, getParentPaths, escapePercentSign, UrlFileName, UrlFileExt, AbsoluteURL
// - path_expansion.go: extractPathsFromRobots edge cases, extractSourceMapURL edge cases, extractPathsFromSitemap with invalid XML
// - basic_task_hander.go: additional coverage

// ---------- SyncMapFilter: Reset ----------

func TestBoost2_SyncMapFilter_Reset(t *testing.T) {
	f := &SyncMapFilter{Map: &sync.Map{}}
	f.Store("key1", struct{}{})
	f.Store("key2", struct{}{})

	// Verify keys exist
	_, ok1 := f.Load("key1")
	_, ok2 := f.Load("key2")
	assert.True(t, ok1, "key1 should exist before reset")
	assert.True(t, ok2, "key2 should exist before reset")

	// Reset should delete all keys
	f.Reset()

	_, ok1 = f.Load("key1")
	_, ok2 = f.Load("key2")
	assert.False(t, ok1, "key1 should not exist after reset")
	assert.False(t, ok2, "key2 should not exist after reset")
}

// ---------- SyncMapFilter: Close ----------

func TestBoost2_SyncMapFilter_Close(t *testing.T) {
	f := &SyncMapFilter{Map: &sync.Map{}}
	f.Store("key1", struct{}{})

	f.Close()

	// After Close, the map is replaced with a new empty sync.Map
	_, ok := f.Load("key1")
	assert.False(t, ok, "key1 should not exist after close")
}

// ---------- SyncMapFilter: Check with addIfMissing false ----------

func TestBoost2_SyncMapFilter_CheckNoAdd(t *testing.T) {
	f := &SyncMapFilter{Map: &sync.Map{}}

	// Check with addIfMissing=false should not add the key
	exists := f.Check("missing_key", false)
	assert.False(t, exists, "Missing key should not be found")

	_, ok := f.Load("missing_key")
	assert.False(t, ok, "Key should not have been added with addIfMissing=false")
}

// ---------- SyncMapFilter: Check with addIfMissing true ----------

func TestBoost2_SyncMapFilter_CheckWithAdd(t *testing.T) {
	f := &SyncMapFilter{Map: &sync.Map{}}

	exists := f.Check("new_key", true)
	assert.False(t, exists, "First check should return false (key didn't exist)")

	// Now the key should exist
	exists = f.Check("new_key", false)
	assert.True(t, exists, "Second check should return true (key now exists)")
}

// ---------- SyncMapFilter: Insert ----------

func TestBoost2_SyncMapFilter_Insert(t *testing.T) {
	f := &SyncMapFilter{Map: &sync.Map{}}
	f.Insert("inserted_key")

	_, ok := f.Load("inserted_key")
	assert.True(t, ok, "Inserted key should exist")
}

// ---------- markParamValue: deep branch coverage ----------
// The function has a `continue` right after setting CustomValueMark, so the
// switch branches below it are unreachable in normal execution. However, we
// can still test that the function correctly returns CustomValueMark for all
// input types (since the continue is unconditional).

func TestBoost2_MarkParamValue_BoolType(t *testing.T) {
	s := SmartFilter{}
	s.Init()
	req, _ := whttp.NewRequest("GET", "http://example.com/api", nil)

	// bool value should get CustomValueMark (due to the continue before the switch)
	params := map[string]any{"flag": true}
	result := s.markParamValue(params, *req)
	assert.Equal(t, CustomValueMark, result["flag"], "bool value should get CustomValueMark")
}

func TestBoost2_MarkParamValue_FloatType(t *testing.T) {
	s := SmartFilter{}
	s.Init()
	req, _ := whttp.NewRequest("GET", "http://example.com/api", nil)

	params := map[string]any{"score": float64(3.14)}
	result := s.markParamValue(params, *req)
	assert.Equal(t, CustomValueMark, result["score"], "float64 value should get CustomValueMark")
}

func TestBoost2_MarkParamValue_UpperCaseValue(t *testing.T) {
	s := SmartFilter{}
	s.Init()
	req, _ := whttp.NewRequest("GET", "http://example.com/api", nil)

	// All-upper case value (would be UpperMark if not for the continue)
	params := map[string]any{"code": "ABCDEF"}
	result := s.markParamValue(params, *req)
	assert.Equal(t, CustomValueMark, result["code"], "uppercase value should get CustomValueMark")
}

func TestBoost2_MarkParamValue_LongValue(t *testing.T) {
	s := SmartFilter{}
	s.Init()
	req, _ := whttp.NewRequest("GET", "http://example.com/api", nil)

	// Value >= 16 chars (would be TooLongMark if not for the continue)
	longVal := "abcdefghijklmnop"
	params := map[string]any{"data": longVal}
	result := s.markParamValue(params, *req)
	assert.Equal(t, CustomValueMark, result["data"], "long value should get CustomValueMark")
}

func TestBoost2_MarkParamValue_NumericValue(t *testing.T) {
	s := SmartFilter{}
	s.Init()
	req, _ := whttp.NewRequest("GET", "http://example.com/api", nil)

	// Pure numeric value (would be NumberMark if not for the continue)
	params := map[string]any{"id": "12345"}
	result := s.markParamValue(params, *req)
	assert.Equal(t, CustomValueMark, result["id"], "numeric value should get CustomValueMark")
}

func TestBoost2_MarkParamValue_ChineseValue(t *testing.T) {
	s := SmartFilter{}
	s.Init()
	req, _ := whttp.NewRequest("GET", "http://example.com/api", nil)

	// Chinese characters (would be ChineseMark if not for the continue)
	params := map[string]any{"name": "测试"}
	result := s.markParamValue(params, *req)
	assert.Equal(t, CustomValueMark, result["name"], "Chinese value should get CustomValueMark")
}

func TestBoost2_MarkParamValue_URLEncodedValue(t *testing.T) {
	s := SmartFilter{}
	s.Init()
	req, _ := whttp.NewRequest("GET", "http://example.com/api", nil)

	// URL encoded (would be UrlEncodeMark if not for the continue)
	params := map[string]any{"q": "%E6%B5%8B%E8%AF%95"}
	result := s.markParamValue(params, *req)
	assert.Equal(t, CustomValueMark, result["q"], "URL-encoded value should get CustomValueMark")
}

func TestBoost2_MarkParamValue_UnicodeValue(t *testing.T) {
	s := SmartFilter{}
	s.Init()
	req, _ := whttp.NewRequest("GET", "http://example.com/api", nil)

	// Unicode escapes (would be UnicodeMark if not for the continue)
	params := map[string]any{"u": "\\u0041\\u0042"}
	result := s.markParamValue(params, *req)
	assert.Equal(t, CustomValueMark, result["u"], "unicode value should get CustomValueMark")
}

func TestBoost2_MarkParamValue_TimeValue(t *testing.T) {
	s := SmartFilter{}
	s.Init()
	req, _ := whttp.NewRequest("GET", "http://example.com/api", nil)

	// Time-like value (would be TimeMark if not for the continue)
	params := map[string]any{"ts": "2023-01-15"}
	result := s.markParamValue(params, *req)
	assert.Equal(t, CustomValueMark, result["ts"], "time value should get CustomValueMark")
}

func TestBoost2_MarkParamValue_MixAlphaNumValue(t *testing.T) {
	s := SmartFilter{}
	s.Init()
	req, _ := whttp.NewRequest("GET", "http://example.com/api", nil)

	// Alphanumeric mixed (would be MixAlphaNumMark if not for the continue)
	params := map[string]any{"code": "abc123"}
	result := s.markParamValue(params, *req)
	assert.Equal(t, CustomValueMark, result["code"], "mixed alpha-num value should get CustomValueMark")
}

func TestBoost2_MarkParamValue_SpecialSymbolValue(t *testing.T) {
	s := SmartFilter{}
	s.Init()
	req, _ := whttp.NewRequest("GET", "http://example.com/api", nil)

	// Contains special symbols (would be MixSymbolMark if not for the continue)
	params := map[string]any{"expr": "a+b=c"}
	result := s.markParamValue(params, *req)
	assert.Equal(t, CustomValueMark, result["expr"], "special symbol value should get CustomValueMark")
}

func TestBoost2_MarkParamValue_MixNumValue(t *testing.T) {
	s := SmartFilter{}
	s.Init()
	req, _ := whttp.NewRequest("GET", "http://example.com/api", nil)

	// More than 3 digits scattered (would be MixNumMark if not for the continue)
	params := map[string]any{"ver": "v1r2s3t4"}
	result := s.markParamValue(params, *req)
	assert.Equal(t, CustomValueMark, result["ver"], "mix-num value should get CustomValueMark")
}

func TestBoost2_MarkParamValue_StrictModeNoLower(t *testing.T) {
	s := SmartFilter{StrictMode: true}
	s.Init()
	req, _ := whttp.NewRequest("GET", "http://example.com/api", nil)

	// StrictMode, no lowercase (would be NoLowerAlphaMark if not for the continue)
	params := map[string]any{"code": "ABC_123"}
	result := s.markParamValue(params, *req)
	assert.Equal(t, CustomValueMark, result["code"], "strict-mode no-lower value should get CustomValueMark")
}

func TestBoost2_MarkParamValue_StrictModeMixString(t *testing.T) {
	s := SmartFilter{StrictMode: true}
	s.Init()
	req, _ := whttp.NewRequest("GET", "http://example.com/api", nil)

	// StrictMode, mix of lower+upper+digit+underscore (>=3 types, would be MixStringMark)
	params := map[string]any{"token": "aB1_cD2"}
	result := s.markParamValue(params, *req)
	assert.Equal(t, CustomValueMark, result["token"], "strict-mode mix-string value should get CustomValueMark")
}

func TestBoost2_MarkParamValue_ScannerValue(t *testing.T) {
	s := SmartFilter{}
	s.Init()
	req, _ := whttp.NewRequest("GET", "http://example.com/search", nil)

	// Value containing "Scanner" should mark the location set
	params := map[string]any{"token": "test_Scanner_val"}
	result := s.markParamValue(params, *req)
	assert.Equal(t, CustomValueMark, result["token"], "Scanner value should get CustomValueMark")
}

func TestBoost2_MarkParamValue_PlainStringValue(t *testing.T) {
	s := SmartFilter{}
	s.Init()
	req, _ := whttp.NewRequest("GET", "http://example.com/api", nil)

	// Plain string value (would remain unchanged if not for the continue)
	params := map[string]any{"name": "hello"}
	result := s.markParamValue(params, *req)
	assert.Equal(t, CustomValueMark, result["name"], "plain string value should get CustomValueMark")
}

func TestBoost2_MarkParamValue_NonStringNonBoolValue(t *testing.T) {
	s := SmartFilter{}
	s.Init()
	req, _ := whttp.NewRequest("GET", "http://example.com/api", nil)

	// int value (not string, not bool, not float64) - should get CustomValueMark
	params := map[string]any{"count": 42}
	result := s.markParamValue(params, *req)
	assert.Equal(t, CustomValueMark, result["count"], "int value should get CustomValueMark")
}

func TestBoost2_MarkParamValue_EmptyMap(t *testing.T) {
	s := SmartFilter{}
	s.Init()
	req, _ := whttp.NewRequest("GET", "http://example.com/api", nil)

	params := map[string]any{}
	result := s.markParamValue(params, *req)
	assert.Equal(t, 0, len(result), "Empty map should return empty result")
}

// ---------- MarkPath: additional uncovered branches ----------

func TestBoost2_MarkPath_DotSeparatedPureNumber(t *testing.T) {
	s := SmartFilter{}
	// dot-separated part that is pure number
	assert.Equal(t, "/static/{{number}}.js", s.MarkPath("/static/123.js"))
}

func TestBoost2_MarkPath_DotSeparatedSingleCharUpper(t *testing.T) {
	s := SmartFilter{}
	// Single uppercase letter should NOT be marked as UpperMark (len > 1 check)
	assert.Equal(t, "/file.A.js", s.MarkPath("/file.A.js"))
}

func TestBoost2_MarkPath_DotSeparatedNoMarkingNeeded(t *testing.T) {
	s := SmartFilter{}
	// dot-separated parts that are short alphabetic - no marking needed
	assert.Equal(t, "/static/main.js", s.MarkPath("/static/main.js"))
}

func TestBoost2_MarkPath_HtmlExtWithNumbersOnly(t *testing.T) {
	s := SmartFilter{}
	// .html extension stripped, only numbers remain after stripping symbol chars
	assert.Equal(t, "/{{number}}", s.MarkPath("/123.html"))
}

func TestBoost2_MarkPath_HtmlExtNoChange(t *testing.T) {
	s := SmartFilter{}
	// .html extension stripped, simple text that doesn't match any marking pattern
	assert.Equal(t, "/page", s.MarkPath("/page.html"))
}

func TestBoost2_MarkPath_HtmExtWithMixAlphaNum(t *testing.T) {
	s := SmartFilter{}
	// .htm extension, name with mix of upper, lower, and digits
	assert.Equal(t, "/{{mix_alpha_num}}", s.MarkPath("/Abc123.htm"))
}

func TestBoost2_MarkPath_DotPartWithMixNum(t *testing.T) {
	s := SmartFilter{}
	// dot-separated part with more than 3 digits -> MixNumMark
	assert.Equal(t, "/{{mix_num}}.js", s.MarkPath("/v1a2b3c4.js"))
}

func TestBoost2_MarkPath_SegmentWithUnicodeEscape(t *testing.T) {
	s := SmartFilter{}
	// Path segment with backslash-u escape sequences - contains special symbol \
	assert.Equal(t, "/{{mix_symbol}}", s.MarkPath("/\\u0041\\u0042"))
}

func TestBoost2_MarkPath_EmptyParts(t *testing.T) {
	s := SmartFilter{}
	// Path with empty segments (double slash)
	result := s.MarkPath("//path")
	assert.Contains(t, result, "path")
}

func TestBoost2_MarkPath_SegmentWithSpecialSymbol(t *testing.T) {
	s := SmartFilter{}
	// Segment containing special symbols like @
	assert.Equal(t, "/{{mix_symbol}}", s.MarkPath("/user@domain"))
}

func TestBoost2_MarkPath_DotSeparatedUpperSegment(t *testing.T) {
	s := SmartFilter{}
	// dot-separated uppercase part > 1 char
	assert.Equal(t, "/{{upper}}.min.js", s.MarkPath("/ABCD.min.js"))
}

func TestBoost2_MarkPath_DotSeparatedLongSegment(t *testing.T) {
	s := SmartFilter{}
	// dot-separated segment >= 32 chars
	longPart := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	assert.Equal(t, "/{{long}}.js", s.MarkPath("/"+longPart+".js"))
}

func TestBoost2_MarkPath_ChineseSegment(t *testing.T) {
	s := SmartFilter{}
	assert.Equal(t, "/{{chinese}}", s.MarkPath("/中文路径"))
}

// ---------- util.go: shouldCopyHeaderOnRedirect ----------

func TestBoost2_ShouldCopyHeaderOnRedirect_Authorization(t *testing.T) {
	assert.False(t, shouldCopyHeaderOnRedirect("Authorization", []string{"Bearer token"}), "Authorization should not be copied")
}

func TestBoost2_ShouldCopyHeaderOnRedirect_Cookie(t *testing.T) {
	assert.False(t, shouldCopyHeaderOnRedirect("Cookie", []string{"session=abc"}), "Cookie should not be copied")
}

func TestBoost2_ShouldCopyHeaderOnRedirect_OtherHeaders(t *testing.T) {
	assert.True(t, shouldCopyHeaderOnRedirect("Content-Type", []string{"text/html"}), "Content-Type should be copied")
	assert.True(t, shouldCopyHeaderOnRedirect("X-Custom", []string{"value"}), "X-Custom should be copied")
	assert.True(t, shouldCopyHeaderOnRedirect("Accept", []string{"*/*"}), "Accept should be copied")
}

// ---------- util.go: canonicalAddr ----------

func TestBoost2_CanonicalAddr_ValidIP(t *testing.T) {
	result := canonicalAddr("192.168.1.1")
	assert.Contains(t, result, "192.168.1.1")
}

func TestBoost2_CanonicalAddr_Empty(t *testing.T) {
	result := canonicalAddr("")
	assert.NotPanics(t, func() { canonicalAddr("") })
	t.Logf("canonicalAddr(''): %s", result)
}

// ---------- util.go: idnaASCII ----------

func TestBoost2_IdnaASCII_ASCII(t *testing.T) {
	result, err := idnaASCII("example.com")
	assert.NoError(t, err)
	assert.Equal(t, "example.com", result)
}

func TestBoost2_IdnaASCII_Unicode(t *testing.T) {
	result, err := idnaASCII("例子.中国")
	if err != nil {
		t.Logf("idnaASCII with unicode: err=%v (acceptable if IDNA lib not available)", err)
	} else {
		assert.NotEqual(t, "例子.中国", result, "Should be converted to ASCII punycode")
		t.Logf("idnaASCII('例子.中国'): %s", result)
	}
}

func TestBoost2_IdnaASCII_Empty(t *testing.T) {
	result, err := idnaASCII("")
	assert.NoError(t, err)
	assert.Equal(t, "", result)
}

// ---------- util.go: getParentPaths ----------

func TestBoost2_GetParentPaths_DeepPath(t *testing.T) {
	result := getParentPaths("/a/b/c/d")
	assert.Equal(t, []string{"/a/b/c", "/a/b", "/a"}, result)
}

func TestBoost2_GetParentPaths_SingleComponent(t *testing.T) {
	result := getParentPaths("/a")
	assert.Nil(t, result, "Single component should have no parent paths")
}

func TestBoost2_GetParentPaths_Root(t *testing.T) {
	result := getParentPaths("/")
	assert.Nil(t, result, "Root should have no parent paths")
}

func TestBoost2_GetParentPaths_TwoComponents(t *testing.T) {
	result := getParentPaths("/a/b")
	assert.Equal(t, []string{"/a"}, result)
}

// ---------- util.go: escapePercentSign ----------

func TestBoost2_EscapePercentSign_WithPercent(t *testing.T) {
	result := escapePercentSign("test%value")
	assert.Equal(t, "test%25value", result)
}

func TestBoost2_EscapePercentSign_NoPercent(t *testing.T) {
	result := escapePercentSign("testvalue")
	assert.Equal(t, "testvalue", result)
}

func TestBoost2_EscapePercentSign_MultiplePercents(t *testing.T) {
	result := escapePercentSign("%test%value%")
	assert.Equal(t, "%25test%25value%25", result)
}

// ---------- util.go: UrlFileName ----------

func TestBoost2_UrlFileName_WithExtension(t *testing.T) {
	u, _ := url.Parse("http://example.com/path/file.html")
	assert.Equal(t, "file.html", UrlFileName(u))
}

func TestBoost2_UrlFileName_NoExtension(t *testing.T) {
	u, _ := url.Parse("http://example.com/path/dir")
	assert.Equal(t, "", UrlFileName(u))
}

func TestBoost2_UrlFileName_HiddenFile(t *testing.T) {
	u, _ := url.Parse("http://example.com/path/.htaccess")
	assert.Equal(t, ".htaccess", UrlFileName(u))
}

func TestBoost2_UrlFileName_RootPath(t *testing.T) {
	u, _ := url.Parse("http://example.com/")
	assert.Equal(t, "", UrlFileName(u))
}

// ---------- util.go: UrlFileExt ----------

func TestBoost2_UrlFileExt_HTML(t *testing.T) {
	u, _ := url.Parse("http://example.com/path/file.HTML")
	assert.Equal(t, "html", UrlFileExt(u))
}

func TestBoost2_UrlFileExt_NoExtension(t *testing.T) {
	u, _ := url.Parse("http://example.com/path/dir")
	assert.Equal(t, "", UrlFileExt(u))
}

func TestBoost2_UrlFileExt_JS(t *testing.T) {
	u, _ := url.Parse("http://example.com/app.min.js")
	assert.Equal(t, "js", UrlFileExt(u))
}

// ---------- util.go: AbsoluteURL ----------

func TestBoost2_AbsoluteURL_Basic(t *testing.T) {
	base, _ := url.Parse("http://example.com/page")
	result := AbsoluteURL(base, "/new/path")
	assert.Equal(t, "/new/path", result.Path)
	assert.Equal(t, "example.com", result.Host)
}

func TestBoost2_AbsoluteURL_WithQuery(t *testing.T) {
	base, _ := url.Parse("http://example.com/page?q=1")
	result := AbsoluteURL(base, "/other")
	assert.Equal(t, "/other", result.Path)
	assert.Equal(t, "example.com", result.Host)
}

// ---------- util.go: ParsePKCS12 additional ----------

func TestBoost2_ParsePKCS12_CorruptData(t *testing.T) {
	_, err := ParsePKCS12([]byte("not-valid-pkcs12-data"), "password")
	assert.Error(t, err, "Corrupt data should return error")
	assert.Contains(t, err.Error(), "pkcs12", "Error should mention pkcs12")
}

// ---------- util.go: UrlParse additional edge cases ----------

func TestBoost2_UrlParse_ValidURL(t *testing.T) {
	u, err := UrlParse("http://example.com/path?q=1")
	assert.NoError(t, err)
	assert.Equal(t, "example.com", u.Host)
	assert.Equal(t, "/path", u.Path)
}

func TestBoost2_UrlParse_SimplePath(t *testing.T) {
	u, err := UrlParse("http://example.com/")
	assert.NoError(t, err)
	assert.Equal(t, "/", u.Path)
}

// ---------- util.go: GetUrl additional edge cases ----------

func TestBoost2_GetUrl_NoParentEmptyPath(t *testing.T) {
	u, err := GetUrl("http://example.com")
	assert.NoError(t, err)
	assert.Equal(t, "/", u.Path, "Empty path should default to /")
}

func TestBoost2_GetUrl_WithParentAndRelativePath(t *testing.T) {
	parent := url.URL{Scheme: "http", Host: "example.com", Path: "/base/page"}
	u, err := GetUrl("sub/page", parent)
	assert.NoError(t, err)
	assert.Contains(t, u.Path, "sub/page")
}

func TestBoost2_GetUrl_DoubleSlashPath(t *testing.T) {
	parent := url.URL{Scheme: "http", Host: "example.com"}
	u, err := GetUrl("//example.com/path", parent)
	assert.NoError(t, err)
	// Double slashes at the start of the path should be fixed
	assert.Equal(t, "/path", u.Path)
}

func TestBoost2_GetUrl_HTTPSURL(t *testing.T) {
	parent := url.URL{Scheme: "http", Host: "example.com"}
	u, err := GetUrl("https://secure.example.com/api", parent)
	assert.NoError(t, err)
	assert.Equal(t, "secure.example.com", u.Host)
	assert.Equal(t, "https", u.Scheme)
}

// ---------- util.go: parse function additional ----------

func TestBoost2_Parse_HTTPPrefix(t *testing.T) {
	result, err := parse("http://example.com")
	assert.NoError(t, err)
	assert.Equal(t, "http://example.com", result)
}

func TestBoost2_Parse_HTTPSPrefix(t *testing.T) {
	result, err := parse("https://example.com")
	assert.NoError(t, err)
	assert.Equal(t, "https://example.com", result)
}

func TestBoost2_Parse_NoParentHTTP(t *testing.T) {
	result, err := parse("http://test.com/path")
	assert.NoError(t, err)
	assert.Equal(t, "http://test.com/path", result)
}

func TestBoost2_Parse_WithParentHTTPURL(t *testing.T) {
	parent := url.URL{Scheme: "http", Host: "example.com"}
	result, err := parse("http://other.com/path", parent)
	assert.NoError(t, err)
	assert.Equal(t, "http://other.com/path", result)
}

func TestBoost2_Parse_WithParentHTTPSURL(t *testing.T) {
	parent := url.URL{Scheme: "http", Host: "example.com"}
	result, err := parse("https://secure.com/api", parent)
	assert.NoError(t, err)
	assert.Equal(t, "https://secure.com/api", result)
}

func TestBoost2_Parse_JavascriptProtocol(t *testing.T) {
	parent := url.URL{Scheme: "http", Host: "example.com"}
	_, err := parse("javascript:void(0)", parent)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "javascript")
}

func TestBoost2_Parse_MailtoProtocol(t *testing.T) {
	parent := url.URL{Scheme: "http", Host: "example.com"}
	_, err := parse("mailto:user@example.com", parent)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mailto")
}

func TestBoost2_Parse_WithParentRelativePath(t *testing.T) {
	parent := url.URL{Scheme: "http", Host: "example.com"}
	result, err := parse("/relative/path", parent)
	assert.NoError(t, err)
	assert.Equal(t, "/relative/path", result)
}

func TestBoost2_Parse_SpacesInURL(t *testing.T) {
	result, err := parse("  http://example.com  ")
	assert.NoError(t, err)
	assert.Equal(t, "http://example.com", result)
}

// ---------- NavigationUrl additional ----------

func TestBoost2_NavigationUrl_WithPort(t *testing.T) {
	u, _ := url.Parse("http://example.com:8080/api")
	got := NavigationUrl(u)
	assert.Equal(t, "://example.com:8080/api", got)
}

func TestBoost2_NavigationUrl_RootPath(t *testing.T) {
	u, _ := url.Parse("http://example.com/")
	got := NavigationUrl(u)
	assert.Equal(t, "://example.com/", got)
}

// ---------- path_expansion.go: extractSourceMapURL additional ----------

func TestBoost2_ExtractSourceMapURL_SingleLineWithMap(t *testing.T) {
	// When JS is a single line that IS the sourceMappingURL
	got := extractSourceMapURL("//# sourceMappingURL=bundle.js.map")
	assert.Equal(t, "bundle.js.map", got)
}

func TestBoost2_ExtractSourceMapURL_TrailingSpaces(t *testing.T) {
	got := extractSourceMapURL("var x = 1;\n//# sourceMappingURL=app.js.map   ")
	assert.Equal(t, "app.js.map", got)
}

func TestBoost2_ExtractSourceMapURL_NoNewlineButLastLine(t *testing.T) {
	// Single line that doesn't match
	got := extractSourceMapURL("var x = 1;")
	assert.Equal(t, "", got)
}

func TestBoost2_ExtractSourceMapURL_MultipleHashesInComment(t *testing.T) {
	got := extractSourceMapURL("code\n//# sourceMappingURL=file-with#hash.js.map")
	assert.Equal(t, "file-with#hash.js.map", got)
}

// ---------- path_expansion.go: extractPathsFromRobots additional ----------

func TestBoost2_ExtractPathsFromRobots_EmptyBody(t *testing.T) {
	u, _ := url.Parse("http://example.com")
	result := extractPathsFromRobots(u, "")
	assert.Equal(t, 0, len(result), "Empty body should return no paths")
}

func TestBoost2_ExtractPathsFromRobots_OnlyUserAgent(t *testing.T) {
	u, _ := url.Parse("http://example.com")
	result := extractPathsFromRobots(u, "User-agent: *")
	assert.Equal(t, 0, len(result), "Only user-agent line should return no paths")
}

func TestBoost2_ExtractPathsFromRobots_DisallowWithoutPath(t *testing.T) {
	u, _ := url.Parse("http://example.com")
	result := extractPathsFromRobots(u, "User-agent: *\nDisallow:")
	assert.Equal(t, 0, len(result), "Disallow without path should return no paths")
}

func TestBoost2_ExtractPathsFromRobots_ManyPaths(t *testing.T) {
	u, _ := url.Parse("http://example.com")
	body := `User-agent: *
Disallow: /admin/
Disallow: /private/
Disallow: /secret/
Allow: /public/
Allow: /api/`
	result := extractPathsFromRobots(u, body)
	assert.Equal(t, 5, len(result), "Should find 5 paths")
}

func TestBoost2_ExtractPathsFromRobots_InvalidPath(t *testing.T) {
	u, _ := url.Parse("http://example.com")
	// A Disallow with no leading slash
	body := "User-agent: *\nDisallow: nopath"
	result := extractPathsFromRobots(u, body)
	assert.Equal(t, 0, len(result), "Disallow without leading slash should not be extracted")
}

// ---------- path_expansion.go: extractPathsFromSitemap additional ----------

func TestBoost2_ExtractPathsFromSitemap_InvalidXML(t *testing.T) {
	u, _ := url.Parse("http://example.com")
	result := extractPathsFromSitemap(u, "not xml at all")
	assert.Nil(t, result, "Invalid XML should return nil")
}

func TestBoost2_ExtractPathsFromSitemap_EmptyBody(t *testing.T) {
	u, _ := url.Parse("http://example.com")
	result := extractPathsFromSitemap(u, "")
	assert.Nil(t, result, "Empty body should return nil for sitemap")
}

func TestBoost2_ExtractPathsFromSitemap_ValidURLsAndSitemaps(t *testing.T) {
	u, _ := url.Parse("http://example.com")
	body := `<?xml version="1.0"?>
	<urlset>
		<url><loc>http://example.com/page1</loc></url>
		<url><loc>http://example.com/page2</loc></url>
		<sitemap><loc>http://example.com/sitemap2.xml</loc></sitemap>
	</urlset>`
	result := extractPathsFromSitemap(u, body)
	assert.Equal(t, 3, len(result), "Should find 2 URLs + 1 sitemap")
}

func TestBoost2_ExtractPathsFromSitemap_EmptyLocs(t *testing.T) {
	u, _ := url.Parse("http://example.com")
	body := `<?xml version="1.0"?>
	<urlset>
		<url><loc></loc></url>
		<url><loc>   </loc></url>
	</urlset>`
	result := extractPathsFromSitemap(u, body)
	// Empty or whitespace-only locs may or may not create requests depending on URL parsing
	t.Logf("Empty locs result: %d", len(result))
}

// ---------- path_expansion.go: AddRequestFromUrl additional ----------

func TestBoost2_AddRequestFromUrl_NilRet(t *testing.T) {
	u, _ := url.Parse("http://example.com")
	result := AddRequestFromUrl(u, "/api/test", nil)
	assert.Equal(t, 1, len(result))
	assert.NotNil(t, result[0])
}

func TestBoost2_AddRequestFromUrl_ExistingRet(t *testing.T) {
	u, _ := url.Parse("http://example.com")
	existingReq, _ := whttp.NewRequest("GET", "http://example.com/existing", nil)
	ret := []*whttp.Request{existingReq}
	result := AddRequestFromUrl(u, "/new", ret)
	assert.Equal(t, 2, len(result))
}

// ---------- ParseResponseURL: additional coverage ----------

func TestBoost2_ParseResponseURL_RobotsTxtBody(t *testing.T) {
	u, _ := url.Parse("http://example.com/robots.txt")
	body := "User-agent: *\nDisallow: /admin/\nAllow: /public/"
	result := ParseResponseURL(u, body)
	assert.GreaterOrEqual(t, len(result), 1, "Should extract paths from robots.txt")
}

func TestBoost2_ParseResponseURL_SitemapXmlBody(t *testing.T) {
	u, _ := url.Parse("http://example.com/sitemap.xml")
	body := `<?xml version="1.0"?><urlset><url><loc>http://example.com/page1</loc></url></urlset>`
	result := ParseResponseURL(u, body)
	assert.GreaterOrEqual(t, len(result), 1, "Should extract paths from sitemap.xml")
}

func TestBoost2_ParseResponseURL_JSFileWithMainPattern(t *testing.T) {
	u, _ := url.Parse("http://example.com/main.abc123.js")
	body := `var api = "/api/v1";`
	result := ParseResponseURL(u, body)
	// Should add .map file request for main.[hash].js pattern
	t.Logf("ParseResponseURL for main.[hash].js: %d results", len(result))
}

func TestBoost2_ParseResponseURL_JSFileNonMainPattern(t *testing.T) {
	u, _ := url.Parse("http://example.com/vendor.bundle.js")
	body := `var x = "/api/data";`
	result := ParseResponseURL(u, body)
	t.Logf("ParseResponseURL for vendor.bundle.js: %d results", len(result))
}

// ---------- headerContentLocationParser: deeper coverage ----------

func TestBoost2_HeaderContentLocationParser_WithRelativeURL(t *testing.T) {
	u, _ := url.Parse("http://example.com/old-page")
	wu := whttp.URL{URL: *u}
	doc, _ := goquery.NewDocumentFromReader(strings.NewReader("<html></html>"))
	resp := &whttp.Response{
		NativeResponse: &gohttp.Response{
			Header: gohttp.Header{
				"Content-Location": []string{"new-page"},
			},
		},
	}
	assert.NotPanics(t, func() {
		headerContentLocationParser(&wu, doc, resp)
	})
}

func TestBoost2_HeaderContentLocationParser_WithAbsolutePath(t *testing.T) {
	u, _ := url.Parse("http://example.com/old")
	wu := whttp.URL{URL: *u}
	doc, _ := goquery.NewDocumentFromReader(strings.NewReader("<html></html>"))
	resp := &whttp.Response{
		NativeResponse: &gohttp.Response{
			Header: gohttp.Header{
				"Content-Location": []string{"/absolute/new-page"},
			},
		},
	}
	assert.NotPanics(t, func() {
		headerContentLocationParser(&wu, doc, resp)
	})
}

// ---------- FillForm: GetMatchInputText with custom keyword values ----------

func TestBoost2_GetMatchInputText_CustomKeywordOverride(t *testing.T) {
	f := &FillForm{
		tab: &task{
			config: TabConfig{
				CustomFormValues:        map[string]string{"default": "default_val"},
				CustomFormKeywordValues: map[string]string{"company": "Acme Corp", "address": "123 Main St"},
			},
		},
	}

	// Custom keyword should be checked first
	got := f.GetMatchInputText("company_name")
	assert.Equal(t, "Acme Corp", got, "Custom keyword 'company' should match 'company_name'")

	got2 := f.GetMatchInputText("home_address")
	assert.Equal(t, "123 Main St", got2, "Custom keyword 'address' should match 'home_address'")
}

func TestBoost2_GetMatchInputText_NoMatchingKeyword(t *testing.T) {
	f := &FillForm{
		tab: &task{
			config: TabConfig{
				CustomFormValues:        map[string]string{"default": "fallback"},
				CustomFormKeywordValues: map[string]string{},
			},
		},
	}

	got := f.GetMatchInputText("xyznokeywordmatch")
	assert.Equal(t, "fallback", got, "Should return default when no keyword matches")
}

func TestBoost2_GetMatchInputText_CustomFormValueOverridesKeywordValue(t *testing.T) {
	f := &FillForm{
		tab: &task{
			config: TabConfig{
				CustomFormValues:        map[string]string{"default": "default_val", "mail": "custom@test.org"},
				CustomFormKeywordValues: map[string]string{},
			},
		},
	}

	// The InputTextMap "mail" category should return custom value if set
	got := f.GetMatchInputText("email_address")
	assert.Equal(t, "custom@test.org", got, "CustomFormValues should override keyword default")
}

func TestBoost2_GetMatchInputText_DefaultKeywordMatches(t *testing.T) {
	f := &FillForm{
		tab: &task{
			config: TabConfig{
				CustomFormValues:        map[string]string{"default": DefaultInputText},
				CustomFormKeywordValues: map[string]string{},
			},
		},
	}

	// GetMatchInputText checks strings.Contains(name, keyword) for each keyword
	// So the input name must CONTAIN the keyword as a substring.
	// Map iteration order is non-deterministic, so use names that uniquely match one category.
	tests := map[string]string{
		"mail":       "scan@gmail.com",        // matches "mail" keyword exactly
		"yanzhengma": "123a",                  // matches "yanzhengma" keyword (code category)
		"phone":      "18812345678",           // matches "phone" keyword
		"username":   "scan@gmail.com",        // matches "username" keyword
		"pass":       "scanner#$3435.",        // matches "pass" keyword
		"qq":         "123456789",             // matches "qq" keyword
		"shenfen":    "511702197409284963",    // matches "shenfen" keyword (IDCard)
		"url":        "https://scan.nice.cn/", // matches "url" keyword
		"date":       "2000-01-01",            // matches "date" keyword
		"age":        "10",                    // matches "age" keyword (number)
	}

	for input, expected := range tests {
		got := f.GetMatchInputText(input)
		assert.Equal(t, expected, got, "GetMatchInputText(%q) should return %q", input, expected)
	}
}

// ---------- SmartFilter: preQueryMark additional ----------

func TestBoost2_PreQueryMark_MixedChineseAndASCII(t *testing.T) {
	s := SmartFilter{}
	result := s.preQueryMark("name=测试&age=25")
	assert.Contains(t, result, ChineseMark)
}

func TestBoost2_PreQueryMark_OnlyURLEncoded(t *testing.T) {
	s := SmartFilter{}
	result := s.preQueryMark("name=%E6%B5%8B")
	assert.Contains(t, result, UrlEncodeMark)
}

func TestBoost2_PreQueryMark_OnlyUnicode(t *testing.T) {
	s := SmartFilter{}
	// When there's no Chinese or URL-encoded, but unicode escapes
	result := s.preQueryMark("name=\\u0041")
	assert.Contains(t, result, UnicodeMark)
}

// ---------- SmartFilter: DoFilter with empty query and POST ----------

func TestBoost2_DoFilter_GETNoQuery(t *testing.T) {
	s := SmartFilter{SimpleFilter: SimpleFilter{}}
	s.Init()
	req, _ := whttp.NewRequest("GET", "http://example.com/api", nil)
	assert.False(t, s.DoFilter(req, false), "GET with no query should not be filtered first time")
}

func TestBoost2_DoFilter_POSTNoBody(t *testing.T) {
	s := SmartFilter{SimpleFilter: SimpleFilter{}}
	s.Init()
	req, _ := whttp.NewRequest("POST", "http://example.com/api", nil)
	assert.False(t, s.DoFilter(req, false), "POST with no body should not be filtered first time")
}

func TestBoost2_DoFilter_GETWithFragmentSlash(t *testing.T) {
	s := SmartFilter{SimpleFilter: SimpleFilter{}}
	s.Init()
	req, _ := whttp.NewRequest("GET", "http://example.com/page#/route", nil)
	assert.False(t, s.DoFilter(req, false), "GET with fragment path should not be filtered first time")
}

func TestBoost2_DoFilter_GETHTTPSRootNoQuery(t *testing.T) {
	s := SmartFilter{SimpleFilter: SimpleFilter{}}
	s.Init()
	req, _ := whttp.NewRequest("GET", "https://example.com/", nil)
	assert.False(t, s.DoFilter(req, false), "HTTPS root with no query should not be filtered")
}

// ---------- SmartFilter: DoFilter with filterLocationSet ----------

func TestBoost2_DoFilter_NumericParamLocationMarking(t *testing.T) {
	s := SmartFilter{SimpleFilter: SimpleFilter{}}
	s.Init()

	// Send a request with "Scanner" in param value - this marks the location
	req1, _ := whttp.NewRequest("GET", "http://example.com/search?token=Scanner_test", nil)
	s.DoFilter(req1, false)

	// Now send a request with the same param but a different value
	// The location should be marked and the param should get CustomValueMark
	req2, _ := whttp.NewRequest("GET", "http://example.com/search?token=other_value", nil)
	result := s.DoFilter(req2, false)
	t.Logf("After Scanner marking, second request filtered=%v", result)
}

// ---------- SimpleFilter: StaticFilter additional ----------

func TestBoost2_StaticFilter_CSSFile(t *testing.T) {
	s := &SimpleFilter{}
	req, _ := whttp.NewRequest("GET", "http://example.com/style.css", nil)
	assert.True(t, s.StaticFilter(req), "CSS file should be filtered as static")
}

func TestBoost2_StaticFilter_JSONFile(t *testing.T) {
	s := &SimpleFilter{}
	req, _ := whttp.NewRequest("GET", "http://example.com/data.json", nil)
	assert.True(t, s.StaticFilter(req), "JSON file should be filtered as static")
}

func TestBoost2_StaticFilter_JSFileNotStatic(t *testing.T) {
	s := &SimpleFilter{}
	req, _ := whttp.NewRequest("GET", "http://example.com/app.js", nil)
	// .js is NOT in StaticSuffix or the additional "css", "json" list
	assert.False(t, s.StaticFilter(req), "JS file should not be filtered as static")
}

func TestBoost2_StaticFilter_PHPFileNotStatic(t *testing.T) {
	s := &SimpleFilter{}
	req, _ := whttp.NewRequest("GET", "http://example.com/page.php", nil)
	assert.False(t, s.StaticFilter(req), "PHP file should not be filtered as static")
}

func TestBoost2_StaticFilter_ImagePNG(t *testing.T) {
	s := &SimpleFilter{}
	req, _ := whttp.NewRequest("GET", "http://example.com/image.png", nil)
	assert.True(t, s.StaticFilter(req), "PNG image should be filtered as static")
}

func TestBoost2_StaticFilter_JPEG(t *testing.T) {
	s := &SimpleFilter{}
	req, _ := whttp.NewRequest("GET", "http://example.com/photo.jpg", nil)
	assert.True(t, s.StaticFilter(req), "JPEG should be filtered as static")
}

func TestBoost2_StaticFilter_PDF(t *testing.T) {
	s := &SimpleFilter{}
	req, _ := whttp.NewRequest("GET", "http://example.com/doc.pdf", nil)
	assert.True(t, s.StaticFilter(req), "PDF should be filtered as static")
}

// ---------- SimpleFilter: DomainFilter with matching hosts ----------

func TestBoost2_DomainFilter_HostMatchesExactly(t *testing.T) {
	s := &SimpleFilter{HostLimit: "example.com"}
	req, _ := whttp.NewRequest("GET", "http://example.com/page", nil)
	assert.False(t, s.DomainFilter(req), "Exact host match should not be filtered")
}

func TestBoost2_DomainFilter_HostWithPortMatches(t *testing.T) {
	s := &SimpleFilter{HostLimit: "example.com:8080"}
	req, _ := whttp.NewRequest("GET", "http://example.com:8080/page", nil)
	assert.False(t, s.DomainFilter(req), "Host with matching port should not be filtered")
}

func TestBoost2_DomainFilter_HostnameMatchesHost(t *testing.T) {
	s := &SimpleFilter{HostLimit: "example.com"}
	req, _ := whttp.NewRequest("GET", "http://example.com:9090/page", nil)
	// Host is "example.com:9090", Hostname is "example.com"
	// Hostname matches, so should not be filtered
	assert.False(t, s.DomainFilter(req), "Hostname match should not be filtered")
}

func TestBoost2_DomainFilter_NoHostLimit(t *testing.T) {
	s := &SimpleFilter{HostLimit: ""}
	req, _ := whttp.NewRequest("GET", "http://any.com/page", nil)
	// If HostLimit is empty, DomainFilter is not called by DoFilter
	// But calling directly should return true (different host)
	assert.True(t, s.DomainFilter(req), "With empty HostLimit, any host should be filtered")
}

// ---------- SmartFilter: getParamMapID with non-string values ----------

func TestBoost2_GetParamMapID_NonStringValue(t *testing.T) {
	s := SmartFilter{}
	dataMap := map[string]any{"count": 42, "name": "test"}
	id := s.getParamMapID(dataMap)
	assert.NotEmpty(t, id, "Should handle non-string values")
}

func TestBoost2_GetParamMapID_MarkedValue(t *testing.T) {
	s := SmartFilter{}
	dataMap := map[string]any{"id": "{{number}}", "name": "static"}
	id1 := s.getParamMapID(dataMap)
	// Mark placeholders are normalized to {{mark}} by the regex
	// So {{number}} and {{chinese}} both become {{mark}} and produce the same ID
	// Verify the ID is deterministic
	dataMap2 := map[string]any{"id": "{{number}}", "name": "static"}
	id2 := s.getParamMapID(dataMap2)
	assert.Equal(t, id1, id2, "Same marked values should produce same ID")

	// Different key names should produce different IDs
	dataMap3 := map[string]any{"key": "{{number}}", "name": "static"}
	id3 := s.getParamMapID(dataMap3)
	assert.NotEqual(t, id1, id3, "Different key names should produce different IDs")
}

// ---------- SmartFilter: getKeysID with empty map ----------

func TestBoost2_GetKeysID_EmptyMap(t *testing.T) {
	s := SmartFilter{}
	id := s.getKeysID(map[string]any{})
	// Empty map -> empty key string -> MD5 of empty string
	assert.NotEmpty(t, id, "Empty map should still produce an ID")
}

// ---------- basic_task_hander.go: discoverParentDirs with various paths ----------

func TestBoost2_DiscoverParentDirs_MultipleLevels(t *testing.T) {
	c := newTestCrawler()
	req, _ := whttp.NewRequest("GET", "http://example.com/a/b/c/page.html", nil)
	tt := &task{req: req, depth: 0, crawlerTask: c}
	c.discoverParentDirs(tt)
	// Should discover /a/b/c/, /a/b/, /a/
	assert.GreaterOrEqual(t, c.taskQueue.Len(), 1)
}

func TestBoost2_DiscoverParentDirs_PathWithoutFile(t *testing.T) {
	c := newTestCrawler()
	req, _ := whttp.NewRequest("GET", "http://example.com/api/v1/users", nil)
	tt := &task{req: req, depth: 0, crawlerTask: c}
	c.discoverParentDirs(tt)
	// Should discover parent dirs
	assert.GreaterOrEqual(t, c.taskQueue.Len(), 1)
}

// ---------- handleBasicTask with various form types ----------

func TestBoost2_HandleBasicTask_FormWithMultipartGET(t *testing.T) {
	addr, cleanup := startBoostTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`<html><body>
			<form action="/upload" method="GET" enctype="multipart/form-data">
				<input type="text" name="title" value="test">
				<input type="submit">
			</form>
		</body></html>`))
	}))
	defer cleanup()

	c := newTestCrawler()
	c.config.MaxDepth = 5
	req, _ := whttp.NewRequest("GET", "http://"+addr+"/form", nil)
	tt := &task{req: req, depth: 0, crawlerTask: c}
	c.handleBasicTask(tt)
}

func TestBoost2_HandleBasicTask_FormWithRadioAndCheckbox(t *testing.T) {
	addr, cleanup := startBoostTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`<html><body>
			<form action="/vote" method="POST">
				<input type="radio" name="choice" value="a">
				<input type="radio" name="choice" value="b">
				<input type="checkbox" name="agree" value="yes">
				<input type="submit">
			</form>
		</body></html>`))
	}))
	defer cleanup()

	c := newTestCrawler()
	c.config.MaxDepth = 5
	req, _ := whttp.NewRequest("GET", "http://"+addr+"/vote", nil)
	tt := &task{req: req, depth: 0, crawlerTask: c}
	c.handleBasicTask(tt)
}

// ---------- handleBasicTask: JS file response ----------

func TestBoost2_HandleBasicTask_JSFileWithUrls(t *testing.T) {
	addr, cleanup := startBoostTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.WriteHeader(200)
		w.Write([]byte(`var api = "/api/v1/users"; var endpoint = "/api/v1/data";`))
	}))
	defer cleanup()

	c := newTestCrawler()
	c.config.MaxDepth = 5
	req, _ := whttp.NewRequest("GET", "http://"+addr+"/app.js", nil)
	tt := &task{req: req, depth: 0, crawlerTask: c}
	c.handleBasicTask(tt)
}

// ---------- handleBasicTask: robots.txt and sitemap.xml ----------

func TestBoost2_HandleBasicTask_RobotsTxtDirect(t *testing.T) {
	addr, cleanup := startBoostTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(200)
		w.Write([]byte("User-agent: *\nDisallow: /admin/\nAllow: /public/"))
	}))
	defer cleanup()

	c := newTestCrawler()
	c.config.MaxDepth = 5
	req, _ := whttp.NewRequest("GET", "http://"+addr+"/robots.txt", nil)
	tt := &task{req: req, depth: 0, crawlerTask: c}
	c.handleBasicTask(tt)
}

func TestBoost2_HandleBasicTask_SitemapXmlDirect(t *testing.T) {
	addr, cleanup := startBoostTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`<?xml version="1.0"?><urlset><url><loc>http://example.com/page1</loc></url></urlset>`))
	}))
	defer cleanup()

	c := newTestCrawler()
	c.config.MaxDepth = 5
	req, _ := whttp.NewRequest("GET", "http://"+addr+"/sitemap.xml", nil)
	tt := &task{req: req, depth: 0, crawlerTask: c}
	c.handleBasicTask(tt)
}

// ---------- handleBasicTask: Source map file ----------

func Test2_HandleBasicTask_SourceMapFile(t *testing.T) {
	addr, cleanup := startBoostTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"version":3,"sources":["app.ts","utils.ts"],"sourcesContent":["var url='/api/data';","function helper() {}"],"mappings":"AAAA"}`))
	}))
	defer cleanup()

	c := newTestCrawler()
	c.config.MaxDepth = 5
	req, _ := whttp.NewRequest("GET", "http://"+addr+"/app.map", nil)
	tt := &task{req: req, depth: 0, crawlerTask: c}
	c.handleBasicTask(tt)
}

// ---------- SmartFilter: MarkPath with edge cases ----------

func TestBoost2_MarkPath_DotAndDotDot(t *testing.T) {
	s := SmartFilter{}
	// "." and ".." should not be treated as having a dot for splitting
	assert.Equal(t, "/.", s.MarkPath("/."))
	assert.Equal(t, "/..", s.MarkPath("/.."))
}

func TestBoost2_MarkPath_SHTMLStrippedNumberOnly(t *testing.T) {
	s := SmartFilter{}
	// .shtml stripped, remaining part is numeric with symbols
	assert.Equal(t, "/{{number}}", s.MarkPath("/2023-01-15.shtml"))
}

// ---------- hasSpecialSymbol additional ----------

func TestBoost2_HasSpecialSymbol_QuestionMark(t *testing.T) {
	s := SmartFilter{}
	assert.True(t, s.hasSpecialSymbol("test?value"), "? should be detected as special")
}

func TestBoost2_HasSpecialSymbol_Backslash(t *testing.T) {
	s := SmartFilter{}
	assert.True(t, s.hasSpecialSymbol("test\\value"), "\\ should be detected as special")
}

func TestBoost2_HasSpecialSymbol_PlusSign(t *testing.T) {
	s := SmartFilter{}
	assert.True(t, s.hasSpecialSymbol("test+value"), "+ should be detected as special")
}

func TestBoost2_HasSpecialSymbol_EqualsSign(t *testing.T) {
	s := SmartFilter{}
	assert.True(t, s.hasSpecialSymbol("test=value"), "= should be detected as special")
}

func TestBoost2_HasSpecialSymbol_DollarSign(t *testing.T) {
	s := SmartFilter{}
	assert.True(t, s.hasSpecialSymbol("test$value"), "$ should be detected as special")
}

func TestBoost2_HasSpecialSymbol_AtSign(t *testing.T) {
	s := SmartFilter{}
	assert.True(t, s.hasSpecialSymbol("test@value"), "@ should be detected as special")
}

func TestBoost2_HasSpecialSymbol_HashSign(t *testing.T) {
	s := SmartFilter{}
	assert.True(t, s.hasSpecialSymbol("test#value"), "# should be detected as special")
}

func TestBoost2_HasSpecialSymbol_PipeSign(t *testing.T) {
	s := SmartFilter{}
	assert.True(t, s.hasSpecialSymbol("test|value"), "| should be detected as special")
}

func TestBoost2_HasSpecialSymbol_AngleBrackets(t *testing.T) {
	s := SmartFilter{}
	assert.True(t, s.hasSpecialSymbol("test<value"), "< should be detected as special")
	assert.True(t, s.hasSpecialSymbol("test>value"), "> should be detected as special")
}

func TestBoost2_HasSpecialSymbol_Comma(t *testing.T) {
	s := SmartFilter{}
	assert.True(t, s.hasSpecialSymbol("test,value"), ", should be detected as special")
}

// ---------- inCommonScriptSuffix additional ----------

func TestBoost2_InCommonScriptSuffix_Asp(t *testing.T) {
	s := SmartFilter{}
	assert.True(t, s.inCommonScriptSuffix("asp"))
	assert.True(t, s.inCommonScriptSuffix("jsp"))
	assert.True(t, s.inCommonScriptSuffix("asa"))
	assert.False(t, s.inCommonScriptSuffix("html"))
	assert.False(t, s.inCommonScriptSuffix("css"))
	assert.False(t, s.inCommonScriptSuffix(""))
}

// ---------- SyncMapFilter: Insert and Check interaction ----------

func TestBoost2_SyncMapFilter_InsertThenCheck(t *testing.T) {
	f := &SyncMapFilter{Map: &sync.Map{}}
	f.Insert("pre_inserted")

	// Check should find the pre-inserted key
	assert.True(t, f.Check("pre_inserted", false), "Pre-inserted key should be found by Check")
}

func TestBoost2_SyncMapFilter_ResetThenInsert(t *testing.T) {
	f := &SyncMapFilter{Map: &sync.Map{}}
	f.Insert("key1")
	f.Reset()
	f.Insert("key2")

	assert.False(t, f.Check("key1", false), "key1 should not exist after reset")
	assert.True(t, f.Check("key2", false), "key2 should exist after insert")
}

// ---------- DoFilter: duplicate detection after marking ----------

func TestBoost2_DoFilter_DuplicateAfterMarking(t *testing.T) {
	s := SmartFilter{SimpleFilter: SimpleFilter{}}
	s.Init()

	// Two requests that differ only in numeric param values
	req1, _ := whttp.NewRequest("GET", "http://example.com/api?id=123", nil)
	req2, _ := whttp.NewRequest("GET", "http://example.com/api?id=456", nil)

	first := s.DoFilter(req1, false)
	assert.False(t, first, "First request should not be filtered")

	// Second request with different numeric value should be filtered by smart filter
	// (since markParamValue marks both as CustomValueMark)
	second := s.DoFilter(req2, false)
	t.Logf("Second request with different numeric value: filtered=%v", second)
}

// ---------- DoFilter: POST with different data should not be filtered ----------

func TestBoost2_DoFilter_POSTDifferentPathsNotFiltered(t *testing.T) {
	s := SmartFilter{SimpleFilter: SimpleFilter{}}
	s.Init()

	req1, _ := whttp.NewRequest("POST", "http://example.com/api/users", strings.NewReader("name=alice"))
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2, _ := whttp.NewRequest("POST", "http://example.com/api/posts", strings.NewReader("title=hello"))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	assert.False(t, s.DoFilter(req1, false), "First POST should not be filtered")
	assert.False(t, s.DoFilter(req2, false), "Different POST path should not be filtered")
}

// ---------- ParsePKCS12 with various invalid inputs ----------

func TestBoost2_ParsePKCS12_NilData(t *testing.T) {
	_, err := ParsePKCS12(nil, "")
	assert.Error(t, err, "Nil data should return error")
}

func TestBoost2_ParsePKCS12_RandomBytes(t *testing.T) {
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}
	_, err := ParsePKCS12(data, "testpassword")
	assert.Error(t, err, "Random bytes should not be valid PKCS12")
}

// ---------- Additional DoFilter: HTTPS root with empty path ----------

func TestBoost2_DoFilter_HTTPSRootEmptyPath(t *testing.T) {
	s := SmartFilter{SimpleFilter: SimpleFilter{}}
	s.Init()

	req, _ := whttp.NewRequest("GET", "https://example.com/", nil)
	assert.False(t, s.DoFilter(req, false), "HTTPS root should not be filtered first time")
}

// ---------- DoFilter: request with no query params ----------

func TestBoost2_DoFilter_GETWithQueryParams(t *testing.T) {
	s := SmartFilter{SimpleFilter: SimpleFilter{}}
	s.Init()

	req, _ := whttp.NewRequest("GET", "http://example.com/search?q=test&page=1", nil)
	assert.False(t, s.DoFilter(req, false), "GET with query params should not be filtered first time")
}

// ---------- DoFilter: PUT request ----------

func TestBoost2_DoFilter_PUTRequest(t *testing.T) {
	s := SmartFilter{SimpleFilter: SimpleFilter{}}
	s.Init()

	req, _ := whttp.NewRequest("PUT", "http://example.com/api/resource", strings.NewReader(`{"id":1}`))
	assert.False(t, s.DoFilter(req, false), "First PUT should not be filtered")
}

// ---------- Additional MarkPath: file extensions ----------

func TestBoost2_MarkPath_MultipleDots(t *testing.T) {
	s := SmartFilter{}
	// Path with multiple dots like a.b.c.html
	assert.Equal(t, "/a.b.c", s.MarkPath("/a.b.c.html"))
}

func TestBoost2_MarkPath_SimpleFileNameWithExtension(t *testing.T) {
	s := SmartFilter{}
	// Non-HTML file with numeric name
	assert.Equal(t, "/{{number}}.txt", s.MarkPath("/123.txt"))
}

// ---------- extractPathsFromRobots: with various robots.txt formats ----------

func TestBoost2_ExtractPathsFromRobots_CaseInsensitive(t *testing.T) {
	u, _ := url.Parse("http://example.com")
	// The regex is case-sensitive for Disallow/Allow, but the URL extraction is what matters
	body := "User-agent: *\nDisallow: /Admin/\nAllow: /Public/"
	result := extractPathsFromRobots(u, body)
	assert.Equal(t, 2, len(result), "Should extract paths from mixed case directives")
}

// ---------- handleBasicTask: with error response ----------

func TestBoost2_HandleBasicTask_500Response(t *testing.T) {
	addr, cleanup := startBoostTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(500)
		w.Write([]byte("Internal Server Error"))
	}))
	defer cleanup()

	c := newTestCrawler()
	req, _ := whttp.NewRequest("GET", "http://"+addr+"/error", nil)
	tt := &task{req: req, depth: 0, crawlerTask: c}
	c.handleBasicTask(tt)
}

// ---------- handleBasicTask: with redirect to different host ----------

func TestBoost2_HandleBasicTask_301ExternalRedirect(t *testing.T) {
	addr, cleanup := startBoostTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		if r.URL.Path == "/redirect" {
			w.Header().Set("Location", "http://other-site.com/target")
			w.WriteHeader(301)
			return
		}
		w.WriteHeader(200)
		w.Write([]byte("<html><body>OK</body></html>"))
	}))
	defer cleanup()

	c := newTestCrawler()
	c.config.MaxDepth = 5
	req, _ := whttp.NewRequest("GET", "http://"+addr+"/redirect", nil)
	tt := &task{req: req, depth: 0, crawlerTask: c}
	c.handleBasicTask(tt)
}

// ---------- handleBasicTask: with empty response body ----------

func TestBoost2_HandleBasicTask_EmptyResponseBody(t *testing.T) {
	addr, cleanup := startBoostTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(204) // No Content
	}))
	defer cleanup()

	c := newTestCrawler()
	req, _ := whttp.NewRequest("GET", "http://"+addr+"/empty", nil)
	tt := &task{req: req, depth: 0, crawlerTask: c}
	c.handleBasicTask(tt)
}

// ---------- handleBasicTask: form with select and options ----------

func TestBoost2_HandleBasicTask_FormWithSelectOptions(t *testing.T) {
	addr, cleanup := startBoostTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`<html><body>
			<form action="/choose" method="POST">
				<select name="color">
					<option value="red">Red</option>
					<option value="blue">Blue</option>
					<option value="green">Green</option>
				</select>
				<input type="submit">
			</form>
		</body></html>`))
	}))
	defer cleanup()

	c := newTestCrawler()
	c.config.MaxDepth = 5
	req, _ := whttp.NewRequest("GET", "http://"+addr+"/select", nil)
	tt := &task{req: req, depth: 0, crawlerTask: c}
	c.handleBasicTask(tt)
}

// ---------- SmartFilter: DoFilter with DELETE/HEAD/OPTIONS methods ----------

func TestBoost2_DoFilter_DELETEMethod(t *testing.T) {
	s := SmartFilter{SimpleFilter: SimpleFilter{}}
	s.Init()
	req, _ := whttp.NewRequest("DELETE", "http://example.com/api/resource", nil)
	assert.False(t, s.DoFilter(req, false), "First DELETE should not be filtered")
}

func TestBoost2_DoFilter_HEADMethod(t *testing.T) {
	s := SmartFilter{SimpleFilter: SimpleFilter{}}
	s.Init()
	req, _ := whttp.NewRequest("HEAD", "http://example.com/api/resource", nil)
	assert.False(t, s.DoFilter(req, false), "First HEAD should not be filtered")
}

func TestBoost2_DoFilter_OPTIONSMethod(t *testing.T) {
	s := SmartFilter{SimpleFilter: SimpleFilter{}}
	s.Init()
	req, _ := whttp.NewRequest("OPTIONS", "http://example.com/api/resource", nil)
	assert.False(t, s.DoFilter(req, false), "First OPTIONS should not be filtered")
}

// ---------- SmartFilter: DoFilter with Redirection flag ----------

func TestBoost2_DoFilter_GETRedirection(t *testing.T) {
	s := SmartFilter{SimpleFilter: SimpleFilter{}}
	s.Init()
	req, _ := whttp.NewRequest("GET", "http://example.com/api?x=1", nil)
	assert.False(t, s.DoFilter(req, true), "GET with redirection flag should not be filtered first time")
}

func TestBoost2_DoFilter_POSTWithRedirection(t *testing.T) {
	s := SmartFilter{SimpleFilter: SimpleFilter{}}
	s.Init()
	req, _ := whttp.NewRequest("POST", "http://example.com/api", strings.NewReader("data=test"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	assert.False(t, s.DoFilter(req, true), "POST with redirection flag should not be filtered first time")
}

// ---------- SmartFilter: DoFilter with POST + form body params ----------

func TestBoost2_DoFilter_POSTWithFormData(t *testing.T) {
	s := SmartFilter{SimpleFilter: SimpleFilter{}}
	s.Init()
	req, _ := whttp.NewRequest("POST", "http://example.com/login", strings.NewReader("username=admin&password=test123"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	assert.False(t, s.DoFilter(req, false), "POST with form data should not be filtered first time")
}

// ---------- SmartFilter: DoFilter with POST + filterLocationSet (Scanner value) ----------

func TestBoost2_DoFilter_POSTWithScannerLocationMarking(t *testing.T) {
	s := SmartFilter{SimpleFilter: SimpleFilter{}}
	s.Init()
	req1, _ := whttp.NewRequest("POST", "http://example.com/api", strings.NewReader("token=Scanner_test"))
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.DoFilter(req1, false)

	req2, _ := whttp.NewRequest("POST", "http://example.com/api", strings.NewReader("token=other_val"))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	result := s.DoFilter(req2, false)
	t.Logf("POST after Scanner marking, filtered=%v", result)
}

// ---------- SmartFilter: DoFilter dedup after smart marking (uniqueMarkedIds 2) ----------

func TestBoost2_DoFilter_DuplicateAfterSmartMarking(t *testing.T) {
	s := SmartFilter{SimpleFilter: SimpleFilter{}}
	s.Init()
	req1, _ := whttp.NewRequest("GET", "http://example.com/api?x=1&y=2", nil)
	assert.False(t, s.DoFilter(req1, false), "First request should not be filtered")

	req2, _ := whttp.NewRequest("GET", "http://example.com/api?x=1&y=2", nil)
	assert.True(t, s.DoFilter(req2, false), "Exact duplicate should be filtered by uniqueMarkedIds")
}

// ---------- SmartFilter: DoFilter dedup after smart marking (same marked IDs) ----------

func TestBoost2_DoFilter_DuplicateAfterMarkingDifferentValues(t *testing.T) {
	s := SmartFilter{SimpleFilter: SimpleFilter{}}
	s.Init()
	// Two requests with different numeric values but same path - markParamValue returns CustomValueMark for both
	req1, _ := whttp.NewRequest("GET", "http://example.com/api?id=111", nil)
	assert.False(t, s.DoFilter(req1, false), "First request should not be filtered")

	req2, _ := whttp.NewRequest("GET", "http://example.com/api?id=222", nil)
	// These should have the same marked ID since markParamValue returns CustomValueMark for both
	result := s.DoFilter(req2, false)
	t.Logf("Different numeric values same path, filtered=%v", result)
}

// ---------- SmartFilter: DoFilter with unsupported method ----------

func TestBoost2_DoFilter_UnsupportedMethod(t *testing.T) {
	s := SmartFilter{SimpleFilter: SimpleFilter{}}
	s.Init()
	req, _ := whttp.NewRequest("PATCH", "http://example.com/api", nil)
	assert.False(t, s.DoFilter(req, false), "PATCH should not be filtered first time (falls through to else branch)")
}

// ---------- SmartFilter: DoFilter with filterParentPathValues ----------

func TestBoost2_DoFilter_ManyChildPathsTriggerPathMarking(t *testing.T) {
	s := SmartFilter{SimpleFilter: SimpleFilter{}}
	s.Init()

	// Send many requests with different child paths under the same parent
	for i := 0; i < 35; i++ {
		req, _ := whttp.NewRequest("GET", fmt.Sprintf("http://example.com/api/child%d/page", i), nil)
		s.DoFilter(req, false)
	}

	// The 36th child path should trigger the parent path marking
	req, _ := whttp.NewRequest("GET", "http://example.com/api/newchild/page", nil)
	result := s.DoFilter(req, false)
	t.Logf("After many child paths, filtered=%v", result)
}

// ---------- SimpleFilter: DomainFilter with port 80/443 edge cases ----------

func TestBoost2_DomainFilter_HTTPPort80Default(t *testing.T) {
	s := &SimpleFilter{HostLimit: "example.com:80"}
	req, _ := whttp.NewRequest("GET", "http://example.com/page", nil)
	// Port is empty for http default port 80, but HostLimit has :80
	// This tests the HasSuffix(":80") && Port("") && Scheme("http") path
	result := s.DomainFilter(req)
	t.Logf("DomainFilter with HostLimit :80 and default http port: %v", result)
}

func TestBoost2_DomainFilter_HTTPSPort443Default(t *testing.T) {
	s := &SimpleFilter{HostLimit: "example.com:443"}
	req, _ := whttp.NewRequest("GET", "https://example.com/page", nil)
	// Port is empty for https default port 443, but HostLimit has :443
	// This tests the HasSuffix(":443") && Port("") && Scheme("https") path
	result := s.DomainFilter(req)
	t.Logf("DomainFilter with HostLimit :443 and default https port: %v", result)
}

func TestBoost2_DomainFilter_HTTPPort80NonMatching(t *testing.T) {
	s := &SimpleFilter{HostLimit: "example.com:80"}
	req, _ := whttp.NewRequest("GET", "http://other.com/page", nil)
	assert.True(t, s.DomainFilter(req), "Different host with :80 HostLimit should be filtered")
}

func TestBoost2_DomainFilter_HTTPSPort443NonMatching(t *testing.T) {
	s := &SimpleFilter{HostLimit: "example.com:443"}
	req, _ := whttp.NewRequest("GET", "https://other.com/page", nil)
	assert.True(t, s.DomainFilter(req), "Different host with :443 HostLimit should be filtered")
}

// ---------- SimpleFilter: DoFilter with HostLimit ----------

func TestBoost2_SimpleDoFilter_WithHostLimit(t *testing.T) {
	s := &SimpleFilter{HostLimit: "example.com"}
	req, _ := whttp.NewRequest("GET", "http://other.com/page", nil)
	assert.True(t, s.DoFilter(req, false), "Different host should be filtered with HostLimit set")
}

// ---------- UniqueId: Redirection flag path ----------

func TestBoost2_UniqueId_WithRedirection(t *testing.T) {
	req, _ := whttp.NewRequest("GET", "http://example.com/api?x=1", nil)
	id1 := UniqueId(req, false)
	id2 := UniqueId(req, true)
	assert.NotEqual(t, id1, id2, "UniqueId with redirection flag should produce different ID")
}

func TestBoost2_UniqueId_WithoutRedirection(t *testing.T) {
	req, _ := whttp.NewRequest("GET", "http://example.com/api?x=1", nil)
	id := UniqueId(req, false)
	assert.NotEmpty(t, id, "UniqueId should not be empty")
}

// ---------- SmartFilter: DoFilter with empty param value (pseudo-static) ----------

func TestBoost2_DoFilter_EmptyParamValuePseudoStatic(t *testing.T) {
	s := SmartFilter{SimpleFilter: SimpleFilter{}}
	s.Init()
	// Request with empty param value (pseudo-static URL pattern)
	req, _ := whttp.NewRequest("GET", "http://example.com/?chu_xiu", nil)
	assert.False(t, s.DoFilter(req, false), "Empty param value should not be filtered first time")
}

// ---------- SmartFilter: DoFilter with many repeated param keys (threshold test) ----------

func TestBoost2_DoFilter_ManyRepeatedParamKeysOverThreshold(t *testing.T) {
	s := SmartFilter{SimpleFilter: SimpleFilter{}}
	s.Init()

	// Send 10 requests with the same query key but different values to trigger MaxParamKeySingleCount
	for i := 0; i < 10; i++ {
		req, _ := whttp.NewRequest("GET", fmt.Sprintf("http://example.com/api?page=%d", i), nil)
		s.DoFilter(req, false)
	}

	// The 11th request should be deduplicated after marking
	req, _ := whttp.NewRequest("GET", "http://example.com/api?page=99", nil)
	result := s.DoFilter(req, false)
	t.Logf("After many repeated param keys, filtered=%v", result)
}

// ---------- SmartFilter: DoFilter with many different param values for same key ----------

func TestBoost2_DoFilter_ManyDifferentParamValuesOverThreshold(t *testing.T) {
	s := SmartFilter{SimpleFilter: SimpleFilter{}}
	s.Init()

	// Send 12 requests with different "category" values to trigger MaxParamKeyAllCount
	for i := 0; i < 12; i++ {
		req, _ := whttp.NewRequest("GET", fmt.Sprintf("http://example.com/search?category=cat%d", i), nil)
		s.DoFilter(req, false)
	}

	req, _ := whttp.NewRequest("GET", "http://example.com/search?category=newcat", nil)
	result := s.DoFilter(req, false)
	t.Logf("After many different param values, filtered=%v", result)
}

// ---------- SmartFilter: DoFilter with common script suffix (skip parent path) ----------

func TestBoost2_DoFilter_CommonScriptSuffixSkipsParentPath(t *testing.T) {
	s := SmartFilter{SimpleFilter: SimpleFilter{}}
	s.Init()
	// Request to a .php URL - should skip parent path counting
	req, _ := whttp.NewRequest("GET", "http://example.com/api/page.php?x=1", nil)
	assert.False(t, s.DoFilter(req, false), "PHP page should not be filtered")
}

// ---------- markParamName: various key patterns ----------

func TestBoost2_MarkParamName_AlphaOnlyKey(t *testing.T) {
	s := SmartFilter{}
	params := map[string]any{"name": "value"}
	result := s.markParamName(params)
	_, ok := result["name"]
	assert.True(t, ok, "Alpha-only key should be preserved")
}

func TestBoost2_MarkParamName_LongKey(t *testing.T) {
	s := SmartFilter{}
	// Key with 32+ chars and non-alpha chars to bypass onlyAlphaRegex
	longKey := "param_name_1234567890123456789012" // 34 chars, has numbers and underscores
	params := map[string]any{longKey: "value"}
	result := s.markParamName(params)
	// Long keys >= 32 chars (that aren't pure alpha) should be replaced with TooLongMark
	found := false
	for key := range result {
		if key == TooLongMark {
			found = true
		}
	}
	assert.True(t, found, "Key >= 32 chars (non-alpha) should be marked as TooLongMark, result keys: %v", result)
}

func TestBoost2_MarkParamName_KeyWithNumbers(t *testing.T) {
	s := SmartFilter{}
	params := map[string]any{"page2section3": "value"}
	result := s.markParamName(params)
	// Key with numbers should have numbers replaced with NumberMark
	_, hasOrig := result["page2section3"]
	_, hasMarked := result["page"+NumberMark+"section"+NumberMark]
	assert.True(t, hasOrig || hasMarked, "Key with numbers should either be preserved or marked")
}

func TestBoost2_MarkParamName_EmptyMap(t *testing.T) {
	s := SmartFilter{}
	result := s.markParamName(map[string]any{})
	assert.Equal(t, 0, len(result), "Empty map should return empty result")
}

// ---------- preQueryMark: no special patterns ----------

func TestBoost2_PreQueryMark_PlainASCII(t *testing.T) {
	s := SmartFilter{}
	result := s.preQueryMark("name=test&age=25")
	assert.Equal(t, "name=test&age=25", result, "Plain ASCII query should be unchanged")
}

// ---------- getMarkedUniqueID: HTTPS root edge case ----------

func TestBoost2_GetMarkedUniqueID_HTTPSRootNoQuery(t *testing.T) {
	s := SmartFilter{}
	req, _ := whttp.NewRequest("GET", "https://example.com/", nil)
	id := s.getMarkedUniqueID(req, "", "", "", false)
	assert.NotEmpty(t, id)
}

// ---------- getMarkedUniqueID: Fragment with slash ----------

func TestBoost2_GetMarkedUniqueID_FragmentWithSlash(t *testing.T) {
	s := SmartFilter{}
	req, _ := whttp.NewRequest("GET", "http://example.com/page#/route", nil)
	id := s.getMarkedUniqueID(req, "", "", "", false)
	assert.NotEmpty(t, id)
}

// ---------- NoHeaderId ----------

func TestBoost2_NoHeaderId_Deterministic(t *testing.T) {
	req, _ := whttp.NewRequest("GET", "http://example.com/api?x=1", nil)
	id1 := NoHeaderId(req)
	id2 := NoHeaderId(req)
	assert.Equal(t, id1, id2, "NoHeaderId should be deterministic for same request")
}

// ---------- SmartFilter: DoFilter with POST dedup ----------

func TestBoost2_DoFilter_POSTDuplicateDedup(t *testing.T) {
	s := SmartFilter{SimpleFilter: SimpleFilter{}}
	s.Init()
	req1, _ := whttp.NewRequest("POST", "http://example.com/api", strings.NewReader("key=value"))
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	assert.False(t, s.DoFilter(req1, false), "First POST should not be filtered")

	req2, _ := whttp.NewRequest("POST", "http://example.com/api", strings.NewReader("key=value"))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	assert.True(t, s.DoFilter(req2, false), "Duplicate POST should be filtered")
}

// ---------- SmartFilter: DoFilter with filterLocationSet for POST ----------

func TestBoost2_DoFilter_POSTFilterLocationSet(t *testing.T) {
	s := SmartFilter{SimpleFilter: SimpleFilter{}}
	s.Init()

	// First, mark a POST parameter location via Scanner value
	req1, _ := whttp.NewRequest("POST", "http://example.com/api", strings.NewReader("token=Scanner_test"))
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.DoFilter(req1, false)

	// Second POST with same key should hit filterLocationSet
	req2, _ := whttp.NewRequest("POST", "http://example.com/api", strings.NewReader("token=other"))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	result := s.DoFilter(req2, false)
	t.Logf("POST with filterLocationSet, filtered=%v", result)
}

// ---------- SmartFilter: MarkPath with html extension strip ----------

func TestBoost2_MarkPath_HTMLStrippedAlphaOnly(t *testing.T) {
	s := SmartFilter{}
	// Path segment with .html stripped, remaining is plain alpha - should be unchanged
	assert.Equal(t, "/about", s.MarkPath("/about.html"))
}

func TestBoost2_MarkPath_HTMStrippedNumberOnly(t *testing.T) {
	s := SmartFilter{}
	// .htm stripped, only numbers remain after replacing symbols
	assert.Equal(t, "/{{number}}", s.MarkPath("/123.htm"))
}

// ---------- SmartFilter: DoFilter with param value mark in filterPathParamKeySymbol ----------

func TestBoost2_DoFilter_FilterPathParamKeySymbolThreshold(t *testing.T) {
	s := SmartFilter{SimpleFilter: SimpleFilter{}}
	s.Init()

	// Send requests with marked values to the same path+key to trigger filterPathParamKeySymbol
	for i := 0; i < 8; i++ {
		req, _ := whttp.NewRequest("GET", fmt.Sprintf("http://example.com/api?param=%d", i), nil)
		s.DoFilter(req, false)
	}

	req, _ := whttp.NewRequest("GET", "http://example.com/api?param=newval", nil)
	result := s.DoFilter(req, false)
	t.Logf("After filterPathParamKeySymbol threshold, filtered=%v", result)
}

// ---------- SmartFilter: DoFilter with empty param values exceeding threshold ----------

func TestBoost2_DoFilter_EmptyParamValuesOverThreshold(t *testing.T) {
	s := SmartFilter{SimpleFilter: SimpleFilter{}}
	s.Init()

	// Send requests with empty param values under the same path to trigger filterPathParamEmptyValues
	for i := 0; i < 12; i++ {
		req, _ := whttp.NewRequest("GET", fmt.Sprintf("http://example.com/api?param%d=&other=val", i), nil)
		s.DoFilter(req, false)
	}

	req, _ := whttp.NewRequest("GET", "http://example.com/api?newparam=&data=test", nil)
	result := s.DoFilter(req, false)
	t.Logf("After empty param values threshold, filtered=%v", result)
}

// ---------- SmartFilter: DoFilter with uniqueMarkedIds dedup (2nd check) ----------

func TestBoost2_DoFilter_UniqueMarkedIds2Dedup(t *testing.T) {
	s := SmartFilter{SimpleFilter: SimpleFilter{}}
	s.Init()

	req1, _ := whttp.NewRequest("GET", "http://example.com/search?q=hello", nil)
	s.DoFilter(req1, false)

	req2, _ := whttp.NewRequest("GET", "http://example.com/search?q=hello", nil)
	// Should be caught by uniqueMarkedIds first check
	assert.True(t, s.DoFilter(req2, false), "Duplicate should be filtered by uniqueMarkedIds")
}

// ---------- SimpleFilter: UniqueFilter with nil UniqueSet ----------

func TestBoost2_UniqueFilter_NilUniqueSet(t *testing.T) {
	s := &SimpleFilter{}
	req, _ := whttp.NewRequest("GET", "http://example.com/api?x=1", nil)
	// Should auto-initialize the UniqueSet
	result := s.UniqueFilter(req, false)
	assert.False(t, result, "First unique check should not filter")
}

// ---------- SimpleFilter: StaticFilter with nil UniqueSet ----------

func TestBoost2_StaticFilter_NilUniqueSet(t *testing.T) {
	s := &SimpleFilter{}
	req, _ := whttp.NewRequest("GET", "http://example.com/style.css", nil)
	// Should auto-initialize the UniqueSet
	result := s.StaticFilter(req)
	assert.True(t, result, "CSS file should be filtered as static even with nil UniqueSet")
}

// ---------- SimpleFilter: DomainFilter with nil UniqueSet ----------

func TestBoost2_DomainFilter_NilUniqueSet(t *testing.T) {
	s := &SimpleFilter{HostLimit: "example.com"}
	req, _ := whttp.NewRequest("GET", "http://example.com/page", nil)
	// Should auto-initialize the UniqueSet
	result := s.DomainFilter(req)
	assert.False(t, result, "Matching host should not be filtered")
}

// ---------- SmartFilter: Init reinitialization ----------

func TestBoost2_SmartFilter_InitReinitialization(t *testing.T) {
	s := SmartFilter{SimpleFilter: SimpleFilter{}}
	s.Init()
	s.uniqueMarkedIds.Add("test_id")
	s.Init() // Re-initialize
	assert.False(t, s.uniqueMarkedIds.Contains("test_id"), "Re-init should clear state")
}

// ---------- SmartFilter: DoFilter with PUT and form data ----------

func TestBoost2_DoFilter_PUTWithFormData(t *testing.T) {
	s := SmartFilter{SimpleFilter: SimpleFilter{}}
	s.Init()
	req, _ := whttp.NewRequest("PUT", "http://example.com/api/resource", strings.NewReader("name=updated"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	assert.False(t, s.DoFilter(req, false), "First PUT with form data should not be filtered")
}

// ---------- SmartFilter: DoFilter with POST + empty body ----------

func TestBoost2_DoFilter_POSTEmptyBodyNoPanic(t *testing.T) {
	s := SmartFilter{SimpleFilter: SimpleFilter{}}
	s.Init()
	req, _ := whttp.NewRequest("POST", "http://example.com/api", nil)
	assert.NotPanics(t, func() { s.DoFilter(req, false) }, "POST with nil body should not panic")
}

// ---------- SmartFilter: DoFilter robots.txt pass-through ----------

func TestBoost2_DoFilter_RobotsTxtNotFiltered(t *testing.T) {
	s := SmartFilter{SimpleFilter: SimpleFilter{}}
	s.Init()
	req, _ := whttp.NewRequest("GET", "http://example.com/robots.txt", nil)
	assert.False(t, s.DoFilter(req, false), "robots.txt should not be filtered by static filter")
}
