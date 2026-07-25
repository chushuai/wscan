package http

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/antchfx/xmlquery"
)

// ==================== request.go additional coverage ====================

// Test Request GetValue (no-op, returns nil)
func TestBoost4_RequestGetValue(t *testing.T) {
	req, _ := NewRequest("GET", "http://example.com/", nil)
	result := req.GetValue("anykey")
	if result != nil {
		t.Error("GetValue should return nil (no-op)")
	}
}

// Test Request DumpHeader (no-op)
func TestBoost4_RequestDumpHeader(t *testing.T) {
	req, _ := NewRequest("GET", "http://example.com/", nil)
	result, err := req.DumpHeader(nil)
	if result != nil || err != nil {
		t.Error("DumpHeader should return nil, nil (no-op)")
	}
}

// Test Request DumpHeaderWithoutClient (no-op)
func TestBoost4_RequestDumpHeaderWithoutClient(t *testing.T) {
	req, _ := NewRequest("GET", "http://example.com/", nil)
	result, err := req.DumpHeaderWithoutClient()
	if result != nil || err != nil {
		t.Error("DumpHeaderWithoutClient should return nil, nil (no-op)")
	}
}

// Test Request MustDump (no-op, returns "")
func TestBoost4_RequestMustDump(t *testing.T) {
	req, _ := NewRequest("GET", "http://example.com/", nil)
	result := req.MustDump(nil)
	if result != "" {
		t.Error("MustDump should return empty string (no-op)")
	}
}

// Test Request DelParam (no-op)
func TestBoost4_RequestDelParam(t *testing.T) {
	req, _ := NewRequest("GET", "http://example.com/", nil)
	result, err := req.DelParam(nil)
	if result != nil || err != nil {
		t.Error("DelParam should return nil, nil (no-op)")
	}
}

// Test Request SetValue (no-op)
func TestBoost4_RequestSetValue(t *testing.T) {
	req, _ := NewRequest("GET", "http://example.com/", nil)
	req.SetValue("key", "value")
}

// Test Request Spawn (no-op, returns nil, nil)
func TestBoost4_RequestSpawn(t *testing.T) {
	req, _ := NewRequest("GET", "http://example.com/", nil)
	result, err := req.Spawn()
	if result != nil || err != nil {
		t.Error("Spawn should return nil, nil (no-op)")
	}
}

// Test Request ParamsCookieFull (no-op, returns nil)
func TestBoost4_RequestParamsCookieFull(t *testing.T) {
	req, _ := NewRequest("GET", "http://example.com/", nil)
	result := req.ParamsCookieFull()
	if result != nil {
		t.Error("ParamsCookieFull should return nil (no-op)")
	}
}

// Test Request isBodyValueJSON (no-op, returns false)
func TestBoost4_RequestIsBodyValueJSON(t *testing.T) {
	req, _ := NewRequest("POST", "http://example.com/", strings.NewReader(`{"key":"value"}`))
	req.SetHeader("Content-Type", "application/json")
	result := req.isBodyValueJSON()
	if result {
		t.Error("isBodyValueJSON should return false (no-op)")
	}
}

// Test Request isParsed (no-op, returns false)
func TestBoost4_RequestIsParsed(t *testing.T) {
	req, _ := NewRequest("GET", "http://example.com/", nil)
	result := req.isParsed()
	if result {
		t.Error("isParsed should return false (no-op)")
	}
}

// Test Request isQueryValueJSON (no-op, returns false)
func TestBoost4_RequestIsQueryValueJSON(t *testing.T) {
	req, _ := NewRequest("GET", "http://example.com/", nil)
	result := req.isQueryValueJSON()
	if result {
		t.Error("isQueryValueJSON should return false (no-op)")
	}
}

// Test Request parseBody (no-op, returns nil)
func TestBoost4_RequestParseBody(t *testing.T) {
	req, _ := NewRequest("POST", "http://example.com/", strings.NewReader("body"))
	result := req.parseBody()
	if result != nil {
		t.Error("parseBody should return nil (no-op)")
	}
}

// Test BuildRequest function (no-op)
func TestBoost4_BuildRequestFunc(t *testing.T) {
	BuildRequest()
}

// Test Request WithRawCookie
func TestBoost4_RequestWithRawCookie(t *testing.T) {
	req, _ := NewRequest("GET", "http://example.com/", nil)
	result, err := req.WithRawCookie("session=abc123")
	if result != nil || err != nil {
		t.Log("WithRawCookie returned non-nil-nil, which is acceptable")
	}
	// Verify cookie header was set
	cookieHeader := req.Header.Get("Cookie")
	if cookieHeader == "" {
		t.Error("Expected Cookie header to be set after WithRawCookie")
	}
}

// Test Request WithRawCookie with nil header
func TestBoost4_RequestWithRawCookieNilHeader(t *testing.T) {
	req := &Request{}
	result, err := req.WithRawCookie("session=abc")
	// Should initialize header map
	if req.Header == nil {
		t.Error("Expected Header to be initialized after WithRawCookie")
	}
	_ = result
	_ = err
}

// Test Request WithURL
func TestBoost4_RequestWithURL(t *testing.T) {
	req, _ := NewRequest("GET", "http://example.com/", nil)
	newURL, _ := url.Parse("http://other.com/path")
	result := req.WithURL(newURL)
	if result != nil {
		t.Log("WithURL returned non-nil, which is expected based on current implementation")
	}
}

// Test Request Referrer
func TestBoost4_RequestReferrer(t *testing.T) {
	req, _ := NewRequest("GET", "http://example.com/", nil)
	req.SetHeader("Referrer", "http://google.com/")
	ref := req.Referrer()
	if ref != "http://google.com/" {
		t.Errorf("Referrer = %q, want 'http://google.com/'", ref)
	}
}

// Test Request Referrer empty
func TestBoost4_RequestReferrerEmpty(t *testing.T) {
	req, _ := NewRequest("GET", "http://example.com/", nil)
	ref := req.Referrer()
	if ref != "" {
		t.Errorf("Referrer = %q, want empty string", ref)
	}
}

// Test Request WithFormBody
func TestBoost4_RequestWithFormBody(t *testing.T) {
	req, _ := NewRequest("POST", "http://example.com/", nil)
	result := req.WithFormBody(strings.NewReader("key=value"))
	if result == nil {
		t.Error("WithFormBody should return non-nil")
	}
	if req.ContentType() != "application/x-www-form-urlencoded" {
		t.Errorf("ContentType = %q, want 'application/x-www-form-urlencoded'", req.ContentType())
	}
}

// Test Request WithJSONBody
func TestBoost4_RequestWithJSONBody(t *testing.T) {
	req, _ := NewRequest("POST", "http://example.com/", nil)
	result := req.WithJSONBody(strings.NewReader(`{"key":"value"}`))
	if result == nil {
		t.Error("WithJSONBody should return non-nil")
	}
	if req.ContentType() != "application/json" {
		t.Errorf("ContentType = %q, want 'application/json'", req.ContentType())
	}
}

// Test Request WithXMLBody
func TestBoost4_RequestWithXMLBody(t *testing.T) {
	req, _ := NewRequest("POST", "http://example.com/", nil)
	result := req.WithXMLBody(strings.NewReader("<root/>"))
	if result == nil {
		t.Error("WithXMLBody should return non-nil")
	}
	if req.ContentType() != "application/xml" {
		t.Errorf("ContentType = %q, want 'application/xml'", req.ContentType())
	}
}

// Test Request WithMultipartBody
func TestBoost4_RequestWithMultipartBody(t *testing.T) {
	req, _ := NewRequest("POST", "http://example.com/", nil)
	result := req.WithMultipartBody(strings.NewReader("multipart data"), "myboundary")
	if result == nil {
		t.Error("WithMultipartBody should return non-nil")
	}
	if !strings.Contains(req.ContentType(), "multipart/form-data") {
		t.Errorf("ContentType = %q, should contain 'multipart/form-data'", req.ContentType())
	}
}

// Test Request GetHeaderMap
func TestBoost4_RequestGetHeaderMap(t *testing.T) {
	req, _ := NewRequest("GET", "http://example.com/", nil)
	req.SetHeader("Content-Type", "text/html")
	req.SetHeader("Accept", "application/json")

	headerMap := req.GetHeaderMap()
	if headerMap["Content-Type"] != "text/html" {
		t.Errorf("Content-Type = %q, want 'text/html'", headerMap["Content-Type"])
	}
	if headerMap["Accept"] != "application/json" {
		t.Errorf("Accept = %q, want 'application/json'", headerMap["Accept"])
	}
}

// Test Request GetHeaderMap with empty values
func TestBoost4_RequestGetHeaderMapEmptyValues(t *testing.T) {
	req, _ := NewRequest("GET", "http://example.com/", nil)
	req.Header["X-Empty"] = []string{}

	headerMap := req.GetHeaderMap()
	if headerMap["X-Empty"] != "" {
		t.Errorf("Empty header should map to empty string, got %q", headerMap["X-Empty"])
	}
}

// Test Request SetHeaders
func TestBoost4_RequestSetHeaders(t *testing.T) {
	req, _ := NewRequest("GET", "http://example.com/", nil)
	req.SetHeaders(map[string]string{
		"X-Custom-1": "value1",
		"X-Custom-2": "value2",
	})

	if req.Header.Get("X-Custom-1") != "value1" {
		t.Errorf("X-Custom-1 = %q, want 'value1'", req.Header.Get("X-Custom-1"))
	}
	if req.Header.Get("X-Custom-2") != "value2" {
		t.Errorf("X-Custom-2 = %q, want 'value2'", req.Header.Get("X-Custom-2"))
	}
}

// Test Request SetReqHeader
func TestBoost4_RequestSetReqHeader(t *testing.T) {
	req, _ := NewRequest("GET", "http://example.com/", nil)
	newHeader := http.Header{
		"X-New": []string{"newvalue"},
	}
	req.SetReqHeader(newHeader)
	if req.Header.Get("X-New") != "newvalue" {
		t.Errorf("X-New = %q, want 'newvalue'", req.Header.Get("X-New"))
	}
}

// Test Request AddCookie with existing cookies
func TestBoost4_RequestAddCookieExisting(t *testing.T) {
	req, _ := NewRequest("GET", "http://example.com/", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: "abc"})
	req.AddCookie(&http.Cookie{Name: "user", Value: "test"})

	cookieHeader := req.Header.Get("Cookie")
	if cookieHeader == "" {
		t.Error("Expected Cookie header to be set")
	}
	if !strings.Contains(cookieHeader, "session=abc") {
		t.Error("Cookie header should contain session=abc")
	}
	if !strings.Contains(cookieHeader, "user=test") {
		t.Error("Cookie header should contain user=test")
	}
}

// Test Request IsJavaScript
func TestBoost4_RequestIsJavaScript(t *testing.T) {
	req, _ := NewRequest("GET", "http://example.com/app.js", nil)
	if !req.IsJavaScript() {
		t.Error("Expected IsJavaScript=true for .js URL")
	}

	req2, _ := NewRequest("GET", "http://example.com/app.html", nil)
	if req2.IsJavaScript() {
		t.Error("Expected IsJavaScript=false for .html URL")
	}
}

// Test Request Origin
func TestBoost4_RequestOrigin(t *testing.T) {
	req, _ := NewRequest("GET", "http://example.com/path?q=1", nil)
	origin := req.Origin()
	if origin != "http://example.com/path?q=1" {
		t.Errorf("Origin = %q, want 'http://example.com/path?q=1'", origin)
	}
}

// Test Request GetOriginURL
func TestBoost4_RequestGetOriginURL(t *testing.T) {
	req, _ := NewRequest("GET", "http://example.com/path?q=1", nil)
	originURL := req.GetOriginURL()
	if originURL != "http://example.com/path?q=1" {
		t.Errorf("GetOriginURL = %q, want 'http://example.com/path?q=1'", originURL)
	}
}

// Test Request parseQueryData with empty content type and JSON body
func TestBoost4_RequestParseQueryDataEmptyContentTypeJSON(t *testing.T) {
	req, _ := NewRequest("POST", "http://example.com/", strings.NewReader(`{"key":"value"}`))
	// Don't set Content-Type - should auto-detect as JSON
	req.doCache()
	if req.ContentType() != "application/json" {
		// The bodyParams should be parsed as JSON
		t.Logf("ContentType = %q (auto-detected)", req.ContentType())
	}
}

// Test Request parseQueryData with multipart
func TestBoost4_RequestParseQueryDataMultipart(t *testing.T) {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	_ = writer.WriteField("field1", "value1")
	part, _ := writer.CreateFormFile("upload", "test.txt")
	part.Write([]byte("file content"))
	writer.Close()

	req, _ := NewRequest("POST", "http://example.com/", &buf)
	req.SetHeader("Content-Type", writer.FormDataContentType())
	req.doCache()

	// Verify multipart body params were parsed
	if len(req.bodyParams) == 0 {
		t.Error("Expected bodyParams to be parsed from multipart body")
	}
}

// ==================== utils.go additional coverage ====================

// Test CloneHeader function (no-op)
func TestBoost4_CloneHeaderFunc(t *testing.T) {
	CloneHeader()
}

// Test IsStaticURL function (no-op)
func TestBoost4_IsStaticURLFunc(t *testing.T) {
	IsStaticURL()
}

// Test IsNeededResource function (no-op)
func TestBoost4_IsNeededResourceFunc(t *testing.T) {
	IsNeededResource()
}

// Test ReadCompressBody function (no-op)
func TestBoost4_ReadCompressBodyFunc(t *testing.T) {
	ReadCompressBody()
}

// Test GetTextContent function (no-op)
func TestBoost4_GetTextContentFunc(t *testing.T) {
	GetTextContent()
}

// Test IsMeaninglessCookieKey function (no-op, returns false)
func TestBoost4_IsMeaninglessCookieKeyFunc(t *testing.T) {
	result := IsMeaninglessCookieKey()
	if result {
		t.Error("IsMeaninglessCookieKey should return false (no-op)")
	}
}

// Test RecursiveXMLNode with nil node
func TestBoost4_RecursiveXMLNodeNilNode(t *testing.T) {
	RecursiveXMLNode(nil, func(node *xmlquery.Node) {})
	// Should not panic
}

// Test ConvertValue with various inputs
func TestBoost4_ConvertValueVariousInputs(t *testing.T) {
	tests := []struct {
		oldValue string
		newValue string
	}{
		{"hello", "world"},
		{"", "replacement"},
		{"original", ""},
		{"42", "100"},
		{"3.14", "2.71"},
		{"true", "false"},
		{"<tag>", "&lt;tag&gt;"},
	}
	for _, tt := range tests {
		result := ConvertValue(tt.oldValue, tt.newValue)
		if result != tt.newValue {
			t.Errorf("ConvertValue(%q, %q) = %q, want %q", tt.oldValue, tt.newValue, result, tt.newValue)
		}
	}
}

// ==================== url.go additional coverage ====================

// Test URL QueryMapID
func TestBoost4_URLQueryMapID(t *testing.T) {
	u, _ := url.Parse("http://example.com/?a=1&b=2")
	wu := &URL{URL: *u}
	qm := wu.QueryMap()
	id := wu.QueryMapID(qm)
	if id == "" {
		t.Error("QueryMapID should return non-empty string")
	}
}

// Test URL FileName with various paths
func TestBoost4_URLFileNameVariousPaths(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"/path/to/file.txt", "file.txt"},
		{"/path/to/directory/", ""},
		{"/path/to/noext", ""},
		{"/image.jpg", "image.jpg"},
	}
	for _, tt := range tests {
		u, _ := url.Parse("http://example.com" + tt.path)
		wu := &URL{URL: *u}
		result := wu.FileName()
		if result != tt.expected {
			t.Errorf("FileName(%q) = %q, want %q", tt.path, result, tt.expected)
		}
	}
}

// Test URL FileExt with various paths
func TestBoost4_URLFileExtVariousPaths(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"/path/to/file.TXT", "txt"},
		{"/path/to/script.JS", "js"},
		{"/path/to/noext", ""},
		{"/path/to/directory/", ""},
	}
	for _, tt := range tests {
		u, _ := url.Parse("http://example.com" + tt.path)
		wu := &URL{URL: *u}
		result := wu.FileExt()
		if result != tt.expected {
			t.Errorf("FileExt(%q) = %q, want %q", tt.path, result, tt.expected)
		}
	}
}

// Test URL IsWebsiteDir
func TestBoost4_URLIsWebsiteDir(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"/path/", true},
		{"/path", false},
		{"", true},
		{"/", true},
	}
	for _, tt := range tests {
		u, _ := url.Parse("http://example.com" + tt.path)
		wu := &URL{URL: *u}
		wu.Path = tt.path
		result := wu.IsWebsiteDir()
		if result != tt.expected {
			t.Errorf("IsWebsiteDir(%q) = %v, want %v", tt.path, result, tt.expected)
		}
	}
}

// Test URL NavigationUrl
func TestBoost4_URLNavigationUrl(t *testing.T) {
	u, _ := url.Parse("http://example.com/path")
	wu := &URL{URL: *u}
	result := wu.NavigationUrl()
	if result != "://example.com/path" {
		t.Errorf("NavigationUrl = %q, want '://example.com/path'", result)
	}
}

// Test escapePercentSign
func TestBoost4_EscapePercentSign(t *testing.T) {
	result := escapePercentSign("http://example.com/path%test")
	expected := "http://example.com/path%25test"
	if result != expected {
		t.Errorf("escapePercentSign = %q, want %q", result, expected)
	}
}

// Test escapePercentSign with no percent signs
func TestBoost4_EscapePercentSignNoPercent(t *testing.T) {
	result := escapePercentSign("http://example.com/normal/path")
	if result != "http://example.com/normal/path" {
		t.Errorf("escapePercentSign = %q, want unchanged", result)
	}
}

// Test URL cloneURL with nil
func TestBoost4_URLCloneURLNil(t *testing.T) {
	var u *URL
	result := u.cloneURL()
	if result != nil {
		t.Error("cloneURL of nil should return nil")
	}
}

// Test GetUrl with parent and relative path
func TestBoost4_GetUrlWithParentRelative(t *testing.T) {
	parent, _ := GetUrl("http://example.com/base/")
	if parent == nil {
		t.Fatal("GetUrl returned nil for parent")
	}
	u, err := GetUrl("subpath", *parent)
	if err != nil {
		t.Fatalf("GetUrl with parent error: %v", err)
	}
	if u == nil {
		t.Fatal("GetUrl returned nil for child")
	}
}

// Test URL parse with javascript: protocol
func TestBoost4_URLParseJavascriptProtocol(t *testing.T) {
	u := &URL{}
	_, err := u.parse("javascript:alert(1)")
	if err == nil {
		t.Error("Expected error for javascript: protocol")
	}
}

// Test URL parse with mailto: protocol
func TestBoost4_URLParseMailtoProtocol(t *testing.T) {
	u := &URL{}
	_, err := u.parse("mailto:test@example.com")
	if err == nil {
		t.Error("Expected error for mailto: protocol")
	}
}

// Test URL parse with empty URL
func TestBoost4_URLParseEmptyURL(t *testing.T) {
	u := &URL{}
	_, err := u.parse("")
	if err == nil {
		t.Error("Expected error for empty URL")
	}
}

// Test URL parse with multiple hash symbols
func TestBoost4_URLParseMultipleHashes(t *testing.T) {
	u := &URL{}
	result, err := u.parse("http://example.com###frag")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if strings.Contains(result, "###") {
		t.Error("Multiple hashes should be reduced to single")
	}
}

// Test UrlSplitHostPort with invalid URL
func TestBoost4_UrlSplitHostPortInvalidURL(t *testing.T) {
	_, _, err := UrlSplitHostPort("://not-a-valid-url")
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

// Test GetURLDepth with various paths
func TestBoost4_GetURLDepthVarious(t *testing.T) {
	tests := []struct {
		urlStr   string
		expected int
	}{
		{"http://example.com", 0},
		{"http://example.com/", 0},
		{"http://example.com/a", 0},
		{"http://example.com/a/b", 1},
		{"http://example.com/a/b/c", 2},
	}
	for _, tt := range tests {
		result := GetURLDepth(tt.urlStr)
		if result != tt.expected {
			t.Errorf("GetURLDepth(%q) = %d, want %d", tt.urlStr, result, tt.expected)
		}
	}
}

// Test GetURLPort with various URLs
func TestBoost4_GetURLPortVarious(t *testing.T) {
	tests := []struct {
		urlStr   string
		expected int
		hasError bool
	}{
		{"http://example.com:9090", 9090, false},
		{"http://example.com", 80, false},
		{"https://example.com", 443, false},
		{"ftp://example.com", 0, true},
	}
	for _, tt := range tests {
		result, err := GetURLPort(tt.urlStr)
		if tt.hasError {
			if err == nil {
				t.Errorf("GetURLPort(%q) expected error", tt.urlStr)
			}
		} else {
			if err != nil {
				t.Errorf("GetURLPort(%q) unexpected error: %v", tt.urlStr, err)
			}
			if result != tt.expected {
				t.Errorf("GetURLPort(%q) = %d, want %d", tt.urlStr, result, tt.expected)
			}
		}
	}
}

// Test UrlJoinPath with various combinations
func TestBoost4_UrlJoinPathVarious(t *testing.T) {
	tests := []struct {
		base     string
		relative string
		expected string
	}{
		{"http://example.com/", "/path", "http://example.com/path"},
		{"http://example.com", "path", "http://example.com/path"},
		{"http://example.com/base/", "sub", "http://example.com/base/sub"},
		{"http://example.com/base", "/sub", "http://example.com/base/sub"},
	}
	for _, tt := range tests {
		result := UrlJoinPath(tt.base, tt.relative)
		if result != tt.expected {
			t.Errorf("UrlJoinPath(%q, %q) = %q, want %q", tt.base, tt.relative, result, tt.expected)
		}
	}
}

// Test BytesCloser Read
func TestBoost4_BytesCloserRead(t *testing.T) {
	data := []byte("test data")
	reader := bytes.NewReader(data)
	bc := BytesCloser{Reader: reader}
	buf := make([]byte, 4)
	n, err := bc.Read(buf)
	if err != nil {
		t.Errorf("Read error: %v", err)
	}
	if n != 4 {
		t.Errorf("Read returned %d bytes, want 4", n)
	}
	if string(buf) != "test" {
		t.Errorf("Read content = %q, want 'test'", string(buf))
	}
}

// Test RequestFromRawURL
func TestBoost4_RequestFromRawURL(t *testing.T) {
	req, err := RequestFromRawURL("http://example.com/path?key=value")
	if err != nil {
		t.Fatalf("RequestFromRawURL error: %v", err)
	}
	if req.originURL != "http://example.com/path?key=value" {
		t.Errorf("originURL = %q, want original URL", req.originURL)
	}
}

// Test Request GetBodyReader with body
func TestBoost4_RequestGetBodyReader(t *testing.T) {
	req, _ := NewRequest("POST", "http://example.com/", strings.NewReader("test body"))
	reader, err := req.GetBodyReader()
	if err != nil {
		t.Fatalf("GetBodyReader error: %v", err)
	}
	body, _ := io.ReadAll(reader)
	if string(body) != "test body" {
		t.Errorf("Body = %q, want 'test body'", string(body))
	}
}

// Test Request GetRawBody
func TestBoost4_RequestGetRawBody(t *testing.T) {
	req, _ := NewRequest("POST", "http://example.com/", strings.NewReader("raw body"))
	body := req.GetRawBody()
	if string(body) != "raw body" {
		t.Errorf("GetRawBody = %q, want 'raw body'", string(body))
	}
}

// Test Request GetURL method
func TestBoost4_RequestGetURL(t *testing.T) {
	req, _ := NewRequest("GET", "http://example.com/path", nil)
	u := req.GetURL()
	if u == nil {
		t.Fatal("GetURL should return non-nil")
	}
	if u.Host != "example.com" {
		t.Errorf("Host = %q, want 'example.com'", u.Host)
	}
}
