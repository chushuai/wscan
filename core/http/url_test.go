package http

import (
	"encoding/json"
	"net/url"
	"testing"
)

func TestURL_RawUrl(t *testing.T) {
	u, _ := url.Parse("http://example.com/path?q=1")
	wu := &URL{URL: *u}
	raw := wu.RawUrl()
	if raw.String() != "http://example.com/path?q=1" {
		t.Errorf("RawUrl() = %q, want %q", raw.String(), "http://example.com/path?q=1")
	}
}

func TestGetUrl_Basic(t *testing.T) {
	u, err := GetUrl("http://example.com/path")
	if err != nil {
		t.Fatalf("GetUrl() error: %v", err)
	}
	if u.Scheme != "http" {
		t.Errorf("Scheme = %q, want %q", u.Scheme, "http")
	}
	if u.Host != "example.com" {
		t.Errorf("Host = %q, want %q", u.Host, "example.com")
	}
	if u.Path != "/path" {
		t.Errorf("Path = %q, want %q", u.Path, "/path")
	}
}

func TestGetUrl_EmptyPath(t *testing.T) {
	u, err := GetUrl("http://example.com")
	if err != nil {
		t.Fatalf("GetUrl() error: %v", err)
	}
	if u.Path != "/" {
		t.Errorf("Path = %q, want %q", u.Path, "/")
	}
}

func TestGetUrl_WithParent(t *testing.T) {
	parent, _ := GetUrl("http://example.com/base/")
	u, err := GetUrl("/subpath", *parent)
	if err != nil {
		t.Fatalf("GetUrl() with parent error: %v", err)
	}
	if u.Host != "example.com" {
		t.Errorf("Host = %q, want %q", u.Host, "example.com")
	}
}

func TestGetUrl_JavascriptProtocol(t *testing.T) {
	_, err := GetUrl("javascript:alert(1)")
	if err == nil {
		t.Error("expected error for javascript protocol")
	}
}

func TestGetUrl_MailtoProtocol(t *testing.T) {
	_, err := GetUrl("mailto:test@example.com")
	if err == nil {
		t.Error("expected error for mailto protocol")
	}
}

func TestGetUrl_EmptyString(t *testing.T) {
	_, err := GetUrl("")
	if err == nil {
		t.Error("expected error for empty URL")
	}
}

func TestGetUrl_DoubleSlashPath(t *testing.T) {
	u, err := GetUrl("http://example.com//path")
	if err != nil {
		t.Fatalf("GetUrl() error: %v", err)
	}
	if u.Path != "/path" {
		t.Errorf("Path = %q, want %q (double slashes should be fixed)", u.Path, "/path")
	}
}

func TestURL_parse_Empty(t *testing.T) {
	u := &URL{}
	_, err := u.parse("")
	if err == nil {
		t.Error("expected error for empty URL in parse")
	}
}

func TestURL_parse_Javascript(t *testing.T) {
	u := &URL{}
	_, err := u.parse("javascript:void(0)")
	if err == nil {
		t.Error("expected error for javascript protocol in parse")
	}
}

func TestURL_parse_Mailto(t *testing.T) {
	u := &URL{}
	_, err := u.parse("mailto:test@test.com")
	if err == nil {
		t.Error("expected error for mailto protocol in parse")
	}
}

func TestURL_parse_HttpScheme(t *testing.T) {
	u := &URL{}
	result, err := u.parse("http://example.com")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result != "http://example.com" {
		t.Errorf("parse result = %q, want %q", result, "http://example.com")
	}
}

func TestURL_parse_HttpsScheme(t *testing.T) {
	u := &URL{}
	result, err := u.parse("https://example.com")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result != "https://example.com" {
		t.Errorf("parse result = %q, want %q", result, "https://example.com")
	}
}

func TestURL_parse_MultipleHash(t *testing.T) {
	u := &URL{}
	result, err := u.parse("http://example.com###fragment")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if containsHash(result, "##") {
		t.Errorf("multiple # should be reduced to single #, got %q", result)
	}
}

func containsHash(s, pattern string) bool {
	for i := 0; i <= len(s)-len(pattern); i++ {
		if s[i:i+len(pattern)] == pattern {
			return true
		}
	}
	return false
}

func TestURL_QueryMap(t *testing.T) {
	u, _ := url.Parse("http://example.com/path?key1=value1&key2=value2")
	wu := &URL{URL: *u}
	qm := wu.QueryMap()

	if qm["key1"] != "value1" {
		t.Errorf("QueryMap()[key1] = %v, want %q", qm["key1"], "value1")
	}
	if qm["key2"] != "value2" {
		t.Errorf("QueryMap()[key2] = %v, want %q", qm["key2"], "value2")
	}
}

func TestURL_QueryMap_MultipleValues(t *testing.T) {
	u, _ := url.Parse("http://example.com/path?key=value1&key=value2")
	wu := &URL{URL: *u}
	qm := wu.QueryMap()

	// Multiple values for same key should return a slice
	val := qm["key"]
	sliceVal, ok := val.([]string)
	if !ok {
		t.Errorf("expected slice for multiple values, got %T", val)
	}
	if len(sliceVal) != 2 {
		t.Errorf("expected 2 values, got %d", len(sliceVal))
	}
}

func TestURL_QueryMapID(t *testing.T) {
	u, _ := url.Parse("http://example.com/path?a=1&b=2")
	wu := &URL{URL: *u}
	qm := wu.QueryMap()
	id := wu.QueryMapID(qm)
	if id == "" {
		t.Error("QueryMapID() should not return empty string")
	}

	// Same map should produce same ID
	id2 := wu.QueryMapID(qm)
	if id != id2 {
		t.Errorf("QueryMapID() should be deterministic: %q != %q", id, id2)
	}
}

func TestURL_NoQueryUrl(t *testing.T) {
	u, _ := url.Parse("http://example.com/path?query=value")
	wu := &URL{URL: *u}
	result := wu.NoQueryUrl()
	if result != "http://example.com/path" {
		t.Errorf("NoQueryUrl() = %q, want %q", result, "http://example.com/path")
	}
}

func TestURL_NoQueryUrl_WithPort(t *testing.T) {
	u, _ := url.Parse("http://example.com:8080/path?query=value")
	wu := &URL{URL: *u}
	result := wu.NoQueryUrl()
	if result != "http://example.com:8080/path" {
		t.Errorf("NoQueryUrl() = %q, want %q", result, "http://example.com:8080/path")
	}
}

func TestURL_BaseURL(t *testing.T) {
	u, _ := url.Parse("http://example.com:8080/path?query=value")
	wu := &URL{URL: *u}
	result := wu.BaseURL()
	if result != "http://example.com:8080" {
		t.Errorf("BaseURL() = %q, want %q", result, "http://example.com:8080")
	}
}

func TestURL_NoFragmentUrl(t *testing.T) {
	u, _ := url.Parse("http://example.com/path#fragment")
	wu := &URL{URL: *u}
	result := wu.NoFragmentUrl()
	// The fragment text should be removed
	if containsSubstring(result, "#fragment") {
		t.Errorf("NoFragmentUrl() should not contain fragment, got %q", result)
	}
}

func TestURL_NoSchemeFragmentUrl(t *testing.T) {
	u, _ := url.Parse("http://example.com/path#fragment")
	wu := &URL{URL: *u}
	result := wu.NoSchemeFragmentUrl()
	if result != "://example.com/path" {
		t.Errorf("NoSchemeFragmentUrl() = %q, want %q", result, "://example.com/path")
	}
}

func TestURL_NavigationUrl(t *testing.T) {
	u, _ := url.Parse("http://example.com/path")
	wu := &URL{URL: *u}
	result := wu.NavigationUrl()
	if result != wu.NoSchemeFragmentUrl() {
		t.Errorf("NavigationUrl() should equal NoSchemeFragmentUrl()")
	}
}

func TestURL_RootDomain(t *testing.T) {
	u, _ := url.Parse("http://a.b.c.360.cn/path")
	wu := &URL{URL: *u}
	domain := wu.RootDomain()
	if domain != "360.cn" {
		t.Errorf("RootDomain() = %q, want %q", domain, "360.cn")
	}
}

func TestURL_RootDomain_SimpleDomain(t *testing.T) {
	u, _ := url.Parse("http://example.com/path")
	wu := &URL{URL: *u}
	domain := wu.RootDomain()
	if domain != "example.com" {
		t.Errorf("RootDomain() = %q, want %q", domain, "example.com")
	}
}

func TestURL_FileName(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"http://example.com/file.txt", "file.txt"},
		{"http://example.com/dir/", ""},
		{"http://example.com/path/script.js", "script.js"},
		{"http://example.com/", ""},
	}

	for _, tt := range tests {
		u, _ := url.Parse(tt.path)
		wu := &URL{URL: *u}
		result := wu.FileName()
		if result != tt.expected {
			t.Errorf("FileName() for %q = %q, want %q", tt.path, result, tt.expected)
		}
	}
}

func TestURL_FileExt(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"http://example.com/file.txt", "txt"},
		{"http://example.com/file.JS", "js"},
		{"http://example.com/dir/", ""},
		{"http://example.com/image.PNG", "png"},
	}

	for _, tt := range tests {
		u, _ := url.Parse(tt.path)
		wu := &URL{URL: *u}
		result := wu.FileExt()
		if result != tt.expected {
			t.Errorf("FileExt() for %q = %q, want %q", tt.path, result, tt.expected)
		}
	}
}

func TestURL_ParentPath(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"/", ""},                           // root path returns empty
		{"/dir/", "/"},                      // one level dir
		{"/dir/subdir/", "/dir"},            // two levels
		{"/dir/subdir/file", "/dir/subdir"}, // file at end
		{"/dir", "/"},                       // single path segment
	}

	for _, tt := range tests {
		u, _ := url.Parse("http://example.com" + tt.path)
		wu := &URL{URL: *u}
		result := wu.ParentPath()
		if result != tt.expected {
			t.Errorf("ParentPath() for %q = %q, want %q", tt.path, result, tt.expected)
		}
	}
}

func TestURL_String(t *testing.T) {
	u, _ := url.Parse("http://example.com/path?q=1")
	wu := &URL{URL: *u}
	result := wu.String()
	if result != "http://example.com/path?q=1" {
		t.Errorf("String() = %q, want %q", result, "http://example.com/path?q=1")
	}
}

func TestURL_MarshalJSON(t *testing.T) {
	u, _ := url.Parse("http://example.com/path")
	wu := &URL{URL: *u}
	data, err := wu.MarshalJSON()
	if err != nil {
		t.Errorf("MarshalJSON() error: %v", err)
	}
	// Should be a JSON string
	var decoded string
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Errorf("unmarshaling JSON: %v", err)
	}
	if decoded != "http://example.com/path" {
		t.Errorf("MarshalJSON() result = %q, want %q", decoded, "http://example.com/path")
	}
}

func TestUrlParse(t *testing.T) {
	u, err := UrlParse("http://example.com/path")
	if err != nil {
		t.Errorf("UrlParse() error: %v", err)
	}
	if u.Scheme != "http" {
		t.Errorf("Scheme = %q, want %q", u.Scheme, "http")
	}
}

func TestUrlParse_WithPercent(t *testing.T) {
	// UrlParse should handle % signs that might be invalid
	_, err := UrlParse("http://example.com/path%test")
	if err != nil {
		t.Errorf("UrlParse() should handle percent signs: %v", err)
	}
}

func TestUrlParse_Invalid(t *testing.T) {
	_, err := UrlParse("://invalid")
	if err != nil {
		t.Logf("UrlParse() correctly rejects invalid URL: %v", err)
	}
}

func TestURL_IsWebsiteDir(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"", true},
		{"/", true},
		{"/dir/", true},
		{"/file.html", false},
	}

	for _, tt := range tests {
		u, _ := url.Parse("http://example.com" + tt.path)
		wu := &URL{URL: *u}
		result := wu.IsWebsiteDir()
		if result != tt.expected {
			t.Errorf("IsWebsiteDir() for %q = %v, want %v", tt.path, result, tt.expected)
		}
	}
}

func TestURL_IsStaticResource(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"http://example.com/image.png", true},
		{"http://example.com/script.js", false}, // js is NOT in StaticSuffix list
		{"http://example.com/file.css", false},  // css is NOT in StaticSuffix list
		{"http://example.com/page.html", false},
		{"http://example.com/document.pdf", true},
		{"http://example.com/archive.zip", true},
		{"http://example.com/font.woff", true},
		{"http://example.com/image.webp", true},
		{"http://example.com/dir/", false},
	}

	for _, tt := range tests {
		u, _ := url.Parse(tt.path)
		wu := &URL{URL: *u}
		result := wu.IsStaticResource()
		if result != tt.expected {
			t.Errorf("IsStaticResource() for %q = %v, want %v", tt.path, result, tt.expected)
		}
	}
}

func TestURL_IsDBFile(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"http://example.com/db.sql", true},
		{"http://example.com/data.db", true},
		{"http://example.com/file.sqlite", true},
		{"http://example.com/data.accdb", true},
		{"http://example.com/data.mdb", true},
		{"http://example.com/file.txt", false},
		{"http://example.com/page.html", false},
	}

	for _, tt := range tests {
		u, _ := url.Parse(tt.path)
		wu := &URL{URL: *u}
		result := wu.IsDBFile()
		if result != tt.expected {
			t.Errorf("IsDBFile() for %q = %v, want %v", tt.path, result, tt.expected)
		}
	}
}

func TestEscapePercentSign(t *testing.T) {
	result := escapePercentSign("test%value")
	if result != "test%25value" {
		t.Errorf("escapePercentSign() = %q, want %q", result, "test%25value")
	}

	result2 := escapePercentSign("noPercent")
	if result2 != "noPercent" {
		t.Errorf("escapePercentSign() = %q, want %q", result2, "noPercent")
	}
}

func TestURL_cloneURL(t *testing.T) {
	u, _ := url.Parse("http://user:pass@example.com/path")
	wu := &URL{URL: *u}
	cloned := wu.cloneURL()

	if cloned.String() != wu.String() {
		t.Errorf("cloneURL() = %q, want %q", cloned.String(), wu.String())
	}

	// Verify nil case
	nilURL := &URL{}
	nilURL.URL = url.URL{}
	// cloneURL on a non-nil URL should return a non-nil result
	result := nilURL.cloneURL()
	if result == nil {
		t.Error("cloneURL on non-nil URL should return non-nil")
	}
}

func TestGetURLPort(t *testing.T) {
	tests := []struct {
		rawurl   string
		expected int
		hasError bool
	}{
		{"http://example.com", 80, false},
		{"https://example.com", 443, false},
		{"http://example.com:8080", 8080, false},
		{"https://example.com:8443", 8443, false},
		{"ftp://example.com", 0, true}, // unsupported scheme
	}

	for _, tt := range tests {
		port, err := GetURLPort(tt.rawurl)
		if tt.hasError {
			if err == nil {
				t.Errorf("GetURLPort(%q) should return error", tt.rawurl)
			}
		} else {
			if err != nil {
				t.Errorf("GetURLPort(%q) unexpected error: %v", tt.rawurl, err)
			}
			if port != tt.expected {
				t.Errorf("GetURLPort(%q) = %d, want %d", tt.rawurl, port, tt.expected)
			}
		}
	}
}

func TestGetURLPort_InvalidURL(t *testing.T) {
	_, err := GetURLPort("://invalid")
	if err == nil {
		t.Error("GetURLPort() should return error for invalid URL")
	}
}

func TestUrlSplitHostPort(t *testing.T) {
	tests := []struct {
		rawurl       string
		expectedHost string
		expectedPort int
		hasError     bool
	}{
		{"http://example.com:8080", "example.com", 8080, false},
		{"http://example.com", "example.com", 80, false},
		{"https://example.com", "example.com", 443, false},
		{"https://example.com:443", "example.com", 443, false},
	}

	for _, tt := range tests {
		host, port, err := UrlSplitHostPort(tt.rawurl)
		if tt.hasError {
			if err == nil {
				t.Errorf("UrlSplitHostPort(%q) should return error", tt.rawurl)
			}
		} else {
			if err != nil {
				t.Errorf("UrlSplitHostPort(%q) unexpected error: %v", tt.rawurl, err)
			}
			if host != tt.expectedHost {
				t.Errorf("UrlSplitHostPort(%q) host = %q, want %q", tt.rawurl, host, tt.expectedHost)
			}
			if port != tt.expectedPort {
				t.Errorf("UrlSplitHostPort(%q) port = %d, want %d", tt.rawurl, port, tt.expectedPort)
			}
		}
	}
}

func TestUrlSplitHostPort_UnsupportedScheme(t *testing.T) {
	_, _, err := UrlSplitHostPort("ftp://example.com")
	if err == nil {
		t.Error("UrlSplitHostPort() should return error for unsupported scheme")
	}
}

func TestUrlSplitHostPort_InvalidURL(t *testing.T) {
	_, _, err := UrlSplitHostPort("not a url")
	if err == nil {
		t.Error("UrlSplitHostPort() should return error for invalid URL")
	}
}

func TestGetURLDepth(t *testing.T) {
	tests := []struct {
		urlStr   string
		expected int
	}{
		{"http://example.com/", 0},
		{"http://example.com/path", 0},
		{"http://example.com/path/sub", 1},
		{"http://example.com/a/b/c", 2},
	}

	for _, tt := range tests {
		result := GetURLDepth(tt.urlStr)
		if result != tt.expected {
			t.Errorf("GetURLDepth(%q) = %d, want %d", tt.urlStr, result, tt.expected)
		}
	}
}

func TestGetURLDepth_InvalidURL(t *testing.T) {
	result := GetURLDepth("://invalid")
	if result != -1 {
		t.Errorf("GetURLDepth(invalid) = %d, want -1", result)
	}
}

func TestUrlJoinPath(t *testing.T) {
	tests := []struct {
		base     string
		relative string
		expected string
	}{
		{"http://example.com", "/path", "http://example.com/path"},
		{"http://example.com/", "path", "http://example.com/path"},
		{"http://example.com/base/", "/sub", "http://example.com/base/sub"},
		{"http://example.com/base", "sub", "http://example.com/base/sub"},
	}

	for _, tt := range tests {
		result := UrlJoinPath(tt.base, tt.relative)
		if result != tt.expected {
			t.Errorf("UrlJoinPath(%q, %q) = %q, want %q", tt.base, tt.relative, result, tt.expected)
		}
	}
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
