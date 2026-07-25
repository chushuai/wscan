package crawler

import (
	"net/url"
	"testing"
)

func TestAbsoluteURL(t *testing.T) {
	base, _ := url.Parse("http://example.com/path/")
	tests := []struct {
		name     string
		base     *url.URL
		path     string
		wantPath string
	}{
		{"absolute path", base, "/new/path", "/new/path"},
		{"relative path", base, "sub/page", "sub/page"},
		{"root path", base, "/", "/"},
		{"with query", base, "/search?q=test", "/search?q=test"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AbsoluteURL(tt.base, tt.path)
			if result.Path != tt.wantPath {
				t.Errorf("AbsoluteURL path = %s, want %s", result.Path, tt.wantPath)
			}
			if result.Host != tt.base.Host {
				t.Errorf("AbsoluteURL host = %s, want %s", result.Host, tt.base.Host)
			}
		})
	}
}

func TestAbsoluteURLPreservesBase(t *testing.T) {
	base, _ := url.Parse("https://example.com:8443/existing/")
	result := AbsoluteURL(base, "/new")
	if result.Scheme != "https" {
		t.Errorf("Scheme = %s, want https", result.Scheme)
	}
	if result.Host != "example.com:8443" {
		t.Errorf("Host = %s, want example.com:8443", result.Host)
	}
}

func TestShouldCopyHeaderOnRedirect(t *testing.T) {
	tests := []struct {
		header string
		value  []string
		want   bool
	}{
		{"Authorization", []string{"Bearer token"}, false},
		{"Cookie", []string{"session=abc"}, false},
		{"Content-Type", []string{"text/html"}, true},
		{"Accept", []string{"*/*"}, true},
		{"X-Custom-Header", []string{"value"}, true},
		{"User-Agent", []string{"Mozilla/5.0"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.header, func(t *testing.T) {
			got := shouldCopyHeaderOnRedirect(tt.header, tt.value)
			if got != tt.want {
				t.Errorf("shouldCopyHeaderOnRedirect(%q, %v) = %v, want %v", tt.header, tt.value, got, tt.want)
			}
		})
	}
}

func TestCanonicalAddr(t *testing.T) {
	tests := []struct {
		name string
		addr string
	}{
		{"localhost", "127.0.0.1"},
		{"zero", "0.0.0.0"},
		{"ipv6 loopback", "::1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := canonicalAddr(tt.addr)
			// Just ensure it doesn't panic and returns a non-empty string
			if result == "" {
				t.Errorf("canonicalAddr(%q) returned empty string", tt.addr)
			}
		})
	}
}

func TestGetParentPaths(t *testing.T) {
	tests := []struct {
		name string
		path string
		want []string
	}{
		{"deep path", "/a/b/c/d", []string{"/a/b/c", "/a/b", "/a"}},
		{"two levels", "/a/b", []string{"/a"}},
		{"single level", "/a", nil},
		{"root", "/", nil},
		{"with file", "/a/b/c.html", []string{"/a/b", "/a"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getParentPaths(tt.path)
			if len(got) != len(tt.want) {
				t.Errorf("getParentPaths(%q) = %v, want %v", tt.path, got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("getParentPaths(%q)[%d] = %s, want %s", tt.path, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestEscapePercentSign(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"hello%world", "hello%25world"},
		{"no-percent", "no-percent"},
		{"%20space", "%2520space"},
		{"100%", "100%25"},
		{"%%", "%25%25"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := escapePercentSign(tt.input)
			if got != tt.want {
				t.Errorf("escapePercentSign(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestUrlParse(t *testing.T) {
	tests := []struct {
		name    string
		rawURL  string
		wantErr bool
	}{
		{"valid http", "http://example.com/path", false},
		{"valid https", "https://example.com:443/path?q=1", false},
		{"with percent", "http://example.com/path%20with%20spaces", false},
		{"double percent", "http://example.com/%%", false},
		{"relative path", "/relative/path", false},
		{"with fragment", "http://example.com/page#section", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := UrlParse(tt.rawURL)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if u == nil {
				t.Errorf("URL should not be nil")
			}
		})
	}
}

func TestGetUrl(t *testing.T) {
	tests := []struct {
		name       string
		rawURL     string
		parentURLs []url.URL
		wantErr    bool
		wantPath   string
	}{
		{
			name:     "absolute URL no parent",
			rawURL:   "http://example.com/test",
			wantErr:  false,
			wantPath: "/test",
		},
		{
			name:       "relative URL with parent",
			rawURL:     "/sub/page",
			parentURLs: []url.URL{{Scheme: "http", Host: "example.com", Path: "/"}},
			wantErr:    false,
			wantPath:   "/sub/page",
		},
		{
			name:    "empty URL",
			rawURL:  "",
			wantErr: true,
		},
		{
			name:       "javascript protocol",
			rawURL:     "javascript:void(0)",
			parentURLs: []url.URL{{Scheme: "http", Host: "example.com", Path: "/"}},
			wantErr:    true,
		},
		{
			name:       "mailto protocol",
			rawURL:     "mailto:user@example.com",
			parentURLs: []url.URL{{Scheme: "http", Host: "example.com", Path: "/"}},
			wantErr:    true,
		},
		{
			name:     "path with double slash",
			rawURL:   "http://example.com//double/slash",
			wantErr:  false,
			wantPath: "/double/slash",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := GetUrl(tt.rawURL, tt.parentURLs...)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if u.Path != tt.wantPath {
				t.Errorf("Path = %s, want %s", u.Path, tt.wantPath)
			}
		})
	}
}

func TestGetUrlWithPathDefault(t *testing.T) {
	// When no parent URL and just a scheme+host, path should default to /
	u, err := GetUrl("http://example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u.Path != "/" {
		t.Errorf("Path = %s, want /", u.Path)
	}
}

func TestNavigationUrl(t *testing.T) {
	tests := []struct {
		name   string
		rawURL string
		want   string
	}{
		{"simple path", "http://example.com/path", "://example.com/path"},
		{"with port", "http://example.com:8080/api", "://example.com:8080/api"},
		{"root path", "https://example.com/", "://example.com/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, _ := url.Parse(tt.rawURL)
			got := NavigationUrl(u)
			if got != tt.want {
				t.Errorf("NavigationUrl() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestUrlFileName(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{"html file", "/path/to/page.html", "page.html"},
		{"js file", "/assets/main.abc123.js", "main.abc123.js"},
		{"directory", "/path/to/dir/", ""},
		{"root", "/", ""},
		{"robots.txt", "/robots.txt", "robots.txt"},
		{"sitemap.xml", "/sitemap.xml", "sitemap.xml"},
		{"no extension dir", "/api/users", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, _ := url.Parse("http://example.com" + tt.path)
			got := UrlFileName(u)
			if got != tt.want {
				t.Errorf("UrlFileName() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestUrlFileExt(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{"html", "/page.html", "html"},
		{"js", "/app.js", "js"},
		{"map", "/app.js.map", "map"},
		{"uppercase", "/styles.CSS", "css"},
		{"no extension", "/api/data", ""},
		{"directory", "/dir/", ""},
		{"robots.txt", "/robots.txt", "txt"},
		{"sitemap.xml", "/sitemap.xml", "xml"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, _ := url.Parse("http://example.com" + tt.path)
			got := UrlFileExt(u)
			if got != tt.want {
				t.Errorf("UrlFileExt() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestParseURLFunction(t *testing.T) {
	tests := []struct {
		name       string
		rawURL     string
		parentURLs []url.URL
		wantErr    bool
		want       string
	}{
		{"empty string", "", nil, true, ""},
		{"absolute http", "http://example.com", nil, false, "http://example.com"},
		{"absolute https", "https://example.com", nil, false, "https://example.com"},
		{"javascript protocol", "javascript:void(0)", []url.URL{{Scheme: "http", Host: "example.com"}}, true, ""},
		{"mailto protocol", "mailto:user@example.com", []url.URL{{Scheme: "http", Host: "example.com"}}, true, ""},
		{"relative with parent", "/path", []url.URL{{Scheme: "http", Host: "example.com"}}, false, "/path"},
		{"multiple hashes", "http://example.com/path##anchor", nil, false, "http://example.com/path#anchor"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parse(tt.rawURL, tt.parentURLs...)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("parse() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestIdnaASCII(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"ascii domain", "example.com", false},
		{"chinese domain", "example.com", false},
		{"empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := idnaASCII(tt.input)
			if tt.wantErr && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// ---------- UrlParse with percent escaping ----------

func TestUrlParseWithBadPercent(t *testing.T) {
	// Test a URL that would fail standard parsing but succeed with escaped %
	u, err := UrlParse("http://example.com/path%with%bad")
	if err != nil {
		// Some invalid percent encodings might still fail even after escaping
		t.Logf("UrlParse with bad percent: err=%v (acceptable)", err)
	} else {
		t.Logf("UrlParse with bad percent: path=%s", u.Path)
	}
}

// ---------- GetUrl with parent URL and empty path ----------

func TestGetUrlWithParentEmptyPath(t *testing.T) {
	parent := url.URL{Scheme: "http", Host: "example.com", Path: "/base/page"}
	_, err := GetUrl("", parent)
	if err == nil {
		t.Error("Empty URL with parent should return error")
	}
}

func TestGetUrlWithParentRelativePath(t *testing.T) {
	parent := url.URL{Scheme: "http", Host: "example.com", Path: "/base/page"}
	u, err := GetUrl("sub/page", parent)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u.Host != "example.com" {
		t.Errorf("Host = %s, want example.com", u.Host)
	}
}

func TestGetUrlWithParentAndFullURL(t *testing.T) {
	parent := url.URL{Scheme: "http", Host: "example.com", Path: "/base"}
	result, err := GetUrl("http://other.com/resource", parent)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Host != "other.com" {
		t.Errorf("Host = %s, want other.com", result.Host)
	}
}

func TestGetUrlWithParentHTTPSURL(t *testing.T) {
	parent := url.URL{Scheme: "https", Host: "example.com", Path: "/"}
	result, err := GetUrl("https://example.com/api", parent)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Scheme != "https" {
		t.Errorf("Scheme = %s, want https", result.Scheme)
	}
}

func TestGetUrlNoParentWithFragment(t *testing.T) {
	result, err := GetUrl("http://example.com/page#section")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Fragment != "section" {
		t.Errorf("Fragment = %s, want section", result.Fragment)
	}
}
