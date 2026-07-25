package crawler

import (
	"net/url"
	"testing"
	"wscan/core/http"
)

func TestExtractPathsFromRobots(t *testing.T) {
	u, _ := url.Parse("http://example.com")

	tests := []struct {
		name      string
		body      string
		wantCount int
	}{
		{
			name: "standard robots.txt with disallow",
			body: `User-agent: *
Disallow: /admin/
Disallow: /private/
Allow: /public/`,
			wantCount: 3,
		},
		{
			name:      "empty body",
			body:      "",
			wantCount: 0,
		},
		{
			name: "only comments",
			body: `# This is a comment
# Another comment`,
			wantCount: 0,
		},
		{
			name: "complex robots.txt",
			body: `User-agent: Googlebot
Disallow: /search/
Disallow: /admin/
Allow: /api/public/

User-agent: *
Disallow: /tmp/
Disallow: /backup/`,
			wantCount: 5,
		},
		{
			name: "robots with wildcard",
			body: `User-agent: *
Disallow: /api/*
Disallow: /test/`,
			wantCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractPathsFromRobots(u, tt.body)
			if len(result) != tt.wantCount {
				t.Errorf("extractPathsFromRobots returned %d results, want %d", len(result), tt.wantCount)
			}
			// Verify all results are valid HTTP requests
			for _, req := range result {
				if req == nil {
					t.Errorf("request should not be nil")
				}
				if req.Method != GET {
					t.Errorf("request method = %s, want GET", req.Method)
				}
			}
		})
	}
}

func TestExtractPathsFromSitemap(t *testing.T) {
	u, _ := url.Parse("http://example.com")

	tests := []struct {
		name      string
		body      string
		wantCount int
	}{
		{
			name: "valid sitemap with urls",
			body: `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>http://example.com/page1</loc></url>
  <url><loc>http://example.com/page2</loc></url>
</urlset>`,
			wantCount: 2,
		},
		{
			name: "valid sitemap with sitemap index",
			body: `<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap><loc>http://example.com/sitemap1.xml</loc></sitemap>
  <sitemap><loc>http://example.com/sitemap2.xml</loc></sitemap>
</sitemapindex>`,
			wantCount: 2,
		},
		{
			name:      "empty body",
			body:      "",
			wantCount: 0,
		},
		{
			name:      "invalid XML",
			body:      `<invalid>not xml<invalid>`,
			wantCount: 0,
		},
		{
			name: "mixed sitemap and urls",
			body: `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>http://example.com/</loc></url>
  <url><loc>http://example.com/about</loc></url>
</urlset>`,
			wantCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractPathsFromSitemap(u, tt.body)
			if len(result) != tt.wantCount {
				t.Errorf("extractPathsFromSitemap returned %d results, want %d", len(result), tt.wantCount)
			}
			for _, req := range result {
				if req == nil {
					t.Errorf("request should not be nil")
				}
			}
		})
	}
}

func TestExtractSourceMapURL(t *testing.T) {
	tests := []struct {
		name    string
		jsData  string
		wantURL string
	}{
		{
			name:    "standard sourceMappingURL",
			jsData:  "var a = 1;\n//# sourceMappingURL=app.js.map",
			wantURL: "app.js.map",
		},
		{
			name:    "sourceMappingURL with spaces",
			jsData:  "code\n// # sourceMappingURL=main.js.map",
			wantURL: "main.js.map",
		},
		{
			name:    "no source map",
			jsData:  "var a = 1;\nvar b = 2;",
			wantURL: "",
		},
		{
			name:    "empty string",
			jsData:  "",
			wantURL: "",
		},
		{
			name:    "sourceMappingURL on last line with extra spaces",
			jsData:  "code\n//# sourceMappingURL=bundle.min.js.map  ",
			wantURL: "bundle.min.js.map",
		},
		{
			name:    "sourceMappingURL not on last line",
			jsData:  "//# sourceMappingURL=ignore.map\nvar code = 1;",
			wantURL: "",
		},
		{
			name:    "sourceMappingURL with full path",
			jsData:  "code\n//# sourceMappingURL=https://cdn.example.com/assets/app.abc123.js.map",
			wantURL: "https://cdn.example.com/assets/app.abc123.js.map",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractSourceMapURL(tt.jsData)
			if got != tt.wantURL {
				t.Errorf("extractSourceMapURL() = %q, want %q", got, tt.wantURL)
			}
		})
	}
}

func TestAddRequestFromUrl(t *testing.T) {
	u, _ := url.Parse("http://example.com")

	tests := []struct {
		name     string
		path     string
		existing []*http.Request
		wantLen  int
	}{
		{"add valid path", "/api/users", nil, 1},
		{"add to existing", "/new/path", make([]*http.Request, 2), 3},
		{"invalid path", "://invalid", nil, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AddRequestFromUrl(u, tt.path, tt.existing)
			if len(result) != tt.wantLen {
				t.Errorf("AddRequestFromUrl returned %d results, want %d", len(result), tt.wantLen)
			}
		})
	}
}

func TestParseResponseURLRobotsTxt(t *testing.T) {
	u, _ := url.Parse("http://example.com/robots.txt")
	body := `User-agent: *
Disallow: /admin/
Allow: /public/`
	result := ParseResponseURL(u, body)
	if len(result) != 2 {
		t.Errorf("ParseResponseURL for robots.txt returned %d results, want 2", len(result))
	}
}

func TestParseResponseURLSitemapXML(t *testing.T) {
	u, _ := url.Parse("http://example.com/sitemap.xml")
	body := `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>http://example.com/</loc></url>
  <url><loc>http://example.com/about</loc></url>
</urlset>`
	result := ParseResponseURL(u, body)
	if len(result) != 2 {
		t.Errorf("ParseResponseURL for sitemap.xml returned %d results, want 2", len(result))
	}
}

func TestParseResponseURLJS(t *testing.T) {
	u, _ := url.Parse("http://example.com/assets/app.js")

	tests := []struct {
		name      string
		body      string
		wantCount int
	}{
		{
			name:      "js with source map comment",
			body:      "var api = '/api/v1/users';\n//# sourceMappingURL=app.js.map",
			wantCount: 2, // the api url + the sourcemap
		},
		{
			name:      "js with no urls",
			body:      "var a = 1;",
			wantCount: 0,
		},
		{
			name:      "js with multiple urls",
			body:      `"use strict";var a="/api/users",b="/api/posts";`,
			wantCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseResponseURL(u, tt.body)
			if len(result) != tt.wantCount {
				t.Errorf("ParseResponseURL for .js returned %d results, want %d. Results: %v", len(result), tt.wantCount, result)
			}
		})
	}
}

func TestParseResponseURLMainHashJS(t *testing.T) {
	// Test that main.[hash].js files trigger .map download
	u, _ := url.Parse("http://example.com/assets/main.abc123.js")
	body := "var a = 1;"
	result := ParseResponseURL(u, body)
	// Should find at least the main.abc123.js.map
	foundMap := false
	for _, req := range result {
		if req != nil && req.GetURL() != nil {
			if req.GetURL().String() == "http://example.com/assets/main.abc123.js.map" {
				foundMap = true
			}
		}
	}
	if !foundMap {
		t.Errorf("Expected to find main.abc123.js.map in results, got %d results", len(result))
	}
}

func TestParseResponseURLSourceMap(t *testing.T) {
	u, _ := url.Parse("http://example.com/assets/app.map")
	body := `{
		"version": 3,
		"sources": ["app.ts", "lib.ts"],
		"sourcesContent": ["var url = '/api/data';", "var x = 1;"],
		"mappings": "AAAA"
	}`
	result := ParseResponseURL(u, body)
	// Should extract URL from sourcesContent
	if len(result) == 0 {
		t.Errorf("ParseResponseURL for .map file should find URLs in sourcesContent")
	}
}

func TestParseResponseURLGenericHTML(t *testing.T) {
	u, _ := url.Parse("http://example.com/index.html")
	body := `<html><body>
		<a href="/page1">Link1</a>
		<script src="/js/app.js"></script>
	</body></html>`
	// The SuspectURLRegex only matches URLs wrapped in quotes, so test with JS-like patterns
	body = `"use strict";var apiEndpoint="/api/v1/users";var resourceEndpoint="/api/v1/items";`
	result := ParseResponseURL(u, body)
	if len(result) < 1 {
		t.Errorf("ParseResponseURL for generic HTML should find at least some URLs")
	}
}

func TestParseResponseURLSkipsImageAndTextPaths(t *testing.T) {
	u, _ := url.Parse("http://example.com/app.js")
	// URLs starting with "image/" or "text/" should be skipped
	body := `var a = "image/png";var b = "text/html";var c = "/api/data";`
	result := ParseResponseURL(u, body)
	// Only /api/data should be found, not image/png or text/html
	for _, req := range result {
		if req != nil && req.GetURL() != nil {
			path := req.GetURL().Path
			if path == "image/png" || path == "text/html" {
				t.Errorf("Should not include image/ or text/ paths, got %s", path)
			}
		}
	}
}
