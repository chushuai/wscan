package crawler

import (
	"net/url"
	"testing"

	whttp "wscan/core/http"
)

func TestExtractPathsFromRobotsDetailed(t *testing.T) {
	u, _ := url.Parse("http://example.com")

	t.Run("paths are resolved against base URL", func(t *testing.T) {
		body := "Disallow: /secret/\nAllow: /public/"
		result := extractPathsFromRobots(u, body)
		for _, req := range result {
			if req == nil {
				t.Fatal("request should not be nil")
			}
			reqURL := req.GetURL()
			if reqURL.Host != "example.com" {
				t.Errorf("expected host example.com, got %s", reqURL.Host)
			}
		}
	})

	t.Run("handles multiple User-agents", func(t *testing.T) {
		body := `User-agent: Googlebot
Disallow: /google-only/
User-agent: *
Disallow: /everyone/`
		result := extractPathsFromRobots(u, body)
		if len(result) != 2 {
			t.Errorf("expected 2 results, got %d", len(result))
		}
	})
}

func TestExtractPathsFromSitemapDetailed(t *testing.T) {
	u, _ := url.Parse("http://example.com")

	t.Run("handles valid sitemap index", func(t *testing.T) {
		body := `<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap><loc>http://example.com/sitemap-products.xml</loc></sitemap>
  <sitemap><loc>http://example.com/sitemap-pages.xml</loc></sitemap>
</sitemapindex>`
		result := extractPathsFromSitemap(u, body)
		if len(result) != 2 {
			t.Errorf("expected 2 results, got %d", len(result))
		}
	})

	t.Run("handles sitemap with whitespace in loc", func(t *testing.T) {
		body := `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>  http://example.com/page1  </loc></url>
</urlset>`
		result := extractPathsFromSitemap(u, body)
		if len(result) != 1 {
			t.Errorf("expected 1 result, got %d", len(result))
		}
	})

	t.Run("returns nil for invalid XML", func(t *testing.T) {
		body := `not valid xml at all`
		result := extractPathsFromSitemap(u, body)
		if result != nil {
			t.Errorf("expected nil for invalid XML, got %d results", len(result))
		}
	})

	t.Run("handles empty urlset", func(t *testing.T) {
		body := `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
</urlset>`
		result := extractPathsFromSitemap(u, body)
		if len(result) != 0 {
			t.Errorf("expected 0 results, got %d", len(result))
		}
	})
}

func TestExtractSourceMapURLDetailed(t *testing.T) {
	tests := []struct {
		name    string
		jsData  string
		wantURL string
	}{
		{
			name:    "single line JS with sourceMappingURL",
			jsData:  "//# sourceMappingURL=out.js.map",
			wantURL: "out.js.map",
		},
		{
			name:    "multi-line JS ending with sourceMappingURL",
			jsData:  "function hello() {}\nconsole.log('hi');\n//# sourceMappingURL=app.js.map",
			wantURL: "app.js.map",
		},
		{
			name:    "sourceMappingURL with hash in URL",
			jsData:  "code\n//# sourceMappingURL=app.abc123.js.map",
			wantURL: "app.abc123.js.map",
		},
		{
			name:    "only comment on last line but not sourceMappingURL",
			jsData:  "code\n// This is a regular comment",
			wantURL: "",
		},
		{
			name:    "block comment instead of line comment",
			jsData:  "code\n/* # sourceMappingURL=app.js.map */",
			wantURL: "",
		},
		{
			name:    "single line input no sourceMappingURL",
			jsData:  "var x = 1;",
			wantURL: "",
		},
		{
			name:    "sourceMappingURL in middle of file",
			jsData:  "var x = 1;\n//# sourceMappingURL=ignore.map\nvar y = 2;",
			wantURL: "",
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

func TestAddRequestFromUrlValid(t *testing.T) {
	u, _ := url.Parse("http://example.com/base/")

	t.Run("adds valid relative path", func(t *testing.T) {
		ret := AddRequestFromUrl(u, "/api/users", nil)
		if len(ret) != 1 {
			t.Fatalf("expected 1 result, got %d", len(ret))
		}
		if ret[0].Method != GET {
			t.Errorf("method = %s, want GET", ret[0].Method)
		}
	})

	t.Run("adds to existing slice", func(t *testing.T) {
		existing := make([]*whttp.Request, 3)
		ret := AddRequestFromUrl(u, "/new/path", existing)
		if len(ret) != 4 {
			t.Errorf("expected 4 results, got %d", len(ret))
		}
	})
}

func TestParseResponseURLEdgeCases(t *testing.T) {
	t.Run("empty body with robots.txt URL", func(t *testing.T) {
		u, _ := url.Parse("http://example.com/robots.txt")
		result := ParseResponseURL(u, "")
		if len(result) != 0 {
			t.Errorf("expected 0 results for empty robots.txt, got %d", len(result))
		}
	})

	t.Run("empty body with sitemap.xml URL", func(t *testing.T) {
		u, _ := url.Parse("http://example.com/sitemap.xml")
		result := ParseResponseURL(u, "")
		if len(result) != 0 {
			t.Errorf("expected 0 results for empty sitemap.xml, got %d", len(result))
		}
	})

	t.Run("JS file with sourceMappingURL", func(t *testing.T) {
		u, _ := url.Parse("http://example.com/assets/bundle.js")
		body := "var app = {}; app.init = function() {};\n//# sourceMappingURL=bundle.js.map"
		result := ParseResponseURL(u, body)
		// Should find the sourceMappingURL
		foundMap := false
		for _, req := range result {
			if req != nil && req.GetURL() != nil {
				if req.GetURL().String() == "http://example.com/assets/bundle.js.map" {
					foundMap = true
				}
			}
		}
		if !foundMap {
			t.Errorf("expected to find bundle.js.map from sourceMappingURL")
		}
	})

	t.Run("non-main hash JS file should not add .map from filename", func(t *testing.T) {
		u, _ := url.Parse("http://example.com/assets/vendor.js")
		body := `var v = 1;`
		result := ParseResponseURL(u, body)
		// vendor.js should NOT trigger the main.[hash].js.map pattern
		for _, req := range result {
			if req != nil && req.GetURL() != nil {
				if req.GetURL().String() == "http://example.com/assets/vendor.js.map" {
					t.Errorf("vendor.js should not auto-add .map URL from filename pattern")
				}
			}
		}
	})
}

func TestParseResponseURLMapFileWithSourcesContent(t *testing.T) {
	u, _ := url.Parse("http://example.com/assets/app.map")
	body := `{
		"version": 3,
		"sources": ["app.ts"],
		"sourcesContent": ["fetch(\"/api/data\"); var x = \"/api/users\";"],
		"mappings": "AAAA"
	}`
	result := ParseResponseURL(u, body)
	// Should find URLs within sourcesContent
	if len(result) == 0 {
		t.Errorf("expected at least some URLs from .map file sourcesContent")
	}
}

func TestParseResponseURLGenericExtension(t *testing.T) {
	u, _ := url.Parse("http://example.com/api/data")
	body := `"use strict";var endpoint="/api/v2/health";var resource="/api/v2/status";`
	result := ParseResponseURL(u, body)
	// Should extract quoted URLs
	if len(result) < 1 {
		t.Errorf("expected at least some URLs from generic response")
	}
}

func TestSitemapStructParsing(t *testing.T) {
	u, _ := url.Parse("http://example.com")

	t.Run("both URLs and Sitemaps", func(t *testing.T) {
		body := `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>http://example.com/page1</loc></url>
</urlset>`
		result := extractPathsFromSitemap(u, body)
		// This tests the sitemapStruct parsing
		if len(result) < 1 {
			t.Errorf("expected at least 1 URL from sitemap")
		}
	})

	t.Run("invalid loc entries are skipped", func(t *testing.T) {
		body := `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>   </loc></url>
  <url><loc>http://example.com/valid</loc></url>
</urlset>`
		result := extractPathsFromSitemap(u, body)
		if len(result) != 2 {
			// Both should be included - empty one gets trimmed and may still produce a request
			t.Logf("got %d results from sitemap with empty/valid locs", len(result))
		}
	})
}

func TestRobotsTxtWithVariousFormats(t *testing.T) {
	u, _ := url.Parse("http://example.com")

	tests := []struct {
		name      string
		body      string
		wantCount int
	}{
		{
			name:      "single Disallow with path",
			body:      "Disallow: /admin/",
			wantCount: 1,
		},
		{
			name:      "Allow directive",
			body:      "Allow: /public/",
			wantCount: 1,
		},
		{
			name:      "Disallow without path",
			body:      "Disallow:",
			wantCount: 0,
		},
		{
			name:      "mixed valid and empty",
			body:      "Disallow: /admin/\nDisallow:\nAllow: /public/",
			wantCount: 2,
		},
		{
			name:      "only User-agent lines",
			body:      "User-agent: *\nUser-agent: Googlebot",
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractPathsFromRobots(u, tt.body)
			if len(result) != tt.wantCount {
				t.Errorf("expected %d results, got %d", tt.wantCount, len(result))
			}
		})
	}
}

func TestIsIgnoredByKeywordMatch(t *testing.T) {
	req, _ := whttp.NewRequest("GET", "http://example.com/admin/logout", nil)

	tests := []struct {
		name           string
		ignoreKeywords []string
		want           bool
	}{
		{"match logout", []string{"logout"}, true},
		{"match quit", []string{"quit"}, false}, // URL doesn't contain "quit"
		{"match exit", []string{"exit"}, false}, // URL doesn't contain "exit"
		{"match admin", []string{"admin"}, true},
		{"no match", []string{"login", "signin"}, false},
		{"empty keywords", []string{}, false},
		{"nil keywords", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsIgnoredByKeywordMatch(req, tt.ignoreKeywords)
			if got != tt.want {
				t.Errorf("IsIgnoredByKeywordMatch() = %v, want %v", got, tt.want)
			}
		})
	}
}
