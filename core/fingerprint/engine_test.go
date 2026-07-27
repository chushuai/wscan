package fingerprint

import (
	"sort"
	"strings"
	"testing"
)

func loadEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := DefaultEngine()
	if err != nil {
		t.Fatalf("DefaultEngine: %v", err)
	}
	if e == nil {
		t.Skip("no technologies.json available")
	}
	return e
}

func namesOf(ts []Tech) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.Name)
	}
	sort.Strings(out)
	return out
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if strings.EqualFold(s, needle) {
			return true
		}
	}
	return false
}

func TestLoadDB(t *testing.T) {
	e := loadEngine(t)
	if e.Count() < 1000 {
		t.Errorf("expected a large technology DB, got %d", e.Count())
	}
}

func TestDetectNginxByHeader(t *testing.T) {
	e := loadEngine(t)
	ts := e.AnalyzeStatic(PageInput{
		URL:     "http://example.com/",
		Headers: map[string]string{"Server": "nginx/1.18.0 (Ubuntu)"},
		HTML:    "<html><head></head><body>ok</body></html>",
	})
	names := namesOf(ts)
	if !contains(names, "nginx") {
		t.Fatalf("expected nginx detection, got %v", names)
	}
}

func TestDetectPHPByHeader(t *testing.T) {
	e := loadEngine(t)
	ts := e.AnalyzeStatic(PageInput{
		URL:     "http://example.com/",
		Headers: map[string]string{"X-Powered-By": "PHP/7.4.3"},
		HTML:    "<html></html>",
	})
	names := namesOf(ts)
	if !contains(names, "PHP") {
		t.Fatalf("expected PHP detection, got %v", names)
	}
}

func TestDetectByScriptSrc(t *testing.T) {
	e := loadEngine(t)
	html := `<html><head><script src="/js/jquery-3.5.1.min.js"></script></head></html>`
	ts := e.AnalyzeStatic(PageInput{
		URL:     "http://example.com/",
		HTML:    html,
		Scripts: ExtractScriptSrcs(html, "http://example.com/"),
	})
	names := namesOf(ts)
	if !contains(names, "jQuery") {
		t.Fatalf("expected jQuery detection, got %v", names)
	}
}

func TestExtractMeta(t *testing.T) {
	html := `<html><head>
		<meta name="generator" content="WordPress 5.8">
		<meta property="og:title" content="Hello">
	</head></html>`
	m := ExtractMeta(html)
	if len(m["generator"]) == 0 || !strings.Contains(m["generator"][0], "WordPress") {
		t.Errorf("generator meta not parsed: %v", m)
	}
	if len(m["og:title"]) == 0 {
		t.Errorf("og:title meta not parsed: %v", m)
	}
}

func TestAggregate(t *testing.T) {
	pages := []AggPage{
		{URL: "http://x/a", Technologies: []Tech{{Name: "nginx", Version: "1.18", Confidence: 100}}},
		{URL: "http://x/b", Technologies: []Tech{{Name: "nginx", Version: "1.18.0", Confidence: 50}}},
		{URL: "http://x/c", Technologies: []Tech{{Name: "PHP", Confidence: 100}}},
	}
	agg := Aggregate(pages)
	if len(agg) != 2 {
		t.Fatalf("expected 2 aggregated techs, got %d: %+v", len(agg), agg)
	}
	for _, a := range agg {
		if a.Name == "nginx" {
			if a.Version != "1.18.0" {
				t.Errorf("expected longest version 1.18.0, got %q", a.Version)
			}
			if a.Hits != 2 {
				t.Errorf("expected 2 hits, got %d", a.Hits)
			}
			if len(a.SampleURLs) != 2 {
				t.Errorf("expected 2 sample urls, got %d", len(a.SampleURLs))
			}
		}
	}
}

func TestEmptyInputNoCrash(t *testing.T) {
	e := loadEngine(t)
	ts := e.AnalyzeStatic(PageInput{})
	if ts == nil {
		t.Fatal("nil result for empty input")
	}
}
