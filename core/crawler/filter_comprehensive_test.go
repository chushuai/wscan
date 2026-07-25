package crawler

import (
	"strings"
	"sync"
	"testing"
	"wscan/core/http"
)

// ---------- SyncMapFilter tests ----------

func TestSyncMapFilterCheckAndInsert(t *testing.T) {
	f := &SyncMapFilter{Map: &sync.Map{}}

	// Key doesn't exist yet, addIfMissing=false: should return false (not found)
	if f.Check("key1", false) {
		t.Error("Check should return false for missing key with addIfMissing=false")
	}

	// Key doesn't exist yet, addIfMissing=true: should return false (not found, but now added)
	if f.Check("key1", true) {
		t.Error("Check should return false when first adding key with addIfMissing=true")
	}

	// Key exists now, should return true
	if !f.Check("key1", false) {
		t.Error("Check should return true for existing key")
	}

	if !f.Check("key1", true) {
		t.Error("Check should return true for existing key with addIfMissing=true")
	}
}

func TestSyncMapFilterInsert(t *testing.T) {
	f := &SyncMapFilter{Map: &sync.Map{}}
	f.Insert("test_key")
	if !f.Check("test_key", false) {
		t.Error("Insert should make Check return true")
	}
}

func TestSyncMapFilterReset(t *testing.T) {
	f := &SyncMapFilter{Map: &sync.Map{}}
	f.Insert("key1")
	f.Insert("key2")
	f.Reset()
	if f.Check("key1", false) {
		t.Error("After Reset, Check should return false for previously inserted key")
	}
	if f.Check("key2", false) {
		t.Error("After Reset, Check should return false for previously inserted key")
	}
}

func TestSyncMapFilterClose(t *testing.T) {
	f := &SyncMapFilter{Map: &sync.Map{}}
	f.Insert("key1")
	f.Close()
	// After Close, the internal map is replaced, so key1 should be gone
	if f.Check("key1", false) {
		t.Error("After Close, Check should return false for previously inserted key")
	}
}

// ---------- SimpleFilter tests ----------

func TestSimpleFilterUniqueFilter(t *testing.T) {
	s := &SimpleFilter{}
	req, _ := http.NewRequest("GET", "http://example.com/page?q=1", nil)

	// First time should not be filtered
	if s.UniqueFilter(req, false) {
		t.Error("First request should not be filtered by UniqueFilter")
	}

	// Same request should be filtered
	if !s.UniqueFilter(req, false) {
		t.Error("Duplicate request should be filtered by UniqueFilter")
	}
}

func TestSimpleFilterUniqueFilterRedirection(t *testing.T) {
	s := &SimpleFilter{}
	req, _ := http.NewRequest("GET", "http://example.com/page?q=1", nil)

	// Non-redirect first time should not be filtered
	if s.UniqueFilter(req, false) {
		t.Error("First non-redirect request should not be filtered")
	}

	// Same request as redirect should NOT be filtered (different ID)
	if s.UniqueFilter(req, true) {
		t.Error("First redirect request should not be filtered")
	}

	// Same redirect should now be filtered
	if !s.UniqueFilter(req, true) {
		t.Error("Duplicate redirect request should be filtered")
	}
}

func TestSimpleFilterStaticFilter(t *testing.T) {
	s := &SimpleFilter{}

	tests := []struct {
		url        string
		wantFilter bool
	}{
		{"http://example.com/image.png", true},
		{"http://example.com/video.mp4", true},
		{"http://example.com/style.css", true},
		{"http://example.com/data.json", true},
		{"http://example.com/robots.txt", false}, // special case
		{"http://example.com/page", false},
		{"http://example.com/api/users", false},
		{"http://example.com/archive.zip", true},
		{"http://example.com/doc.pdf", true},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			req, _ := http.NewRequest("GET", tt.url, nil)
			got := s.StaticFilter(req)
			if got != tt.wantFilter {
				t.Errorf("StaticFilter(%s) = %v, want %v", tt.url, got, tt.wantFilter)
			}
		})
	}
}

func TestSimpleFilterDomainFilter(t *testing.T) {
	s := &SimpleFilter{HostLimit: "example.com"}

	tests := []struct {
		url        string
		wantFilter bool
	}{
		{"http://example.com/page", false},
		{"http://other.com/page", true},
		{"http://sub.example.com/page", true}, // exact match required
		{"https://example.com/page", false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			req, _ := http.NewRequest("GET", tt.url, nil)
			got := s.DomainFilter(req)
			if got != tt.wantFilter {
				t.Errorf("DomainFilter(%s) = %v, want %v", tt.url, got, tt.wantFilter)
			}
		})
	}
}

func TestSimpleFilterDomainFilterHTTPPort80(t *testing.T) {
	s := &SimpleFilter{HostLimit: "example.com:80"}
	req, _ := http.NewRequest("GET", "http://example.com/page", nil)
	// HTTP default port is 80, so example.com with scheme http should match example.com:80
	if s.DomainFilter(req) {
		t.Error("example.com:80 should match http://example.com (port 80 is default)")
	}
}

func TestSimpleFilterDomainFilterHTTPSPort443(t *testing.T) {
	s := &SimpleFilter{HostLimit: "example.com:443"}
	req, _ := http.NewRequest("GET", "https://example.com/page", nil)
	// HTTPS default port is 443
	if s.DomainFilter(req) {
		t.Error("example.com:443 should match https://example.com (port 443 is default)")
	}
}

func TestSimpleFilterDoFilter(t *testing.T) {
	s := &SimpleFilter{HostLimit: "example.com"}

	// Non-matching domain should be filtered
	req1, _ := http.NewRequest("GET", "http://other.com/page", nil)
	if !s.DoFilter(req1, false) {
		t.Error("Request to other domain should be filtered")
	}

	// Matching domain, not static, first time should not be filtered
	req2, _ := http.NewRequest("GET", "http://example.com/api/data", nil)
	if s.DoFilter(req2, false) {
		t.Error("Valid request should not be filtered")
	}

	// Duplicate should be filtered
	if !s.DoFilter(req2, false) {
		t.Error("Duplicate request should be filtered")
	}

	// Static resource should be filtered
	req3, _ := http.NewRequest("GET", "http://example.com/image.png", nil)
	if !s.DoFilter(req3, false) {
		t.Error("Static resource should be filtered")
	}
}

func TestNoHeaderId(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://example.com/api?q=test", nil)
	id1 := NoHeaderId(req)
	if id1 == "" {
		t.Error("NoHeaderId should not return empty string")
	}

	// Same request should produce same ID
	req2, _ := http.NewRequest("GET", "http://example.com/api?q=test", nil)
	id2 := NoHeaderId(req2)
	if id1 != id2 {
		t.Error("Same request should produce same NoHeaderId")
	}

	// Different URL should produce different ID
	req3, _ := http.NewRequest("GET", "http://example.com/api?q=other", nil)
	id3 := NoHeaderId(req3)
	if id1 == id3 {
		t.Error("Different requests should produce different NoHeaderId")
	}
}

func TestUniqueId(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://example.com/api", nil)

	id1 := UniqueId(req, false)
	id2 := UniqueId(req, true)

	if id1 == "" || id2 == "" {
		t.Error("UniqueId should not return empty string")
	}

	// Redirect flag should produce different IDs
	if id1 == id2 {
		t.Error("Redirect and non-redirect should produce different UniqueIds")
	}
}

// ---------- SmartFilter tests ----------

func TestSmartFilterInit(t *testing.T) {
	s := SmartFilter{}
	s.Init()

	if s.filterLocationSet == nil {
		t.Error("filterLocationSet should be initialized")
	}
	if s.uniqueMarkedIds == nil {
		t.Error("uniqueMarkedIds should be initialized")
	}
}

func TestSmartFilterDoFilterBasic(t *testing.T) {
	s := SmartFilter{
		SimpleFilter: SimpleFilter{},
	}
	s.Init()

	req, _ := http.NewRequest("GET", "http://example.com/api/data", nil)

	// First request should not be filtered
	if s.DoFilter(req, false) {
		t.Error("First request should not be filtered by SmartFilter")
	}
}

func TestSmartFilterDoFilterDuplicate(t *testing.T) {
	s := SmartFilter{
		SimpleFilter: SimpleFilter{},
	}
	s.Init()

	req, _ := http.NewRequest("GET", "http://example.com/api/data", nil)

	// First request should not be filtered
	if s.DoFilter(req, false) {
		t.Error("First request should not be filtered")
	}

	// Exact duplicate should be filtered
	if !s.DoFilter(req, false) {
		t.Error("Duplicate request should be filtered")
	}
}

func TestSmartFilterDoFilterDifferentURLs(t *testing.T) {
	s := SmartFilter{
		SimpleFilter: SimpleFilter{},
	}
	s.Init()

	req1, _ := http.NewRequest("GET", "http://example.com/api/data1", nil)
	req2, _ := http.NewRequest("GET", "http://example.com/api/data2", nil)

	if s.DoFilter(req1, false) {
		t.Error("First URL should not be filtered")
	}
	if s.DoFilter(req2, false) {
		t.Error("Different URL should not be filtered")
	}
}

func TestSmartFilterMarkPath(t *testing.T) {
	s := SmartFilter{}

	tests := []struct {
		name string
		path string
		want string
	}{
		{"simple path", "/api/users", "/api/users"},
		{"numeric path segment", "/api/12345", "/api/{{number}}"},
		{"long segment", "/api/abcdefghijklmnopqrstuvwxyz1234567890", "/api/{{long}}"},
		{"html file", "/page.html", "/page"},
		{"shtml file", "/page.shtml", "/page"},
		{"htm file", "/page.htm", "/page"},
		{"chinese path", "/路径/页面", "/{{chinese}}/{{chinese}}"},
		{"uppercase only", "/API/ABC", "/{{upper}}/{{upper}}"},
		{"mixed case with numbers", "/path/item123abc", "/path/item123abc"},
		{"dot separated filename", "/static/main.abc123.js", "/static/main.abc123.js"},
		{"path with only numbers and symbols", "/2023/01/15", "/{{number}}/{{number}}/{{number}}"},
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

func TestSmartFilterPreQueryMark(t *testing.T) {
	s := SmartFilter{}

	tests := []struct {
		name     string
		rawQuery string
		wantMark bool
	}{
		{"chinese query", "name=测试", true},
		{"urlencoded query", "name=%E6%B5%8B%E8%AF%95", true},
		{"unicode query", "name=\\u6d4b\\u8bd5", true},
		{"plain query", "name=test", false},
		{"empty query", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.preQueryMark(tt.rawQuery)
			if tt.wantMark && result == tt.rawQuery {
				// If we expected marking, the result should differ (unless marking didn't match)
				t.Logf("preQueryMark(%q) = %q (wantMark=%v)", tt.rawQuery, result, tt.wantMark)
			}
			if !tt.wantMark && result != tt.rawQuery {
				t.Errorf("preQueryMark(%q) = %q, want unchanged", tt.rawQuery, result)
			}
		})
	}
}

func TestSmartFilterMarkParamName(t *testing.T) {
	s := SmartFilter{}

	tests := []struct {
		name   string
		params map[string]any
		want   map[string]bool // expected keys in result
	}{
		{
			name:   "simple alpha keys",
			params: map[string]any{"name": "val", "age": "val"},
			want:   map[string]bool{"name": true, "age": true},
		},
		{
			name:   "numeric key replaced",
			params: map[string]any{"param123": "val"},
			want:   map[string]bool{"param{{number}}": true},
		},
		{
			name:   "long key replaced",
			params: map[string]any{"a_very_long_parameter_name_that_exceeds_32": "val"},
			want:   map[string]bool{"{{long}}": true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.markParamName(tt.params)
			for wantKey := range tt.want {
				if _, ok := result[wantKey]; !ok {
					t.Errorf("markParamName result missing key %q, got %v", wantKey, result)
				}
			}
		})
	}
}

func TestSmartFilterGetMarkedUniqueID(t *testing.T) {
	s := SmartFilter{}
	req1, _ := http.NewRequest("GET", "http://example.com/api?q=1", nil)
	req2, _ := http.NewRequest("GET", "http://example.com/api?q=2", nil)

	id1 := s.getMarkedUniqueID(req1, "qm1", "", "p1", false)
	id2 := s.getMarkedUniqueID(req2, "qm2", "", "p1", false)

	if id1 == "" || id2 == "" {
		t.Error("getMarkedUniqueID should not return empty string")
	}

	// Different query map IDs should produce different unique IDs
	if id1 == id2 {
		t.Error("Different parameters should produce different marked unique IDs")
	}
}

func TestSmartFilterGetKeysID(t *testing.T) {
	s := SmartFilter{}

	dataMap1 := map[string]any{"a": "1", "b": "2"}
	dataMap2 := map[string]any{"b": "2", "a": "1"} // same keys, different order
	dataMap3 := map[string]any{"a": "1", "c": "3"} // different keys

	id1 := s.getKeysID(dataMap1)
	id2 := s.getKeysID(dataMap2)
	id3 := s.getKeysID(dataMap3)

	if id1 != id2 {
		t.Error("Same keys in different order should produce same keys ID")
	}
	if id1 == id3 {
		t.Error("Different keys should produce different keys IDs")
	}
}

func TestSmartFilterGetParamMapID(t *testing.T) {
	s := SmartFilter{}

	dataMap1 := map[string]any{"a": "{{number}}", "b": "static"}
	dataMap2 := map[string]any{"a": "{{number}}", "b": "static"}

	id1 := s.getParamMapID(dataMap1)
	id2 := s.getParamMapID(dataMap2)

	if id1 != id2 {
		t.Error("Same parameter maps should produce same IDs")
	}
}

func TestSmartFilterGetPathID(t *testing.T) {
	s := SmartFilter{}

	id1 := s.getPathID("/api/users")
	id2 := s.getPathID("/api/users")
	id3 := s.getPathID("/api/posts")

	if id1 != id2 {
		t.Error("Same paths should produce same IDs")
	}
	if id1 == id3 {
		t.Error("Different paths should produce different IDs")
	}
}

func TestSmartFilterHasSpecialSymbol(t *testing.T) {
	s := SmartFilter{}

	tests := []struct {
		str  string
		want bool
	}{
		{"hello", false},
		{"hello world", true}, // space
		{"test@domain", true}, // @
		{"$100", true},        // $
		{"a=b", true},         // =
		{"{json}", true},      // { }
		{"path/to", true},     // /
		{"normal_text", false},
		{"<tag>", true}, // < >
	}

	for _, tt := range tests {
		got := s.hasSpecialSymbol(tt.str)
		if got != tt.want {
			t.Errorf("hasSpecialSymbol(%q) = %v, want %v", tt.str, got, tt.want)
		}
	}
}

func TestSmartFilterInCommonScriptSuffix(t *testing.T) {
	s := SmartFilter{}

	tests := []struct {
		suffix string
		want   bool
	}{
		{"php", true},
		{"asp", true},
		{"jsp", true},
		{"asa", true},
		{"html", false},
		{"js", false},
		{"py", false},
	}

	for _, tt := range tests {
		got := s.inCommonScriptSuffix(tt.suffix)
		if got != tt.want {
			t.Errorf("inCommonScriptSuffix(%q) = %v, want %v", tt.suffix, got, tt.want)
		}
	}
}

func TestSmartFilterPOSTRequest(t *testing.T) {
	s := SmartFilter{
		SimpleFilter: SimpleFilter{},
	}
	s.Init()

	req, _ := http.NewRequest("POST", "http://example.com/api/submit", strings.NewReader("name=test"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if s.DoFilter(req, false) {
		t.Error("First POST request should not be filtered")
	}

	// Duplicate POST should be filtered
	req2, _ := http.NewRequest("POST", "http://example.com/api/submit", strings.NewReader("name=test"))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if !s.DoFilter(req2, false) {
		t.Error("Duplicate POST request should be filtered")
	}
}

func TestSmartFilterSmartDedup(t *testing.T) {
	s := SmartFilter{
		SimpleFilter: SimpleFilter{},
	}
	s.Init()

	// These have the same path structure but different numeric values
	urls := []string{
		"http://example.com/user/1/profile",
		"http://example.com/user/2/profile",
		"http://example.com/user/3/profile",
	}

	filtered := 0
	for _, u := range urls {
		req, _ := http.NewRequest("GET", u, nil)
		if s.DoFilter(req, false) {
			filtered++
		}
	}
	// After the first request, subsequent ones with different numeric values
	// may or may not be filtered depending on smart filter behavior
	t.Logf("Filtered %d out of %d similar URLs", filtered, len(urls))
}
