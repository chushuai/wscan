package http

import (
	"net/http"
	"net/url"
	"testing"
)

func TestCloneURLValues_Nil(t *testing.T) {
	result := cloneURLValues(nil)
	if result != nil {
		t.Errorf("expected nil, got %v", result)
	}
}

func TestCloneURLValues_Empty(t *testing.T) {
	v := url.Values{}
	result := cloneURLValues(v)
	if len(result) != 0 {
		t.Errorf("expected empty url.Values, got %v", result)
	}
}

func TestCloneURLValues_WithData(t *testing.T) {
	v := url.Values{}
	v.Set("key1", "value1")
	v.Set("key2", "value2")
	v.Add("key1", "value1b")

	result := cloneURLValues(v)

	// Verify original is not modified
	if v.Get("key1") != "value1" {
		t.Errorf("original key1 should be value1, got %s", v.Get("key1"))
	}

	// Verify clone has same data
	if result.Get("key1") != "value1" {
		t.Errorf("cloned key1 should be value1, got %s", result.Get("key1"))
	}
	if result.Get("key2") != "value2" {
		t.Errorf("cloned key2 should be value2, got %s", result.Get("key2"))
	}

	// Verify independence - modifying clone doesn't affect original
	result.Set("key1", "modified")
	if v.Get("key1") != "value1" {
		t.Errorf("modifying clone should not affect original; original key1 = %s", v.Get("key1"))
	}
}

func TestCloneURL_Nil(t *testing.T) {
	result := cloneURL(nil)
	if result != nil {
		t.Errorf("expected nil, got %v", result)
	}
}

func TestCloneURL_Basic(t *testing.T) {
	u, _ := url.Parse("http://example.com/path?query=value#fragment")
	result := cloneURL(u)

	if result.String() != u.String() {
		t.Errorf("expected %s, got %s", u.String(), result.String())
	}

	// Verify independence
	result.Path = "/modified"
	if u.Path != "/path" {
		t.Errorf("modifying clone should not affect original; original path = %s", u.Path)
	}
}

func TestCloneURL_WithUserInfo(t *testing.T) {
	u, _ := url.Parse("http://user:pass@example.com/path")
	result := cloneURL(u)

	if result.User.Username() != "user" {
		t.Errorf("expected username 'user', got %s", result.User.Username())
	}

	pass, _ := result.User.Password()
	if pass != "pass" {
		t.Errorf("expected password 'pass', got %s", pass)
	}

	// Verify independence
	result.User = url.UserPassword("other", "otherpass")
	if u.User.Username() != "user" {
		t.Errorf("modifying clone should not affect original; original username = %s", u.User.Username())
	}
}

func TestCloneHeader_Nil(t *testing.T) {
	h := map[string][]string{}
	result := cloneHeader(h)
	if len(result) != 0 {
		t.Errorf("expected empty header, got %v", result)
	}
}

func TestCloneHeader_WithData(t *testing.T) {
	h := map[string][]string{
		"Content-Type": {"text/html"},
		"Accept":       {"text/html", "application/json"},
	}

	result := cloneHeader(h)

	// Verify values are copied
	if result["Content-Type"][0] != "text/html" {
		t.Errorf("expected Content-Type text/html, got %s", result["Content-Type"][0])
	}
	if len(result["Accept"]) != 2 {
		t.Errorf("expected 2 Accept values, got %d", len(result["Accept"]))
	}

	// Verify independence
	result["Content-Type"][0] = "modified"
	if h["Content-Type"][0] != "text/html" {
		t.Errorf("modifying clone should not affect original; original = %s", h["Content-Type"][0])
	}
}

func TestCloneHeader_EmptyMap(t *testing.T) {
	h := map[string][]string{}
	result := cloneHeader(h)
	if len(result) != 0 {
		t.Errorf("expected empty header, got %v", result)
	}
}

func TestCloneHeader_NilHeader(t *testing.T) {
	// Test with nil input map - this would panic, so test with empty map
	var h map[string][]string
	// cloneHeader with nil map would crash since it does range over nil map
	// But in Go, ranging over nil map is fine (produces zero iterations)
	result := cloneHeader(h)
	if len(result) != 0 {
		t.Errorf("expected empty header, got %v", result)
	}
}

// Test that cloneHeader works with http.Header (which is map[string][]string)
func TestCloneHeader_HttpHeader(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Type", "text/html")
	h.Add("Accept", "text/html")
	h.Add("Accept", "application/json")

	result := cloneHeader(h)

	// result is map[string][]string, access directly
	if result["Content-Type"][0] != "text/html" {
		t.Errorf("expected Content-Type text/html, got %s", result["Content-Type"][0])
	}

	// Verify independence
	result["Content-Type"][0] = "modified"
	if h.Get("Content-Type") != "text/html" {
		t.Errorf("modifying clone should not affect original; original = %s", h.Get("Content-Type"))
	}
}
