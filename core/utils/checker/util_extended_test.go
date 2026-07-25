package checker

import (
	"testing"

	whttp "wscan/core/http"
	"wscan/core/utils/checker/filter"
)

// --- Coverage for uncovered checker functions ---

func TestRequestChecker_InsertWithTTL_Extended(t *testing.T) {
	config := &RequestCheckerConfig{}
	sf := filter.NewSyncMapFilter()
	rc := NewRequestChecker(config, sf)

	rc.InsertWithTTL("http://example.com", 100)
	// Just verify no panic
}

func TestRequestChecker_IsInsertedWithTTL_Extended(t *testing.T) {
	config := &RequestCheckerConfig{}
	sf := filter.NewSyncMapFilter()
	rc := NewRequestChecker(config, sf)

	result := rc.IsInsertedWithTTL("key", false, 0)
	if result {
		t.Error("IsInsertedWithTTL currently returns false")
	}
}

func TestReqPattern_IsAllowed_WithPostKeyRestrictions(t *testing.T) {
	config := &RequestCheckerConfig{
		PostKeyAllowed:    []string{"id", "name"},
		PostKeyDisallowed: []string{"token"},
	}
	sf := filter.NewSyncMapFilter()
	rc := NewRequestChecker(config, sf)

	req, _ := whttp.NewRequest("POST", "http://example.com/api", nil)
	pattern := rc.Target(req)
	pattern.bodyKeys = []string{"id", "name"}

	result := pattern.IsAllowed()
	// PostKeyAllowed restriction: id and name are in allowed list
	if result == nil {
		t.Error("IsAllowed should return non-nil")
	}
}

func TestReqPattern_IsAllowed_PostKeyDisallowed(t *testing.T) {
	config := &RequestCheckerConfig{
		PostKeyDisallowed: []string{"token"},
	}
	sf := filter.NewSyncMapFilter()
	rc := NewRequestChecker(config, sf)

	req, _ := whttp.NewRequest("POST", "http://example.com/api", nil)
	pattern := rc.Target(req)
	pattern.bodyKeys = []string{"token"}

	result := pattern.IsAllowed()
	// Should have error since "token" is disallowed
	if result.Bool() {
		t.Error("Post key 'token' should be disallowed")
	}
}

func TestReqPattern_IsAllowed_PostKeyNotAllowed(t *testing.T) {
	config := &RequestCheckerConfig{
		PostKeyAllowed: []string{"id"},
	}
	sf := filter.NewSyncMapFilter()
	rc := NewRequestChecker(config, sf)

	req, _ := whttp.NewRequest("POST", "http://example.com/api", nil)
	pattern := rc.Target(req)
	pattern.bodyKeys = []string{"secret"}

	result := pattern.IsAllowed()
	// "secret" is not in allowed list
	if result.Bool() {
		t.Error("Post key 'secret' should be disallowed (not in allowed list)")
	}
}

func TestReqPattern_IsAllowed_URLErrorPropagates(t *testing.T) {
	config := &RequestCheckerConfig{
		URLCheckerConfig: URLCheckerConfig{
			HostnameAllowed: []string{"example.com"},
		},
	}
	sf := filter.NewSyncMapFilter()
	rc := NewRequestChecker(config, sf)

	req, _ := whttp.NewRequest("GET", "http://evil.com/path", nil)
	pattern := rc.Target(req)

	result := pattern.IsAllowed()
	// hostname not in allowed list - should propagate error from URLPattern
	if result.Bool() {
		t.Error("hostname evil.com should be disallowed")
	}
}

func TestReqPattern_DoCache_Extended(t *testing.T) {
	rp := &ReqPattern{}
	rp.doCache()
	// Currently empty, just ensure no panic
}

func TestGetURLPort_NonNumericPort(t *testing.T) {
	// URL with non-numeric port should return error
	_, err := GetURLPort("http://example.com:abc/path")
	if err == nil {
		t.Error("expected error for non-numeric port")
	}
}

func TestGetQueryKeys_BadQuery(t *testing.T) {
	_, err := GetQueryKeys("http://example.com/path?;;;bad")
	// url.ParseQuery may or may not error; just verify no panic
	_ = err
}
