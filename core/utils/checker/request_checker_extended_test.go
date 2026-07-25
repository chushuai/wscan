package checker

import (
	"testing"

	"wscan/core/http"
	"wscan/core/utils/checker/filter"
)

func TestNewRequestChecker(t *testing.T) {
	config := &RequestCheckerConfig{}
	sf := filter.NewSyncMapFilter()
	rc := NewRequestChecker(config, sf)

	if rc == nil {
		t.Fatal("NewRequestChecker returned nil")
	}
	if rc.URLChecker == nil {
		t.Error("URLChecker should not be nil")
	}
}

func TestRequestChecker_Target(t *testing.T) {
	config := &RequestCheckerConfig{}
	sf := filter.NewSyncMapFilter()
	rc := NewRequestChecker(config, sf)

	req, err := http.NewRequest("GET", "http://example.com/path", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	pattern := rc.Target(req)
	if pattern == nil {
		t.Fatal("Target returned nil")
	}
	if pattern.Req == nil {
		t.Error("Req should not be nil")
	}
	if pattern.Checker != rc {
		t.Error("Checker should match request checker")
	}
}

func TestRequestChecker_TargetStr(t *testing.T) {
	config := &RequestCheckerConfig{}
	sf := filter.NewSyncMapFilter()
	rc := NewRequestChecker(config, sf)

	pattern := rc.TargetStr("http://example.com/path")
	if pattern == nil {
		t.Fatal("TargetStr returned nil")
	}
}

func TestRequestChecker_NewSubChecker(t *testing.T) {
	config := &RequestCheckerConfig{}
	sf := filter.NewSyncMapFilter()
	rc := NewRequestChecker(config, sf)
	rc.Scope = "parent"

	sub := rc.NewSubChecker("child")
	if sub == nil {
		t.Fatal("NewSubChecker returned nil")
	}
	if sub.Scope != "parent.child" {
		t.Errorf("Scope = %q, expected 'parent.child'", sub.Scope)
	}
}

func TestRequestChecker_AddScope(t *testing.T) {
	config := &RequestCheckerConfig{}
	sf := filter.NewSyncMapFilter()
	rc := NewRequestChecker(config, sf)

	result := rc.AddScope("scope")
	// Currently returns nil
	if result != nil {
		t.Error("AddScope currently returns nil")
	}
}

func TestRequestChecker_Close(t *testing.T) {
	config := &RequestCheckerConfig{}
	sf := filter.NewSyncMapFilter()
	rc := NewRequestChecker(config, sf)

	err := rc.Close()
	if err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
}

func TestRequestChecker_Reset(t *testing.T) {
	config := &RequestCheckerConfig{}
	sf := filter.NewSyncMapFilter()
	rc := NewRequestChecker(config, sf)

	err := rc.Reset()
	if err != nil {
		t.Errorf("Reset() returned error: %v", err)
	}
}

func TestRequestChecker_DisableAutoInsert(t *testing.T) {
	config := &RequestCheckerConfig{}
	sf := filter.NewSyncMapFilter()
	rc := NewRequestChecker(config, sf)

	result := rc.DisableAutoInsert()
	if result != nil {
		t.Error("DisableAutoInsert currently returns nil")
	}
}

func TestRequestChecker_WithTTL(t *testing.T) {
	config := &RequestCheckerConfig{}
	sf := filter.NewSyncMapFilter()
	rc := NewRequestChecker(config, sf)

	result := rc.WithTTL(100)
	if result != nil {
		t.Error("WithTTL currently returns nil")
	}
}

func TestRequestChecker_Insert(t *testing.T) {
	config := &RequestCheckerConfig{}
	sf := filter.NewSyncMapFilter()
	rc := NewRequestChecker(config, sf)

	rc.Insert("key")
	// No-op, just verify it doesn't panic
}

func TestRequestChecker_IsInserted(t *testing.T) {
	config := &RequestCheckerConfig{}
	sf := filter.NewSyncMapFilter()
	rc := NewRequestChecker(config, sf)

	result := rc.IsInserted("key", false)
	if result {
		t.Error("IsInserted currently returns false")
	}
}

func TestReqPattern_Bool(t *testing.T) {
	rp := &ReqPattern{}
	if rp.Bool() {
		t.Error("ReqPattern.Bool() currently returns false")
	}
}

func TestReqPattern_Error(t *testing.T) {
	rp := &ReqPattern{}
	if rp.Error() != nil {
		t.Error("ReqPattern.Error() currently returns nil")
	}
}

func TestReqPattern_Hash(t *testing.T) {
	rp := &ReqPattern{hash: "testhash"}
	if rp.Hash() != "testhash" {
		t.Errorf("Hash() = %q, expected 'testhash'", rp.Hash())
	}
}

func TestReqPattern_URLString(t *testing.T) {
	sf := filter.NewSyncMapFilter()
	config := &URLCheckerConfig{}
	uc := NewURLChecker(config, sf)

	rp := &ReqPattern{
		URLPattern: uc.TargetStr("http://example.com/path"),
	}
	if rp.URLString() != "http://example.com/path" {
		t.Errorf("URLString() = %q, expected 'http://example.com/path'", rp.URLString())
	}
}

func TestReqPattern_AddScope(t *testing.T) {
	rp := &ReqPattern{}
	result := rp.AddScope("scope")
	if result != nil {
		t.Error("AddScope currently returns nil")
	}
}

func TestReqPattern_DisableAutoInsert(t *testing.T) {
	rp := &ReqPattern{}
	result := rp.DisableAutoInsert()
	if result != nil {
		t.Error("DisableAutoInsert currently returns nil")
	}
}

func TestReqPattern_WithTTL(t *testing.T) {
	rp := &ReqPattern{}
	result := rp.WithTTL(100)
	if result != nil {
		t.Error("WithTTL currently returns nil")
	}
}

func TestReqPattern_IsAllowed_NoRestrictions(t *testing.T) {
	config := &RequestCheckerConfig{}
	sf := filter.NewSyncMapFilter()
	rc := NewRequestChecker(config, sf)

	req, _ := http.NewRequest("GET", "http://example.com/path", nil)
	pattern := rc.Target(req)
	result := pattern.IsAllowed()
	// Should return the pattern (no restrictions set)
	if result == nil {
		t.Error("IsAllowed should return non-nil")
	}
}

func TestNewRequestChecker_WithConfig(t *testing.T) {
	config := &RequestCheckerConfig{
		URLCheckerConfig: URLCheckerConfig{
			HostnameAllowed: []string{"example.com"},
		},
		MethodAllowed:    []string{"GET", "POST"},
		MethodDisallowed: []string{"DELETE"},
	}
	sf := filter.NewSyncMapFilter()
	rc := NewRequestChecker(config, sf)

	if rc.MethodAllowedMatcher.IsEmpty() {
		t.Error("MethodAllowedMatcher should not be empty")
	}
	if rc.MethodDisallowedMatcher.IsEmpty() {
		t.Error("MethodDisallowedMatcher should not be empty")
	}
}
