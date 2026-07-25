package checker

import (
	"net/url"
	"testing"

	"wscan/core/utils/checker/filter"
)

func TestNewURLChecker(t *testing.T) {
	config := &URLCheckerConfig{}
	sf := filter.NewSyncMapFilter()
	uc := NewURLChecker(config, sf)

	if uc == nil {
		t.Fatal("NewURLChecker returned nil")
	}
	if uc.Filter == nil {
		t.Error("Filter should not be nil")
	}
}

func TestURLChecker_AddScope(t *testing.T) {
	config := &URLCheckerConfig{}
	sf := filter.NewSyncMapFilter()
	uc := NewURLChecker(config, sf)

	result := uc.AddScope("test_scope")
	if result != uc {
		t.Error("AddScope should return the URLChecker")
	}
	if uc.Scope != "test_scope" {
		t.Errorf("Scope = %q, expected 'test_scope'", uc.Scope)
	}
}

func TestURLChecker_DisableAutoInsert(t *testing.T) {
	config := &URLCheckerConfig{}
	sf := filter.NewSyncMapFilter()
	uc := NewURLChecker(config, sf)

	result := uc.DisableAutoInsert()
	if result != uc {
		t.Error("DisableAutoInsert should return the URLChecker")
	}
	if !uc.AutoInsertDisabled {
		t.Error("AutoInsertDisabled should be true")
	}
}

func TestURLChecker_WithTTL(t *testing.T) {
	config := &URLCheckerConfig{}
	sf := filter.NewSyncMapFilter()
	uc := NewURLChecker(config, sf)

	result := uc.WithTTL(3600)
	if result != uc {
		t.Error("WithTTL should return the URLChecker")
	}
	if uc.TTL != 3600 {
		t.Errorf("TTL = %d, expected 3600", uc.TTL)
	}
}

func TestURLChecker_Close(t *testing.T) {
	config := &URLCheckerConfig{}
	sf := filter.NewSyncMapFilter()
	uc := NewURLChecker(config, sf)

	err := uc.Close()
	if err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
}

func TestURLChecker_Reset(t *testing.T) {
	config := &URLCheckerConfig{}
	sf := filter.NewSyncMapFilter()
	uc := NewURLChecker(config, sf)

	uc.AutoInsertDisabled = true
	uc.TTL = 3600

	err := uc.Reset()
	if err != nil {
		t.Errorf("Reset() returned error: %v", err)
	}
	if uc.AutoInsertDisabled {
		t.Error("AutoInsertDisabled should be false after reset")
	}
	if uc.TTL != 0 {
		t.Errorf("TTL = %d, expected 0 after reset", uc.TTL)
	}
}

func TestURLChecker_Insert(t *testing.T) {
	config := &URLCheckerConfig{}
	sf := filter.NewSyncMapFilter()
	uc := NewURLChecker(config, sf)

	uc.Insert("http://example.com")
}

func TestURLChecker_IsInserted(t *testing.T) {
	config := &URLCheckerConfig{}
	sf := filter.NewSyncMapFilter()
	uc := NewURLChecker(config, sf)

	// Initially not inserted
	if uc.IsInserted("http://example.com", false) {
		t.Error("URL should not be inserted initially")
	}
}

func TestURLChecker_IsInsertedWithTTL_AutoInsertEnabled(t *testing.T) {
	config := &URLCheckerConfig{}
	sf := filter.NewSyncMapFilter()
	uc := NewURLChecker(config, sf)

	// AutoInsertDisabled is false, so it inserts and returns false
	result := uc.IsInsertedWithTTL("http://example.com", false, 0)
	if result {
		t.Error("IsInsertedWithTTL with auto-insert enabled should return false")
	}
}

func TestURLChecker_IsInsertedWithTTL_AutoInsertDisabled(t *testing.T) {
	config := &URLCheckerConfig{}
	sf := filter.NewSyncMapFilter()
	uc := NewURLChecker(config, sf)
	uc.DisableAutoInsert()

	result := uc.IsInsertedWithTTL("http://example.com", false, 0)
	// Should check filter
	if result {
		t.Error("URL should not be inserted in filter yet")
	}
}

func TestURLChecker_TargetStr(t *testing.T) {
	config := &URLCheckerConfig{}
	sf := filter.NewSyncMapFilter()
	uc := NewURLChecker(config, sf)

	pattern := uc.TargetStr("http://example.com/path?q=1")
	if pattern == nil {
		t.Fatal("TargetStr returned nil")
	}
	if pattern.URL == nil {
		t.Error("URL should not be nil")
	}
	if pattern.urlStr != "http://example.com/path?q=1" {
		t.Errorf("urlStr = %q, expected original URL", pattern.urlStr)
	}
}

func TestURLChecker_TargetStr_InvalidURL(t *testing.T) {
	config := &URLCheckerConfig{}
	sf := filter.NewSyncMapFilter()
	uc := NewURLChecker(config, sf)

	pattern := uc.TargetStr("://invalid")
	if pattern == nil {
		t.Fatal("TargetStr returned nil")
	}
	if pattern.err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestURLChecker_TargetURL(t *testing.T) {
	config := &URLCheckerConfig{}
	sf := filter.NewSyncMapFilter()
	uc := NewURLChecker(config, sf)
	uc.Scope = "test_scope"
	uc.AutoInsertDisabled = true
	uc.TTL = 100

	u, _ := url.Parse("http://example.com/path")
	pattern := uc.TargetURL(u)

	if pattern == nil {
		t.Fatal("TargetURL returned nil")
	}
	if pattern.URL != u {
		t.Error("URL should match input")
	}
	if pattern.Scope != "test_scope" {
		t.Errorf("Scope = %q, expected 'test_scope'", pattern.Scope)
	}
	if !pattern.AutoInsertDisabled {
		t.Error("AutoInsertDisabled should be true")
	}
	if pattern.TTL != 100 {
		t.Errorf("TTL = %d, expected 100", pattern.TTL)
	}
}

func TestURLChecker_NewSubChecker(t *testing.T) {
	config := &URLCheckerConfig{}
	sf := filter.NewSyncMapFilter()
	uc := NewURLChecker(config, sf)

	result := uc.NewSubChecker("sub")
	if result != nil {
		t.Error("NewSubChecker should return nil (currently unimplemented)")
	}
}

func TestNewURLPattern(t *testing.T) {
	p := NewURLPattern("http://example.com/path")
	if p == nil {
		t.Fatal("NewURLPattern returned nil")
	}
	if p.URL == nil {
		t.Error("URL should not be nil")
	}
	if p.Scope != "example.com" {
		t.Errorf("Scope = %q, expected 'example.com'", p.Scope)
	}
}

func TestNewURLPattern_InvalidURL(t *testing.T) {
	p := NewURLPattern("://invalid")
	if p == nil {
		t.Fatal("NewURLPattern returned nil")
	}
	if p.err == nil {
		t.Error("expected error for invalid URL")
	}
	if p.Bool() {
		t.Error("Bool() should return false when error is set")
	}
}

func TestURLPattern_Bool(t *testing.T) {
	p := NewURLPattern("http://example.com")
	if !p.Bool() {
		t.Error("Bool() should return true when no error")
	}
}

func TestURLPattern_DisableAutoInsert(t *testing.T) {
	p := NewURLPattern("http://example.com")
	result := p.DisableAutoInsert()
	if result != p {
		t.Error("DisableAutoInsert should return the URLPattern")
	}
	if !p.AutoInsertDisabled {
		t.Error("AutoInsertDisabled should be true")
	}
}

func TestURLPattern_AddScope(t *testing.T) {
	p := NewURLPattern("http://example.com")
	result := p.AddScope("/api")
	if result != p {
		t.Error("AddScope should return the URLPattern")
	}
	if p.Scope != "example.com/api" {
		t.Errorf("Scope = %q, expected 'example.com/api'", p.Scope)
	}
}

func TestNoQueryUrl(t *testing.T) {
	u, _ := url.Parse("http://example.com/path?key=value")
	result := NoQueryUrl(u)
	if result != "http://example.com/path" {
		t.Errorf("NoQueryUrl = %q, expected 'http://example.com/path'", result)
	}
}

func TestNoQueryUrl_NoQuery(t *testing.T) {
	u, _ := url.Parse("http://example.com/path")
	result := NoQueryUrl(u)
	if result != "http://example.com/path" {
		t.Errorf("NoQueryUrl = %q, expected 'http://example.com/path'", result)
	}
}

func TestNoQueryUrl_WithPort(t *testing.T) {
	u, _ := url.Parse("http://example.com:8080/path?key=value")
	result := NoQueryUrl(u)
	if result != "http://example.com:8080/path" {
		t.Errorf("NoQueryUrl = %q, expected 'http://example.com:8080/path'", result)
	}
}

func TestURLChecker_SchemeRestriction(t *testing.T) {
	config := &URLCheckerConfig{
		SchemeAllowed:    []string{"http"},
		SchemeDisallowed: []string{"ftp"},
	}
	sf := filter.NewSyncMapFilter()
	uc := NewURLChecker(config, sf)

	if uc.SchemeAllowedMatcher.IsEmpty() {
		t.Error("SchemeAllowedMatcher should not be empty")
	}
}

func TestURLChecker_PathRestriction(t *testing.T) {
	config := &URLCheckerConfig{
		PathAllowed:    []string{"/api/*"},
		PathDisallowed: []string{"/admin/*"},
	}
	sf := filter.NewSyncMapFilter()
	uc := NewURLChecker(config, sf)

	pattern := uc.TargetStr("http://example.com/admin/secret")
	result := pattern.IsAllowed()
	if result.Bool() {
		t.Error("path /admin/secret should be disallowed")
	}

	pattern2 := uc.TargetStr("http://example.com/api/users")
	result2 := pattern2.IsAllowed()
	if !result2.Bool() {
		t.Error("path /api/users should be allowed")
	}
}

func TestURLPattern_IsNewWebsiteDir(t *testing.T) {
	sf := filter.NewSyncMapFilter()
	config := &URLCheckerConfig{}
	uc := NewURLChecker(config, sf)

	pattern := uc.TargetStr("http://example.com/dir/")
	// SyncMapFilter does not auto-insert on IsInserted, so IsNewWebsiteDir always returns non-nil
	result := pattern.IsNewWebsiteDir()
	if result == nil {
		t.Error("first call should return non-nil (new website dir)")
	}

	// Since SyncMapFilter doesn't implement auto-insert via IsInserted,
	// subsequent calls also return non-nil
	pattern2 := uc.TargetStr("http://example.com/dir/")
	result2 := pattern2.IsNewWebsiteDir()
	if result2 == nil {
		t.Error("with SyncMapFilter, IsNewWebsiteDir returns non-nil (no auto-insert)")
	}
}

func TestURLPattern_IsNewWebsitePath(t *testing.T) {
	sf := filter.NewSyncMapFilter()
	config := &URLCheckerConfig{}
	uc := NewURLChecker(config, sf)

	pattern := uc.TargetStr("http://example.com/path")
	result := pattern.IsNewWebsitePath()
	if result == nil {
		t.Error("first call should return non-nil (new path)")
	}

	// SyncMapFilter doesn't auto-insert, so subsequent calls also return non-nil
	pattern2 := uc.TargetStr("http://example.com/path")
	result2 := pattern2.IsNewWebsitePath()
	if result2 == nil {
		t.Error("with SyncMapFilter, IsNewWebsitePath returns non-nil (no auto-insert)")
	}
}

func TestURLPattern_IsNewWebsite(t *testing.T) {
	sf := filter.NewSyncMapFilter()
	config := &URLCheckerConfig{}
	uc := NewURLChecker(config, sf)

	pattern := uc.TargetStr("http://example.com/path")
	result := pattern.IsNewWebsite()
	if result == nil {
		t.Error("first call should return non-nil (new website)")
	}

	// SyncMapFilter doesn't auto-insert, so subsequent calls also return non-nil
	pattern2 := uc.TargetStr("http://example.com/other")
	result2 := pattern2.IsNewWebsite()
	if result2 == nil {
		t.Error("with SyncMapFilter, IsNewWebsite returns non-nil (no auto-insert)")
	}
}

func TestURLPattern_IsNewHostPort(t *testing.T) {
	sf := filter.NewSyncMapFilter()
	config := &URLCheckerConfig{}
	uc := NewURLChecker(config, sf)

	pattern := uc.TargetStr("http://example.com:8080/")
	// IsNewHostPort currently always returns the pattern
	result := pattern.IsNewHostPort()
	if result == nil {
		t.Error("IsNewHostPort should return non-nil")
	}
}

func TestURLPattern_IsNewWebsiteQueryKey(t *testing.T) {
	sf := filter.NewSyncMapFilter()
	config := &URLCheckerConfig{}
	uc := NewURLChecker(config, sf)

	pattern := uc.TargetStr("http://example.com/?key=value")
	// IsNewWebsiteQueryKey currently always returns the pattern
	result := pattern.IsNewWebsiteQueryKey()
	if result == nil {
		t.Error("IsNewWebsiteQueryKey should return non-nil")
	}
}

func TestURLChecker_InsertWithTTL(t *testing.T) {
	sf := filter.NewSyncMapFilter()
	config := &URLCheckerConfig{}
	uc := NewURLChecker(config, sf)

	// InsertWithTTL with valid URL
	uc.InsertWithTTL("http://example.com", 3600)
	// Should not panic - function currently has early return
}

func TestURLChecker_InsertWithTTL_InvalidURL(t *testing.T) {
	sf := filter.NewSyncMapFilter()
	config := &URLCheckerConfig{}
	uc := NewURLChecker(config, sf)

	// InsertWithTTL with invalid URL - should return early without panic
	uc.InsertWithTTL("://invalid", 3600)
}
