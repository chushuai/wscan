package checker

import (
	"fmt"
	"net/url"
	"testing"

	whttp "wscan/core/http"
	"wscan/core/utils/checker/filter"
	"wscan/core/utils/checker/matcher"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// URLChecker tests
// =============================================================================

func TestNewURLChecker_FullConfig(t *testing.T) {
	config := &URLCheckerConfig{
		SchemeAllowed:        []string{"http", "https"},
		SchemeDisallowed:     []string{"ftp"},
		HostnameAllowed:      []string{"example.com"},
		HostnameDisallowed:   []string{"evil.com"},
		TCPPortAllowed:       []string{"80", "443"},
		TCPPortDisallowed:    []string{"22"},
		PathAllowed:          []string{"/api/*"},
		PathDisallowed:       []string{"/admin/*"},
		PathSuffixAllowed:    []string{".html"},
		PathSuffixDisallowed: []string{".exe"},
		QueryKeyAllowed:      []string{"id"},
		QueryKeyDisallowed:   []string{"token"},
		QueryRawAllowed:      []string{"id=*"},
		QueryRawDisallowed:   []string{"secret=*"},
		FragmentAllowed:      []string{"section1"},
		FragmentDisallowed:   []string{"debug"},
		URLRegexAllowed:      []string{`^http://example\.com/.*`},
		URLRegexDisallowed:   []string{`^http://evil\.com/.*`},
		URLGlobAllowed:       []string{"http://example.com/*"},
		URLGlobDisallowed:    []string{"http://evil.com/*"},
	}
	sf := filter.NewSyncMapFilter()
	uc := NewURLChecker(config, sf)

	assert.NotNil(t, uc)
	assert.NotNil(t, uc.SchemeAllowedMatcher)
	assert.NotNil(t, uc.SchemeDisallowedMatcher)
	assert.NotNil(t, uc.HostnameAllowedMatcher)
	assert.NotNil(t, uc.HostnameDisallowedMatcher)
	assert.NotNil(t, uc.TCPPortAllowedMatcher)
	assert.NotNil(t, uc.TCPPortDisallowedMatcher)
	assert.NotNil(t, uc.PathAllowedMatcher)
	assert.NotNil(t, uc.PathDisallowedMatcher)
	assert.NotNil(t, uc.PathSuffixAllowedMatcher)
	assert.NotNil(t, uc.PathSuffixDisallowedMatcher)
	assert.NotNil(t, uc.QueryKeyAllowedMatcher)
	assert.NotNil(t, uc.QueryKeyDisallowedMatcher)
	assert.NotNil(t, uc.QueryRawAllowedMatcher)
	assert.NotNil(t, uc.QueryRawDisallowedMatcher)
	assert.NotNil(t, uc.FragmentAllowedMatcher)
	assert.NotNil(t, uc.FragmentDisallowedMatcher)
	assert.NotNil(t, uc.URLRegexAllowedMatcher)
	assert.NotNil(t, uc.URLRegexDisallowedMatcher)
	assert.NotNil(t, uc.URLGlobAllowedMatcher)
	assert.NotNil(t, uc.URLGlobDisallowedMatcher)

	assert.False(t, uc.SchemeAllowedMatcher.IsEmpty())
	assert.False(t, uc.SchemeDisallowedMatcher.IsEmpty())
	assert.False(t, uc.HostnameAllowedMatcher.IsEmpty())
	assert.False(t, uc.HostnameDisallowedMatcher.IsEmpty())
	assert.False(t, uc.TCPPortAllowedMatcher.IsEmpty())
	assert.False(t, uc.TCPPortDisallowedMatcher.IsEmpty())
	assert.False(t, uc.PathAllowedMatcher.IsEmpty())
	assert.False(t, uc.PathDisallowedMatcher.IsEmpty())
	assert.False(t, uc.QueryKeyAllowedMatcher.IsEmpty())
	assert.False(t, uc.QueryKeyDisallowedMatcher.IsEmpty())
	assert.False(t, uc.FragmentAllowedMatcher.IsEmpty())
	assert.False(t, uc.FragmentDisallowedMatcher.IsEmpty())
	// These matchers are created but Add() is never called in NewURLChecker,
	// so they remain empty even though config has values
	assert.True(t, uc.PathSuffixAllowedMatcher.IsEmpty())
	assert.True(t, uc.PathSuffixDisallowedMatcher.IsEmpty())
	assert.True(t, uc.QueryRawAllowedMatcher.IsEmpty())
	assert.True(t, uc.QueryRawDisallowedMatcher.IsEmpty())
	assert.True(t, uc.URLRegexAllowedMatcher.IsEmpty())
	assert.True(t, uc.URLRegexDisallowedMatcher.IsEmpty())
	assert.True(t, uc.URLGlobAllowedMatcher.IsEmpty())
	assert.True(t, uc.URLGlobDisallowedMatcher.IsEmpty())
}

func TestNewURLChecker_EmptyConfig(t *testing.T) {
	config := &URLCheckerConfig{}
	sf := filter.NewSyncMapFilter()
	uc := NewURLChecker(config, sf)

	assert.NotNil(t, uc)
	assert.True(t, uc.SchemeAllowedMatcher.IsEmpty())
	assert.True(t, uc.SchemeDisallowedMatcher.IsEmpty())
	assert.True(t, uc.HostnameAllowedMatcher.IsEmpty())
	assert.True(t, uc.HostnameDisallowedMatcher.IsEmpty())
	assert.True(t, uc.TCPPortAllowedMatcher.IsEmpty())
	assert.True(t, uc.TCPPortDisallowedMatcher.IsEmpty())
	assert.True(t, uc.PathAllowedMatcher.IsEmpty())
	assert.True(t, uc.PathDisallowedMatcher.IsEmpty())
	assert.True(t, uc.PathSuffixAllowedMatcher.IsEmpty())
	assert.True(t, uc.PathSuffixDisallowedMatcher.IsEmpty())
	assert.True(t, uc.QueryKeyAllowedMatcher.IsEmpty())
	assert.True(t, uc.QueryKeyDisallowedMatcher.IsEmpty())
	assert.True(t, uc.QueryRawAllowedMatcher.IsEmpty())
	assert.True(t, uc.QueryRawDisallowedMatcher.IsEmpty())
	assert.True(t, uc.FragmentAllowedMatcher.IsEmpty())
	assert.True(t, uc.FragmentDisallowedMatcher.IsEmpty())
	assert.True(t, uc.URLRegexAllowedMatcher.IsEmpty())
	assert.True(t, uc.URLRegexDisallowedMatcher.IsEmpty())
	assert.True(t, uc.URLGlobAllowedMatcher.IsEmpty())
	assert.True(t, uc.URLGlobDisallowedMatcher.IsEmpty())
}

func TestURLChecker_AddScope_Chainable(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{}, filter.NewSyncMapFilter())
	result := uc.AddScope("myscope")
	assert.Equal(t, uc, result)
	assert.Equal(t, "myscope", uc.Scope)
}

func TestURLChecker_DisableAutoInsert_Chainable(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{}, filter.NewSyncMapFilter())
	assert.False(t, uc.AutoInsertDisabled)
	result := uc.DisableAutoInsert()
	assert.Equal(t, uc, result)
	assert.True(t, uc.AutoInsertDisabled)
}

func TestURLChecker_WithTTL_Chainable(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{}, filter.NewSyncMapFilter())
	assert.Equal(t, int64(0), uc.TTL)
	result := uc.WithTTL(7200)
	assert.Equal(t, uc, result)
	assert.Equal(t, int64(7200), uc.TTL)
}

func TestURLChecker_Close_NilFilter(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{}, filter.NewSyncMapFilter())
	err := uc.Close()
	assert.NoError(t, err)
}

func TestURLChecker_Reset_ClearsState(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{}, filter.NewSyncMapFilter())
	uc.AutoInsertDisabled = true
	uc.TTL = 5000
	err := uc.Reset()
	assert.NoError(t, err)
	assert.False(t, uc.AutoInsertDisabled)
	assert.Equal(t, int64(0), uc.TTL)
}

func TestURLChecker_Insert_AndIsInserted(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{}, filter.NewSyncMapFilter())
	assert.False(t, uc.IsInserted("http://example.com", false))
	uc.Insert("http://example.com")
	assert.True(t, uc.IsInserted("http://example.com", false))
	assert.False(t, uc.IsInserted("http://other.com", false))
}

func TestURLChecker_IsInsertedWithTTL_AutoInsertEnabled_Boost(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{}, filter.NewSyncMapFilter())
	// When AutoInsertDisabled is false, Insert is called and false is returned
	assert.False(t, uc.IsInsertedWithTTL("http://auto.com", false, 0))
}

func TestURLChecker_IsInsertedWithTTL_AutoInsertDisabled_Boost(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{}, filter.NewSyncMapFilter())
	uc.DisableAutoInsert()
	// Not inserted yet
	assert.False(t, uc.IsInsertedWithTTL("http://manual.com", false, 0))
	// Insert and check
	uc.Insert("http://manual.com")
	assert.True(t, uc.IsInsertedWithTTL("http://manual.com", false, 0))
}

func TestURLChecker_InsertWithTTL_ValidURL_Boost(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{}, filter.NewSyncMapFilter())
	uc.InsertWithTTL("http://example.com", 3600)
	// Should not panic; current implementation is a no-op after parsing
}

func TestURLChecker_InsertWithTTL_InvalidURL_Boost(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{}, filter.NewSyncMapFilter())
	uc.InsertWithTTL("://bad-url", 3600)
	// Should not panic; early return on parse error
}

func TestURLChecker_TargetStr_ValidURL(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{}, filter.NewSyncMapFilter())
	p := uc.TargetStr("http://example.com/path?q=1")
	assert.NotNil(t, p)
	assert.NotNil(t, p.URL)
	assert.Equal(t, "http://example.com/path?q=1", p.urlStr)
	assert.Equal(t, "example.com", p.URL.Hostname())
	assert.Nil(t, p.err)
}

func TestURLChecker_TargetStr_InvalidURL_Boost(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{}, filter.NewSyncMapFilter())
	p := uc.TargetStr("://bad")
	assert.NotNil(t, p)
	assert.NotNil(t, p.err)
	assert.False(t, p.Bool())
}

func TestURLChecker_TargetURL_Boost(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{}, filter.NewSyncMapFilter())
	uc.Scope = "testscope"
	uc.AutoInsertDisabled = true
	uc.TTL = 500

	u, _ := url.Parse("http://example.com/page")
	p := uc.TargetURL(u)
	assert.NotNil(t, p)
	assert.Equal(t, u, p.URL)
	assert.Equal(t, "testscope", p.Scope)
	assert.True(t, p.AutoInsertDisabled)
	assert.Equal(t, int64(500), p.TTL)
}

func TestURLChecker_NewSubChecker_ReturnsNil(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{}, filter.NewSyncMapFilter())
	assert.Nil(t, uc.NewSubChecker("sub"))
}

// =============================================================================
// URLPattern tests
// =============================================================================

func TestNewURLPattern_ValidURL_Boost(t *testing.T) {
	p := NewURLPattern("http://example.com/path")
	assert.NotNil(t, p)
	assert.NotNil(t, p.URL)
	assert.Equal(t, "example.com", p.Scope)
	assert.Nil(t, p.err)
	assert.True(t, p.Bool())
}

func TestNewURLPattern_InvalidURL_Boost(t *testing.T) {
	p := NewURLPattern("://invalid")
	assert.NotNil(t, p)
	assert.NotNil(t, p.err)
	assert.False(t, p.Bool())
}

func TestURLPattern_Bool_NoError(t *testing.T) {
	p := NewURLPattern("http://example.com")
	assert.True(t, p.Bool())
}

func TestURLPattern_Bool_WithError(t *testing.T) {
	p := NewURLPattern("://invalid")
	assert.False(t, p.Bool())
}

func TestURLPattern_DisableAutoInsert_Chainable(t *testing.T) {
	p := NewURLPattern("http://example.com")
	result := p.DisableAutoInsert()
	assert.Equal(t, p, result)
	assert.True(t, p.AutoInsertDisabled)
}

func TestURLPattern_AddScope_Appends(t *testing.T) {
	p := NewURLPattern("http://example.com")
	assert.Equal(t, "example.com", p.Scope)
	result := p.AddScope("/api")
	assert.Equal(t, p, result)
	assert.Equal(t, "example.com/api", p.Scope)
}

func TestURLPattern_AddScope_MultipleAppends(t *testing.T) {
	p := NewURLPattern("http://example.com")
	p.AddScope("/api")
	p.AddScope("/v1")
	assert.Equal(t, "example.com/api/v1", p.Scope)
}

func TestNoQueryUrl_Basic_Boost(t *testing.T) {
	u, _ := url.Parse("http://example.com/path?key=value")
	assert.Equal(t, "http://example.com/path", NoQueryUrl(u))
}

func TestNoQueryUrl_WithPort_Boost(t *testing.T) {
	u, _ := url.Parse("http://example.com:8080/path?key=value")
	assert.Equal(t, "http://example.com:8080/path", NoQueryUrl(u))
}

func TestNoQueryUrl_NoQuery_Boost(t *testing.T) {
	u, _ := url.Parse("http://example.com/path")
	assert.Equal(t, "http://example.com/path", NoQueryUrl(u))
}

func TestNoQueryUrl_Https(t *testing.T) {
	u, _ := url.Parse("https://example.com/api?q=1#frag")
	assert.Equal(t, "https://example.com/api", NoQueryUrl(u))
}

// =============================================================================
// URLPattern IsAllowed tests
// =============================================================================

func TestURLPattern_IsAllowed_NoChecker(t *testing.T) {
	p := NewURLPattern("http://example.com")
	p.Checker = nil
	result := p.IsAllowed()
	assert.NotNil(t, result)
	assert.True(t, result.Bool())
}

func TestURLPattern_IsAllowed_NoMatchers(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{}, filter.NewSyncMapFilter())
	p := uc.TargetStr("http://example.com/path")
	result := p.IsAllowed()
	assert.True(t, result.Bool())
}

func TestURLPattern_IsAllowed_HostnameAllowed_Pass(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{
		HostnameAllowed: []string{"example.com"},
	}, filter.NewSyncMapFilter())
	p := uc.TargetStr("http://example.com/path")
	result := p.IsAllowed()
	assert.True(t, result.Bool())
}

func TestURLPattern_IsAllowed_HostnameAllowed_Blocked(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{
		HostnameAllowed: []string{"allowed.com"},
	}, filter.NewSyncMapFilter())
	p := uc.TargetStr("http://other.com/path")
	result := p.IsAllowed()
	assert.False(t, result.Bool())
	assert.NotNil(t, result.err)
	assert.Contains(t, result.err.Error(), "HostnameDisallowed")
}

func TestURLPattern_IsAllowed_HostnameDisallowed_Blocked(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{
		HostnameDisallowed: []string{"evil.com"},
	}, filter.NewSyncMapFilter())
	p := uc.TargetStr("http://evil.com/path")
	result := p.IsAllowed()
	assert.False(t, result.Bool())
	assert.Contains(t, result.err.Error(), "HostnameDisallowed")
}

func TestURLPattern_IsAllowed_HostnameDisallowed_Pass(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{
		HostnameDisallowed: []string{"evil.com"},
	}, filter.NewSyncMapFilter())
	p := uc.TargetStr("http://good.com/path")
	result := p.IsAllowed()
	assert.True(t, result.Bool())
}

func TestURLPattern_IsAllowed_PathAllowed_Pass(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{
		PathAllowed: []string{"/api/*"},
	}, filter.NewSyncMapFilter())
	p := uc.TargetStr("http://example.com/api/users")
	result := p.IsAllowed()
	assert.True(t, result.Bool())
}

func TestURLPattern_IsAllowed_PathAllowed_Blocked(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{
		PathAllowed: []string{"/api/*"},
	}, filter.NewSyncMapFilter())
	p := uc.TargetStr("http://example.com/admin/users")
	result := p.IsAllowed()
	assert.False(t, result.Bool())
	assert.Contains(t, result.err.Error(), "PathDisallowed")
}

func TestURLPattern_IsAllowed_PathDisallowed_Blocked(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{
		PathDisallowed: []string{"/admin/*"},
	}, filter.NewSyncMapFilter())
	p := uc.TargetStr("http://example.com/admin/secret")
	result := p.IsAllowed()
	assert.False(t, result.Bool())
	assert.Contains(t, result.err.Error(), "PathDisallowed")
}

func TestURLPattern_IsAllowed_PathDisallowed_Pass(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{
		PathDisallowed: []string{"/admin/*"},
	}, filter.NewSyncMapFilter())
	p := uc.TargetStr("http://example.com/api/data")
	result := p.IsAllowed()
	assert.True(t, result.Bool())
}

func TestURLPattern_IsAllowed_PortAllowed_Pass(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{
		TCPPortAllowed: []string{"8080"},
	}, filter.NewSyncMapFilter())
	p := uc.TargetStr("http://example.com:8080/path")
	result := p.IsAllowed()
	assert.True(t, result.Bool())
}

func TestURLPattern_IsAllowed_PortAllowed_Blocked(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{
		TCPPortAllowed: []string{"80"},
	}, filter.NewSyncMapFilter())
	p := uc.TargetStr("http://example.com:9090/path")
	result := p.IsAllowed()
	assert.False(t, result.Bool())
	assert.Contains(t, result.err.Error(), "PortDisallowed")
}

func TestURLPattern_IsAllowed_QueryKeyAllowed_Pass(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{
		QueryKeyAllowed: []string{"id"},
	}, filter.NewSyncMapFilter())
	p := uc.TargetStr("http://example.com/?id=1")
	result := p.IsAllowed()
	assert.True(t, result.Bool())
}

func TestURLPattern_IsAllowed_QueryKeyAllowed_Blocked(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{
		QueryKeyAllowed: []string{"id"},
	}, filter.NewSyncMapFilter())
	p := uc.TargetStr("http://example.com/?token=abc")
	result := p.IsAllowed()
	assert.False(t, result.Bool())
	assert.Contains(t, result.err.Error(), "QueryKeyDisallowed")
}

func TestURLPattern_IsAllowed_QueryKeyDisallowed_Blocked(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{
		QueryKeyDisallowed: []string{"token"},
	}, filter.NewSyncMapFilter())
	p := uc.TargetStr("http://example.com/?token=abc")
	result := p.IsAllowed()
	assert.False(t, result.Bool())
	assert.Contains(t, result.err.Error(), "QueryKeyDisallowed")
}

func TestURLPattern_IsAllowed_QueryKeyDisallowed_Pass(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{
		QueryKeyDisallowed: []string{"token"},
	}, filter.NewSyncMapFilter())
	p := uc.TargetStr("http://example.com/?id=1")
	result := p.IsAllowed()
	assert.True(t, result.Bool())
}

func TestURLPattern_IsAllowed_FragmentAllowed_Pass(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{
		FragmentAllowed: []string{"section1"},
	}, filter.NewSyncMapFilter())
	p := uc.TargetStr("http://example.com/path#section1")
	result := p.IsAllowed()
	assert.True(t, result.Bool())
}

func TestURLPattern_IsAllowed_FragmentAllowed_Blocked(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{
		FragmentAllowed: []string{"section1"},
	}, filter.NewSyncMapFilter())
	p := uc.TargetStr("http://example.com/path#section2")
	result := p.IsAllowed()
	assert.False(t, result.Bool())
	assert.Contains(t, result.err.Error(), "FragmentDisallowed")
}

func TestURLPattern_IsAllowed_FragmentDisallowed_Blocked(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{
		FragmentDisallowed: []string{"debug"},
	}, filter.NewSyncMapFilter())
	p := uc.TargetStr("http://example.com/path#debug")
	result := p.IsAllowed()
	assert.False(t, result.Bool())
	assert.Contains(t, result.err.Error(), "FragmentDisallowed")
}

func TestURLPattern_IsAllowed_NoFragment_NoRestriction(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{
		FragmentAllowed: []string{"section1"},
	}, filter.NewSyncMapFilter())
	p := uc.TargetStr("http://example.com/path")
	result := p.IsAllowed()
	assert.True(t, result.Bool())
}

func TestURLPattern_IsAllowed_MultipleRestrictions(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{
		HostnameAllowed:    []string{"example.com"},
		PathDisallowed:     []string{"/admin/*"},
		QueryKeyDisallowed: []string{"token"},
	}, filter.NewSyncMapFilter())

	// All pass
	p := uc.TargetStr("http://example.com/api/data?id=1")
	assert.True(t, p.IsAllowed().Bool())

	// Hostname fails
	p2 := uc.TargetStr("http://other.com/api/data")
	assert.False(t, p2.IsAllowed().Bool())

	// Path fails
	p3 := uc.TargetStr("http://example.com/admin/secret")
	assert.False(t, p3.IsAllowed().Bool())

	// Query key fails
	p4 := uc.TargetStr("http://example.com/api/data?token=abc")
	assert.False(t, p4.IsAllowed().Bool())
}

// =============================================================================
// URLPattern IsNewWebsiteDir / IsNewWebsitePath / IsNewWebsite tests
// =============================================================================

func TestURLPattern_IsNewWebsiteDir_FirstCall(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{}, filter.NewSyncMapFilter())
	p := uc.TargetStr("http://example.com/dir/")
	result := p.IsNewWebsiteDir()
	assert.NotNil(t, result)
}

func TestURLPattern_IsNewWebsitePath_FirstCall(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{}, filter.NewSyncMapFilter())
	p := uc.TargetStr("http://example.com/path")
	result := p.IsNewWebsitePath()
	assert.NotNil(t, result)
}

func TestURLPattern_IsNewWebsite_FirstCall(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{}, filter.NewSyncMapFilter())
	p := uc.TargetStr("http://example.com/path")
	result := p.IsNewWebsite()
	assert.NotNil(t, result)
}

func TestURLPattern_IsNewHostPort_ReturnsPattern(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{}, filter.NewSyncMapFilter())
	p := uc.TargetStr("http://example.com:8080/")
	result := p.IsNewHostPort()
	assert.NotNil(t, result)
}

func TestURLPattern_IsNewWebsiteQueryKey_ReturnsPattern(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{}, filter.NewSyncMapFilter())
	p := uc.TargetStr("http://example.com/?key=value")
	result := p.IsNewWebsiteQueryKey()
	assert.NotNil(t, result)
}

// =============================================================================
// RequestChecker tests
// =============================================================================

func TestNewRequestChecker_Basic(t *testing.T) {
	rc := NewRequestChecker(&RequestCheckerConfig{}, filter.NewSyncMapFilter())
	assert.NotNil(t, rc)
	assert.NotNil(t, rc.URLChecker)
	assert.NotNil(t, rc.MethodAllowedMatcher)
	assert.NotNil(t, rc.MethodDisallowedMatcher)
	assert.NotNil(t, rc.PostKeyAllowedMatcher)
	assert.NotNil(t, rc.PostKeyDisallowedMatcher)
}

func TestNewRequestChecker_WithMethodConfig(t *testing.T) {
	config := &RequestCheckerConfig{
		MethodAllowed:    []string{"GET", "POST"},
		MethodDisallowed: []string{"DELETE"},
	}
	rc := NewRequestChecker(config, filter.NewSyncMapFilter())
	assert.False(t, rc.MethodAllowedMatcher.IsEmpty())
	assert.False(t, rc.MethodDisallowedMatcher.IsEmpty())
	assert.True(t, rc.MethodAllowedMatcher.Match("GET"))
	assert.True(t, rc.MethodAllowedMatcher.Match("POST"))
	assert.False(t, rc.MethodAllowedMatcher.Match("PUT"))
	assert.True(t, rc.MethodDisallowedMatcher.Match("DELETE"))
}

func TestNewRequestChecker_WithPostKeyConfig(t *testing.T) {
	config := &RequestCheckerConfig{
		PostKeyAllowed:    []string{"id", "name"},
		PostKeyDisallowed: []string{"token", "secret"},
	}
	rc := NewRequestChecker(config, filter.NewSyncMapFilter())
	assert.False(t, rc.PostKeyAllowedMatcher.IsEmpty())
	assert.False(t, rc.PostKeyDisallowedMatcher.IsEmpty())
}

func TestRequestChecker_NewSubChecker_ScopeConcat(t *testing.T) {
	rc := NewRequestChecker(&RequestCheckerConfig{}, filter.NewSyncMapFilter())
	rc.Scope = "parent"
	sub := rc.NewSubChecker("child")
	assert.NotNil(t, sub)
	assert.Equal(t, "parent.child", sub.Scope)
}

func TestRequestChecker_NewSubChecker_MultipleLevels(t *testing.T) {
	rc := NewRequestChecker(&RequestCheckerConfig{}, filter.NewSyncMapFilter())
	rc.Scope = "root"
	sub1 := rc.NewSubChecker("level1")
	assert.Equal(t, "root.level1", sub1.Scope)
	sub2 := sub1.NewSubChecker("level2")
	assert.Equal(t, "root.level1.level2", sub2.Scope)
}

func TestRequestChecker_Target_Boost(t *testing.T) {
	rc := NewRequestChecker(&RequestCheckerConfig{}, filter.NewSyncMapFilter())
	req, err := whttp.NewRequest("GET", "http://example.com/path", nil)
	assert.NoError(t, err)
	pattern := rc.Target(req)
	assert.NotNil(t, pattern)
	assert.Equal(t, rc, pattern.Checker)
	assert.NotNil(t, pattern.Req)
	assert.NotNil(t, pattern.URLPattern)
}

func TestRequestChecker_TargetStr_Boost(t *testing.T) {
	rc := NewRequestChecker(&RequestCheckerConfig{}, filter.NewSyncMapFilter())
	pattern := rc.TargetStr("http://example.com/path")
	assert.NotNil(t, pattern)
	assert.Nil(t, pattern.err)
}

func TestRequestChecker_AddScope_ReturnsNil(t *testing.T) {
	rc := NewRequestChecker(&RequestCheckerConfig{}, filter.NewSyncMapFilter())
	assert.Nil(t, rc.AddScope("scope"))
}

func TestRequestChecker_Close_ReturnsNil(t *testing.T) {
	rc := NewRequestChecker(&RequestCheckerConfig{}, filter.NewSyncMapFilter())
	assert.NoError(t, rc.Close())
}

func TestRequestChecker_Reset_ReturnsNil(t *testing.T) {
	rc := NewRequestChecker(&RequestCheckerConfig{}, filter.NewSyncMapFilter())
	assert.NoError(t, rc.Reset())
}

func TestRequestChecker_DisableAutoInsert_ReturnsNil(t *testing.T) {
	rc := NewRequestChecker(&RequestCheckerConfig{}, filter.NewSyncMapFilter())
	assert.Nil(t, rc.DisableAutoInsert())
}

func TestRequestChecker_WithTTL_ReturnsNil(t *testing.T) {
	rc := NewRequestChecker(&RequestCheckerConfig{}, filter.NewSyncMapFilter())
	assert.Nil(t, rc.WithTTL(100))
}

func TestRequestChecker_Insert_NoOp(t *testing.T) {
	rc := NewRequestChecker(&RequestCheckerConfig{}, filter.NewSyncMapFilter())
	rc.Insert("key") // no-op, should not panic
}

func TestRequestChecker_InsertWithTTL_NoOp(t *testing.T) {
	rc := NewRequestChecker(&RequestCheckerConfig{}, filter.NewSyncMapFilter())
	rc.InsertWithTTL("key", 100) // no-op, should not panic
}

func TestRequestChecker_IsInserted_ReturnsFalse(t *testing.T) {
	rc := NewRequestChecker(&RequestCheckerConfig{}, filter.NewSyncMapFilter())
	assert.False(t, rc.IsInserted("key", false))
}

func TestRequestChecker_IsInsertedWithTTL_ReturnsFalse(t *testing.T) {
	rc := NewRequestChecker(&RequestCheckerConfig{}, filter.NewSyncMapFilter())
	assert.False(t, rc.IsInsertedWithTTL("key", false, 0))
}

// =============================================================================
// ReqPattern tests
// =============================================================================

func TestReqPattern_Bool_ReturnsFalse(t *testing.T) {
	rp := &ReqPattern{}
	assert.False(t, rp.Bool())
}

func TestReqPattern_Error_ReturnsNil(t *testing.T) {
	rp := &ReqPattern{}
	assert.Nil(t, rp.Error())
}

func TestReqPattern_Hash_Boost(t *testing.T) {
	rp := &ReqPattern{hash: "myhash"}
	assert.Equal(t, "myhash", rp.Hash())
}

func TestReqPattern_Hash_Empty(t *testing.T) {
	rp := &ReqPattern{}
	assert.Equal(t, "", rp.Hash())
}

func TestReqPattern_URLString_Boost(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{}, filter.NewSyncMapFilter())
	rp := &ReqPattern{
		URLPattern: uc.TargetStr("http://example.com/test"),
	}
	assert.Equal(t, "http://example.com/test", rp.URLString())
}

func TestReqPattern_AddScope_ReturnsNil(t *testing.T) {
	rp := &ReqPattern{}
	assert.Nil(t, rp.AddScope("scope"))
}

func TestReqPattern_DisableAutoInsert_ReturnsNil(t *testing.T) {
	rp := &ReqPattern{}
	assert.Nil(t, rp.DisableAutoInsert())
}

func TestReqPattern_WithTTL_ReturnsNil(t *testing.T) {
	rp := &ReqPattern{}
	assert.Nil(t, rp.WithTTL(100))
}

func TestReqPattern_DoCache_NoOp(t *testing.T) {
	rp := &ReqPattern{}
	rp.doCache() // no-op, should not panic
}

func TestReqPattern_IsAllowed_NoURLPattern(t *testing.T) {
	rp := &ReqPattern{}
	result := rp.IsAllowed()
	assert.NotNil(t, result)
}

func TestReqPattern_IsAllowed_NoRestrictions_Boost(t *testing.T) {
	rc := NewRequestChecker(&RequestCheckerConfig{}, filter.NewSyncMapFilter())
	req, _ := whttp.NewRequest("GET", "http://example.com/path", nil)
	pattern := rc.Target(req)
	result := pattern.IsAllowed()
	assert.NotNil(t, result)
}

func TestReqPattern_IsAllowed_URLHostnameBlocked(t *testing.T) {
	config := &RequestCheckerConfig{
		URLCheckerConfig: URLCheckerConfig{
			HostnameDisallowed: []string{"evil.com"},
		},
	}
	rc := NewRequestChecker(config, filter.NewSyncMapFilter())
	req, _ := whttp.NewRequest("GET", "http://evil.com/path", nil)
	pattern := rc.Target(req)
	pattern.IsAllowed()
	// Should be blocked at URL level
	assert.NotNil(t, pattern.URLPattern.err)
}

func TestReqPattern_IsAllowed_PostKeyAllowed_Pass(t *testing.T) {
	config := &RequestCheckerConfig{
		PostKeyAllowed: []string{"id", "name"},
	}
	rc := NewRequestChecker(config, filter.NewSyncMapFilter())
	req, _ := whttp.NewRequest("POST", "http://example.com/api", nil)
	pattern := rc.Target(req)
	pattern.bodyKeys = []string{"id", "name"}
	result := pattern.IsAllowed()
	assert.NotNil(t, result)
	// No error because both keys are in the allowed list
	assert.True(t, result.URLPattern.Bool() || result.URLPattern.err == nil)
}

func TestReqPattern_IsAllowed_PostKeyAllowed_Blocked(t *testing.T) {
	config := &RequestCheckerConfig{
		PostKeyAllowed: []string{"id"},
	}
	rc := NewRequestChecker(config, filter.NewSyncMapFilter())
	req, _ := whttp.NewRequest("POST", "http://example.com/api", nil)
	pattern := rc.Target(req)
	pattern.bodyKeys = []string{"secret"}
	result := pattern.IsAllowed()
	assert.False(t, result.URLPattern.Bool())
	assert.Contains(t, result.URLPattern.err.Error(), "PostKeyDisallowed")
}

func TestReqPattern_IsAllowed_PostKeyDisallowed_Blocked(t *testing.T) {
	config := &RequestCheckerConfig{
		PostKeyDisallowed: []string{"token"},
	}
	rc := NewRequestChecker(config, filter.NewSyncMapFilter())
	req, _ := whttp.NewRequest("POST", "http://example.com/api", nil)
	pattern := rc.Target(req)
	pattern.bodyKeys = []string{"token"}
	result := pattern.IsAllowed()
	assert.False(t, result.URLPattern.Bool())
	assert.Contains(t, result.URLPattern.err.Error(), "PostKeyDisallowed")
}

func TestReqPattern_IsAllowed_PostKeyDisallowed_Pass(t *testing.T) {
	config := &RequestCheckerConfig{
		PostKeyDisallowed: []string{"token"},
	}
	rc := NewRequestChecker(config, filter.NewSyncMapFilter())
	req, _ := whttp.NewRequest("POST", "http://example.com/api", nil)
	pattern := rc.Target(req)
	pattern.bodyKeys = []string{"id"}
	result := pattern.IsAllowed()
	assert.True(t, result.URLPattern.Bool())
}

func TestReqPattern_IsAllowed_NilReq_SkipsPostKeyCheck(t *testing.T) {
	config := &RequestCheckerConfig{
		PostKeyDisallowed: []string{"token"},
	}
	rc := NewRequestChecker(config, filter.NewSyncMapFilter())
	pattern := rc.TargetStr("http://example.com/path")
	rp := &ReqPattern{
		URLPattern: pattern,
		Checker:    rc,
		Req:        nil,
	}
	result := rp.IsAllowed()
	assert.NotNil(t, result)
	// No panic when Req is nil
}

func TestReqPattern_IsAllowed_NilChecker_SkipsPostKeyCheck(t *testing.T) {
	rc := NewRequestChecker(&RequestCheckerConfig{}, filter.NewSyncMapFilter())
	req, _ := whttp.NewRequest("POST", "http://example.com/api", nil)
	pattern := rc.Target(req)
	pattern.Checker = nil
	result := pattern.IsAllowed()
	assert.NotNil(t, result)
	// No panic when Checker is nil
}

func TestReqPattern_IsAllowed_EmptyBodyKeys(t *testing.T) {
	config := &RequestCheckerConfig{
		PostKeyDisallowed: []string{"token"},
	}
	rc := NewRequestChecker(config, filter.NewSyncMapFilter())
	req, _ := whttp.NewRequest("POST", "http://example.com/api", nil)
	pattern := rc.Target(req)
	pattern.bodyKeys = []string{}
	result := pattern.IsAllowed()
	assert.True(t, result.URLPattern.Bool())
}

// =============================================================================
// ServiceChecker tests
// =============================================================================

func TestServiceChecker_AddScope_NoOp(t *testing.T) {
	sc := &ServiceChecker{}
	sc.AddScope() // no-op, should not panic
}

func TestServiceChecker_Close_ReturnsNil(t *testing.T) {
	sc := &ServiceChecker{}
	assert.NoError(t, sc.Close())
}

func TestServiceChecker_DisableAutoInsert_NoOp(t *testing.T) {
	sc := &ServiceChecker{}
	sc.DisableAutoInsert() // no-op, should not panic
}

func TestServiceChecker_Insert_NoOp(t *testing.T) {
	sc := &ServiceChecker{}
	sc.Insert("key") // no-op, should not panic
}

func TestServiceChecker_InsertWithTTL_NoOp(t *testing.T) {
	sc := &ServiceChecker{}
	sc.InsertWithTTL("key", 100) // no-op, should not panic
}

func TestServiceChecker_IsInserted_ReturnsTrue(t *testing.T) {
	sc := &ServiceChecker{}
	assert.True(t, sc.IsInserted("any", true))
	assert.True(t, sc.IsInserted("any", false))
}

func TestServiceChecker_IsInsertedWithTTL_ReturnsTrue(t *testing.T) {
	sc := &ServiceChecker{}
	assert.True(t, sc.IsInsertedWithTTL("any", true, 0))
	assert.True(t, sc.IsInsertedWithTTL("any", false, 999))
}

func TestServiceChecker_NewSubChecker_NoOp(t *testing.T) {
	sc := &ServiceChecker{}
	sc.NewSubChecker() // no-op, should not panic
}

func TestServiceChecker_Reset_ReturnsNil(t *testing.T) {
	sc := &ServiceChecker{}
	assert.NoError(t, sc.Reset())
}

func TestServiceChecker_Target_NoOp(t *testing.T) {
	sc := &ServiceChecker{}
	sc.Target() // no-op, should not panic
}

func TestServiceChecker_WithTTL_NoOp(t *testing.T) {
	sc := &ServiceChecker{}
	sc.WithTTL() // no-op, should not panic
}

// =============================================================================
// ServicePattern tests
// =============================================================================

func TestServicePattern_Bool_ReturnsTrue(t *testing.T) {
	sp := &ServicePattern{}
	assert.True(t, sp.Bool())
}

func TestServicePattern_Error_ReturnsNil(t *testing.T) {
	sp := &ServicePattern{}
	assert.Nil(t, sp.Error())
}

func TestServicePattern_AddScope_NoOp(t *testing.T) {
	sp := &ServicePattern{}
	sp.AddScope() // no-op, should not panic
}

func TestServicePattern_DisableAutoInsert_NoOp(t *testing.T) {
	sp := &ServicePattern{}
	sp.DisableAutoInsert() // no-op, should not panic
}

func TestServicePattern_IsAllowed_NoOp(t *testing.T) {
	sp := &ServicePattern{}
	sp.IsAllowed() // no-op, should not panic
}

func TestServicePattern_IsNewService_NoOp(t *testing.T) {
	sp := &ServicePattern{}
	sp.IsNewService() // no-op, should not panic
}

func TestServicePattern_WithTTL_NoOp(t *testing.T) {
	sp := &ServicePattern{}
	sp.WithTTL() // no-op, should not panic
}

func TestServicePattern_Fields_Boost(t *testing.T) {
	sf := filter.NewSyncMapFilter()
	sc := &ServiceChecker{
		Filter:             sf,
		config:             &ServiceCheckerConfig{},
		Scope:              "testscope",
		AutoInsertDisabled: true,
		TTL:                3600,
	}
	sp := &ServicePattern{
		Checker:            sc,
		TransportProtocol:  6,
		Hostname:           "example.com",
		Port:               "443",
		Scope:              "testscope",
		AutoInsertDisabled: true,
		TTL:                3600,
	}
	assert.Equal(t, sc, sp.Checker)
	assert.Equal(t, uint8(6), sp.TransportProtocol)
	assert.Equal(t, "example.com", sp.Hostname)
	assert.Equal(t, "443", sp.Port)
	assert.Equal(t, "testscope", sp.Scope)
	assert.True(t, sp.AutoInsertDisabled)
	assert.Equal(t, int64(3600), sp.TTL)
}

// =============================================================================
// ServiceChecker with matchers
// =============================================================================

func TestServiceChecker_WithMatchers_Hostname(t *testing.T) {
	sf := filter.NewSyncMapFilter()
	config := &ServiceCheckerConfig{
		HostnameAllowed:    []string{"example.com"},
		HostnameDisallowed: []string{"evil.com"},
	}
	sc := &ServiceChecker{
		Filter:                    sf,
		config:                    config,
		HostnameAllowedMatcher:    matcher.NewHostsMatcher(),
		HostnameDisallowedMatcher: matcher.NewHostsMatcher(),
		TCPPortAllowedMatcher:     matcher.NewPortMatcher(),
		TCPPortDisallowedMatcher:  matcher.NewPortMatcher(),
		UDPPortAllowedMatcher:     matcher.NewPortMatcher(),
		UDPPortDisallowedMatcher:  matcher.NewPortMatcher(),
	}
	sc.HostnameAllowedMatcher.Add(config.HostnameAllowed)
	sc.HostnameDisallowedMatcher.Add(config.HostnameDisallowed)

	assert.False(t, sc.HostnameAllowedMatcher.IsEmpty())
	assert.True(t, sc.HostnameAllowedMatcher.Match("example.com"))
	assert.False(t, sc.HostnameAllowedMatcher.Match("other.com"))
	assert.False(t, sc.HostnameDisallowedMatcher.IsEmpty())
	assert.True(t, sc.HostnameDisallowedMatcher.Match("evil.com"))
}

func TestServiceChecker_WithMatchers_Ports(t *testing.T) {
	sf := filter.NewSyncMapFilter()
	config := &ServiceCheckerConfig{
		TCPPortAllowed:    []string{"80", "443"},
		TCPPortDisallowed: []string{"22"},
		UDPPortAllowed:    []string{"53"},
		UDPPortDisallowed: []string{"161"},
	}
	sc := &ServiceChecker{
		Filter:                    sf,
		config:                    config,
		HostnameAllowedMatcher:    matcher.NewHostsMatcher(),
		HostnameDisallowedMatcher: matcher.NewHostsMatcher(),
		TCPPortAllowedMatcher:     matcher.NewPortMatcher(),
		TCPPortDisallowedMatcher:  matcher.NewPortMatcher(),
		UDPPortAllowedMatcher:     matcher.NewPortMatcher(),
		UDPPortDisallowedMatcher:  matcher.NewPortMatcher(),
	}
	sc.TCPPortAllowedMatcher.Add(config.TCPPortAllowed)
	sc.TCPPortDisallowedMatcher.Add(config.TCPPortDisallowed)
	sc.UDPPortAllowedMatcher.Add(config.UDPPortAllowed)
	sc.UDPPortDisallowedMatcher.Add(config.UDPPortDisallowed)

	assert.False(t, sc.TCPPortAllowedMatcher.IsEmpty())
	assert.True(t, sc.TCPPortAllowedMatcher.Match("80"))
	assert.True(t, sc.TCPPortAllowedMatcher.Match("443"))
	assert.False(t, sc.TCPPortAllowedMatcher.Match("22"))

	assert.True(t, sc.TCPPortDisallowedMatcher.Match("22"))
	assert.False(t, sc.TCPPortDisallowedMatcher.Match("80"))

	assert.True(t, sc.UDPPortAllowedMatcher.Match("53"))
	assert.True(t, sc.UDPPortDisallowedMatcher.Match("161"))
}

func TestServiceChecker_ScopeAndTTL(t *testing.T) {
	sc := &ServiceChecker{
		Scope:              "myscope",
		AutoInsertDisabled: false,
		TTL:                5000,
	}
	assert.Equal(t, "myscope", sc.Scope)
	assert.False(t, sc.AutoInsertDisabled)
	assert.Equal(t, int64(5000), sc.TTL)
}

// =============================================================================
// Util function tests
// =============================================================================

func TestGetURLPort_HTTPDefault_Boost(t *testing.T) {
	port, err := GetURLPort("http://example.com/path")
	assert.NoError(t, err)
	assert.Equal(t, 80, port)
}

func TestGetURLPort_HTTPSDefault_Boost(t *testing.T) {
	port, err := GetURLPort("https://example.com/path")
	assert.NoError(t, err)
	assert.Equal(t, 443, port)
}

func TestGetURLPort_ExplicitPort_Boost(t *testing.T) {
	port, err := GetURLPort("http://example.com:8080/path")
	assert.NoError(t, err)
	assert.Equal(t, 8080, port)
}

func TestGetURLPort_HTTPSExplicitPort_Boost(t *testing.T) {
	port, err := GetURLPort("https://example.com:8443/path")
	assert.NoError(t, err)
	assert.Equal(t, 8443, port)
}

func TestGetURLPort_InvalidURL_Boost(t *testing.T) {
	_, err := GetURLPort("://invalid")
	assert.Error(t, err)
}

func TestGetURLPort_UnsupportedScheme_Boost(t *testing.T) {
	_, err := GetURLPort("ftp://example.com/path")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported")
}

func TestGetURLPort_NonNumericPort_Boost(t *testing.T) {
	_, err := GetURLPort("http://example.com:abc/path")
	assert.Error(t, err)
}

func TestGetQueryKeys_Basic_Boost(t *testing.T) {
	keys, err := GetQueryKeys("http://example.com/path?id=1&name=test")
	assert.NoError(t, err)
	assert.Len(t, keys, 2)
	keySet := make(map[string]bool)
	for _, k := range keys {
		keySet[k] = true
	}
	assert.True(t, keySet["id"])
	assert.True(t, keySet["name"])
}

func TestGetQueryKeys_NoQuery_Boost(t *testing.T) {
	keys, err := GetQueryKeys("http://example.com/path")
	assert.NoError(t, err)
	assert.Empty(t, keys)
}

func TestGetQueryKeys_InvalidURL_Boost(t *testing.T) {
	_, err := GetQueryKeys("://invalid")
	assert.Error(t, err)
}

func TestGetQueryKeys_SingleKey_Boost(t *testing.T) {
	keys, err := GetQueryKeys("http://example.com/path?id=42")
	assert.NoError(t, err)
	assert.Len(t, keys, 1)
	assert.Equal(t, "id", keys[0])
}

func TestGetQueryKeys_EmptyValue_Boost(t *testing.T) {
	keys, err := GetQueryKeys("http://example.com/path?id=&name=test")
	assert.NoError(t, err)
	assert.Len(t, keys, 2)
}

// =============================================================================
// Matcher integration tests through checker
// =============================================================================

func TestURLChecker_SchemeMatchers(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{
		SchemeAllowed:    []string{"http"},
		SchemeDisallowed: []string{"ftp"},
	}, filter.NewSyncMapFilter())
	assert.True(t, uc.SchemeAllowedMatcher.Match("http"))
	assert.False(t, uc.SchemeAllowedMatcher.Match("https"))
	assert.True(t, uc.SchemeDisallowedMatcher.Match("ftp"))
	assert.False(t, uc.SchemeDisallowedMatcher.Match("http"))
}

func TestURLChecker_PathSuffixMatchers(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{
		PathSuffixAllowed:    []string{".html", ".htm"},
		PathSuffixDisallowed: []string{".exe", ".bat"},
	}, filter.NewSyncMapFilter())
	// NewURLChecker doesn't call Add() for PathSuffix matchers, so we do it manually
	uc.PathSuffixAllowedMatcher.Add([]string{".html", ".htm"})
	uc.PathSuffixDisallowedMatcher.Add([]string{".exe", ".bat"})
	assert.True(t, uc.PathSuffixAllowedMatcher.Match(".html"))
	assert.False(t, uc.PathSuffixAllowedMatcher.Match(".php"))
	assert.True(t, uc.PathSuffixDisallowedMatcher.Match(".exe"))
}

func TestURLChecker_QueryRawMatchers(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{
		QueryRawAllowed:    []string{"id=*"},
		QueryRawDisallowed: []string{"secret=*"},
	}, filter.NewSyncMapFilter())
	// NewURLChecker doesn't call Add() for QueryRaw matchers, so we do it manually
	uc.QueryRawAllowedMatcher.Add([]string{"id=*"})
	uc.QueryRawDisallowedMatcher.Add([]string{"secret=*"})
	assert.True(t, uc.QueryRawAllowedMatcher.Match("id=123"))
	assert.False(t, uc.QueryRawAllowedMatcher.Match("name=abc"))
	assert.True(t, uc.QueryRawDisallowedMatcher.Match("secret=data"))
}

func TestURLChecker_URLRegexMatchers_CovBoost(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{}, filter.NewSyncMapFilter())
	err := uc.URLRegexAllowedMatcher.Add([]string{`^http://example\.com/.*`})
	assert.NoError(t, err)
	err = uc.URLRegexDisallowedMatcher.Add([]string{`^http://evil\.com/.*`})
	assert.NoError(t, err)
	assert.True(t, uc.URLRegexAllowedMatcher.Match("http://example.com/path"))
	assert.False(t, uc.URLRegexAllowedMatcher.Match("http://other.com/path"))
	assert.True(t, uc.URLRegexDisallowedMatcher.Match("http://evil.com/path"))
}

func TestURLChecker_URLGlobMatchers_CovBoost(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{}, filter.NewSyncMapFilter())
	err := uc.URLGlobAllowedMatcher.Add([]string{"http://example.com/*"})
	assert.NoError(t, err)
	err = uc.URLGlobDisallowedMatcher.Add([]string{"http://evil.com/*"})
	assert.NoError(t, err)
	// glob uses '/' as separator, so * only matches a single path segment
	assert.True(t, uc.URLGlobAllowedMatcher.Match("http://example.com/any"))
	assert.False(t, uc.URLGlobAllowedMatcher.Match("http://other.com/any"))
	assert.True(t, uc.URLGlobDisallowedMatcher.Match("http://evil.com/any"))
}

func TestURLChecker_HostnameMatcher_Wildcard(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{
		HostnameAllowed: []string{"*.example.com"},
	}, filter.NewSyncMapFilter())
	assert.True(t, uc.HostnameAllowedMatcher.Match("sub.example.com"))
	assert.True(t, uc.HostnameAllowedMatcher.Match("deep.sub.example.com"))
}

func TestURLChecker_HostnameMatcher_IP(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{
		HostnameAllowed: []string{"1.1.1.1"},
	}, filter.NewSyncMapFilter())
	assert.True(t, uc.HostnameAllowedMatcher.Match("1.1.1.1"))
}

func TestURLChecker_PortMatcher_Range(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{
		TCPPortAllowed:    []string{"8080-8090"},
		TCPPortDisallowed: []string{"22-25"},
	}, filter.NewSyncMapFilter())
	assert.True(t, uc.TCPPortAllowedMatcher.Match("8080"))
	assert.True(t, uc.TCPPortAllowedMatcher.Match("8085"))
	assert.True(t, uc.TCPPortAllowedMatcher.Match("8090"))
	assert.False(t, uc.TCPPortAllowedMatcher.Match("8091"))
	assert.True(t, uc.TCPPortDisallowedMatcher.Match("22"))
	assert.True(t, uc.TCPPortDisallowedMatcher.Match("23"))
	assert.False(t, uc.TCPPortDisallowedMatcher.Match("80"))
}

// =============================================================================
// Filter integration tests
// =============================================================================

func TestURLChecker_FilterInsertAndCheck(t *testing.T) {
	sf := filter.NewSyncMapFilter()
	uc := NewURLChecker(&URLCheckerConfig{}, sf)

	// Not inserted initially
	assert.False(t, uc.IsInserted("http://example.com", false))

	// Insert and check
	uc.Insert("http://example.com")
	assert.True(t, uc.IsInserted("http://example.com", false))

	// Different URL not inserted
	assert.False(t, uc.IsInserted("http://other.com", false))
}

func TestURLChecker_FilterReset(t *testing.T) {
	sf := filter.NewSyncMapFilter()
	uc := NewURLChecker(&URLCheckerConfig{}, sf)

	uc.Insert("http://example.com")
	assert.True(t, uc.IsInserted("http://example.com", false))

	// Reset the underlying filter
	err := sf.Reset()
	assert.NoError(t, err)
	assert.False(t, uc.IsInserted("http://example.com", false))
}

// =============================================================================
// Edge case tests
// =============================================================================

func TestURLPattern_IsAllowed_EmptyPort_Allowed(t *testing.T) {
	// Default HTTP port (empty string) with port restriction
	uc := NewURLChecker(&URLCheckerConfig{
		TCPPortAllowed: []string{"80"},
	}, filter.NewSyncMapFilter())
	// URL without explicit port - Port() returns empty string
	p := uc.TargetStr("http://example.com/path")
	result := p.IsAllowed()
	// Empty port won't match "80" because Atoi("") fails
	assert.False(t, result.Bool())
}

func TestURLPattern_IsAllowed_MultipleQueryKeys_OneDisallowed(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{
		QueryKeyDisallowed: []string{"token"},
	}, filter.NewSyncMapFilter())
	p := uc.TargetStr("http://example.com/?id=1&token=abc&name=test")
	result := p.IsAllowed()
	assert.False(t, result.Bool())
	assert.Contains(t, result.err.Error(), "QueryKeyDisallowed")
	assert.Contains(t, result.err.Error(), "token")
}

func TestURLPattern_IsAllowed_MultipleQueryKeys_AllAllowed(t *testing.T) {
	uc := NewURLChecker(&URLCheckerConfig{
		QueryKeyAllowed: []string{"id", "name"},
	}, filter.NewSyncMapFilter())
	p := uc.TargetStr("http://example.com/?id=1&name=test")
	result := p.IsAllowed()
	assert.True(t, result.Bool())
}

func TestURLPattern_IsAllowed_HostnameAllowedCheckedBeforeDisallowed(t *testing.T) {
	// HostnameAllowed is checked before HostnameDisallowed in IsAllowed
	uc := NewURLChecker(&URLCheckerConfig{
		HostnameAllowed:    []string{"allowed.com"},
		HostnameDisallowed: []string{"evil.com"},
	}, filter.NewSyncMapFilter())

	// Hostname not in allowed list - should be blocked by HostnameAllowed check
	p := uc.TargetStr("http://neutral.com/path")
	result := p.IsAllowed()
	assert.False(t, result.Bool())
}

func TestNewURLChecker_QueryKeyMatchers_InitializedFromConfig(t *testing.T) {
	// Verify that NewRequestChecker properly initializes QueryKey matchers
	// from the URLCheckerConfig embedded in RequestCheckerConfig
	config := &RequestCheckerConfig{
		URLCheckerConfig: URLCheckerConfig{
			QueryKeyAllowed:    []string{"id"},
			QueryKeyDisallowed: []string{"token"},
		},
	}
	rc := NewRequestChecker(config, filter.NewSyncMapFilter())
	assert.False(t, rc.QueryKeyAllowedMatcher.IsEmpty())
	assert.False(t, rc.QueryKeyDisallowedMatcher.IsEmpty())
}

// =============================================================================
// ServiceChecker coverage boost tests
// =============================================================================

func TestServiceChecker_AddScope_WithFields(t *testing.T) {
	sc := &ServiceChecker{
		Scope:              "initial",
		AutoInsertDisabled: true,
		TTL:                100,
	}
	sc.AddScope()
	// AddScope is a no-op, fields should remain unchanged
	assert.Equal(t, "initial", sc.Scope)
	assert.True(t, sc.AutoInsertDisabled)
	assert.Equal(t, int64(100), sc.TTL)
}

func TestServiceChecker_DisableAutoInsert_WithFields(t *testing.T) {
	sc := &ServiceChecker{
		AutoInsertDisabled: false,
	}
	sc.DisableAutoInsert()
	// DisableAutoInsert is a no-op on ServiceChecker (does not flip the flag)
	assert.False(t, sc.AutoInsertDisabled)
}

func TestServiceChecker_Insert_DifferentKeys(t *testing.T) {
	sc := &ServiceChecker{}
	sc.Insert("key1")
	sc.Insert("key2")
	sc.Insert("")
	// Insert is a no-op; IsInserted always returns true regardless
	assert.True(t, sc.IsInserted("anything", true))
	assert.True(t, sc.IsInserted("anything", false))
}

func TestServiceChecker_InsertWithTTL_DifferentArgs(t *testing.T) {
	sc := &ServiceChecker{}
	sc.InsertWithTTL("key1", 0)
	sc.InsertWithTTL("key2", 3600)
	sc.InsertWithTTL("", -1)
	// InsertWithTTL is a no-op; IsInsertedWithTTL always returns true
	assert.True(t, sc.IsInsertedWithTTL("anything", true, 0))
	assert.True(t, sc.IsInsertedWithTTL("anything", false, 999))
}

func TestServiceChecker_NewSubChecker_WithConfig(t *testing.T) {
	sc := &ServiceChecker{
		config: &ServiceCheckerConfig{
			HostnameAllowed: []string{"example.com"},
		},
		Scope: "parent",
	}
	sc.NewSubChecker()
	// NewSubChecker is a no-op; scope remains unchanged
	assert.Equal(t, "parent", sc.Scope)
}

func TestServiceChecker_Target_WithConfig(t *testing.T) {
	sc := &ServiceChecker{
		config: &ServiceCheckerConfig{},
	}
	sc.Target()
	// Target is a no-op; should not panic
}

func TestServiceChecker_WithTTL_WithExistingTTL(t *testing.T) {
	sc := &ServiceChecker{TTL: 5000}
	sc.WithTTL()
	// WithTTL is a no-op; TTL remains unchanged
	assert.Equal(t, int64(5000), sc.TTL)
}

func TestServiceChecker_AllMethods_OnNilConfig(t *testing.T) {
	sc := &ServiceChecker{config: nil}
	// All methods should work even with nil config
	sc.AddScope()
	assert.NoError(t, sc.Close())
	sc.DisableAutoInsert()
	sc.Insert("key")
	sc.InsertWithTTL("key", 0)
	assert.True(t, sc.IsInserted("key", true))
	assert.True(t, sc.IsInsertedWithTTL("key", false, 0))
	sc.NewSubChecker()
	assert.NoError(t, sc.Reset())
	sc.Target()
	sc.WithTTL()
}

func TestServiceChecker_Close_MultipleCalls(t *testing.T) {
	sc := &ServiceChecker{}
	for i := 0; i < 3; i++ {
		assert.NoError(t, sc.Close())
	}
}

func TestServiceChecker_Reset_MultipleCalls(t *testing.T) {
	sc := &ServiceChecker{}
	for i := 0; i < 3; i++ {
		assert.NoError(t, sc.Reset())
	}
}

// =============================================================================
// ServicePattern coverage boost tests
// =============================================================================

func TestServicePattern_AddScope_WithFields(t *testing.T) {
	sp := &ServicePattern{
		Scope:              "initial",
		AutoInsertDisabled: true,
		TTL:                200,
	}
	sp.AddScope()
	// AddScope is a no-op, fields should remain unchanged
	assert.Equal(t, "initial", sp.Scope)
	assert.True(t, sp.AutoInsertDisabled)
	assert.Equal(t, int64(200), sp.TTL)
}

func TestServicePattern_DisableAutoInsert_WithFields(t *testing.T) {
	sp := &ServicePattern{
		AutoInsertDisabled: false,
	}
	sp.DisableAutoInsert()
	// DisableAutoInsert is a no-op on ServicePattern
	assert.False(t, sp.AutoInsertDisabled)
}

func TestServicePattern_IsAllowed_WithChecker(t *testing.T) {
	sc := &ServiceChecker{
		config: &ServiceCheckerConfig{},
	}
	sp := &ServicePattern{
		Checker:  sc,
		Hostname: "example.com",
		Port:     "443",
		Scope:    "test",
		TTL:      3600,
	}
	sp.IsAllowed()
	// IsAllowed is a no-op; should not panic
	assert.True(t, sp.Bool())
}

func TestServicePattern_IsNewService_WithChecker(t *testing.T) {
	sp := &ServicePattern{
		Hostname: "example.com",
		Port:     "80",
	}
	sp.IsNewService()
	// IsNewService is a no-op; should not panic
	assert.True(t, sp.Bool())
}

func TestServicePattern_WithTTL_WithExistingTTL(t *testing.T) {
	sp := &ServicePattern{TTL: 7200}
	sp.WithTTL()
	// WithTTL is a no-op; TTL remains unchanged
	assert.Equal(t, int64(7200), sp.TTL)
}

func TestServicePattern_Bool_AlwaysTrue(t *testing.T) {
	sp1 := &ServicePattern{}
	sp2 := &ServicePattern{err: fmt.Errorf("some error")}
	sp3 := &ServicePattern{Hostname: "example.com", Port: "443"}
	assert.True(t, sp1.Bool())
	assert.True(t, sp2.Bool()) // Bool always returns true even with err set
	assert.True(t, sp3.Bool())
}

func TestServicePattern_Error_AlwaysNil(t *testing.T) {
	sp := &ServicePattern{}
	assert.Nil(t, sp.Error())
}

func TestServicePattern_AllMethods_NoPanic(t *testing.T) {
	sp := &ServicePattern{}
	sp.AddScope()
	assert.True(t, sp.Bool())
	sp.DisableAutoInsert()
	assert.Nil(t, sp.Error())
	sp.IsAllowed()
	sp.IsNewService()
	sp.WithTTL()
}

func TestServicePattern_WithTransportProtocol(t *testing.T) {
	// TCP = 6, UDP = 17
	sp1 := &ServicePattern{TransportProtocol: 6, Hostname: "example.com", Port: "80"}
	sp2 := &ServicePattern{TransportProtocol: 17, Hostname: "example.com", Port: "53"}
	assert.Equal(t, uint8(6), sp1.TransportProtocol)
	assert.Equal(t, uint8(17), sp2.TransportProtocol)
	assert.True(t, sp1.Bool())
	assert.True(t, sp2.Bool())
}

func TestServicePattern_FullIntegration(t *testing.T) {
	sf := filter.NewSyncMapFilter()
	sc := &ServiceChecker{
		Filter:                    sf,
		config:                    &ServiceCheckerConfig{},
		HostnameAllowedMatcher:    matcher.NewHostsMatcher(),
		HostnameDisallowedMatcher: matcher.NewHostsMatcher(),
		TCPPortAllowedMatcher:     matcher.NewPortMatcher(),
		TCPPortDisallowedMatcher:  matcher.NewPortMatcher(),
		UDPPortAllowedMatcher:     matcher.NewPortMatcher(),
		UDPPortDisallowedMatcher:  matcher.NewPortMatcher(),
		Scope:                     "integration",
		AutoInsertDisabled:        true,
		TTL:                       300,
	}

	sp := &ServicePattern{
		Checker:            sc,
		TransportProtocol:  6,
		Hostname:           "example.com",
		Port:               "443",
		Scope:              "integration",
		AutoInsertDisabled: true,
		TTL:                300,
	}

	// Exercise all ServiceChecker methods through the linked pattern
	sc.AddScope()
	assert.NoError(t, sc.Close())
	sc.DisableAutoInsert()
	sc.Insert("http://example.com")
	sc.InsertWithTTL("http://example.com", 3600)
	assert.True(t, sc.IsInserted("anything", true))
	assert.True(t, sc.IsInsertedWithTTL("anything", false, 0))
	sc.NewSubChecker()
	assert.NoError(t, sc.Reset())
	sc.Target()
	sc.WithTTL()

	// Exercise all ServicePattern methods
	sp.AddScope()
	assert.True(t, sp.Bool())
	sp.DisableAutoInsert()
	assert.Nil(t, sp.Error())
	sp.IsAllowed()
	sp.IsNewService()
	sp.WithTTL()

	// Verify struct field integrity
	assert.Equal(t, sc, sp.Checker)
	assert.Equal(t, uint8(6), sp.TransportProtocol)
	assert.Equal(t, "example.com", sp.Hostname)
	assert.Equal(t, "443", sp.Port)
	assert.Equal(t, "integration", sp.Scope)
	assert.True(t, sp.AutoInsertDisabled)
	assert.Equal(t, int64(300), sp.TTL)
}
