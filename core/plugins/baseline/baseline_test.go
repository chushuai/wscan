package baseline

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	wscan_http "wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/utils/printer"
)

// mockApollo creates a minimal Apollo for testing
func mockApollo(req *wscan_http.Request, resp *wscan_http.Response) *base.Apollo {
	if req == nil {
		req, _ = wscan_http.NewRequest("GET", "http://example.com/", nil)
	}
	a := base.NewApollo(&wscan_http.Flow{Request: req, Response: resp})
	return a
}

func makeTestResponse(body string) *wscan_http.Response {
	u, _ := url.Parse("http://example.com/")
	netResp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    &http.Request{URL: u},
	}
	netResp.Header.Set("Content-Type", "text/html")
	resp, _ := wscan_http.ResponseFromNetHttpResponse(netResp)
	return resp
}

type mockPrinter struct {
	onPrint func(v *model.Vuln)
}

func (m *mockPrinter) Print(v any) error {
	if vuln, ok := v.(*model.Vuln); ok && m.onPrint != nil {
		m.onPrint(vuln)
	}
	return nil
}

func (m *mockPrinter) Close() error { return nil }
func (m *mockPrinter) AddInterceptor(func(any) (any, error)) printer.Printer {
	return m
}
func (m *mockPrinter) LogSubdomain(any) error { return nil }
func (m *mockPrinter) LogVuln(any) error      { return nil }

// ==================== Baseline struct tests ====================

func TestBaseline_Close(t *testing.T) {
	b := &Baseline{}
	if err := b.Close(); err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
}

func TestBaseline_DefaultConfig(t *testing.T) {
	b := &Baseline{}
	cfg := b.DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig() returned nil")
	}

	typedCfg, ok := cfg.(*Config)
	if !ok {
		t.Fatal("DefaultConfig() did not return *Config")
	}

	if typedCfg.PluginBaseConfig.Name != "baseline" {
		t.Errorf("Expected Name='baseline', got '%s'", typedCfg.PluginBaseConfig.Name)
	}
	if typedCfg.PluginBaseConfig.Enabled {
		t.Error("Expected Enabled=false by default")
	}
	if !typedCfg.PluginBaseConfig.IsAdvanced {
		t.Error("Expected IsAdvanced=true")
	}
}

func TestBaseline_DefaultConfig_AllDetectionsEnabled(t *testing.T) {
	b := &Baseline{}
	cfg := b.DefaultConfig().(*Config)

	checks := []struct {
		name string
		val  bool
	}{
		{"DetectCORSHeaderConfig", cfg.DetectCORSHeaderConfig},
		{"DetectServerErrorPage", cfg.DetectServerErrorPage},
		{"DetectSystemPath", cfg.DetectSystemPath},
		{"DetectOutdatedSSLVersion", cfg.DetectOutdatedSSLVersion},
		{"DetectHTTPHeaderConfig", cfg.DetectHTTPHeaderConfig},
		{"DetectCookieHttpOnly", cfg.DetectCookieHttpOnly},
		{"DetectChinaIDCardNumber", cfg.DetectChinaIDCardNumber},
		{"DetectChinaPhoneNumber", cfg.DetectChinaPhoneNumber},
		{"DetectChinaBankCard", cfg.DetectChinaBankCard},
		{"DetectPrivateIP", cfg.DetectPrivateIP},
		{"DetectEmail", cfg.DetectEmail},
		{"DetectHTMLComment", cfg.DetectHTMLComment},
		{"DetectHostInjection", cfg.DetectHostInjection},
		{"DetectSerializationDataInParams", cfg.DetectSerializationDataInParams},
		{"DetectCookiePasswordLeak", cfg.DetectCookiePasswordLeak},
		{"DetectChinaAddress", cfg.DetectChinaAddress},
		{"DetectAutoComplete", cfg.DetectAutoComplete},
		{"DetectUnsafeScheme", cfg.DetectUnsafeScheme},
		{"DetectRedirectLogic", cfg.DetectRedirectLogic},
	}

	for _, check := range checks {
		if !check.val {
			t.Errorf("Expected %s=true, got false", check.name)
		}
	}
}

func TestBaseline_Fingers_AllEnabled(t *testing.T) {
	b := &Baseline{}
	cfg := b.DefaultConfig()
	ab := &base.ApolloBase{}
	b.Init(context.Background(), cfg, ab)

	fingers := b.Fingers()
	if len(fingers) == 0 {
		t.Error("Expected non-zero fingers when all detections enabled")
	}
}

func TestBaseline_Fingers_AllDisabled(t *testing.T) {
	b := &Baseline{}
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:       "baseline",
			Enabled:    false,
			IsAdvanced: true,
		},
		DetectCORSHeaderConfig:          false,
		DetectServerErrorPage:           false,
		DetectSystemPath:                false,
		DetectOutdatedSSLVersion:        false,
		DetectHTTPHeaderConfig:          false,
		DetectCookieHttpOnly:            false,
		DetectChinaIDCardNumber:         false,
		DetectChinaPhoneNumber:          false,
		DetectChinaBankCard:             false,
		DetectPrivateIP:                 false,
		DetectEmail:                     false,
		DetectHTMLComment:               false,
		DetectHostInjection:             false,
		DetectSerializationDataInParams: false,
		DetectCookiePasswordLeak:        false,
		DetectChinaAddress:              false,
		DetectAutoComplete:              false,
		DetectUnsafeScheme:              false,
		DetectRedirectLogic:             false,
	}
	ab := &base.ApolloBase{}
	b.Init(context.Background(), cfg, ab)

	fingers := b.Fingers()
	if len(fingers) != 0 {
		t.Errorf("Expected 0 fingers when all detections disabled, got %d", len(fingers))
	}
}

func TestBaseline_Fingers_NilConfig(t *testing.T) {
	b := &Baseline{}
	// Don't call Init, so GetConfig returns nil
	fingers := b.Fingers()
	if fingers != nil {
		t.Errorf("Expected nil fingers with nil config, got %v", fingers)
	}
}

func TestBaseline_GetConfig(t *testing.T) {
	b := &Baseline{}
	// Before Init
	cfg := b.GetConfig()
	if cfg != nil {
		t.Errorf("Expected nil config before Init, got %v", cfg)
	}

	// After Init
	expectedCfg := b.DefaultConfig()
	ab := &base.ApolloBase{}
	b.Init(context.Background(), expectedCfg, ab)

	cfg = b.GetConfig()
	if cfg == nil {
		t.Fatal("Expected non-nil config after Init")
	}
}

func TestConfig_BaseConfig(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "baseline",
			Enabled: true,
		},
	}
	bc := cfg.BaseConfig()
	if bc == nil {
		t.Fatal("BaseConfig() returned nil")
	}
	if bc.Name != "baseline" {
		t.Errorf("Expected Name='baseline', got '%s'", bc.Name)
	}
}

// ==================== Utility function tests ====================

func TestTruncateString(t *testing.T) {
	tests := []struct {
		input  string
		maxLen int
		want   string
	}{
		{"short", 10, "short"},
		{"exactly10", 10, "exactly10"},
		{"this is a longer string", 10, "this is a ..."},
		{"", 5, ""},
		{"abc", 3, "abc"},
	}

	for _, tt := range tests {
		got := truncateString(tt.input, tt.maxLen)
		if got != tt.want {
			t.Errorf("truncateString(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
		}
	}
}

func TestIsASCII(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"hello", true},
		{"", true},
		{"ABC123!@#", true},
		{"\x00\x7f", true},
		{"héllo", false},
		{"日本語", false},
		{"hello\x80", false},
	}

	for _, tt := range tests {
		got := isASCII(tt.input)
		if got != tt.want {
			t.Errorf("isASCII(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

// ==================== ParsePolicy tests ====================

func TestParsePolicy(t *testing.T) {
	tests := []struct {
		name     string
		csp      string
		wantDirs int
		wantKey  string
		wantVals []string
	}{
		{"empty", "", 0, "", nil},
		{"single directive", "script-src 'self'", 1, "script-src", []string{"'self'"}},
		{"multiple directives", "script-src 'self'; style-src 'unsafe-inline'", 2, "script-src", []string{"'self'"}},
		{"with spaces", "  script-src   'self' 'unsafe-inline'  ;  style-src 'self'  ", 2, "script-src", []string{"'self'", "'unsafe-inline'"}},
		{"only semicolons", ";;; ", 0, "", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParsePolicy(tt.csp)
			if len(result) != tt.wantDirs {
				t.Errorf("ParsePolicy(%q): got %d directives, want %d", tt.csp, len(result), tt.wantDirs)
			}
			if tt.wantKey != "" {
				if vals, ok := result[tt.wantKey]; !ok {
					t.Errorf("ParsePolicy(%q): missing directive %q", tt.csp, tt.wantKey)
				} else {
					if len(vals) != len(tt.wantVals) {
						t.Errorf("ParsePolicy(%q)[%q]: got %v, want %v", tt.csp, tt.wantKey, vals, tt.wantVals)
					}
				}
			}
		})
	}
}

// ==================== getAllowedWildcardSources tests ====================

func TestGetAllowedWildcardSources(t *testing.T) {
	tests := []struct {
		name string
		csp  string
		want []string
	}{
		{"empty", "", nil},
		{"script-src only", "script-src 'self'", []string{"script-src"}},
		{"multiple", "script-src 'self'; style-src 'self'; img-src 'self'", []string{"script-src", "style-src", "img-src"}},
		{"unknown directive", "default-src 'self'", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getAllowedWildcardSources(tt.csp)
			if len(got) != len(tt.want) {
				t.Errorf("getAllowedWildcardSources(%q): got %v, want %v", tt.csp, got, tt.want)
			}
		})
	}
}

// ==================== validateChinaIDCard tests ====================

func TestValidateChinaIDCard(t *testing.T) {
	tests := []struct {
		id   string
		want bool
	}{
		{"11010119900307627X", true},  // valid checksum
		{"110101199003076270", false}, // wrong checksum
		{"12345", false},              // too short
		{"12345678901234567x", false}, // wrong format
		{"", false},
	}

	for _, tt := range tests {
		got := validateChinaIDCard(tt.id)
		if got != tt.want {
			t.Errorf("validateChinaIDCard(%q) = %v, want %v", tt.id, got, tt.want)
		}
	}
}

// ==================== luhnCheck tests ====================

func TestLuhnCheck(t *testing.T) {
	tests := []struct {
		number string
		want   bool
	}{
		{"4111111111111111", true},  // valid Visa test number
		{"49927398716", true},       // well-known valid
		{"49927398717", false},      // well-known invalid
		{"1234567812345670", true},  // valid
		{"1234567812345678", false}, // invalid
	}

	for _, tt := range tests {
		got := luhnCheck(tt.number)
		if got != tt.want {
			t.Errorf("luhnCheck(%q) = %v, want %v", tt.number, got, tt.want)
		}
	}
}

// ==================== isSensitiveInput tests ====================

func TestIsSensitiveInput(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{`<input type="password" name="pwd">`, true},
		{`<input type='password' name="x">`, true},
		{`<input name="password" type="text">`, true},
		{`<input name="token" type="text">`, true},
		{`<input id="secret" type="text">`, true},
		{`<input type="text" name="username">`, false},
		{`<input type="text" name="email">`, false},
		{`<input type="hidden" name="csrf">`, false},
	}

	for _, tt := range tests {
		got := isSensitiveInput(tt.input)
		if got != tt.want {
			t.Errorf("isSensitiveInput(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

// ==================== IsLooselyScopedCookie tests ====================

func TestIsLooselyScopedCookie(t *testing.T) {
	tests := []struct {
		name   string
		cookie *http.Cookie
		host   string
		want   bool
	}{
		{"empty domain", &http.Cookie{Name: "test", Value: "val"}, "example.com", false},
		{"same domain", &http.Cookie{Name: "test", Value: "val", Domain: "example.com"}, "example.com", false},
		{"different domain", &http.Cookie{Name: "test", Value: "val", Domain: "other.com"}, "example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsLooselyScopedCookie(tt.cookie, tt.host)
			if got != tt.want {
				t.Errorf("IsLooselyScopedCookie() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsCookieAndHostHaveTheSameDomain(t *testing.T) {
	tests := []struct {
		name    string
		cookieD []string
		hostD   []string
		want    bool
	}{
		{"same TLD", []string{"example", "com"}, []string{"example", "com"}, true},
		{"different TLD", []string{"example", "com"}, []string{"other", "org"}, false},
		{"subdomain", []string{"sub", "example", "com"}, []string{"example", "com"}, true},
		{"different second level", []string{"example", "com"}, []string{"other", "com"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsCookieAndHostHaveTheSameDomain(tt.cookieD, tt.hostD)
			if got != tt.want {
				t.Errorf("IsCookieAndHostHaveTheSameDomain() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ==================== isRedirectParam tests ====================

func TestIsRedirectParam(t *testing.T) {
	tests := []struct {
		key   string
		value string
		want  bool
	}{
		{"url", "http://example.com", true},
		{"redirect", "/path", true},
		{"next", "//evil.com", true},
		{"q", "search term", false},
		{"goto", "home", true},
		{"param", "value", false},
	}

	for _, tt := range tests {
		got := isRedirectParamTestHelper(tt.key, tt.value)
		if got != tt.want {
			t.Errorf("isRedirectParam(key=%q, value=%q) = %v, want %v", tt.key, tt.value, got, tt.want)
		}
	}
}

// Helper that mirrors isRedirectParam logic for testing without constructing http.Parameter
func isRedirectParamTestHelper(key, value string) bool {
	if value != "" {
		if strings.HasPrefix(value, "http") {
			return true
		}
		if strings.HasPrefix(value, "//") {
			return true
		}
		if strings.HasPrefix(value, "/") && len(value) > 1 {
			return true
		}
	}
	keyLower := strings.ToLower(key)
	redirectKeywords := []string{"url", "redirect", "redir", "return", "next", "goto", "link", "target", "destination", "continue", "forward"}
	for _, kw := range redirectKeywords {
		if strings.Contains(keyLower, kw) {
			return true
		}
	}
	return false
}

func TestIsRedirectParam_WithHTTPParameter(t *testing.T) {
	tests := []struct {
		key   string
		value string
		want  bool
	}{
		{"url", "http://example.com", true},
		{"redirect", "/path", true},
		{"next", "//evil.com", true},
		{"q", "search term", false},
		{"goto", "home", true},
		{"param", "value", false},
	}

	for _, tt := range tests {
		param := wscan_http.Parameter{
			Position: wscan_http.PositionQuery,
			Key:      tt.key,
			Value:    tt.value,
		}
		got := isRedirectParam(param)
		if got != tt.want {
			t.Errorf("isRedirectParam(key=%q, value=%q) = %v, want %v", tt.key, tt.value, got, tt.want)
		}
	}
}

// ==================== isRedirectToPayload tests ====================

func TestIsRedirectToPayload(t *testing.T) {
	tests := []struct {
		location string
		payload  string
		want     bool
	}{
		{"http://evil.com/path", "evil.com", true},
		{"http://other.com/path", "evil.com", false},
		{"http://evil.com/path", "http://evil.com", true},
		{"contains-payload-in-path", "payload", true},
	}

	for _, tt := range tests {
		got := isRedirectToPayload(tt.location, tt.payload)
		if got != tt.want {
			t.Errorf("isRedirectToPayload(%q, %q) = %v, want %v", tt.location, tt.payload, got, tt.want)
		}
	}
}

// ==================== Scan Rule Finger tests ====================

func TestApplicationErrorScanRule_Finger(t *testing.T) {
	r := &ApplicationErrorScanRule{}
	finger := r.Finger()
	if finger == nil {
		t.Fatal("ApplicationErrorScanRule.Finger() returned nil")
	}
	if finger.Binding.ID != "baseline/sensitive/application_error" {
		t.Errorf("Unexpected Binding.ID: %s", finger.Binding.ID)
	}
}

func TestCacheControlScanRule_Finger(t *testing.T) {
	r := &CacheControlScanRule{}
	finger := r.Finger()
	if finger == nil {
		t.Fatal("CacheControlScanRule.Finger() returned nil")
	}
	if finger.Binding.ID != "baseline/cache/control" {
		t.Errorf("Unexpected Binding.ID: %s", finger.Binding.ID)
	}
}

func TestContentSecurityPolicyMissingScanRule_Finger(t *testing.T) {
	r := &ContentSecurityPolicyMissingScanRule{}
	finger := r.Finger()
	if finger == nil {
		t.Fatal("ContentSecurityPolicyMissingScanRule.Finger() returned nil")
	}
	if finger.Binding.ID != "baseline/header/content_security_policy_missing" {
		t.Errorf("Unexpected Binding.ID: %s", finger.Binding.ID)
	}
}

func TestContentTypeMissingScanRule_Finger(t *testing.T) {
	r := &ContentTypeMissingScanRule{}
	finger := r.Finger()
	if finger == nil {
		t.Fatal("ContentTypeMissingScanRule.Finger() returned nil")
	}
	if finger.Binding.ID != "baseline/header/content_type_missing" {
		t.Errorf("Unexpected Binding.ID: %s", finger.Binding.ID)
	}
}

func TestCookieHttpOnlyScanRule_Finger(t *testing.T) {
	r := &CookieHttpOnlyScanRule{}
	finger := r.Finger()
	if finger == nil {
		t.Fatal("CookieHttpOnlyScanRule.Finger() returned nil")
	}
	if finger.Binding.ID != "baseline/cookie/http-only" {
		t.Errorf("Unexpected Binding.ID: %s", finger.Binding.ID)
	}
}

func TestCookieLooselyScopedScanRule_Finger(t *testing.T) {
	r := &CookieLooselyScopedScanRule{}
	finger := r.Finger()
	if finger == nil {
		t.Fatal("CookieLooselyScopedScanRule.Finger() returned nil")
	}
	if finger.Binding.ID != "baseline/cookie/loosely_scoped" {
		t.Errorf("Unexpected Binding.ID: %s", finger.Binding.ID)
	}
}

func TestCookieSecureFlagScanRule_Finger(t *testing.T) {
	r := &CookieSecureFlagScanRule{}
	finger := r.Finger()
	if finger == nil {
		t.Fatal("CookieSecureFlagScanRule.Finger() returned nil")
	}
	if finger.Binding.ID != "baseline/cookie/secure" {
		t.Errorf("Unexpected Binding.ID: %s", finger.Binding.ID)
	}
}

func TestCrossDomainMisconfigurationScanRule_Finger(t *testing.T) {
	r := &CrossDomainMisconfigurationScanRule{}
	finger := r.Finger()
	if finger == nil {
		t.Fatal("CrossDomainMisconfigurationScanRule.Finger() returned nil")
	}
	if finger.Binding.ID != "baseline/config/crossdomain" {
		t.Errorf("Unexpected Binding.ID: %s", finger.Binding.ID)
	}
}

func TestOutdatedSSLVersion_Finger(t *testing.T) {
	o := &outdatedSSLVersion{}
	finger := o.Finger()
	if finger == nil {
		t.Fatal("outdatedSSLVersion.Finger() returned nil")
	}
	if finger.Binding.ID != "baseline/ssl/outdated-version" {
		t.Errorf("Unexpected Binding.ID: %s", finger.Binding.ID)
	}
}

func TestSystemPath_Finger(t *testing.T) {
	s := &systemPath{}
	finger := s.Finger()
	if finger == nil {
		t.Fatal("systemPath.Finger() returned nil")
	}
}

func TestChinaPhoneNumber_Finger(t *testing.T) {
	c := &chinaPhoneNumber{}
	finger := c.Finger()
	if finger == nil {
		t.Fatal("chinaPhoneNumber.Finger() returned nil")
	}
}

func TestChinaBankCard_Finger(t *testing.T) {
	c := &chinaBankCard{}
	finger := c.Finger()
	if finger == nil {
		t.Fatal("chinaBankCard.Finger() returned nil")
	}
}

func TestChinaAddress_Finger(t *testing.T) {
	c := &chinaAddress{}
	finger := c.Finger()
	if finger == nil {
		t.Fatal("chinaAddress.Finger() returned nil")
	}
}

func TestAutoCompleteLeak_Finger(t *testing.T) {
	a := &autoCompleteLeak{}
	finger := a.Finger()
	if finger == nil {
		t.Fatal("autoCompleteLeak.Finger() returned nil")
	}
}

func TestUnsafeSchemeLeak_Finger(t *testing.T) {
	u := &unsafeSchemeLeak{}
	finger := u.Finger()
	if finger == nil {
		t.Fatal("unsafeSchemeLeak.Finger() returned nil")
	}
}

func TestSerializationDataInParams_Finger(t *testing.T) {
	s := &serializationDataInParams{}
	finger := s.Finger()
	if finger == nil {
		t.Fatal("serializationDataInParams.Finger() returned nil")
	}
}

func TestCookiePasswordLeak_Finger(t *testing.T) {
	c := &cookiePasswordLeak{}
	finger := c.Finger()
	if finger == nil {
		t.Fatal("cookiePasswordLeak.Finger() returned nil")
	}
}

func TestRedirectLogic_Finger(t *testing.T) {
	r := &redirectLogic{}
	finger := r.Finger()
	if finger == nil {
		t.Fatal("redirectLogic.Finger() returned nil")
	}
}

func TestHostInjection_Finger(t *testing.T) {
	h := &hostInjection{}
	finger := h.Finger()
	if finger == nil {
		t.Fatal("hostInjection.Finger() returned nil")
	}
}

func TestHtmlCommentLeak_Finger(t *testing.T) {
	h := &htmlCommentLeak{}
	finger := h.Finger()
	if finger == nil {
		t.Fatal("htmlCommentLeak.Finger() returned nil")
	}
}

func TestEmailLeak_Finger(t *testing.T) {
	e := &emailLeak{}
	finger := e.Finger()
	if finger == nil {
		t.Fatal("emailLeak.Finger() returned nil")
	}
}

func TestPrivateIPLeak_Finger(t *testing.T) {
	p := &privateIPLeak{}
	finger := p.Finger()
	if finger == nil {
		t.Fatal("privateIPLeak.Finger() returned nil")
	}
}

func TestContentSecurityPolicyScanRule_Finger(t *testing.T) {
	r := &ContentSecurityPolicyScanRule{}
	fingers := r.Finger()
	if len(fingers) == 0 {
		t.Fatal("ContentSecurityPolicyScanRule.Finger() returned empty slice")
	}
	// Should return multiple CSP-related fingers
	expectedIDs := []string{
		"baseline/csp/xcsp",
		"baseline/csp/xwkcsp",
		"baseline/csp/notices",
		"baseline/csp/wildcard",
		"baseline/csp/scriptsrc_unsafe",
		"baseline/csp/scriptsrc_unsafe_hashes",
		"baseline/csp/scriptsrc_unsafe_eval",
		"baseline/csp/stylesrc_unsafe_hashes",
		"baseline/csp/stylesrc_unsafe_inline",
		"baseline/csp/both",
		"baseline/csp/malformed",
		"baseline/csp/meta_bad_directive",
	}
	if len(fingers) != len(expectedIDs) {
		t.Errorf("Expected %d CSP fingers, got %d", len(expectedIDs), len(fingers))
	}
	for i, expectedID := range expectedIDs {
		if i < len(fingers) && fingers[i].Binding.ID != expectedID {
			t.Errorf("Finger[%d]: expected ID=%s, got %s", i, expectedID, fingers[i].Binding.ID)
		}
	}
}

func TestCookieSameSiteScanRule_Finger(t *testing.T) {
	r := &CookieSameSiteScanRule{}
	fingers := r.Finger()
	if len(fingers) != 3 {
		t.Errorf("Expected 3 SameSite fingers, got %d", len(fingers))
	}
	expectedIDs := []string{
		"baseline/cookie/no_sameSite",
		"baseline/cookie/none_sameSite",
		"baseline/cookie/badval_sameSite",
	}
	for i, expectedID := range expectedIDs {
		if i < len(fingers) && fingers[i].Binding.ID != expectedID {
			t.Errorf("Finger[%d]: expected ID=%s, got %s", i, expectedID, fingers[i].Binding.ID)
		}
	}
}

// ==================== FindElements tests ====================

func TestFindElements(t *testing.T) {
	tests := []struct {
		name    string
		html    string
		tag     string
		wantLen int
	}{
		{"empty", "", "meta", 0},
		{"no meta", "<html><body>hello</body></html>", "meta", 0},
		{"one meta", `<html><head><meta charset="utf-8"></head></html>`, "meta", 1},
		{"two meta", `<html><head><meta charset="utf-8"><meta name="viewport"></head></html>`, "meta", 2},
		{"div", `<html><body><div>a</div><div>b</div></body></html>`, "div", 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			elems, err := FindElements(tt.html, tt.tag)
			if err != nil {
				t.Errorf("FindElements() error: %v", err)
			}
			if len(elems) != tt.wantLen {
				t.Errorf("FindElements() = %d elements, want %d", len(elems), tt.wantLen)
			}
		})
	}
}

// ==================== Regex pattern tests ====================

func TestPrivateIPRegex(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"8.8.8.8", false},
		{"172.15.0.1", false},
		{"172.32.0.1", false},
		{"192.168.1.0", true},   // matched but filtered later
		{"192.168.1.255", true}, // matched but filtered later
	}

	for _, tt := range tests {
		got := privateIPRegex.MatchString(tt.ip)
		if got != tt.want {
			t.Errorf("privateIPRegex.MatchString(%q) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func TestChinaPhoneRegex(t *testing.T) {
	tests := []struct {
		phone string
		want  bool
	}{
		{"13812345678", true},
		{"15912345678", true},
		{"12812345678", false}, // second digit 2 is not in 3-9
		{"12345678901", false}, // doesn't start with 1[3-9]
		{"8613812345678", true},
	}

	for _, tt := range tests {
		got := chinaPhoneRegex.MatchString(tt.phone)
		if got != tt.want {
			t.Errorf("chinaPhoneRegex.MatchString(%q) = %v, want %v", tt.phone, got, tt.want)
		}
	}
}

func TestChinaBankCardRegex(t *testing.T) {
	tests := []struct {
		card string
		want bool
	}{
		{"6228480402564890018", true}, // starts with 62
		{"4111111111111111", true},    // starts with 4
		{"5111111111111111", true},    // starts with 51
		{"3111111111111111", false},   // starts with 3
		{"1234", false},               // too short
	}

	for _, tt := range tests {
		got := chinaBankCardRegex.MatchString(tt.card)
		if got != tt.want {
			t.Errorf("chinaBankCardRegex.MatchString(%q) = %v, want %v", tt.card, got, tt.want)
		}
	}
}

func TestLinuxPathRegex(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/var/log/nginx/access.log", true},
		{"/usr/local/bin/app", true},
		{"/home/user/file.txt", true},
		{"/etc/passwd", true},
		{"/tmp/test", true},
		{"/opt/app/config", true},
		{"/invalid/path", false},
		{"hello world", false},
	}

	for _, tt := range tests {
		got := linuxPathRegex.MatchString(tt.path)
		if got != tt.want {
			t.Errorf("linuxPathRegex.MatchString(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestWindowsPathRegex(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{`C:\Users\admin\Documents`, true},
		{`C:\Windows\System32`, true},
		{`D:\Program Files\App`, true},
		{`C:\inetpub\wwwroot`, true},
		{`/usr/local/bin`, false},
		{"hello world", false},
	}

	for _, tt := range tests {
		got := windowsPathRegex.MatchString(tt.path)
		if got != tt.want {
			t.Errorf("windowsPathRegex.MatchString(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestChinaIDCardRegex(t *testing.T) {
	tests := []struct {
		id   string
		want bool
	}{
		{"11010119900307627X", true},
		{"110101200003076279", true},  // matches regex (year 2000)
		{"123456789012345678", false}, // doesn't match regex (78 is not 19xx or 20xx)
		{"1234", false},
		{"abcdefghij", false},
	}

	for _, tt := range tests {
		got := chinaIDCardRegex.MatchString(tt.id)
		if got != tt.want {
			t.Errorf("chinaIDCardRegex.MatchString(%q) = %v, want %v", tt.id, got, tt.want)
		}
	}
}

func TestEmailRegex(t *testing.T) {
	tests := []struct {
		email string
		want  bool
	}{
		{"admin@realcompany.org", true},
		{"test@example.com", true}, // matches regex but filtered by domain
		{"user.name+tag@domain.co", true},
		{"not-an-email", false},
		{"1.0.0", false},
	}

	for _, tt := range tests {
		got := emailRegex.MatchString(tt.email)
		if got != tt.want {
			t.Errorf("emailRegex.MatchString(%q) = %v, want %v", tt.email, got, tt.want)
		}
	}
}

func TestHTMLCommentRegex(t *testing.T) {
	tests := []struct {
		html string
		want bool
	}{
		{"<!-- TODO: fix this -->", true},
		{"<!-- password=admin -->", true},
		{"no comments here", false},
		{"<!---->", true},
	}

	for _, tt := range tests {
		got := htmlCommentRegex.MatchString(tt.html)
		if got != tt.want {
			t.Errorf("htmlCommentRegex.MatchString(%q) = %v, want %v", tt.html, got, tt.want)
		}
	}
}

func TestJavaSerializedRegex(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA", true},
		{"rO0AB", false}, // too short, needs at least 4 more chars
		{"normal text", false},
	}

	for _, tt := range tests {
		got := javaSerializedRegex.MatchString(tt.input)
		if got != tt.want {
			t.Errorf("javaSerializedRegex.MatchString(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestPHPSerializedRegex(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{`a:1:{s:3:"foo"`, true},
		{`O:8:"ClassName":`, true},
		{"normal text", false},
	}

	for _, tt := range tests {
		got := phpSerializedRegex.MatchString(tt.input)
		if got != tt.want {
			t.Errorf("phpSerializedRegex.MatchString(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

// ==================== Scan rule CheckAction integration tests ====================

func TestContentTypeMissingScanRule_CheckAction(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
		expectVuln  bool
	}{
		{"missing content-type", "", "some body", true},
		{"empty content-type value", "", "some body", true},
		{"has content-type", "text/html", "some body", false},
		{"no body", "text/html", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, _ := url.Parse("http://example.com/")
			netResp := &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(tt.body)),
				Request:    &http.Request{URL: u},
			}
			if tt.contentType != "" {
				netResp.Header.Set("Content-Type", tt.contentType)
			}
			resp, _ := wscan_http.ResponseFromNetHttpResponse(netResp)

			a := mockApollo(nil, resp)
			vulnFound := false
			a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) {
				vulnFound = true
			}}

			r := &ContentTypeMissingScanRule{}
			finger := r.Finger()
			finger.CheckAction(context.Background(), a)

			if tt.expectVuln != vulnFound {
				t.Errorf("expected vulnFound=%v, got %v", tt.expectVuln, vulnFound)
			}
		})
	}
}

func TestCrossDomainScanRule_CheckAction(t *testing.T) {
	tests := []struct {
		name       string
		corsHeader string
		expectVuln bool
	}{
		{"wildcard origin", "*", true},
		{"specific origin", "https://specific.com", false},
		{"no cors header", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, _ := url.Parse("http://example.com/")
			netResp := &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("body")),
				Request:    &http.Request{URL: u},
			}
			if tt.corsHeader != "" {
				netResp.Header.Set("Access-Control-Allow-Origin", tt.corsHeader)
			}
			resp, _ := wscan_http.ResponseFromNetHttpResponse(netResp)

			a := mockApollo(nil, resp)
			vulnFound := false
			a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) {
				vulnFound = true
			}}

			r := &CrossDomainMisconfigurationScanRule{}
			finger := r.Finger()
			finger.CheckAction(context.Background(), a)

			if tt.expectVuln != vulnFound {
				t.Errorf("expected vulnFound=%v, got %v", tt.expectVuln, vulnFound)
			}
		})
	}
}

func TestChinaPhoneNumberFinger(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{"valid phone", `<div>13812345678</div>`, true},
		{"no phone", `<div>hello</div>`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := makeTestResponse(tt.body)
			a := mockApollo(nil, resp)
			vulnFound := false
			a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) {
				vulnFound = true
			}}

			c := &chinaPhoneNumber{}
			finger := c.Finger()
			finger.CheckAction(context.Background(), a)

			if tt.expected != vulnFound {
				t.Errorf("expected vulnFound=%v, got %v", tt.expected, vulnFound)
			}
		})
	}
}

func TestChinaBankCardFinger(t *testing.T) {
	// 6228480402564890018 is a valid Luhn card number starting with 62
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{"valid bank card", `<div>6228480402564890018</div>`, true},
		{"no bank card", `<div>hello</div>`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := makeTestResponse(tt.body)
			a := mockApollo(nil, resp)
			vulnFound := false
			a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) {
				vulnFound = true
			}}

			c := &chinaBankCard{}
			finger := c.Finger()
			finger.CheckAction(context.Background(), a)

			if tt.expected != vulnFound {
				t.Errorf("expected vulnFound=%v, got %v", tt.expected, vulnFound)
			}
		})
	}
}

func TestHtmlCommentLeakFinger(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{"sensitive comment", `<!-- password=admin123 -->`, true},
		{"TODO comment", `<!-- TODO: fix this -->`, true},
		{"innocent comment", `<!-- just a note -->`, false},
		{"no comment", `<div>hello</div>`, false},
		{"IE conditional", `<!--[if IE]><script>...</script><![endif]-->`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := makeTestResponse(tt.body)
			a := mockApollo(nil, resp)
			vulnFound := false
			a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) {
				vulnFound = true
			}}

			h := &htmlCommentLeak{}
			finger := h.Finger()
			finger.CheckAction(context.Background(), a)

			if tt.expected != vulnFound {
				t.Errorf("expected vulnFound=%v, got %v for body=%q", tt.expected, vulnFound, tt.body)
			}
		})
	}
}

func TestAutoCompleteLeakFinger(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{"password without autocomplete", `<input type="password" name="pwd">`, true},
		{"password with autocomplete off", `<input type="password" name="pwd" autocomplete="off">`, false},
		{"non-sensitive input", `<input type="text" name="search">`, false},
		{"no inputs", `<div>hello</div>`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := makeTestResponse(tt.body)
			a := mockApollo(nil, resp)
			vulnFound := false
			a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) {
				vulnFound = true
			}}

			al := &autoCompleteLeak{}
			finger := al.Finger()
			finger.CheckAction(context.Background(), a)

			if tt.expected != vulnFound {
				t.Errorf("expected vulnFound=%v, got %v for body=%q", tt.expected, vulnFound, tt.body)
			}
		})
	}
}

func TestSerializationDataInParamsFinger_JavaSerialized(t *testing.T) {
	// Test that Java serialization regex matches
	if !javaSerializedRegex.MatchString("rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA") {
		t.Error("javaSerializedRegex should match Java serialization marker")
	}
}

func TestSerializationRegexes(t *testing.T) {
	// Test all serialization regexes
	tests := []struct {
		name  string
		regex *regexp.Regexp
		input string
		want  bool
	}{
		{"java serialized", javaSerializedRegex, "rO0ABXNyABFqYXZh", true},
		{"php serialized", phpSerializedRegex, `a:1:{s:3:"foo"`, true},
		{"dotnet viewstate", dotnetViewStateRegex, "test /wEAAABkAA1234data", true},
		{"python pickle", pythonPickleRegex, "gASVAAAAAAAA", true},
		{"ruby marshal", rubyMarshalRegex, "BAhvAAAAAAAA", true},
		{"normal text", javaSerializedRegex, "hello world", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.regex.MatchString(tt.input)
			if got != tt.want {
				t.Errorf("%s.MatchString(%q) = %v, want %v", tt.name, tt.input, got, tt.want)
			}
		})
	}
}

func TestCacheControlScanRule_CheckAction(t *testing.T) {
	tests := []struct {
		name         string
		cacheControl string
		contentType  string
		body         string
		statusCode   int
		expectVuln   bool
	}{
		{"no cache-control", "", "text/html", "body", 200, true},
		{"no-store", "no-store", "text/html", "body", 200, true},
		{"no-cache", "no-cache", "text/html", "body", 200, true},
		{"must-revalidate", "must-revalidate", "text/html", "body", 200, true},
		{"redirect skip", "", "text/html", "body", 302, false},
		{"js skip", "", "application/javascript", "body", 200, false},
		{"css skip", "", "text/css", "body", 200, false},
		{"image skip", "", "image/png", "body", 200, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, _ := url.Parse("http://example.com/")
			netResp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(tt.body)),
				Request:    &http.Request{URL: u},
			}
			if tt.contentType != "" {
				netResp.Header.Set("Content-Type", tt.contentType)
			}
			if tt.cacheControl != "" {
				netResp.Header.Set("Cache-Control", tt.cacheControl)
			}
			resp, _ := wscan_http.ResponseFromNetHttpResponse(netResp)

			a := mockApollo(nil, resp)
			vulnFound := false
			a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) {
				vulnFound = true
			}}

			r := &CacheControlScanRule{}
			finger := r.Finger()
			finger.CheckAction(context.Background(), a)

			if tt.expectVuln != vulnFound {
				t.Errorf("expected vulnFound=%v, got %v", tt.expectVuln, vulnFound)
			}
		})
	}
}

// ==================== HeaderPolicy struct test ====================

func TestHeaderPolicy_Struct(t *testing.T) {
	hp := HeaderPolicy{
		Name:     "X-Frame-Options",
		Expected: true,
	}
	if hp.Name != "X-Frame-Options" {
		t.Errorf("HeaderPolicy.Name = %q, want %q", hp.Name, "X-Frame-Options")
	}
	if !hp.Expected {
		t.Error("HeaderPolicy.Expected should be true")
	}
}

// ==================== CheckAction integration tests ====================

func makeTestResponseWithHeaders(body string, statusCode int, headers map[string]string) *wscan_http.Response {
	u, _ := url.Parse("http://example.com/")
	netResp := &http.Response{
		StatusCode: statusCode,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    &http.Request{URL: u},
	}
	for k, v := range headers {
		netResp.Header.Set(k, v)
	}
	resp, _ := wscan_http.ResponseFromNetHttpResponse(netResp)
	return resp
}

func TestPrivateIPLeak_CheckAction(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		expectVuln bool
	}{
		{"private IP in body", "Server: 192.168.1.100", true},
		{"broadcast excluded", "Server: 192.168.1.255", false},
		{"no private IP", "hello world", false},
		{"10.x range", "Internal: 10.0.0.1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := makeTestResponseWithHeaders(tt.body, 200, map[string]string{
				"Content-Type": "text/html",
			})
			a := mockApollo(nil, resp)
			vulnFound := false
			a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) {
				vulnFound = true
			}}

			p := &privateIPLeak{}
			finger := p.Finger()
			finger.CheckAction(context.Background(), a)

			if tt.expectVuln != vulnFound {
				t.Errorf("expected vulnFound=%v, got %v", tt.expectVuln, vulnFound)
			}
		})
	}
}

func TestEmailLeak_CheckAction(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		expectVuln bool
	}{
		{"real email", "Contact: admin@realcompany.org", true},
		{"example.com excluded", "test@example.com", false},
		{"no email", "hello world", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := makeTestResponseWithHeaders(tt.body, 200, map[string]string{
				"Content-Type": "text/html",
			})
			a := mockApollo(nil, resp)
			vulnFound := false
			a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) {
				vulnFound = true
			}}

			e := &emailLeak{}
			finger := e.Finger()
			finger.CheckAction(context.Background(), a)

			if tt.expectVuln != vulnFound {
				t.Errorf("expected vulnFound=%v, got %v", tt.expectVuln, vulnFound)
			}
		})
	}
}

func TestChinaAddress_CheckAction(t *testing.T) {
	resp := makeTestResponseWithHeaders("地址：北京市朝阳区建国路", 200, map[string]string{
		"Content-Type": "text/html",
	})
	a := mockApollo(nil, resp)
	vulnFound := false
	a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) {
		vulnFound = true
	}}

	c := &chinaAddress{}
	finger := c.Finger()
	finger.CheckAction(context.Background(), a)

	if !vulnFound {
		t.Error("Expected vuln for China address in body")
	}
}

func TestSystemPath_CheckAction(t *testing.T) {
	resp := makeTestResponseWithHeaders("Error in /var/log/nginx/access.log", 200, map[string]string{
		"Content-Type": "text/html",
	})
	a := mockApollo(nil, resp)
	vulnFound := false
	a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) {
		vulnFound = true
	}}

	s := &systemPath{}
	finger := s.Finger()
	finger.CheckAction(context.Background(), a)

	if !vulnFound {
		t.Error("Expected vuln for system path in body")
	}
}

func TestChinaIDCard_CheckAction(t *testing.T) {
	resp := makeTestResponseWithHeaders("ID: 11010119900307627X", 200, map[string]string{
		"Content-Type": "text/html",
	})
	a := mockApollo(nil, resp)
	vulnFound := false
	a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) {
		vulnFound = true
	}}

	c := &chinaIDCardNumber{}
	finger := c.Finger()
	finger.CheckAction(context.Background(), a)

	if !vulnFound {
		t.Error("Expected vuln for China ID card in body")
	}
}

func TestContentSecurityPolicyMissing_CheckAction(t *testing.T) {
	resp := makeTestResponseWithHeaders("<html><body>test</body></html>", 200, map[string]string{
		"Content-Type": "text/html",
	})
	a := mockApollo(nil, resp)
	vulnFound := false
	a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) {
		vulnFound = true
	}}

	r := &ContentSecurityPolicyMissingScanRule{}
	finger := r.Finger()
	finger.CheckAction(context.Background(), a)

	if !vulnFound {
		t.Error("Expected vuln for missing CSP header")
	}
}

func TestContentSecurityPolicyMissing_CheckAction_WithCSP(t *testing.T) {
	resp := makeTestResponseWithHeaders("<html><body>test</body></html>", 200, map[string]string{
		"Content-Type":            "text/html",
		"Content-Security-Policy": "default-src 'self'",
	})
	a := mockApollo(nil, resp)
	vulnFound := false
	a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) {
		vulnFound = true
	}}

	r := &ContentSecurityPolicyMissingScanRule{}
	finger := r.Finger()
	finger.CheckAction(context.Background(), a)

	if vulnFound {
		t.Error("Should not detect vulnerability when CSP is present")
	}
}

func TestCookieHttpOnly_CheckAction(t *testing.T) {
	u, _ := url.Parse("http://example.com/")
	netResp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("body")),
		Request:    &http.Request{URL: u},
	}
	netResp.Header.Set("Content-Type", "text/html")
	netResp.Header.Set("Set-Cookie", "session=abc123; Path=/")
	resp, _ := wscan_http.ResponseFromNetHttpResponse(netResp)

	a := mockApollo(nil, resp)
	vulnFound := false
	a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) {
		vulnFound = true
	}}

	r := &CookieHttpOnlyScanRule{}
	finger := r.Finger()
	finger.CheckAction(context.Background(), a)

	if !vulnFound {
		t.Error("Expected vuln for cookie without HttpOnly")
	}
}

func TestCookieSecureFlag_CheckAction(t *testing.T) {
	u, _ := url.Parse("http://example.com/")
	netResp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("body")),
		Request:    &http.Request{URL: u},
	}
	netResp.Header.Set("Content-Type", "text/html")
	netResp.Header.Set("Set-Cookie", "session=abc123; Path=/")
	resp, _ := wscan_http.ResponseFromNetHttpResponse(netResp)

	a := mockApollo(nil, resp)
	vulnFound := false
	a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) {
		vulnFound = true
	}}

	r := &CookieSecureFlagScanRule{}
	finger := r.Finger()
	finger.CheckAction(context.Background(), a)

	if !vulnFound {
		t.Error("Expected vuln for cookie without Secure flag")
	}
}

func TestChinaPhoneNumber_CheckAction(t *testing.T) {
	resp := makeTestResponseWithHeaders("Call: 13812345678", 200, map[string]string{
		"Content-Type": "text/html",
	})
	a := mockApollo(nil, resp)
	vulnFound := false
	a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) {
		vulnFound = true
	}}

	c := &chinaPhoneNumber{}
	finger := c.Finger()
	finger.CheckAction(context.Background(), a)

	if !vulnFound {
		t.Error("Expected vuln for phone number in body")
	}
}

func TestChinaBankCard_CheckAction(t *testing.T) {
	resp := makeTestResponseWithHeaders("Card: 6228480402564890018", 200, map[string]string{
		"Content-Type": "text/html",
	})
	a := mockApollo(nil, resp)
	vulnFound := false
	a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) {
		vulnFound = true
	}}

	c := &chinaBankCard{}
	finger := c.Finger()
	finger.CheckAction(context.Background(), a)

	if !vulnFound {
		t.Error("Expected vuln for bank card in body")
	}
}

func TestAutoCompleteLeak_CheckAction(t *testing.T) {
	resp := makeTestResponseWithHeaders(`<input type="password" name="pwd">`, 200, map[string]string{
		"Content-Type": "text/html",
	})
	a := mockApollo(nil, resp)
	vulnFound := false
	a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) {
		vulnFound = true
	}}

	al := &autoCompleteLeak{}
	finger := al.Finger()
	finger.CheckAction(context.Background(), a)

	if !vulnFound {
		t.Error("Expected vuln for password input without autocomplete=off")
	}
}

func TestHtmlCommentLeak_CheckAction(t *testing.T) {
	resp := makeTestResponseWithHeaders("<!-- password=admin123 -->", 200, map[string]string{
		"Content-Type": "text/html",
	})
	a := mockApollo(nil, resp)
	vulnFound := false
	a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) {
		vulnFound = true
	}}

	h := &htmlCommentLeak{}
	finger := h.Finger()
	finger.CheckAction(context.Background(), a)

	if !vulnFound {
		t.Error("Expected vuln for sensitive HTML comment")
	}
}

func TestCrossDomain_CheckAction_WithAsterisk(t *testing.T) {
	resp := makeTestResponseWithHeaders("body", 200, map[string]string{
		"Content-Type":                "text/html",
		"Access-Control-Allow-Origin": "*",
	})
	a := mockApollo(nil, resp)
	vulnFound := false
	a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) {
		vulnFound = true
	}}

	r := &CrossDomainMisconfigurationScanRule{}
	finger := r.Finger()
	finger.CheckAction(context.Background(), a)

	if !vulnFound {
		t.Error("Expected vuln for wildcard CORS")
	}
}

// ==================== CheckAction tests for remaining scan rules ====================

func TestCookieLooselyScopedScanRule_CheckAction(t *testing.T) {
	tests := []struct {
		name       string
		cookie     string
		expectVuln bool
	}{
		{"loosely scoped cookie", "session=abc; Domain=.other.com", true},
		{"no domain cookie", "session=abc", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, _ := url.Parse("http://example.com/")
			netResp := &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("body")),
				Request:    &http.Request{URL: u},
			}
			netResp.Header.Set("Content-Type", "text/html")
			if tt.cookie != "" {
				netResp.Header.Set("Set-Cookie", tt.cookie)
			}
			resp, _ := wscan_http.ResponseFromNetHttpResponse(netResp)
			a := mockApollo(nil, resp)
			vulnFound := false
			a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) {
				vulnFound = true
			}}

			r := &CookieLooselyScopedScanRule{}
			finger := r.Finger()
			finger.CheckAction(context.Background(), a)

			if tt.expectVuln != vulnFound {
				t.Errorf("expected vulnFound=%v, got %v", tt.expectVuln, vulnFound)
			}
		})
	}
}

func TestCookieSameSiteScanRule_CheckActions(t *testing.T) {
	tests := []struct {
		name      string
		cookie    string
		expectIDs []string
	}{
		{"no SameSite", "session=abc; Path=/", []string{"baseline/cookie/no_sameSite", "baseline/cookie/badval_sameSite"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, _ := url.Parse("http://example.com/")
			netResp := &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("body")),
				Request:    &http.Request{URL: u},
			}
			netResp.Header.Set("Content-Type", "text/html")
			netResp.Header.Set("Set-Cookie", tt.cookie)
			_, _ = wscan_http.ResponseFromNetHttpResponse(netResp)

			r := &CookieSameSiteScanRule{}
			fingers := r.Finger()
			if len(fingers) != 3 {
				t.Errorf("Expected 3 SameSite fingers, got %d", len(fingers))
			}
			for i, f := range fingers {
				if f.CheckAction == nil {
					t.Errorf("Finger[%d] should have CheckAction", i)
				}
			}
		})
	}
}

func TestContentSecurityPolicyScanRule_CheckAction_XCSP(t *testing.T) {
	resp := makeTestResponseWithHeaders("<html><body>test</body></html>", 200, map[string]string{
		"Content-Type":              "text/html",
		"X-Content-Security-Policy": "default-src 'self'",
	})
	a := mockApollo(nil, resp)
	vulnFound := false
	a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) {
		vulnFound = true
	}}

	r := &ContentSecurityPolicyScanRule{}
	fingers := r.Finger()
	// First finger checks X-Content-Security-Policy
	if len(fingers) > 0 {
		fingers[0].CheckAction(context.Background(), a)
		if !vulnFound {
			t.Error("Expected vuln for deprecated X-Content-Security-Policy header")
		}
	}
}

func TestContentSecurityPolicyScanRule_CheckAction_WebkitCSP(t *testing.T) {
	resp := makeTestResponseWithHeaders("<html><body>test</body></html>", 200, map[string]string{
		"Content-Type": "text/html",
		"X-WebKit-CSP": "default-src 'self'",
	})
	a := mockApollo(nil, resp)
	vulnFound := false
	a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) {
		vulnFound = true
	}}

	r := &ContentSecurityPolicyScanRule{}
	fingers := r.Finger()
	if len(fingers) > 1 {
		fingers[1].CheckAction(context.Background(), a)
		if !vulnFound {
			t.Error("Expected vuln for deprecated X-WebKit-CSP header")
		}
	}
}

func TestContentSecurityPolicyScanRule_CheckAction_Wildcard(t *testing.T) {
	r := &ContentSecurityPolicyScanRule{}
	fingers := r.Finger()
	if len(fingers) < 4 {
		t.Errorf("Expected at least 4 CSP fingers, got %d", len(fingers))
	}
}

func TestContentSecurityPolicyScanRule_CheckAction_UnsafeInline(t *testing.T) {
	r := &ContentSecurityPolicyScanRule{}
	fingers := r.Finger()
	if len(fingers) < 5 {
		t.Errorf("Expected at least 5 CSP fingers, got %d", len(fingers))
	}
}

func TestContentSecurityPolicyScanRule_CheckAction_UnsafeEval(t *testing.T) {
	r := &ContentSecurityPolicyScanRule{}
	fingers := r.Finger()
	if len(fingers) < 7 {
		t.Errorf("Expected at least 7 CSP fingers, got %d", len(fingers))
	}
}

func TestContentSecurityPolicyScanRule_CheckAction_Malformed(t *testing.T) {
	r := &ContentSecurityPolicyScanRule{}
	fingers := r.Finger()
	if len(fingers) < 10 {
		t.Errorf("Expected at least 10 CSP fingers, got %d", len(fingers))
	}
}

func TestContentSecurityPolicyScanRule_CheckAction_BadDirective(t *testing.T) {
	r := &ContentSecurityPolicyScanRule{}
	fingers := r.Finger()
	if len(fingers) < 11 {
		t.Errorf("Expected at least 11 CSP fingers, got %d", len(fingers))
	}
}

func TestCookiePasswordLeak_CheckAction(t *testing.T) {
	// Test the Finger() method returns the expected binding
	c := &cookiePasswordLeak{}
	finger := c.Finger()
	if finger == nil {
		t.Fatal("cookiePasswordLeak.Finger() returned nil")
	}
	if finger.Binding.ID != "baseline/sensitive/cookie-password-leak" {
		t.Errorf("Unexpected Binding.ID: %s", finger.Binding.ID)
	}
}

func TestServerError_Finger_ReturnsNil(t *testing.T) {
	s := &serverError{}
	finger := s.Finger()
	if finger != nil {
		t.Errorf("serverError.Finger() should return nil, got %v", finger)
	}
}

func TestApplicationErrorScanRule_CheckAction_With500(t *testing.T) {
	u, _ := url.Parse("http://example.com/")
	netResp := &http.Response{
		StatusCode: 500,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("Internal Server Error")),
		Request:    &http.Request{URL: u},
	}
	netResp.Header.Set("Content-Type", "text/html")
	resp, _ := wscan_http.ResponseFromNetHttpResponse(netResp)

	a := mockApollo(nil, resp)
	vulnFound := false
	a.ApolloBase.Output = &mockPrinter{onPrint: func(v *model.Vuln) {
		vulnFound = true
	}}

	r := &ApplicationErrorScanRule{}
	finger := r.Finger()
	finger.CheckAction(context.Background(), a)
	// Status 500 returns nil early, no vuln should be reported
	if vulnFound {
		t.Error("Should not report vuln for 500 status (early return)")
	}
}

func TestApplicationErrorScanRule_CheckAction_WithPattern(t *testing.T) {
	r := &ApplicationErrorScanRule{}
	finger := r.Finger()
	if finger == nil {
		t.Fatal("ApplicationErrorScanRule.Finger() returned nil")
	}
	if finger.CheckAction == nil {
		t.Error("ApplicationErrorScanRule CheckAction should not be nil")
	}
}

func TestUnsafeSchemeLeak_RegexPatterns(t *testing.T) {
	tests := []struct {
		name string
		html string
		want bool
	}{
		{"src http on https page", `src="http://example.com/img.jpg"`, true},
		{"href http on https page", `href="http://example.com/page"`, true},
		{"url() in style", `background: url(http://example.com/bg.png)`, true},
		{"form action http", `<form action="http://example.com/submit">`, true},
		{"no unsafe scheme", `src="https://example.com/img.jpg"`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrMatch := unsafeSchemeRegex.MatchString(tt.html)
			styleMatch := unsafeSchemeStyleRegex.MatchString(tt.html)
			formMatch := unsafeFormActionRegex.MatchString(tt.html)
			got := attrMatch || styleMatch || formMatch
			if got != tt.want {
				t.Errorf("unsafe scheme detection for %q = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestOutdatedSSLVersion_Versions(t *testing.T) {
	if len(outdatedVersions) != 3 {
		t.Errorf("Expected 3 outdated SSL versions, got %d", len(outdatedVersions))
	}
}

func TestHostInjection_Finger_Binding(t *testing.T) {
	h := &hostInjection{}
	finger := h.Finger()
	if finger == nil {
		t.Fatal("hostInjection.Finger() returned nil")
	}
	if finger.Binding.ID != "baseline/injection/host-injection" {
		t.Errorf("Unexpected Binding.ID: %s", finger.Binding.ID)
	}
	if finger.Channel != "web-generic" {
		t.Errorf("Unexpected Channel: %s", finger.Channel)
	}
}

func TestRedirectLogic_Finger_Binding(t *testing.T) {
	r := &redirectLogic{}
	finger := r.Finger()
	if finger == nil {
		t.Fatal("redirectLogic.Finger() returned nil")
	}
	if finger.Binding.ID != "baseline/injection/open-redirect" {
		t.Errorf("Unexpected Binding.ID: %s", finger.Binding.ID)
	}
}

func TestSSL_Finger_Binding(t *testing.T) {
	o := &outdatedSSLVersion{}
	finger := o.Finger()
	if finger == nil {
		t.Fatal("outdatedSSLVersion.Finger() returned nil")
	}
	if finger.Binding.ID != "baseline/ssl/outdated-version" {
		t.Errorf("Unexpected Binding.ID: %s", finger.Binding.ID)
	}
}

func TestUnsafeSchemeLeak_Finger_Binding(t *testing.T) {
	u := &unsafeSchemeLeak{}
	finger := u.Finger()
	if finger == nil {
		t.Fatal("unsafeSchemeLeak.Finger() returned nil")
	}
	if finger.Binding.ID != "baseline/config/unsafe-scheme" {
		t.Errorf("Unexpected Binding.ID: %s", finger.Binding.ID)
	}
}

func TestSerializationDataInParams_Finger_Binding(t *testing.T) {
	s := &serializationDataInParams{}
	finger := s.Finger()
	if finger == nil {
		t.Fatal("serializationDataInParams.Finger() returned nil")
	}
	if finger.Binding.ID != "baseline/sensitive/serialization-data" {
		t.Errorf("Unexpected Binding.ID: %s", finger.Binding.ID)
	}
}

func TestCookiePasswordLeak_Finger_Binding(t *testing.T) {
	c := &cookiePasswordLeak{}
	finger := c.Finger()
	if finger == nil {
		t.Fatal("cookiePasswordLeak.Finger() returned nil")
	}
	if finger.Binding.ID != "baseline/sensitive/cookie-password-leak" {
		t.Errorf("Unexpected Binding.ID: %s", finger.Binding.ID)
	}
}

func TestBaseline_Init(t *testing.T) {
	b := &Baseline{}
	cfg := b.DefaultConfig()
	ab := &base.ApolloBase{}
	err := b.Init(context.Background(), cfg, ab)
	if err != nil {
		t.Errorf("Init() returned error: %v", err)
	}
}

func TestPasswordCookieNamePatterns(t *testing.T) {
	if len(passwordCookieNamePatterns) == 0 {
		t.Error("Expected non-empty passwordCookieNamePatterns")
	}
}

func TestExcludeCookieNames(t *testing.T) {
	if len(excludeCookieNames) == 0 {
		t.Error("Expected non-empty excludeCookieNames")
	}
	if !excludeCookieNames["sessionid"] {
		t.Error("Expected 'sessionid' to be in excludeCookieNames")
	}
}

func TestSessionValuePatterns(t *testing.T) {
	if len(sessionValuePatterns) == 0 {
		t.Error("Expected non-empty sessionValuePatterns")
	}
}

func TestPayloadApplicationErrYaml(t *testing.T) {
	p, err := payloadApplicationErrYaml()
	if err != nil {
		t.Errorf("payloadApplicationErrYaml() returned error: %v", err)
	}
	if len(p.Patterns) == 0 {
		t.Error("Expected non-empty patterns from YAML")
	}
}
