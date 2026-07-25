/**
* @Author: wscan
* @Date: 2026/06/16
* Tests for WAF Fingerprint Database and Detection Engine
 */
package waftest

import (
	"net/http"
	"testing"

	wscanhttp "wscan/core/http"
	"wscan/core/plugins/base"
)

// ==================== Fingerprint Database Tests ====================

func TestBuiltInWAFFingerprints_Count(t *testing.T) {
	fps := BuiltInWAFFingerprints()
	if len(fps) < 50 {
		t.Errorf("Expected at least 50 WAF fingerprints, got %d", len(fps))
	}
	t.Logf("Total fingerprints: %d", len(fps))
}

func TestBuiltInWAFFingerprints_Categories(t *testing.T) {
	fps := BuiltInWAFFingerprints()
	categories := map[string]int{}
	for _, fp := range fps {
		categories[fp.Category]++
	}

	expectedCategories := []string{"cloud-cn", "cloud-intl", "hardware", "software"}
	for _, cat := range expectedCategories {
		if categories[cat] == 0 {
			t.Errorf("Expected at least one fingerprint in category %q", cat)
		}
		t.Logf("Category %q: %d fingerprints", cat, categories[cat])
	}
}

func TestBuiltInWAFFingerprints_RequiredChineseWAFs(t *testing.T) {
	fps := BuiltInWAFFingerprints()
	found := map[string]bool{}

	for _, fp := range fps {
		found[fp.Name] = true
	}

	requiredWAFs := []string{
		"Aliyun WAF (阿里云WAF)",
		"Tencent Cloud WAF (腾讯云WAF)",
		"SafeDog (安全狗)",
		"CloudWAF (知道创宇云防御)",
		"Chuangyu Shield (创宇盾)",
		"Xuanwudun (玄武盾)",
		"Yundun (云盾)",
		"Yunsuo (云锁)",
		"360 WangZhanBao (360网站卫士)",
		"Jiasule (加速乐)",
	}

	for _, waf := range requiredWAFs {
		if !found[waf] {
			t.Errorf("Missing required Chinese WAF fingerprint: %s", waf)
		}
	}
}

func TestBuiltInWAFFingerprints_RequiredInternationalWAFs(t *testing.T) {
	fps := BuiltInWAFFingerprints()
	found := map[string]bool{}

	for _, fp := range fps {
		found[fp.Name] = true
	}

	requiredWAFs := []string{
		"Cloudflare WAF",
		"AWS WAF",
		"Akamai Kona / WAF",
		"Imperva / Incapsula WAF",
		"Azure WAF",
	}

	for _, waf := range requiredWAFs {
		if !found[waf] {
			t.Errorf("Missing required international WAF fingerprint: %s", waf)
		}
	}
}

func TestBuiltInWAFFingerprints_RequiredHardwareWAFs(t *testing.T) {
	fps := BuiltInWAFFingerprints()
	found := map[string]bool{}

	for _, fp := range fps {
		found[fp.Name] = true
	}

	requiredWAFs := []string{
		"ModSecurity",
		"F5 BIG-IP ASM",
		"Fortinet FortiWeb",
		"Barracuda WAF",
		"Citrix NetScaler (AppFirewall)",
		"Radware AppWall",
	}

	for _, waf := range requiredWAFs {
		if !found[waf] {
			t.Errorf("Missing required hardware/software WAF fingerprint: %s", waf)
		}
	}
}

func TestBuiltInWAFFingerprints_HasBypassTips(t *testing.T) {
	fps := BuiltInWAFFingerprints()
	noTips := []string{}
	for _, fp := range fps {
		if len(fp.BypassTips) == 0 {
			noTips = append(noTips, fp.Name)
		}
	}
	if len(noTips) > 0 {
		t.Errorf("The following WAFs have no bypass tips: %v", noTips)
	}
}

func TestBuiltInWAFFingerprints_NoEmptyNames(t *testing.T) {
	fps := BuiltInWAFFingerprints()
	for _, fp := range fps {
		if fp.Name == "" {
			t.Error("Found WAF fingerprint with empty name")
		}
		if fp.Vendor == "" {
			t.Errorf("WAF %q has empty vendor", fp.Name)
		}
		if fp.Category == "" {
			t.Errorf("WAF %q has empty category", fp.Name)
		}
	}
}

func TestBuiltInWAFFingerprints_EachHasDetectionRules(t *testing.T) {
	fps := BuiltInWAFFingerprints()
	for _, fp := range fps {
		hasPassive := len(fp.Headers) > 0 || len(fp.Cookies) > 0 || len(fp.BodyPatterns) > 0 || len(fp.StatusCodes) > 0
		hasActive := fp.BlockResponse != nil
		if !hasPassive && !hasActive {
			t.Errorf("WAF %q has no detection rules (neither passive nor active)", fp.Name)
		}
	}
}

// ==================== Passive Detection Tests ====================

func makeTestResponse(statusCode int, headers map[string]string, cookies []*http.Cookie, body string) *wscanhttp.Response {
	h := http.Header{}
	for k, v := range headers {
		h.Set(k, v)
	}

	return &wscanhttp.Response{
		StatusCode: statusCode,
		Header:     h,
		Text:       body,
	}
}

func TestPassiveDetection_Cloudflare(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: basePluginConfig(),
		BlockStatusCodes: []int{403},
	}
	detector := NewWAFDetector(cfg)

	// Test with Cf-Ray header
	res := makeTestResponse(200, map[string]string{
		"Cf-Ray": "some-ray-id",
		"Server": "cloudflare",
	}, nil, "")
	result := detector.DetectPassive(res)
	if result == nil {
		t.Fatal("Expected Cloudflare detection from Cf-Ray header")
	}
	if result.Name != "Cloudflare WAF" {
		t.Errorf("Expected 'Cloudflare WAF', got %q", result.Name)
	}
	if result.Method != "passive" {
		t.Errorf("Expected method 'passive', got %q", result.Method)
	}
}

func TestPassiveDetection_CloudflareByBody(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: basePluginConfig(),
		BlockStatusCodes: []int{403},
	}
	detector := NewWAFDetector(cfg)

	res := makeTestResponse(403, nil, nil, "Cloudflare Ray ID: abc123")
	result := detector.DetectPassive(res)
	if result == nil {
		t.Fatal("Expected Cloudflare detection from body pattern")
	}
	if result.Name != "Cloudflare WAF" {
		t.Errorf("Expected 'Cloudflare WAF', got %q", result.Name)
	}
}

func TestPassiveDetection_SafeDog(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: basePluginConfig(),
		BlockStatusCodes: []int{403},
	}
	detector := NewWAFDetector(cfg)

	res := makeTestResponse(200, map[string]string{
		"Server": "SafeDog",
	}, nil, "")
	result := detector.DetectPassive(res)
	if result == nil {
		t.Fatal("Expected SafeDog detection from Server header")
	}
	if result.Name != "SafeDog (安全狗)" {
		t.Errorf("Expected 'SafeDog (安全狗)', got %q", result.Name)
	}
}

func TestPassiveDetection_ModSecurity(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: basePluginConfig(),
		BlockStatusCodes: []int{403},
	}
	detector := NewWAFDetector(cfg)

	res := makeTestResponse(200, map[string]string{
		"Server": "mod_security",
	}, nil, "")
	result := detector.DetectPassive(res)
	if result == nil {
		t.Fatal("Expected ModSecurity detection from Server header")
	}
	if result.Name != "ModSecurity" {
		t.Errorf("Expected 'ModSecurity', got %q", result.Name)
	}
}

func TestPassiveDetection_ModSecurityByBody(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: basePluginConfig(),
		BlockStatusCodes: []int{403},
	}
	detector := NewWAFDetector(cfg)

	res := makeTestResponse(403, nil, nil, "This error was generated by Mod_Security")
	result := detector.DetectPassive(res)
	if result == nil {
		t.Fatal("Expected ModSecurity detection from body pattern")
	}
	if result.Name != "ModSecurity" {
		t.Errorf("Expected 'ModSecurity', got %q", result.Name)
	}
}

func TestPassiveDetection_AliyunWAF(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: basePluginConfig(),
		BlockStatusCodes: []int{403},
	}
	detector := NewWAFDetector(cfg)

	res := makeTestResponse(403, nil, nil, `<a href="http://errors.aliyun.com">Aliyun WAF</a>`)
	result := detector.DetectPassive(res)
	if result == nil {
		t.Fatal("Expected Aliyun WAF detection from body pattern")
	}
	if result.Name != "Aliyun WAF (阿里云WAF)" {
		t.Errorf("Expected 'Aliyun WAF (阿里云WAF)', got %q", result.Name)
	}
}

func TestPassiveDetection_IncapsulaCookies(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: basePluginConfig(),
		BlockStatusCodes: []int{403},
	}
	detector := NewWAFDetector(cfg)

	h := http.Header{}
	res := &wscanhttp.Response{
		StatusCode: 200,
		Header:     h,
		Text:       "",
	}

	// Set cookies using NativeResponse
	nativeRes := &http.Response{
		StatusCode: 200,
		Header:     h,
	}
	nativeRes.Header.Set("Set-Cookie", "visid_incap_12345=abcdef; Path=/")
	res.NativeResponse = nativeRes

	result := detector.DetectPassive(res)
	if result == nil {
		t.Fatal("Expected Incapsula detection from cookie pattern")
	}
	if result.Name != "Imperva / Incapsula WAF" {
		t.Errorf("Expected 'Imperva / Incapsula WAF', got %q", result.Name)
	}
}

func TestPassiveDetection_F5BIGIP(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: basePluginConfig(),
		BlockStatusCodes: []int{403},
	}
	detector := NewWAFDetector(cfg)

	// Test with BIGipServer cookie
	h := http.Header{}
	res := &wscanhttp.Response{
		StatusCode: 200,
		Header:     h,
		Text:       "",
	}
	nativeRes := &http.Response{
		StatusCode: 200,
		Header:     h,
	}
	nativeRes.Header.Set("Set-Cookie", "BIGipServerpool=12345.67890; Path=/")
	res.NativeResponse = nativeRes

	result := detector.DetectPassive(res)
	if result == nil {
		t.Fatal("Expected F5 BIG-IP detection from cookie pattern")
	}
	if result.Name != "F5 BIG-IP ASM" {
		t.Errorf("Expected 'F5 BIG-IP ASM', got %q", result.Name)
	}
}

func TestPassiveDetection_NoWAF(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: basePluginConfig(),
		BlockStatusCodes: []int{403},
	}
	detector := NewWAFDetector(cfg)

	res := makeTestResponse(200, map[string]string{
		"Server":       "nginx/1.18.0",
		"Content-Type": "text/html",
	}, nil, "<html><body>Hello World</body></html>")
	result := detector.DetectPassive(res)
	if result != nil {
		t.Errorf("Expected no WAF detection, got %q (confidence: %d)", result.Name, result.Confidence)
	}
}

func TestPassiveDetection_NilResponse(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: basePluginConfig(),
	}
	detector := NewWAFDetector(cfg)
	result := detector.DetectPassive(nil)
	if result != nil {
		t.Error("Expected nil result for nil response")
	}
}

// ==================== Behavior Detection Tests ====================

func TestBehaviorDetection_WAFPresent(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: basePluginConfig(),
		BlockStatusCodes: []int{403},
	}
	detector := NewWAFDetector(cfg)

	baseline := makeTestResponse(200, nil, nil, "<html>Normal page</html>")

	attackResults := []*probeResult{
		{probeName: "xss", response: makeTestResponse(403, nil, nil, "Forbidden")},
		{probeName: "sqli", response: makeTestResponse(403, nil, nil, "Blocked")},
		{probeName: "path", response: makeTestResponse(403, nil, nil, "Access Denied")},
		{probeName: "cmd", response: makeTestResponse(403, nil, nil, "Not Allowed")},
		{probeName: "size", response: makeTestResponse(403, nil, nil, "Forbidden")},
		{probeName: "proto", response: makeTestResponse(403, nil, nil, "Blocked")},
	}

	result := detector.DetectBehavior(attackResults, baseline)
	if result == nil {
		t.Fatal("Expected behavior-based WAF detection")
	}
	if result.Method != "behavior" {
		t.Errorf("Expected method 'behavior', got %q", result.Method)
	}
	if result.Confidence < 50 {
		t.Errorf("Expected confidence >= 50, got %d", result.Confidence)
	}
	if len(result.BypassTips) == 0 {
		t.Error("Expected bypass tips for behavior-detected WAF")
	}
}

func TestBehaviorDetection_NoWAF(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: basePluginConfig(),
		BlockStatusCodes: []int{403},
	}
	detector := NewWAFDetector(cfg)

	baseline := makeTestResponse(200, nil, nil, "<html>Normal page</html>")

	attackResults := []*probeResult{
		{probeName: "xss", response: makeTestResponse(200, nil, nil, "<html>Normal page</html>")},
		{probeName: "sqli", response: makeTestResponse(200, nil, nil, "<html>Normal page</html>")},
		{probeName: "path", response: makeTestResponse(200, nil, nil, "<html>Normal page</html>")},
		{probeName: "cmd", response: makeTestResponse(200, nil, nil, "<html>Normal page</html>")},
	}

	result := detector.DetectBehavior(attackResults, baseline)
	if result != nil {
		t.Errorf("Expected no behavior-based WAF detection, got %q", result.Name)
	}
}

func TestBehaviorDetection_NilBaseline(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: basePluginConfig(),
	}
	detector := NewWAFDetector(cfg)
	result := detector.DetectBehavior(nil, nil)
	if result != nil {
		t.Error("Expected nil result for nil baseline")
	}
}

// ==================== Detection Result Tests ====================

func TestWAFDetectionResult_Fields(t *testing.T) {
	result := &WAFDetectionResult{
		Detected:   true,
		Name:       "Test WAF",
		Vendor:     "Test Vendor",
		Category:   "cloud-intl",
		Confidence: 80,
		Method:     "passive",
		BypassTips: []string{"tip1", "tip2"},
		Evidence:   "Server header matches",
	}
	if !result.Detected {
		t.Error("Expected Detected=true")
	}
	if result.Confidence != 80 {
		t.Errorf("Expected Confidence=80, got %d", result.Confidence)
	}
	if len(result.BypassTips) != 2 {
		t.Errorf("Expected 2 bypass tips, got %d", len(result.BypassTips))
	}
}

// ==================== WAFDetector Tests ====================

func TestNewWAFDetector(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: basePluginConfig(),
	}
	detector := NewWAFDetector(cfg)
	if detector == nil {
		t.Fatal("Expected non-nil detector")
	}
	if len(detector.fingerprints) == 0 {
		t.Error("Expected detector to have fingerprints loaded")
	}
	if detector.cfg != cfg {
		t.Error("Expected detector to use the provided config")
	}
}

// ==================== WAFFinger Tests ====================

func TestNewWAFFinger(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig:       basePluginConfig(),
		UseBuiltinFingerprints: true,
		ActiveProbe:            true,
	}
	finger := NewWAFFinger(cfg)
	if finger == nil {
		t.Fatal("Expected non-nil WAFFinger")
	}
	if finger.cfg != cfg {
		t.Error("Expected WAFFinger to use the provided config")
	}
}

func TestWAFFinger_Finger(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: basePluginConfig(),
	}
	finger := NewWAFFinger(cfg)
	f := finger.Finger()
	if f == nil {
		t.Fatal("Expected non-nil Finger")
	}
	if f.Channel != "website" {
		t.Errorf("Expected Channel='website', got %q", f.Channel)
	}
	if f.Binding == nil {
		t.Fatal("Expected non-nil Binding")
	}
	if f.Binding.Plugin != "waftest" {
		t.Errorf("Expected Plugin='waftest', got %q", f.Binding.Plugin)
	}
	if f.Binding.Category != "waf" {
		t.Errorf("Expected Category='waf', got %q", f.Binding.Category)
	}
	if f.ExecAction == nil {
		t.Error("Expected non-nil ExecAction")
	}
}

// ==================== Config Integration Tests ====================

func TestConfig_NewFields(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig:       basePluginConfig(),
		UseBuiltinFingerprints: true,
		ActiveProbe:            true,
	}
	if !cfg.UseBuiltinFingerprints {
		t.Error("Expected UseBuiltinFingerprints=true")
	}
	if !cfg.ActiveProbe {
		t.Error("Expected ActiveProbe=true")
	}
}

func TestDefaultConfig_NewFields(t *testing.T) {
	ct := &CustomTmpl{}
	cfg := ct.DefaultConfig().(*Config)
	if !cfg.UseBuiltinFingerprints {
		t.Error("Expected UseBuiltinFingerprints=true in default config")
	}
	if !cfg.ActiveProbe {
		t.Error("Expected ActiveProbe=true in default config")
	}
}

// ==================== Helper Functions ====================

func basePluginConfig() base.PluginBaseConfig {
	return base.PluginBaseConfig{Name: "waftest", Enabled: true}
}
