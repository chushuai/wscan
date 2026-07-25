package crawler

import (
	"testing"
)

// newTestFillForm creates a FillForm with default config for testing
func newTestFillForm() *FillForm {
	return &FillForm{
		tab: &task{
			config: TabConfig{
				CustomFormValues: map[string]string{
					"default": DefaultInputText,
				},
				CustomFormKeywordValues: map[string]string{},
			},
		},
	}
}

func TestGetMatchInputTextMail(t *testing.T) {
	f := newTestFillForm()

	// Unique keyword that only matches "mail"
	got := f.GetMatchInputText("email_addr")
	if got != "scan@gmail.com" {
		t.Errorf("GetMatchInputText('email_addr') = %q, want 'scan@gmail.com'", got)
	}
}

func TestGetMatchInputTextPassword(t *testing.T) {
	f := newTestFillForm()

	got := f.GetMatchInputText("password")
	if got != "scanner#$3435." {
		t.Errorf("GetMatchInputText('password') = %q, want 'scanner#$3435.'", got)
	}

	got = f.GetMatchInputText("pwd")
	if got != "scanner#$3435." {
		t.Errorf("GetMatchInputText('pwd') = %q, want 'scanner#$3435.'", got)
	}
}

func TestGetMatchInputTextPhone(t *testing.T) {
	f := newTestFillForm()

	got := f.GetMatchInputText("phone")
	if got != "18812345678" {
		t.Errorf("GetMatchInputText('phone') = %q, want '18812345678'", got)
	}

	got = f.GetMatchInputText("tel")
	if got != "18812345678" {
		t.Errorf("GetMatchInputText('tel') = %q, want '18812345678'", got)
	}
}

func TestGetMatchInputTextUsername(t *testing.T) {
	f := newTestFillForm()

	tests := []struct {
		input string
		want  string
	}{
		{"login", "scan@gmail.com"},
		{"user", "scan@gmail.com"},
	}

	for _, tt := range tests {
		got := f.GetMatchInputText(tt.input)
		if got != tt.want {
			t.Errorf("GetMatchInputText(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestGetMatchInputTextCode(t *testing.T) {
	f := newTestFillForm()

	got := f.GetMatchInputText("captcha")
	if got != "123a" {
		t.Errorf("GetMatchInputText('captcha') = %q, want '123a'", got)
	}

	got = f.GetMatchInputText("yanzhengma")
	if got != "123a" {
		t.Errorf("GetMatchInputText('yanzhengma') = %q, want '123a'", got)
	}
}

func TestGetMatchInputTextQQ(t *testing.T) {
	f := newTestFillForm()

	got := f.GetMatchInputText("qq")
	if got != "123456789" {
		t.Errorf("GetMatchInputText('qq') = %q, want '123456789'", got)
	}

	got = f.GetMatchInputText("wechat")
	if got != "123456789" {
		t.Errorf("GetMatchInputText('wechat') = %q, want '123456789'", got)
	}
}

func TestGetMatchInputTextDefaultFallback(t *testing.T) {
	f := &FillForm{
		tab: &task{
			config: TabConfig{
				CustomFormValues: map[string]string{
					"default": "fallback_value",
				},
				CustomFormKeywordValues: map[string]string{},
			},
		},
	}

	// Use a string that won't match any keyword in InputTextMap
	got := f.GetMatchInputText("zzzyyyxxx")
	if got != "fallback_value" {
		t.Errorf("GetMatchInputText('zzzyyyxxx') = %q, want 'fallback_value'", got)
	}
}

func TestGetMatchInputTextCustomFormValues(t *testing.T) {
	f := &FillForm{
		tab: &task{
			config: TabConfig{
				CustomFormValues: map[string]string{
					"default":  "default_val",
					"username": "custom_user",
					"mail":     "custom@example.com",
				},
				CustomFormKeywordValues: map[string]string{},
			},
		},
	}

	// Custom value overrides default keyword match
	got := f.GetMatchInputText("login") // "login" keyword maps to "username"
	if got != "custom_user" {
		t.Errorf("GetMatchInputText('login') with custom username value = %q, want 'custom_user'", got)
	}
}

func TestGetMatchInputTextCustomFormKeywordValues(t *testing.T) {
	f := &FillForm{
		tab: &task{
			config: TabConfig{
				CustomFormValues: map[string]string{
					"default": "default_val",
				},
				CustomFormKeywordValues: map[string]string{
					"company":   "MyCompany",
					"mydeptkey": "Engineering",
				},
			},
		},
	}

	// Custom keyword value should match when input name contains the keyword
	got := f.GetMatchInputText("company_name")
	if got != "MyCompany" {
		t.Errorf("GetMatchInputText('company_name') with custom keyword = %q, want 'MyCompany'", got)
	}

	// Use a unique keyword that won't collide with InputTextMap
	got = f.GetMatchInputText("mydeptkey_field")
	if got != "Engineering" {
		t.Errorf("GetMatchInputText('mydeptkey_field') with custom keyword = %q, want 'Engineering'", got)
	}

	// Non-matching should fall through to default
	got = f.GetMatchInputText("zzzyyyxxx")
	if got != "default_val" {
		t.Errorf("GetMatchInputText('zzzyyyxxx') = %q, want 'default_val'", got)
	}
}

func TestGetMatchInputTextDate(t *testing.T) {
	f := newTestFillForm()

	got := f.GetMatchInputText("date")
	if got != "2000-01-01" {
		t.Errorf("GetMatchInputText('date') = %q, want '2000-01-01'", got)
	}

	got = f.GetMatchInputText("year")
	if got != "2000-01-01" {
		t.Errorf("GetMatchInputText('year') = %q, want '2000-01-01'", got)
	}
}

func TestGetMatchInputTextNumberType(t *testing.T) {
	f := newTestFillForm()

	// "age" is unique to the "number" category
	got := f.GetMatchInputText("age")
	if got != "10" {
		t.Errorf("GetMatchInputText('age') = %q, want '10'", got)
	}

	got = f.GetMatchInputText("count")
	if got != "10" {
		t.Errorf("GetMatchInputText('count') = %q, want '10'", got)
	}
}

func TestGetMatchInputTextURL(t *testing.T) {
	f := newTestFillForm()

	// "site" is unique to the "url" category
	got := f.GetMatchInputText("site")
	if got != "https://scan.nice.cn/" {
		t.Errorf("GetMatchInputText('site') = %q, want 'https://scan.nice.cn/'", got)
	}

	got = f.GetMatchInputText("blog")
	if got != "https://scan.nice.cn/" {
		t.Errorf("GetMatchInputText('blog') = %q, want 'https://scan.nice.cn/'", got)
	}
}

func TestGetMatchInputTypeIDCard(t *testing.T) {
	f := newTestFillForm()

	// "shenfen" is unique to the "IDCard" category
	got := f.GetMatchInputText("shenfen")
	if got != "511702197409284963" {
		t.Errorf("GetMatchInputText('shenfen') = %q, want '511702197409284963'", got)
	}
}

func TestGetMatchInputTextKeywordPriority(t *testing.T) {
	// CustomFormKeywordValues should be checked first
	f := &FillForm{
		tab: &task{
			config: TabConfig{
				CustomFormValues: map[string]string{
					"default": "default_val",
				},
				CustomFormKeywordValues: map[string]string{
					"mymailkey": "custom_keyword_mail@test.com",
				},
			},
		},
	}

	// Custom keyword should take priority
	got := f.GetMatchInputText("mymailkey_field")
	if got != "custom_keyword_mail@test.com" {
		t.Errorf("GetMatchInputText with custom keyword priority = %q, want 'custom_keyword_mail@test.com'", got)
	}
}

func TestGetMatchInputTextEmailAndPasswordTypes(t *testing.T) {
	f := newTestFillForm()

	// Test with type-based inputs (email, password, tel) that use the type directly
	// These go through a different code path in fillInput, but GetMatchInputText
	// uses the same keyword-based matching
	got := f.GetMatchInputText("email")
	if got != "scan@gmail.com" {
		t.Errorf("GetMatchInputText('email') = %q, want 'scan@gmail.com'", got)
	}

	got = f.GetMatchInputText("pass")
	if got != "scanner#$3435." {
		t.Errorf("GetMatchInputText('pass') = %q, want 'scanner#$3435.'", got)
	}
}

func TestInputTextMapContainsRequiredKeys(t *testing.T) {
	requiredKeys := []string{"mail", "code", "phone", "username", "password", "qq", "IDCard", "url", "date", "number"}
	for _, key := range requiredKeys {
		if _, ok := InputTextMap[key]; !ok {
			t.Errorf("InputTextMap missing required key: %s", key)
		}
	}
}

func TestInputTextMapStructure(t *testing.T) {
	for key, item := range InputTextMap {
		if _, ok := item["keyword"]; !ok {
			t.Errorf("InputTextMap[%s] missing 'keyword' field", key)
		}
		if _, ok := item["value"]; !ok {
			t.Errorf("InputTextMap[%s] missing 'value' field", key)
		}
		keywords, ok := item["keyword"].([]string)
		if !ok {
			t.Errorf("InputTextMap[%s]['keyword'] should be []string", key)
			continue
		}
		if len(keywords) == 0 {
			t.Errorf("InputTextMap[%s]['keyword'] should have at least one keyword", key)
		}
		if _, ok := item["value"].(string); !ok {
			t.Errorf("InputTextMap[%s]['value'] should be string", key)
		}
	}
}

func TestAllowedFormNameContainsDefaults(t *testing.T) {
	expectedNames := []string{"default", "mail", "code", "phone", "username", "password", "qq", "id_card", "url", "date", "number"}
	for _, name := range expectedNames {
		found := false
		for _, allowed := range AllowedFormName {
			if allowed == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("AllowedFormName missing expected entry: %s", name)
		}
	}
}
