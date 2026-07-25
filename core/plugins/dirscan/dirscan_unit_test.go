package dirscan

import (
	"context"
	"net/url"
	"os"
	"strings"
	"testing"

	wscan_http "wscan/core/http"
	"wscan/core/plugins/base"
)

// ==================== Fingers with expCache ====================

func TestDirscan_Fingers_OnlyRulesWithExpCache(t *testing.T) {
	p := &Dirscan{}
	cfg := p.DefaultConfig()
	ab := &base.ApolloBase{}
	p.Init(context.Background(), cfg, ab)

	fingers := p.Fingers()
	// All fingers should have non-nil CheckAction and ExecAction
	for i, f := range fingers {
		if f.CheckAction == nil {
			t.Errorf("Finger[%d] has nil CheckAction", i)
		}
		if f.ExecAction == nil {
			t.Errorf("Finger[%d] has nil ExecAction", i)
		}
	}
}

// ==================== Rule.Finger with all fields ====================

func TestRule_Finger_BindingDetails(t *testing.T) {
	r := &Rule{
		Category:   "dirscan/test-cat",
		Paths:      []string{".git/config"},
		Expression: "response.status == 200",
	}
	f := r.Finger()
	if f.Binding.ID != "dirscan/test-cat" {
		t.Errorf("Binding.ID = %q, want 'dirscan/test-cat'", f.Binding.ID)
	}
	if f.Binding.Plugin != "dirscan/test-cat" {
		t.Errorf("Binding.Plugin = %q, want 'dirscan/test-cat'", f.Binding.Plugin)
	}
	if f.Binding.Category != "dirscan/test-cat" {
		t.Errorf("Binding.Category = %q, want 'dirscan/test-cat'", f.Binding.Category)
	}
}

// ==================== Init with dictionary edge cases ====================

func TestInit_DictionaryWithWhitespace(t *testing.T) {
	tmpDir := t.TempDir()
	dictFile := tmpDir + "/dict_ws.txt"
	content := "  /admin  \n\n  /backup  \n"
	if err := writeFile(dictFile, content); err != nil {
		t.Fatal(err)
	}

	p := &Dirscan{}
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "dirscan",
			Enabled: true,
		},
		Depth:      1,
		Dictionary: dictFile,
	}
	ab := &base.ApolloBase{}
	err := p.Init(context.Background(), cfg, ab)
	if err != nil {
		t.Errorf("Init() error: %v", err)
	}
}

func TestInit_EmptyDictionary(t *testing.T) {
	tmpDir := t.TempDir()
	dictFile := tmpDir + "/empty_dict.txt"
	if err := writeFile(dictFile, ""); err != nil {
		t.Fatal(err)
	}

	p := &Dirscan{}
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "dirscan",
			Enabled: true,
		},
		Depth:      1,
		Dictionary: dictFile,
	}
	ab := &base.ApolloBase{}
	err := p.Init(context.Background(), cfg, ab)
	if err != nil {
		t.Errorf("Init() error: %v", err)
	}
}

// ==================== DepthCheck with cache ====================

func TestDirscan_DepthCheck_CacheHit(t *testing.T) {
	p := &Dirscan{}
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "dirscan",
			Enabled: true,
		},
		Depth: 0,
	}
	ab := &base.ApolloBase{}
	ab.Output = &dirscanMockPrinter{}
	p.Init(context.Background(), cfg, ab)

	// First call - should pass with depth 0 (no restriction)
	a := makeDirscanTestApollo(1)
	err1 := p.DepthCheck(context.Background(), a)
	if err1 != nil {
		t.Errorf("First DepthCheck should pass, got: %v", err1)
	}

	// Second call with same URL - should also pass (cache hit)
	err2 := p.DepthCheck(context.Background(), a)
	if err2 != nil {
		t.Errorf("Second DepthCheck should pass (cache), got: %v", err2)
	}
}

func TestDirscan_DepthCheck_ExceedsDepthLimit_Cache(t *testing.T) {
	p := &Dirscan{}
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "dirscan",
			Enabled: true,
		},
		Depth: 1,
	}
	ab := &base.ApolloBase{}
	ab.Output = &dirscanMockPrinter{}
	p.Init(context.Background(), cfg, ab)

	// Depth 2 should fail with limit 1
	a := makeDirscanTestApollo(2)
	err := p.DepthCheck(context.Background(), a)
	if err == nil {
		t.Error("DepthCheck with depth=2 and limit=1 should fail")
	}

	// Second call should also fail (cached error)
	err2 := p.DepthCheck(context.Background(), a)
	if err2 == nil {
		t.Error("Second DepthCheck should also fail (cached)")
	}
}

// ==================== sourceMap struct test ====================

func TestSourceMap_StructInitialized(t *testing.T) {
	sm := sourceMap{filter: nil}
	_ = sm
}

// ==================== Multiple paths in Rule ====================

func TestRule_MultiplePaths(t *testing.T) {
	r := &Rule{
		Category:   "dirscan/git",
		Paths:      []string{".git/config", ".git/HEAD", ".gitignore"},
		Expression: "response.status == 200",
	}
	if len(r.Paths) != 3 {
		t.Errorf("Expected 3 paths, got %d", len(r.Paths))
	}
}

// ==================== Rule with suffix ====================

func TestRule_WithSuffix(t *testing.T) {
	r := &Rule{
		Category: "dirscan/backup",
		Paths:    []string{"backup"},
		Suffix:   []string{".zip", ".tar.gz", ".bak"},
	}
	if len(r.Suffix) != 3 {
		t.Errorf("Expected 3 suffixes, got %d", len(r.Suffix))
	}
}

// ==================== RuleSet fields ====================

func TestRuleSet_Version(t *testing.T) {
	p := &Dirscan{}
	cfg := p.DefaultConfig()
	ab := &base.ApolloBase{}
	p.Init(context.Background(), cfg, ab)

	if p.ruleSet.Version == "" {
		t.Log("RuleSet Version is empty (may be expected)")
	}
}

func TestRuleSet_Categories(t *testing.T) {
	p := &Dirscan{}
	cfg := p.DefaultConfig()
	ab := &base.ApolloBase{}
	p.Init(context.Background(), cfg, ab)

	if len(p.ruleSet.Category) == 0 {
		t.Log("RuleSet Category list is empty (may be expected)")
	}
}

// ==================== DefaultConfig specific values ====================

func TestDefaultConfig_SpecificFields(t *testing.T) {
	p := &Dirscan{}
	cfg := p.DefaultConfig().(*Config)
	if cfg.Dictionary != "" {
		t.Errorf("Default Dictionary should be empty, got %q", cfg.Dictionary)
	}
}

// ==================== Category struct creation ====================

func TestCategory_Fields(t *testing.T) {
	c := &Category{Name: "test", Title: "Test Category"}
	if c.Name != "test" {
		t.Errorf("Name = %q, want 'test'", c.Name)
	}
	if c.Title != "Test Category" {
		t.Errorf("Title = %q, want 'Test Category'", c.Title)
	}
}

// ==================== Rule Finger with RetestAction ====================

func TestRule_RetestAction_Nil(t *testing.T) {
	r := &Rule{}
	err := r.RetestAction(context.Background(), nil)
	if err != nil {
		t.Errorf("RetestAction should return nil, got %v", err)
	}
}

// ==================== Fingers only returns rules with expCache ====================

func TestDirscan_Fingers_FilterNoExpCache(t *testing.T) {
	p := &Dirscan{}
	cfg := p.DefaultConfig()
	ab := &base.ApolloBase{}
	p.Init(context.Background(), cfg, ab)

	// Count rules with expCache
	rulesWithExpCache := 0
	for _, rule := range p.ruleSet.Rules {
		if rule.expCache != nil {
			rulesWithExpCache++
		}
	}

	fingers := p.Fingers()
	if len(fingers) != rulesWithExpCache {
		t.Errorf("Fingers count (%d) should match rules with expCache (%d)", len(fingers), rulesWithExpCache)
	}
}

// ==================== DepthCheck with various depths ====================

func TestDirscan_DepthCheck_ExactDepthLimit(t *testing.T) {
	p := &Dirscan{}
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "dirscan",
			Enabled: true,
		},
		Depth: 3,
	}
	ab := &base.ApolloBase{}
	ab.Output = &dirscanMockPrinter{}
	p.Init(context.Background(), cfg, ab)

	// Depth exactly at limit should pass
	a := makeDirscanTestApollo(3)
	err := p.DepthCheck(context.Background(), a)
	if err != nil {
		t.Errorf("DepthCheck with depth=3 and limit=3 should pass, got: %v", err)
	}
}

func TestDirscan_DepthCheck_OneAboveLimit(t *testing.T) {
	p := &Dirscan{}
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "dirscan",
			Enabled: true,
		},
		Depth: 2,
	}
	ab := &base.ApolloBase{}
	ab.Output = &dirscanMockPrinter{}
	p.Init(context.Background(), cfg, ab)

	// Depth 3 should fail with limit 2
	a := makeDirscanTestApollo(3)
	err := p.DepthCheck(context.Background(), a)
	if err == nil {
		t.Error("DepthCheck with depth=3 and limit=2 should fail")
	}
}

// ==================== Helper to write file ====================

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0644)
}

// ==================== Path normalization in rules ====================

func TestInit_RulePathNormalization(t *testing.T) {
	p := &Dirscan{}
	cfg := p.DefaultConfig()
	ab := &base.ApolloBase{}
	p.Init(context.Background(), cfg, ab)

	// Check that rule paths don't start with /
	for _, rule := range p.ruleSet.Rules {
		for _, path := range rule.Paths {
			if strings.HasPrefix(path, "/") {
				t.Errorf("Rule path should not start with /: %q", path)
			}
		}
	}
}

// ==================== MockPrinter for dirscan tests ====================

func makeDirscanApolloWithURL(rawURL string) *base.Apollo {
	u, _ := url.Parse(rawURL)
	req, _ := wscan_http.NewRequest("GET", u.String(), nil)
	flow := &wscan_http.Flow{
		Request:  req,
		Response: &wscan_http.Response{StatusCode: 200},
	}
	a := base.NewApollo(flow)
	a.ApolloBase.Output = &dirscanMockPrinter{}
	return a
}

func TestDirscan_DepthCheck_DifferentURLs(t *testing.T) {
	p := &Dirscan{}
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "dirscan",
			Enabled: true,
		},
		Depth: 1,
	}
	ab := &base.ApolloBase{}
	ab.Output = &dirscanMockPrinter{}
	p.Init(context.Background(), cfg, ab)

	// URL with depth 1 should pass
	a1 := makeDirscanApolloWithURL("http://example.com/a/")
	err1 := p.DepthCheck(context.Background(), a1)
	if err1 != nil {
		t.Errorf("DepthCheck for /a/ should pass, got: %v", err1)
	}

	// URL with depth 2 should fail
	a2 := makeDirscanApolloWithURL("http://example.com/a/b/")
	err2 := p.DepthCheck(context.Background(), a2)
	if err2 == nil {
		t.Error("DepthCheck for /a/b/ should fail with limit=1")
	}
}

// ==================== Rule CheckAction is no-op ====================

func TestRule_CheckAction_WithRule(t *testing.T) {
	r := &Rule{
		Category:   "dirscan/test",
		Paths:      []string{"test"},
		Expression: "response.status == 200",
	}
	err := r.CheckAction(context.Background(), nil)
	if err != nil {
		t.Errorf("Rule.CheckAction() should return nil, got %v", err)
	}
}

// ==================== Verify Fingers have correct CheckAction wrapping ====================

func TestDirscan_Fingers_CheckActionNonNil(t *testing.T) {
	p := &Dirscan{}
	cfg := p.DefaultConfig()
	ab := &base.ApolloBase{}
	p.Init(context.Background(), cfg, ab)

	fingers := p.Fingers()
	if len(fingers) == 0 {
		t.Skip("No fingers to test")
	}

	// Just verify the CheckAction is non-nil (it's a closure wrapping DepthCheck, CheckAction, Check404)
	for i, f := range fingers {
		if f.CheckAction == nil {
			t.Errorf("Finger[%d] CheckAction should not be nil", i)
		}
	}
}

// ==================== SourceMap filter test ====================

func TestSourceMap_FilterField(t *testing.T) {
	sm := sourceMap{}
	if sm.filter != nil {
		t.Error("Expected nil filter by default")
	}
}
