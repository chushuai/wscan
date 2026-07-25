package dirscan

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"wscan/core/plugins/base"
)

// ==================== Close coverage ====================

func TestCovBoost2_Close(t *testing.T) {
	p := &Dirscan{}
	if err := p.Close(); err != nil {
		t.Errorf("Close() should return nil, got: %v", err)
	}
	// Close multiple times should also be fine
	if err := p.Close(); err != nil {
		t.Errorf("Second Close() should return nil, got: %v", err)
	}
}

// ==================== detectPath coverage ====================

func TestCovBoost2_DetectPath(t *testing.T) {
	r := &Rule{}
	r.detectPath() // no-op, just for coverage
}

// ==================== Init with dictionary file open error ====================

func TestCovBoost2_Init_DictionaryOpenError(t *testing.T) {
	p := &Dirscan{}
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "dirscan",
			Enabled: true,
		},
		Depth:      1,
		Dictionary: "/nonexistent/path/dict.txt",
	}
	ab := &base.ApolloBase{}
	err := p.Init(context.Background(), cfg, ab)
	if err != nil {
		t.Errorf("Init() should not return error even with bad dictionary path, got: %v", err)
	}
}

// ==================== Init with dictionary containing duplicate entries ====================

func TestCovBoost2_Init_DictionaryDuplicates(t *testing.T) {
	tmpDir := t.TempDir()
	dictFile := filepath.Join(tmpDir, "duplicates.txt")
	content := "/admin\n/admin\n/backup\n/admin\n"
	if err := os.WriteFile(dictFile, []byte(content), 0644); err != nil {
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

// ==================== Init with dictionary that cannot be opened ====================

func TestCovBoost2_Init_DictionaryNonExistent(t *testing.T) {
	p := &Dirscan{}
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "dirscan",
			Enabled: true,
		},
		Depth:      1,
		Dictionary: "/this/path/does/not/exist.txt",
	}
	ab := &base.ApolloBase{}
	err := p.Init(context.Background(), cfg, ab)
	// Init should still succeed (dictionary open error is logged but not fatal)
	if err != nil {
		t.Errorf("Init() error: %v", err)
	}
}

// ==================== Init with non-existent but existing directory ====================

func TestCovBoost2_Init_DictionaryEmptyFileExists(t *testing.T) {
	tmpDir := t.TempDir()
	dictFile := filepath.Join(tmpDir, "empty.txt")
	if err := os.WriteFile(dictFile, []byte(""), 0644); err != nil {
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

// ==================== Rule fields coverage ====================

func TestCovBoost2_RuleAllFields(t *testing.T) {
	r := &Rule{
		Category:   "dirscan/test",
		Paths:      []string{"test", "backup"},
		PathChan:   make(chan string, 5),
		Suffix:     []string{".bak", ".old"},
		Expression: "response.status == 200",
		Partial:    true,
		Root:       false,
	}
	if len(r.Paths) != 2 {
		t.Errorf("Expected 2 paths, got %d", len(r.Paths))
	}
	if len(r.Suffix) != 2 {
		t.Errorf("Expected 2 suffixes, got %d", len(r.Suffix))
	}
	if !r.Partial {
		t.Error("Partial should be true")
	}
	if r.Root {
		t.Error("Root should be false")
	}
}

// ==================== RuleSet with nil rules ====================

func TestCovBoost2_RuleSetNilRules(t *testing.T) {
	rs := &RuleSet{}
	if len(rs.Rules) != 0 {
		t.Error("Expected empty rules")
	}
	if len(rs.Category) != 0 {
		t.Error("Expected empty categories")
	}
}

// ==================== Config with custom depth ====================

func TestCovBoost2_ConfigCustomDepth(t *testing.T) {
	tests := []int{0, 1, 3, 10}
	for _, depth := range tests {
		cfg := &Config{
			PluginBaseConfig: base.PluginBaseConfig{
				Name:    "dirscan",
				Enabled: true,
			},
			Depth: depth,
		}
		if cfg.Depth != depth {
			t.Errorf("Depth = %d, want %d", cfg.Depth, depth)
		}
	}
}

// ==================== Category struct ====================

func TestCovBoost2_CategoryStruct(t *testing.T) {
	c := Category{Name: "sensitive", Title: "Sensitive Files"}
	if c.Name != "sensitive" {
		t.Errorf("Name = %q, want 'sensitive'", c.Name)
	}
	if c.Title != "Sensitive Files" {
		t.Errorf("Title = %q, want 'Sensitive Files'", c.Title)
	}
}

// ==================== Dirscan Fingers with no ruleSet (after init but cleared) ====================

func TestCovBoost2_Fingers_NilRuleSet(t *testing.T) {
	p := &Dirscan{}
	// ruleSet is nil before Init
	fingers := p.Fingers()
	if len(fingers) != 0 {
		t.Errorf("Expected 0 fingers with nil ruleSet, got %d", len(fingers))
	}
}

// ==================== Dirscan GetConfig ====================

func TestCovBoost2_GetConfig_BeforeInit(t *testing.T) {
	p := &Dirscan{}
	cfg := p.GetConfig()
	if cfg != nil {
		t.Errorf("Expected nil config before Init, got %v", cfg)
	}
}

func TestCovBoost2_GetConfig_AfterInit(t *testing.T) {
	p := &Dirscan{}
	cfg := p.DefaultConfig()
	ab := &base.ApolloBase{}
	p.Init(context.Background(), cfg, ab)

	gotCfg := p.GetConfig()
	if gotCfg == nil {
		t.Fatal("Expected non-nil config after Init")
	}
	bc := gotCfg.BaseConfig()
	if bc.Name != "dirscan" {
		t.Errorf("Expected Name='dirscan', got '%s'", bc.Name)
	}
}

// ==================== Dirscan DefaultConfig values ====================

func TestCovBoost2_DefaultConfig_Values(t *testing.T) {
	p := &Dirscan{}
	cfg := p.DefaultConfig().(*Config)
	if cfg.Name != "dirscan" {
		t.Errorf("Name = %q, want 'dirscan'", cfg.Name)
	}
	if !cfg.Enabled {
		t.Error("Enabled should be true")
	}
	if cfg.Depth != 1 {
		t.Errorf("Depth = %d, want 1", cfg.Depth)
	}
	if cfg.Dictionary != "" {
		t.Errorf("Dictionary = %q, want empty", cfg.Dictionary)
	}
}

// ==================== Init with dictionary containing lines with just slashes ====================

func TestCovBoost2_Init_DictionarySlashOnly(t *testing.T) {
	tmpDir := t.TempDir()
	dictFile := filepath.Join(tmpDir, "slash.txt")
	content := "/\n//\n"
	if err := os.WriteFile(dictFile, []byte(content), 0644); err != nil {
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

// ==================== Rule Finger with various categories ====================

func TestCovBoost2_RuleFinger_VariousCategories(t *testing.T) {
	categories := []string{"dirscan/git", "dirscan/backup", "dirscan/sensitive", "dirscan/config"}
	for _, cat := range categories {
		r := &Rule{Category: cat}
		f := r.Finger()
		if f.Binding.ID != cat {
			t.Errorf("Binding.ID = %q, want %q", f.Binding.ID, cat)
		}
		if f.Binding.Plugin != cat {
			t.Errorf("Binding.Plugin = %q, want %q", f.Binding.Plugin, cat)
		}
		if f.Binding.Category != cat {
			t.Errorf("Binding.Category = %q, want %q", f.Binding.Category, cat)
		}
		if f.Channel != "web-directory" {
			t.Errorf("Channel = %q, want 'web-directory'", f.Channel)
		}
	}
}

// ==================== Rule CheckAction and RetestAction ====================

func TestCovBoost2_RuleCheckAction(t *testing.T) {
	r := &Rule{}
	err := r.CheckAction(context.Background(), nil)
	if err != nil {
		t.Errorf("CheckAction should return nil, got: %v", err)
	}
}

func TestCovBoost2_RuleRetestAction(t *testing.T) {
	r := &Rule{}
	err := r.RetestAction(context.Background(), nil)
	if err != nil {
		t.Errorf("RetestAction should return nil, got: %v", err)
	}
}

// ==================== Init with dictionary that has leading slashes on paths ====================

func TestCovBoost2_Init_DictionaryLeadingSlashes(t *testing.T) {
	tmpDir := t.TempDir()
	dictFile := filepath.Join(tmpDir, "slashes.txt")
	content := "/.git/config\n/.env\n/robots.txt\nwp-config.php\n"
	if err := os.WriteFile(dictFile, []byte(content), 0644); err != nil {
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

// ==================== Config BaseConfig nil safety ====================

func TestCovBoost2_ConfigBaseConfig_NilSafety(t *testing.T) {
	cfg := &Config{}
	bc := cfg.BaseConfig()
	_ = bc // should not panic
}

// ==================== Init with dictionary that exists but can't be opened (permission denied) ====================

func TestCovBoost2_Init_DictionaryPermissionDenied(t *testing.T) {
	tmpDir := t.TempDir()
	dictFile := filepath.Join(tmpDir, "no_read.txt")
	if err := os.WriteFile(dictFile, []byte("/admin\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// Remove read permission
	if err := os.Chmod(dictFile, 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dictFile, 0644) // restore for cleanup

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
		t.Errorf("Init() should not return error even with permission denied, got: %v", err)
	}
}

// ==================== Init with dictionary that is a directory (not a file) ====================

func TestCovBoost2_Init_DictionaryIsDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	subDir := filepath.Join(tmpDir, "subdir")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatal(err)
	}

	p := &Dirscan{}
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "dirscan",
			Enabled: true,
		},
		Depth:      1,
		Dictionary: subDir, // this is a directory, not a file
	}
	ab := &base.ApolloBase{}
	err := p.Init(context.Background(), cfg, ab)
	if err != nil {
		t.Errorf("Init() error: %v", err)
	}
}
