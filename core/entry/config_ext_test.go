package entry

import (
	"os"
	"path/filepath"
	"testing"

	"wscan/core/ctrl"
)

func TestNewExampleConfig(t *testing.T) {
	cfg := NewExampleConfig()
	if cfg == nil {
		t.Fatal("NewExampleConfig returned nil")
	}
	if cfg.Version != "1.11" {
		t.Errorf("expected Version '1.11', got %q", cfg.Version)
	}
	if cfg.Parallel != 30 {
		t.Errorf("expected Parallel=30, got %d", cfg.Parallel)
	}
}

func TestNewExampleConfig_HasDefaultHTTP(t *testing.T) {
	cfg := NewExampleConfig()
	if cfg.HTTP == nil {
		t.Fatal("HTTP config should not be nil")
	}
	if !cfg.HTTP.TLSSkipVerify {
		t.Error("TLSSkipVerify should be true by default")
	}
	if cfg.HTTP.MaxConnsPerHost != 50 {
		t.Errorf("expected MaxConnsPerHost=50, got %d", cfg.HTTP.MaxConnsPerHost)
	}
}

func TestNewExampleConfig_HasDefaultCrawler(t *testing.T) {
	cfg := NewExampleConfig()
	if cfg.Crawler.Restriction == nil {
		t.Error("Crawler Restriction should not be nil")
	}
	if len(cfg.Crawler.Restriction.HostnameDisallowed) == 0 {
		t.Error("Crawler should have default HostnameDisallowed entries")
	}
}

func TestNewExampleConfig_HasDefaultMitm(t *testing.T) {
	cfg := NewExampleConfig()
	if cfg.Mitm.CACert != "./ca.crt" {
		t.Errorf("expected Mitm CACert './ca.crt', got %q", cfg.Mitm.CACert)
	}
	if cfg.Mitm.CAKey != "./ca.key" {
		t.Errorf("expected Mitm CAKey './ca.key', got %q", cfg.Mitm.CAKey)
	}
}

func TestNewExampleConfig_HasDefaultReverse(t *testing.T) {
	cfg := NewExampleConfig()
	if cfg.Reverse == nil {
		t.Fatal("Reverse config should not be nil")
	}
}

func TestNewExampleConfig_PluginsInitialized(t *testing.T) {
	cfg := NewExampleConfig()
	if cfg.Plugins == nil {
		t.Fatal("Plugins should not be nil")
	}
	// Plugins should have been populated from the default ctrl config
}

func TestCliEntryConfig_Dump(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := NewExampleConfig()

	dumpPath := filepath.Join(tmpDir, "config.yaml")
	err := cfg.Dump(dumpPath)
	if err != nil {
		t.Fatalf("Dump returned error: %v", err)
	}

	data, err := os.ReadFile(dumpPath)
	if err != nil {
		t.Fatalf("failed to read dumped config: %v", err)
	}
	if len(data) == 0 {
		t.Error("dumped config file is empty")
	}
}

func TestCliEntryConfig_Dump_InvalidPath(t *testing.T) {
	cfg := NewExampleConfig()
	// Writing to a non-existent directory should fail
	err := cfg.Dump("/nonexistent_dir/deep/nested/config.yaml")
	if err == nil {
		t.Error("expected error when dumping to invalid path")
	}
}

func TestCliEntryConfig_EmbedsCtrlConfig(t *testing.T) {
	cfg := NewExampleConfig()
	// The embedded ctrl.Config should have the same default values
	defaultCtrlCfg := ctrl.NewDefaultConfig()
	if cfg.Version != defaultCtrlCfg.Version {
		t.Errorf("Version mismatch: %q vs %q", cfg.Version, defaultCtrlCfg.Version)
	}
	if cfg.Parallel != defaultCtrlCfg.Parallel {
		t.Errorf("Parallel mismatch: %d vs %d", cfg.Parallel, defaultCtrlCfg.Parallel)
	}
}

func TestNewExampleConfig_BrowserConfigDefaults(t *testing.T) {
	cfg := NewExampleConfig()
	if cfg.Crawler.BrowserConfig.MaxDepth != 10 {
		t.Errorf("expected BrowserConfig.MaxDepth=10, got %d", cfg.Crawler.BrowserConfig.MaxDepth)
	}
	if cfg.Crawler.BrowserConfig.MaxPageVisit != 500 {
		t.Errorf("expected BrowserConfig.MaxPageVisit=500, got %d", cfg.Crawler.BrowserConfig.MaxPageVisit)
	}
	if cfg.Crawler.BrowserConfig.MaxPageVisitPerSite != 200 {
		t.Errorf("expected BrowserConfig.MaxPageVisitPerSite=200, got %d", cfg.Crawler.BrowserConfig.MaxPageVisitPerSite)
	}
	if cfg.Crawler.BrowserConfig.MaxPageConcurrent != 10 {
		t.Errorf("expected BrowserConfig.MaxPageConcurrent=10, got %d", cfg.Crawler.BrowserConfig.MaxPageConcurrent)
	}
	if cfg.Crawler.BrowserConfig.NavigateTimeoutSecond != 10 {
		t.Errorf("expected BrowserConfig.NavigateTimeoutSecond=10, got %d", cfg.Crawler.BrowserConfig.NavigateTimeoutSecond)
	}
	if cfg.Crawler.BrowserConfig.LoadTimeoutSecond != 10 {
		t.Errorf("expected BrowserConfig.LoadTimeoutSecond=10, got %d", cfg.Crawler.BrowserConfig.LoadTimeoutSecond)
	}
	if cfg.Crawler.BrowserConfig.PageAnalyzeTimeoutSecond != 10 {
		t.Errorf("expected BrowserConfig.PageAnalyzeTimeoutSecond=10, got %d", cfg.Crawler.BrowserConfig.PageAnalyzeTimeoutSecond)
	}
	if cfg.Crawler.BrowserConfig.DisableHeadless != false {
		t.Error("expected BrowserConfig.DisableHeadless=false")
	}
}

func TestNewExampleConfig_MitmConfigDefaults(t *testing.T) {
	cfg := NewExampleConfig()
	if cfg.Mitm.Queue.MaxLength != 3000 {
		t.Errorf("expected Mitm.Queue.MaxLength=3000, got %d", cfg.Mitm.Queue.MaxLength)
	}
	if cfg.Mitm.Restriction == nil {
		t.Error("expected Mitm Restriction to be set")
	}
}

func TestNewExampleConfig_PluginsFromCtrlConfig(t *testing.T) {
	cfg := NewExampleConfig()
	defaultCtrlCfg := ctrl.NewDefaultConfig()
	// Plugins map should have the same keys as the ctrl config
	if len(cfg.Plugins) != len(defaultCtrlCfg.Plugins) {
		t.Errorf("expected %d plugins, got %d", len(defaultCtrlCfg.Plugins), len(cfg.Plugins))
	}
	for name := range defaultCtrlCfg.Plugins {
		if _, ok := cfg.Plugins[name]; !ok {
			t.Errorf("plugin %q missing from CliEntryConfig.Plugins", name)
		}
	}
}

func TestCliEntryConfig_Dump_Overwrite(t *testing.T) {
	tmpDir := t.TempDir()
	dumpPath := filepath.Join(tmpDir, "config.yaml")

	cfg := NewExampleConfig()
	err := cfg.Dump(dumpPath)
	if err != nil {
		t.Fatalf("first Dump failed: %v", err)
	}

	// Dump again should overwrite
	err = cfg.Dump(dumpPath)
	if err != nil {
		t.Fatalf("second Dump failed: %v", err)
	}
}

func TestCliEntryConfig_Dump_YAMLContent(t *testing.T) {
	tmpDir := t.TempDir()
	dumpPath := filepath.Join(tmpDir, "config.yaml")

	cfg := NewExampleConfig()
	err := cfg.Dump(dumpPath)
	if err != nil {
		t.Fatalf("Dump failed: %v", err)
	}

	data, err := os.ReadFile(dumpPath)
	if err != nil {
		t.Fatalf("failed to read dumped config: %v", err)
	}

	content := string(data)
	// Verify some key YAML fields are present
	if !containsStr(content, "version:") {
		t.Error("expected 'version:' in YAML output")
	}
	if !containsStr(content, "parallel:") {
		t.Error("expected 'parallel:' in YAML output")
	}
	if !containsStr(content, "http:") {
		t.Error("expected 'http:' in YAML output")
	}
	if !containsStr(content, "crawler:") {
		t.Error("expected 'crawler:' in YAML output")
	}
}

func TestNewExampleConfig_HTTPDefaultHeaders(t *testing.T) {
	cfg := NewExampleConfig()
	if cfg.HTTP.DefaultHeaders == nil {
		t.Fatal("expected DefaultHeaders to be set")
	}
	ua, ok := cfg.HTTP.DefaultHeaders["User-Agent"]
	if !ok {
		t.Error("expected User-Agent in DefaultHeaders")
	}
	if ua == "" {
		t.Error("expected non-empty User-Agent")
	}
}

func TestNewExampleConfig_VulnFilter(t *testing.T) {
	cfg := NewExampleConfig()
	if cfg.VulnFilter == nil {
		t.Fatal("expected VulnFilter to be set")
	}
	if cfg.VulnFilter.MinSeverity != "info" {
		t.Errorf("expected MinSeverity='info', got %q", cfg.VulnFilter.MinSeverity)
	}
}
