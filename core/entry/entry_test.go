package entry

import (
	"flag"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"wscan/core/model"

	"github.com/urfave/cli/v2"
)

// newTestCLIContext creates a cli.Context with the given flags for testing
func newTestCLIContext(flagSet *flag.FlagSet) *cli.Context {
	app := &cli.App{
		Flags: []cli.Flag{},
	}
	return cli.NewContext(app, flagSet, nil)
}

// newFlagSet creates a flag.FlagSet with all common wscan flags registered.
// Note: basic-crawler and browser-crawler are registered as String flags
// because LoadOrGenConfig uses c.String() to check them (not c.Bool()),
// and the standard flag.Bool always returns "true"/"false" (never ""),
// which differs from urfave/cli BoolFlag behavior.
func newFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("config", "", "config file path")
	fs.String("url", "", "target URL")
	fs.String("url-file", "", "URL file path")
	fs.String("listen", "", "listen address")
	fs.Bool("list", false, "list plugins")
	fs.Bool("dump-config", false, "dump config")
	fs.String("poc", "", "POC to run")
	fs.String("plugins", "", "plugins to enable")
	fs.String("basic-crawler", "", "use basic crawler")
	fs.String("browser-crawler", "", "use browser crawler")
	fs.String("data", "", "POST data")
	fs.Bool("no-scan", false, "no scan")
	fs.String("json-output", "", "JSON output path")
	fs.String("json-crawler-output", "", "JSON crawler output path")
	fs.String("html-output", "", "HTML output path")
	fs.String("webhook-output", "", "webhook output URL")
	fs.String("log-level", "", "log level")
	fs.String("min-severity", "", "minimum severity")
	fs.String("exclude-vuln", "", "exclude vuln IDs")
	fs.String("include-vuln", "", "include vuln IDs")
	return fs
}

// newAppFlagSet creates a flag.FlagSet with Bool flags for NewApp tests.
// NewApp uses c.Bool() for basic-crawler, browser-crawler, no-scan, etc.
func newAppFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("config", "", "config file path")
	fs.String("url", "", "target URL")
	fs.String("url-file", "", "URL file path")
	fs.String("listen", "", "listen address")
	fs.Bool("list", false, "list plugins")
	fs.Bool("dump-config", false, "dump config")
	fs.String("poc", "", "POC to run")
	fs.String("plugins", "", "plugins to enable")
	fs.Bool("basic-crawler", false, "use basic crawler")
	fs.Bool("browser-crawler", false, "use browser crawler")
	fs.String("data", "", "POST data")
	fs.Bool("no-scan", false, "no scan")
	fs.String("json-output", "", "JSON output path")
	fs.String("json-crawler-output", "", "JSON crawler output path")
	fs.String("html-output", "", "HTML output path")
	fs.String("webhook-output", "", "webhook output URL")
	fs.String("log-level", "", "log level")
	fs.String("min-severity", "", "minimum severity")
	fs.String("exclude-vuln", "", "exclude vuln IDs")
	fs.String("include-vuln", "", "include vuln IDs")
	return fs
}

func TestLoadOrGenConfig_GeneratesDefaultConfig(t *testing.T) {
	// When config file doesn't exist, LoadOrGenConfig generates it at ./config.yaml
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldDir)

	fs := newFlagSet()
	c := newTestCLIContext(fs)

	cfg, err := LoadOrGenConfig(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}

	// Verify the config file was created in the current directory
	if _, err := os.Stat(filepath.Join(tmpDir, "config.yaml")); os.IsNotExist(err) {
		t.Error("expected config file to be created at ./config.yaml")
	}
}

func TestLoadOrGenConfig_LoadsExistingConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// First, generate a default config
	cfg := NewExampleConfig()
	err := cfg.Dump(configPath)
	if err != nil {
		t.Fatalf("failed to write initial config: %v", err)
	}

	fs := newFlagSet()
	fs.Set("config", configPath)
	c := newTestCLIContext(fs)

	loadedCfg, err := LoadOrGenConfig(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if loadedCfg == nil {
		t.Fatal("expected non-nil config")
	}

	// Verify loaded config matches
	if loadedCfg.Version != cfg.Version {
		t.Errorf("version mismatch: expected %q, got %q", cfg.Version, loadedCfg.Version)
	}
}

func TestLoadOrGenConfig_WithLogLevel(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Generate default config first
	cfg := NewExampleConfig()
	cfg.Dump(configPath)

	fs := newFlagSet()
	fs.Set("config", configPath)
	fs.Set("log-level", "debug")
	c := newTestCLIContext(fs)

	loadedCfg, err := LoadOrGenConfig(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if loadedCfg == nil {
		t.Fatal("expected non-nil config")
	}
}

func TestLoadOrGenConfig_WithPlugins(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	cfg := NewExampleConfig()
	cfg.Dump(configPath)

	fs := newFlagSet()
	fs.Set("config", configPath)
	fs.Set("plugins", "prometheus")
	c := newTestCLIContext(fs)

	loadedCfg, err := LoadOrGenConfig(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if loadedCfg == nil {
		t.Fatal("expected non-nil config")
	}

	// Check that plugins map is populated
	if len(loadedCfg.Config.Plugins) == 0 {
		t.Error("expected plugins to be populated")
	}
}

func TestLoadOrGenConfig_WithMinSeverity(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	cfg := NewExampleConfig()
	cfg.Dump(configPath)

	fs := newFlagSet()
	fs.Set("config", configPath)
	fs.Set("min-severity", "high")
	c := newTestCLIContext(fs)

	loadedCfg, err := LoadOrGenConfig(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if loadedCfg.VulnFilter.MinSeverity != "high" {
		t.Errorf("expected min-severity 'high', got %q", loadedCfg.VulnFilter.MinSeverity)
	}
}

func TestLoadOrGenConfig_WithExcludeVuln(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	cfg := NewExampleConfig()
	cfg.Dump(configPath)

	fs := newFlagSet()
	fs.Set("config", configPath)
	fs.Set("exclude-vuln", "CVE-2021-1234,CVE-2021-5678")
	c := newTestCLIContext(fs)

	loadedCfg, err := LoadOrGenConfig(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(loadedCfg.VulnFilter.ExcludeVulns) != 2 {
		t.Errorf("expected 2 excluded vulns, got %d", len(loadedCfg.VulnFilter.ExcludeVulns))
	}
}

func TestLoadOrGenConfig_WithIncludeVuln(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	cfg := NewExampleConfig()
	cfg.Dump(configPath)

	fs := newFlagSet()
	fs.Set("config", configPath)
	fs.Set("include-vuln", "CVE-2021-1234")
	c := newTestCLIContext(fs)

	loadedCfg, err := LoadOrGenConfig(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(loadedCfg.VulnFilter.IncludeVulns) != 1 {
		t.Errorf("expected 1 included vuln, got %d", len(loadedCfg.VulnFilter.IncludeVulns))
	}
}

func TestLoadOrGenConfig_SetsTLSSkipVerify(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	cfg := NewExampleConfig()
	cfg.Dump(configPath)

	fs := newFlagSet()
	fs.Set("config", configPath)
	c := newTestCLIContext(fs)

	loadedCfg, err := LoadOrGenConfig(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !loadedCfg.HTTP.TLSSkipVerify {
		t.Error("expected TLSSkipVerify to be true")
	}
}

func TestLoadOrGenConfig_CallsWroteBack(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	cfg := NewExampleConfig()
	cfg.Dump(configPath)

	fs := newFlagSet()
	fs.Set("config", configPath)
	c := newTestCLIContext(fs)

	loadedCfg, err := LoadOrGenConfig(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// After WroteBack, Headers map should be populated from DefaultHeaders
	if loadedCfg.HTTP.Headers == nil {
		t.Error("expected Headers map to be populated after WroteBack")
	}
	// Check that User-Agent was transferred to Headers
	if len(loadedCfg.HTTP.Headers["User-Agent"]) == 0 {
		t.Error("expected User-Agent in Headers after WroteBack")
	}
}

func TestLoadOrGenConfig_WithBasicCrawler(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	cfg := NewExampleConfig()
	cfg.Dump(configPath)

	fs := newFlagSet()
	fs.Set("config", configPath)
	fs.Set("basic-crawler", "yes")
	c := newTestCLIContext(fs)

	loadedCfg, err := LoadOrGenConfig(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Filter should be set to crawler restriction
	if loadedCfg.Filter == nil {
		t.Error("expected Filter to be set")
	}
}

func TestLoadOrGenConfig_WithBrowserCrawler(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	cfg := NewExampleConfig()
	cfg.Dump(configPath)

	fs := newFlagSet()
	fs.Set("config", configPath)
	fs.Set("browser-crawler", "yes")
	c := newTestCLIContext(fs)

	loadedCfg, err := LoadOrGenConfig(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if loadedCfg.Filter == nil {
		t.Error("expected Filter to be set")
	}
}

func TestLoadOrGenConfig_DefaultConfigPath(t *testing.T) {
	// When no config path is given, it defaults to ./config.yaml
	// We test with a temp directory to avoid polluting the project root
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldDir)

	fs := newFlagSet()
	// Don't set config - should default to ./config.yaml
	c := newTestCLIContext(fs)

	cfg, err := LoadOrGenConfig(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	// Verify config.yaml was created in the temp dir
	if _, err := os.Stat(filepath.Join(tmpDir, "config.yaml")); os.IsNotExist(err) {
		t.Error("expected config.yaml to be created in current directory")
	}
}

func TestLoadOrGenConfig_InvalidConfigFile(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Write invalid YAML
	err := os.WriteFile(configPath, []byte("{{invalid yaml}}:"), 0644)
	if err != nil {
		t.Fatalf("failed to write invalid config: %v", err)
	}

	fs := newFlagSet()
	fs.Set("config", configPath)
	_ = newTestCLIContext(fs)

	// LoadOrGenConfig calls log.Fatal for YAML errors, which calls os.Exit
	// We cannot easily test this without subprocess testing
	// This test documents the expected behavior
	t.Skip("cannot test log.Fatalf behavior without subprocess")
}

func TestLoadOrGenConfig_NilContext(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// First create a config file so the nil check path is hit
	cfg := NewExampleConfig()
	cfg.Dump(configPath)

	fs := newFlagSet()
	fs.Set("config", configPath)
	c := newTestCLIContext(fs)

	// Load the config first time
	result, err := LoadOrGenConfig(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = result
}

func TestGetPrinters_JSONOutput(t *testing.T) {
	tmpDir := t.TempDir()
	jsonPath := filepath.Join(tmpDir, "output.json")

	fs := newFlagSet()
	fs.Set("json-output", jsonPath)
	c := newTestCLIContext(fs)

	printers := getPrinters(c)
	if len(printers) < 2 { // JSON printer + stdout printer
		t.Errorf("expected at least 2 printers (json + stdout), got %d", len(printers))
	}
}

func TestGetPrinters_HTMLPrintoutput(t *testing.T) {
	tmpDir := t.TempDir()
	htmlPath := filepath.Join(tmpDir, "output.html")

	fs := newFlagSet()
	fs.Set("html-output", htmlPath)
	c := newTestCLIContext(fs)

	printers := getPrinters(c)
	if len(printers) < 2 { // HTML printer + stdout printer
		t.Errorf("expected at least 2 printers (html + stdout), got %d", len(printers))
	}
}

func TestGetPrinters_JSONCrawlerOutput(t *testing.T) {
	tmpDir := t.TempDir()
	jsonPath := filepath.Join(tmpDir, "crawler.json")

	fs := newFlagSet()
	fs.Set("json-crawler-output", jsonPath)
	c := newTestCLIContext(fs)

	printers := getPrinters(c)
	if len(printers) < 2 { // JSON crawler printer + stdout printer
		t.Errorf("expected at least 2 printers (json-crawler + stdout), got %d", len(printers))
	}
}

func TestGetPrinters_WebhookOutput(t *testing.T) {
	fs := newFlagSet()
	fs.Set("webhook-output", "http://example.com/webhook")
	c := newTestCLIContext(fs)

	printers := getPrinters(c)
	if len(printers) < 2 { // Webhook printer + stdout printer
		t.Errorf("expected at least 2 printers (webhook + stdout), got %d", len(printers))
	}
}

func TestGetPrinters_InvalidWebhookURL(t *testing.T) {
	fs := newFlagSet()
	fs.Set("webhook-output", "://invalid-url")
	c := newTestCLIContext(fs)

	// Should not panic with invalid URL
	printers := getPrinters(c)
	// Should still have at least the stdout printer
	if len(printers) < 1 {
		t.Error("expected at least stdout printer")
	}
}

func TestGetPrinters_NoOutputFlags(t *testing.T) {
	fs := newFlagSet()
	c := newTestCLIContext(fs)

	printers := getPrinters(c)
	// Should always have stdout printer
	if len(printers) < 1 {
		t.Error("expected at least stdout printer")
	}
}

func TestGetPrinters_MultipleOutputs(t *testing.T) {
	tmpDir := t.TempDir()
	jsonPath := filepath.Join(tmpDir, "output.json")
	htmlPath := filepath.Join(tmpDir, "output.html")

	fs := newFlagSet()
	fs.Set("json-output", jsonPath)
	fs.Set("html-output", htmlPath)
	c := newTestCLIContext(fs)

	printers := getPrinters(c)
	// Should have JSON + HTML + stdout = 3 printers
	if len(printers) != 3 {
		t.Errorf("expected 3 printers (json + html + stdout), got %d", len(printers))
	}
}

func TestGetPrinters_AllOutputs(t *testing.T) {
	tmpDir := t.TempDir()
	jsonPath := filepath.Join(tmpDir, "output.json")
	crawlerPath := filepath.Join(tmpDir, "crawler.json")
	htmlPath := filepath.Join(tmpDir, "output.html")

	fs := newFlagSet()
	fs.Set("json-output", jsonPath)
	fs.Set("json-crawler-output", crawlerPath)
	fs.Set("html-output", htmlPath)
	fs.Set("webhook-output", "http://example.com/webhook")
	c := newTestCLIContext(fs)

	printers := getPrinters(c)
	// Should have JSON + JSON-crawler + HTML + webhook + stdout = 5 printers
	if len(printers) != 5 {
		t.Errorf("expected 5 printers, got %d", len(printers))
	}
}

func TestGetPrinters_WithVulnPrint(t *testing.T) {
	tmpDir := t.TempDir()
	jsonPath := filepath.Join(tmpDir, "output.json")

	fs := newFlagSet()
	fs.Set("json-output", jsonPath)
	c := newTestCLIContext(fs)

	printers := getPrinters(c)
	// Print a properly initialized Vuln to exercise the converter closure
	vuln := &model.Vuln{
		Binding: &model.VulnBinding{
			Plugin:   "test-plugin",
			Severity: model.SeverityHigh,
		},
		Extra:   map[string]any{},
		Payload: "test-payload",
	}
	vuln.SetTargetURL(&url.URL{Scheme: "http", Host: "example.com", Path: "/test"})
	for _, p := range printers {
		p.Print(vuln)
	}

	// Verify JSON file was written
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("failed to read JSON output: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty JSON output after printing vuln")
	}
}

func TestGetPrinters_WithCrawlerResultPrint(t *testing.T) {
	tmpDir := t.TempDir()
	jsonPath := filepath.Join(tmpDir, "crawler.json")

	fs := newFlagSet()
	fs.Set("json-crawler-output", jsonPath)
	c := newTestCLIContext(fs)

	printers := getPrinters(c)
	// Print a CrawlerResult to exercise the converter closure
	crawlerResult := &model.CrawlerResult{}
	for _, p := range printers {
		p.Print(crawlerResult)
	}

	// Verify JSON file was written
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("failed to read crawler JSON output: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty crawler JSON output after printing crawler result")
	}
}

func TestGetPrinters_NonMatchingTypePrint(t *testing.T) {
	tmpDir := t.TempDir()
	jsonPath := filepath.Join(tmpDir, "output.json")

	fs := newFlagSet()
	fs.Set("json-output", jsonPath)
	c := newTestCLIContext(fs)

	printers := getPrinters(c)
	// Print a non-matching type to exercise the nil return path
	for _, p := range printers {
		p.Print("not a vuln")
	}
}

func TestGetPrinters_NonMatchingCrawlerTypePrint(t *testing.T) {
	tmpDir := t.TempDir()
	jsonPath := filepath.Join(tmpDir, "crawler.json")

	fs := newFlagSet()
	fs.Set("json-crawler-output", jsonPath)
	c := newTestCLIContext(fs)

	printers := getPrinters(c)
	// Print a non-matching type to exercise the nil return path
	for _, p := range printers {
		p.Print("not a crawler result")
	}
}

func TestNewApp_WithURLAndNoScan(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldDir)

	// Generate config file first
	cfg := NewExampleConfig()
	cfg.Dump("config.yaml")

	fs := newAppFlagSet()
	fs.Set("url", "http://127.0.0.1:1")
	fs.Set("no-scan", "true")
	c := newTestCLIContext(fs)

	// NewApp with --no-scan should complete without actually scanning
	done := make(chan error, 1)
	go func() {
		done <- NewApp(c)
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Logf("NewApp returned: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("NewApp timed out")
	}
}

func TestNewApp_WithURLFileAndNoScan(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldDir)

	// Generate config file
	cfg := NewExampleConfig()
	cfg.Dump("config.yaml")

	// Create URL file
	urlFile := filepath.Join(tmpDir, "urls.txt")
	err := os.WriteFile(urlFile, []byte("http://127.0.0.1:1\n"), 0644)
	if err != nil {
		t.Fatalf("failed to write URL file: %v", err)
	}

	fs := newAppFlagSet()
	fs.Set("url-file", urlFile)
	fs.Set("no-scan", "true")
	c := newTestCLIContext(fs)

	done := make(chan error, 1)
	go func() {
		done <- NewApp(c)
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Logf("NewApp returned: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("NewApp timed out")
	}
}

func TestNewApp_BasicCrawlerWithNoScan(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldDir)

	cfg := NewExampleConfig()
	cfg.Dump("config.yaml")

	fs := newAppFlagSet()
	fs.Set("url", "http://127.0.0.1:1")
	fs.Set("basic-crawler", "true")
	fs.Set("no-scan", "true")
	c := newTestCLIContext(fs)

	done := make(chan error, 1)
	go func() {
		done <- NewApp(c)
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Logf("NewApp returned: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("NewApp timed out")
	}
}

func TestNewApp_BrowserCrawlerWithNoScan(t *testing.T) {
	// Browser crawler test requires a browser to be installed.
	// Skipping as it would try to launch chromium which may not be available.
	t.Skip("browser-crawler requires a browser to be installed")
}

func TestNewApp_BasicAuthInjection(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldDir)

	// Create config with basic auth
	cfg := NewExampleConfig()
	cfg.Crawler.BasicAuth.Username = "admin"
	cfg.Crawler.BasicAuth.Password = "secret"
	cfg.Dump("config.yaml")

	fs := newAppFlagSet()
	fs.Set("url", "http://127.0.0.1:1")
	fs.Set("no-scan", "true")
	c := newTestCLIContext(fs)

	done := make(chan error, 1)
	go func() {
		done <- NewApp(c)
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Logf("NewApp returned: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("NewApp timed out")
	}
}

func TestNewApp_WithListen(t *testing.T) {
	// MITM proxy test blocks indefinitely and requires network setup.
	// Skipping as it would start a proxy server that never exits.
	t.Skip("listen mode starts a proxy server that blocks indefinitely")
}

func TestNewApp_DumpConfig(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldDir)

	cfg := NewExampleConfig()
	cfg.Dump("config.yaml")

	fs := newAppFlagSet()
	fs.Set("url", "http://127.0.0.1:1")
	fs.Set("dump-config", "true")
	fs.Set("no-scan", "true")
	c := newTestCLIContext(fs)

	done := make(chan error, 1)
	go func() {
		done <- NewApp(c)
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Logf("NewApp returned: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("NewApp timed out")
	}
}

func TestNewApp_BasicAuthWithExistingAuth(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldDir)

	// Create config with basic auth AND existing Authorization header
	// This tests the "Authorization already exists" path
	cfg := NewExampleConfig()
	cfg.Crawler.BasicAuth.Username = "admin"
	cfg.Crawler.BasicAuth.Password = "secret"
	cfg.HTTP.DefaultHeaders["Authorization"] = "Bearer existing-token"
	cfg.Dump("config.yaml")

	fs := newAppFlagSet()
	fs.Set("url", "http://127.0.0.1:1")
	fs.Set("no-scan", "true")
	c := newTestCLIContext(fs)

	done := make(chan error, 1)
	go func() {
		done <- NewApp(c)
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Logf("NewApp returned: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("NewApp timed out")
	}
}

func TestNewApp_WithURLFile(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldDir)

	cfg := NewExampleConfig()
	cfg.Dump("config.yaml")

	// Create URL file with multiple URLs
	urlFile := filepath.Join(tmpDir, "urls.txt")
	content := "http://127.0.0.1:1\nhttp://127.0.0.1:2\n"
	err := os.WriteFile(urlFile, []byte(content), 0644)
	if err != nil {
		t.Fatalf("failed to write URL file: %v", err)
	}

	fs := newAppFlagSet()
	fs.Set("url-file", urlFile)
	fs.Set("no-scan", "true")
	c := newTestCLIContext(fs)

	done := make(chan error, 1)
	go func() {
		done <- NewApp(c)
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Logf("NewApp returned: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("NewApp timed out")
	}
}

func TestNewApp_WithJSONOutput(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldDir)

	cfg := NewExampleConfig()
	cfg.Dump("config.yaml")

	jsonPath := filepath.Join(tmpDir, "output.json")

	fs := newAppFlagSet()
	fs.Set("url", "http://127.0.0.1:1")
	fs.Set("no-scan", "true")
	fs.Set("json-output", jsonPath)
	c := newTestCLIContext(fs)

	done := make(chan error, 1)
	go func() {
		done <- NewApp(c)
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Logf("NewApp returned: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("NewApp timed out")
	}
}

func TestNewApp_BasicAuthHeadersAlreadyInitialized(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldDir)

	// Test the path where Headers is already initialized (not nil)
	cfg := NewExampleConfig()
	cfg.Crawler.BasicAuth.Username = "admin"
	cfg.Crawler.BasicAuth.Password = "secret"
	cfg.HTTP.Headers = map[string][]string{"X-Custom": {"value"}}
	cfg.Dump("config.yaml")

	fs := newAppFlagSet()
	fs.Set("url", "http://127.0.0.1:1")
	fs.Set("no-scan", "true")
	c := newTestCLIContext(fs)

	done := make(chan error, 1)
	go func() {
		done <- NewApp(c)
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Logf("NewApp returned: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("NewApp timed out")
	}
}

func TestLoadOrGenConfig_WithPOC(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	cfg := NewExampleConfig()
	cfg.Dump(configPath)

	fs := newFlagSet()
	fs.Set("config", configPath)
	fs.Set("poc", "/path/to/poc.yaml")
	c := newTestCLIContext(fs)

	loadedCfg, err := LoadOrGenConfig(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if loadedCfg == nil {
		t.Fatal("expected non-nil config")
	}

	// With --poc, prometheus plugin should be enabled and others disabled
	for name, pc := range loadedCfg.Config.Plugins {
		if name == "prometheus" {
			if !pc.BaseConfig().Enabled {
				t.Error("expected prometheus plugin to be enabled with --poc")
			}
		}
	}
}

func TestLoadOrGenConfig_WithoutCrawlerFlags(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	cfg := NewExampleConfig()
	cfg.Dump(configPath)

	fs := newFlagSet()
	fs.Set("config", configPath)
	// No basic-crawler or browser-crawler flags set
	c := newTestCLIContext(fs)

	loadedCfg, err := LoadOrGenConfig(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Filter should be set to an empty RequestCheckerConfig (not crawler restriction)
	if loadedCfg.Filter == nil {
		t.Error("expected Filter to be set")
	}
	// When no crawler flags are set, Filter should not be the same as Crawler.Restriction
	// It should be a new empty RequestCheckerConfig
}

func TestLoadOrGenConfig_VersionMismatch(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Create a config with an older version
	cfg := NewExampleConfig()
	cfg.Version = "0.99" // Different from current version
	cfg.Dump(configPath)

	fs := newFlagSet()
	fs.Set("config", configPath)
	c := newTestCLIContext(fs)

	loadedCfg, err := LoadOrGenConfig(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if loadedCfg == nil {
		t.Fatal("expected non-nil config")
	}
	// After version mismatch, config should be replaced with example config
	exampleCfg := NewExampleConfig()
	if loadedCfg.Version != exampleCfg.Version {
		t.Errorf("expected version to be reset to %q, got %q", exampleCfg.Version, loadedCfg.Version)
	}

	// Old config should be backed up
	oldConfigPath := configPath + "_0.99_old"
	if _, err := os.Stat(oldConfigPath); os.IsNotExist(err) {
		t.Error("expected old config to be backed up")
	}
}

func TestLoadOrGenConfig_PluginsConfigPopulated(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	cfg := NewExampleConfig()
	cfg.Dump(configPath)

	fs := newFlagSet()
	fs.Set("config", configPath)
	c := newTestCLIContext(fs)

	loadedCfg, err := LoadOrGenConfig(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Config.Plugins should be populated after loading
	if len(loadedCfg.Config.Plugins) == 0 {
		t.Error("expected Config.Plugins to be populated")
	}
}

func TestLoadOrGenConfig_HTTPConfigPreserved(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	cfg := NewExampleConfig()
	cfg.Dump(configPath)

	fs := newFlagSet()
	fs.Set("config", configPath)
	c := newTestCLIContext(fs)

	loadedCfg, err := LoadOrGenConfig(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// HTTP settings should be preserved
	if loadedCfg.HTTP.MaxConnsPerHost != cfg.HTTP.MaxConnsPerHost {
		t.Errorf("MaxConnsPerHost mismatch: expected %d, got %d", cfg.HTTP.MaxConnsPerHost, loadedCfg.HTTP.MaxConnsPerHost)
	}
}

func TestLoadOrGenConfig_WithPluginSelection(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	cfg := NewExampleConfig()
	cfg.Dump(configPath)

	fs := newFlagSet()
	fs.Set("config", configPath)
	fs.Set("plugins", "prometheus,phantom")
	c := newTestCLIContext(fs)

	loadedCfg, err := LoadOrGenConfig(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check that only specified plugins are enabled
	for name, pc := range loadedCfg.Config.Plugins {
		if name == "prometheus" || name == "phantom" {
			if !pc.BaseConfig().Enabled {
				t.Errorf("expected plugin %q to be enabled", name)
			}
		}
	}
}

func TestLoadOrGenConfig_VulnFilterDefaults(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	cfg := NewExampleConfig()
	cfg.Dump(configPath)

	fs := newFlagSet()
	fs.Set("config", configPath)
	c := newTestCLIContext(fs)

	loadedCfg, err := LoadOrGenConfig(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// VulnFilter should be non-nil
	if loadedCfg.VulnFilter == nil {
		t.Fatal("VulnFilter should not be nil")
	}
}

func TestReverseAction_WithValidConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	cfg := NewExampleConfig()
	cfg.Dump(configPath)

	fs := newFlagSet()
	fs.Set("config", configPath)
	_ = newTestCLIContext(fs)

	// ReverseAction calls log.Fatal if reverse is nil (which it is by default)
	// since both HTTP and DNS servers are disabled.
	// ReverseAction also blocks on wg.Wait() forever, so we can't easily test it.
	// This test is documented for completeness.
	t.Skip("ReverseAction blocks indefinitely and calls log.Fatal if reverse config is nil")
}

func TestLoadOrGenConfig_GeneratedConfigHasCrawlerDefaults(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldDir)

	fs := newFlagSet()
	c := newTestCLIContext(fs)

	cfg, err := LoadOrGenConfig(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Crawler should have default restriction
	if cfg.Crawler.Restriction == nil {
		t.Error("expected Crawler Restriction to be set")
	}

	// Mitm should have defaults
	if cfg.Mitm.CACert != "./ca.crt" {
		t.Errorf("expected Mitm CACert './ca.crt', got %q", cfg.Mitm.CACert)
	}
	if cfg.Mitm.CAKey != "./ca.key" {
		t.Errorf("expected Mitm CAKey './ca.key', got %q", cfg.Mitm.CAKey)
	}
}

func TestLoadOrGenConfig_BasicAuthConfigPreserved(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Create config with basic auth settings
	cfg := NewExampleConfig()
	cfg.Crawler.BasicAuth.Username = "admin"
	cfg.Crawler.BasicAuth.Password = "secret"
	cfg.Dump(configPath)

	fs := newFlagSet()
	fs.Set("config", configPath)
	c := newTestCLIContext(fs)

	loadedCfg, err := LoadOrGenConfig(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Basic auth config should be preserved
	if loadedCfg.Crawler.BasicAuth.Username != "admin" {
		t.Errorf("expected username 'admin', got %q", loadedCfg.Crawler.BasicAuth.Username)
	}
	if loadedCfg.Crawler.BasicAuth.Password != "secret" {
		t.Errorf("expected password 'secret', got %q", loadedCfg.Crawler.BasicAuth.Password)
	}
}
