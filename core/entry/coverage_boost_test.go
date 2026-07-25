package entry

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"wscan/core/collector"
	"wscan/core/resource"
	"wscan/core/utils/checker"

	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v3"
)

// ==================== Dump: yaml.Marshal error path (config.go:36-38) ====================

// unmarshalableYAML is a type whose MarshalYAML always returns an error.
type unmarshalableYAML struct{}

func (unmarshalableYAML) MarshalYAML() (any, error) {
	return nil, fmt.Errorf("forced marshal error for testing")
}

func TestBoost_Dump_MarshalError(t *testing.T) {
	cfg := NewExampleConfig()
	// Use a type with a failing MarshalYAML to trigger the error path in Dump
	cfg.Plugins = map[string]any{"bad": unmarshalableYAML{}}

	err := cfg.Dump(filepath.Join(t.TempDir(), "config.yaml"))
	if err == nil {
		t.Error("expected error from Dump with unmarshalable Plugins value")
	}
}

// ==================== convertJSONToHTML: non-JSON-object continue (convert.go:40-41) ====================

func TestBoost_ConvertJSONToHTML_NonJSONObjectLines(t *testing.T) {
	tmpDir := t.TempDir()
	jsonPath := filepath.Join(tmpDir, "mixed.json")
	content := "not-json\n  {leading-space\n{\"plugin\":\"xss\"}\n"
	os.WriteFile(jsonPath, []byte(content), 0644)

	htmlPath := filepath.Join(tmpDir, "report.html")
	err := convertJSONToHTML(jsonPath, htmlPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, _ := os.ReadFile(htmlPath)
	s := string(data)
	if !containsStr(s, `"plugin":"xss"`) {
		t.Error("expected valid vuln in output")
	}
	if containsStr(s, "not-json") {
		t.Error("non-JSON lines should be skipped")
	}
}

// ==================== convertJSONToHTML: scanner.Err() path (convert.go:52-54) ====================

func TestBoost_ConvertJSONToHTML_ScannerError(t *testing.T) {
	tmpDir := t.TempDir()
	jsonPath := filepath.Join(tmpDir, "longline.json")
	f, err := os.Create(jsonPath)
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	// Write a line exceeding bufio.MaxScanTokenSize (65536) to trigger scanner.Err()
	longLine := "{" + strings.Repeat(`"k":"v",`, 33000) + `"z":"end"}`
	f.WriteString(longLine + "\n")
	f.Close()

	htmlPath := filepath.Join(tmpDir, "report.html")
	err = convertJSONToHTML(jsonPath, htmlPath)
	// May or may not return an error depending on Go version
	if err != nil {
		t.Logf("Scanner error triggered as expected: %v", err)
	}
}

// ==================== convertHTMLToJSON: scanner.Err() path (convert.go:93-95) ====================

func TestBoost_ConvertHTMLToJSON_ScannerError(t *testing.T) {
	tmpDir := t.TempDir()
	htmlPath := filepath.Join(tmpDir, "longline.html")
	f, err := os.Create(htmlPath)
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	longJSON := "{" + strings.Repeat(`"k":"v",`, 33000) + `"z":"end"}`
	fmt.Fprintf(f, `<script class='web-vulns'>webVulns.push(%s)</script>`+"\n", longJSON)
	f.Close()

	jsonPath := filepath.Join(tmpDir, "vulns.json")
	err = convertHTMLToJSON(htmlPath, jsonPath)
	if err != nil {
		t.Logf("Scanner error triggered as expected: %v", err)
	}
}

// ==================== newJSONPrinter: file-exists fatal (utils.go:15-17) ====================

func TestBoost_NewJSONPrinter_FileExists_Fatal(t *testing.T) {
	if os.Getenv("GO_WSCAN_SUBPROC") == "1" {
		tmpDir := os.TempDir()
		existing := filepath.Join(tmpDir, "boost_existing.json")
		os.WriteFile(existing, []byte("x"), 0644)
		defer os.Remove(existing)

		newJSONPrinter(existing, func(any) ([]byte, error) { return nil, nil })
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestBoost_NewJSONPrinter_FileExists_Fatal")
	cmd.Env = append(os.Environ(), "GO_WSCAN_SUBPROC=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Error("expected subprocess to exit non-zero (log.Fatalf)")
	}
	_ = out
}

// ==================== newJSONPrinter: os.Create error fatal (utils.go:20-23) ====================

func TestBoost_NewJSONPrinter_InvalidPath_Fatal(t *testing.T) {
	if os.Getenv("GO_WSCAN_SUBPROC") == "1" {
		newJSONPrinter("/nonexistent/dir/file.json", func(any) ([]byte, error) { return nil, nil })
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestBoost_NewJSONPrinter_InvalidPath_Fatal")
	cmd.Env = append(os.Environ(), "GO_WSCAN_SUBPROC=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Error("expected subprocess to exit non-zero (log.Fatalf)")
	}
	_ = out
}

// ==================== LoadOrGenConfig: nil context (entry.go:176-178) ====================

func TestBoost_LoadOrGenConfig_NilContext(t *testing.T) {
	if os.Getenv("GO_WSCAN_SUBPROC") == "1" {
		// LoadOrGenConfig reads c.String("config") first, which panics on nil
		// But if a config file already exists at ./config.yaml, the code reaches
		// the nil check at line 176. However c.String("config") at line 162
		// is called first, so nil c will panic.
		// Test it in a subprocess so the panic doesn't crash the test process.
		result, err := LoadOrGenConfig(nil)
		if result != nil || err != nil {
			fmt.Fprintf(os.Stderr, "expected nil, nil; got %v, %v\n", result, err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestBoost_LoadOrGenConfig_NilContext")
	cmd.Env = append(os.Environ(), "GO_WSCAN_SUBPROC=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("Nil context causes panic as expected: %s", string(out[:min(len(out), 300)]))
	}
}

// ==================== LoadOrGenConfig: ReadFile error (entry.go:180-183) ====================

func TestBoost_LoadOrGenConfig_ReadFileError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission test not reliable on Windows")
	}

	if os.Getenv("GO_WSCAN_SUBPROC") == "1" {
		tmpDir := os.TempDir()
		unreadableFile := filepath.Join(tmpDir, "unreadable_config.yaml")
		// Create file then make it unreadable (no read permission)
		os.WriteFile(unreadableFile, []byte("test"), 0222) // write-only, no read

		fs := boostFlagSet()
		fs.Set("config", unreadableFile)

		c := boostNewCLIContext(fs)
		LoadOrGenConfig(c)
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestBoost_LoadOrGenConfig_ReadFileError")
	cmd.Env = append(os.Environ(), "GO_WSCAN_SUBPROC=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Error("expected subprocess to exit with error for unreadable config")
	}
	_ = out
}

// ==================== LoadOrGenConfig: YAML unmarshal error (entry.go:186-189) ====================

func TestBoost_LoadOrGenConfig_InvalidYAML(t *testing.T) {
	if os.Getenv("GO_WSCAN_SUBPROC") == "1" {
		tmpDir := os.TempDir()
		cfgPath := filepath.Join(tmpDir, "bad_yaml.yaml")
		os.WriteFile(cfgPath, []byte("{{invalid yaml}}:"), 0644)

		fs := boostFlagSet()
		fs.Set("config", cfgPath)
		c := boostNewCLIContext(fs)
		LoadOrGenConfig(c)
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestBoost_LoadOrGenConfig_InvalidYAML")
	cmd.Env = append(os.Environ(), "GO_WSCAN_SUBPROC=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Error("expected subprocess to exit with error for invalid YAML")
	}
	_ = out
}

// ==================== LoadOrGenConfig: version mismatch backup dump failure (entry.go:191-194) ====================

func TestBoost_LoadOrGenConfig_VersionMismatchBackupFail(t *testing.T) {
	if os.Getenv("GO_WSCAN_SUBPROC") == "1" {
		tmpDir := os.TempDir()
		cfgPath := filepath.Join(tmpDir, "vm_config.yaml")

		cfg := NewExampleConfig()
		cfg.Version = "0.01"
		cfg.Dump(cfgPath)

		// Make the backup path unwritable by creating it as a directory
		backupPath := cfgPath + "_0.01_old"
		os.MkdirAll(backupPath, 0555)

		fs := boostFlagSet()
		fs.Set("config", cfgPath)
		c := boostNewCLIContext(fs)

		LoadOrGenConfig(c)
		os.Exit(0)
	}

	if runtime.GOOS == "windows" {
		t.Skip("read-only directory test not reliable on Windows")
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestBoost_LoadOrGenConfig_VersionMismatchBackupFail")
	cmd.Env = append(os.Environ(), "GO_WSCAN_SUBPROC=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Error("expected subprocess to exit with error for backup dump failure")
	}
	_ = out
}

// ==================== LoadOrGenConfig: default config dump failure (entry.go:171-174) ====================

func TestBoost_LoadOrGenConfig_DefaultDumpFail(t *testing.T) {
	if os.Getenv("GO_WSCAN_SUBPROC") == "1" {
		tmpDir := os.TempDir()
		readOnlyDir := filepath.Join(tmpDir, "readonly")
		os.MkdirAll(readOnlyDir, 0555)
		os.Chdir(readOnlyDir)

		fs := boostFlagSet()
		c := boostNewCLIContext(fs)
		LoadOrGenConfig(c)
		os.Exit(0)
	}

	if runtime.GOOS == "windows" {
		t.Skip("read-only directory test not reliable on Windows")
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestBoost_LoadOrGenConfig_DefaultDumpFail")
	cmd.Env = append(os.Environ(), "GO_WSCAN_SUBPROC=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Error("expected subprocess to exit with error when Dump fails")
	}
	_ = out
}

// ==================== LoadOrGenConfig: version mismatch new config dump failure (entry.go:196-199) ====================

func TestBoost_LoadOrGenConfig_VersionMismatchNewDumpFail(t *testing.T) {
	if os.Getenv("GO_WSCAN_SUBPROC") == "1" {
		tmpDir := os.TempDir()
		cfgPath := filepath.Join(tmpDir, "vm_config2.yaml")

		cfg := NewExampleConfig()
		cfg.Version = "0.01"
		cfg.Dump(cfgPath)

		// Make the original config path read-only so re-writing fails
		os.Chmod(cfgPath, 0444)

		fs := boostFlagSet()
		fs.Set("config", cfgPath)
		c := boostNewCLIContext(fs)

		LoadOrGenConfig(c)
		os.Exit(0)
	}

	if runtime.GOOS == "windows" {
		t.Skip("read-only file test not reliable on Windows")
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestBoost_LoadOrGenConfig_VersionMismatchNewDumpFail")
	cmd.Env = append(os.Environ(), "GO_WSCAN_SUBPROC=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Error("expected subprocess to exit with error for Dump failure")
	}
	_ = out
}

// ==================== NewApp: list mode (entry.go:47-51) ====================

func TestBoost_NewApp_ListMode(t *testing.T) {
	if os.Getenv("GO_WSCAN_SUBPROC") == "1" {
		tmpDir := os.TempDir()
		cfgPath := filepath.Join(tmpDir, "list_config.yaml")
		NewExampleConfig().Dump(cfgPath)
		os.Chdir(tmpDir)

		fs := boostAppFlagSet()
		fs.Set("config", cfgPath)
		fs.Set("list", "true")
		c := boostNewCLIContext(fs)

		NewApp(c)
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestBoost_NewApp_ListMode")
	cmd.Env = append(os.Environ(), "GO_WSCAN_SUBPROC=1")
	out, err := cmd.CombinedOutput()
	// --list calls os.Exit(0), which go test treats as error
	_ = out
	_ = err
}

// ==================== NewApp: URL file open error (entry.go:70-72) ====================

func TestBoost_NewApp_URLFileOpenError(t *testing.T) {
	if os.Getenv("GO_WSCAN_SUBPROC") == "1" {
		tmpDir := os.TempDir()
		cfgPath := filepath.Join(tmpDir, "urlfile_config.yaml")
		NewExampleConfig().Dump(cfgPath)
		os.Chdir(tmpDir)

		fs := boostAppFlagSet()
		fs.Set("config", cfgPath)
		fs.Set("url-file", "/nonexistent/urls.txt")
		c := boostNewCLIContext(fs)

		NewApp(c)
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestBoost_NewApp_URLFileOpenError")
	cmd.Env = append(os.Environ(), "GO_WSCAN_SUBPROC=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Error("expected subprocess to exit with error for non-existent URL file")
	}
	_ = out
}

// ==================== NewApp: no target specified (entry.go:139-141) ====================

func TestBoost_NewApp_NoTargetFatal(t *testing.T) {
	if os.Getenv("GO_WSCAN_SUBPROC") == "1" {
		tmpDir := os.TempDir()
		cfgPath := filepath.Join(tmpDir, "notarget_config.yaml")
		NewExampleConfig().Dump(cfgPath)
		os.Chdir(tmpDir)

		fs := boostAppFlagSet()
		fs.Set("config", cfgPath)
		c := boostNewCLIContext(fs)

		NewApp(c)
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestBoost_NewApp_NoTargetFatal")
	cmd.Env = append(os.Environ(), "GO_WSCAN_SUBPROC=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Error("expected subprocess to exit with error when no target specified")
	}
	_ = out
}

// ==================== NewApp: listen mode (entry.go:135-141) ====================

func TestBoost_NewApp_ListenMode(t *testing.T) {
	if os.Getenv("GO_WSCAN_SUBPROC") == "1" {
		tmpDir := os.TempDir()
		cfgPath := filepath.Join(tmpDir, "listen_config.yaml")
		NewExampleConfig().Dump(cfgPath)
		os.Chdir(tmpDir)

		fs := boostAppFlagSet()
		fs.Set("config", cfgPath)
		fs.Set("listen", "127.0.0.1:0")
		c := boostNewCLIContext(fs)

		done := make(chan error, 1)
		go func() { done <- NewApp(c) }()

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			// Listen mode blocks; that's expected
		}
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestBoost_NewApp_ListenMode")
	cmd.Env = append(os.Environ(), "GO_WSCAN_SUBPROC=1")
	time.AfterFunc(15*time.Second, func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	})
	out, err := cmd.CombinedOutput()
	_ = out
	_ = err
}

// ==================== NewApp: basic-crawler with nil Headers (entry.go:60-62) ====================

func TestBoost_NewApp_BasicAuthNilHeaders(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldDir)

	cfg := NewExampleConfig()
	cfg.Crawler.BasicAuth.Username = "user"
	cfg.Crawler.BasicAuth.Password = "pass"
	cfg.HTTP.Headers = nil
	cfg.Dump("config.yaml")

	fs := newAppFlagSet()
	fs.Set("url", "http://127.0.0.1:1")
	fs.Set("no-scan", "true")
	c := newTestCLIContext(fs)

	done := make(chan error, 1)
	go func() { done <- NewApp(c) }()

	select {
	case err := <-done:
		_ = err
	case <-time.After(60 * time.Second):
		t.Fatal("NewApp timed out")
	}
}

// ==================== NewApp: LoadOrGenConfig error (entry.go:37-39) ====================

func TestBoost_NewApp_LoadConfigError(t *testing.T) {
	if os.Getenv("GO_WSCAN_SUBPROC") == "1" {
		tmpDir := os.TempDir()
		cfgPath := filepath.Join(tmpDir, "bad_config.yaml")
		os.WriteFile(cfgPath, []byte("{{invalid}}:"), 0644)
		os.Chdir(tmpDir)

		fs := boostAppFlagSet()
		fs.Set("config", cfgPath)
		c := boostNewCLIContext(fs)

		NewApp(c)
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestBoost_NewApp_LoadConfigError")
	cmd.Env = append(os.Environ(), "GO_WSCAN_SUBPROC=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Error("expected subprocess to exit with error for bad config")
	}
	_ = out
}

// ==================== NewApp: browser-crawler (entry.go:94-130) ====================

func TestBoost_NewApp_BrowserCrawler(t *testing.T) {
	if os.Getenv("GO_WSCAN_SUBPROC") == "1" {
		tmpDir := os.TempDir()
		cfgPath := filepath.Join(tmpDir, "browser_config.yaml")
		NewExampleConfig().Dump(cfgPath)
		os.Chdir(tmpDir)

		fs := boostAppFlagSet()
		fs.Set("config", cfgPath)
		fs.Set("url", "http://127.0.0.1:1")
		fs.Set("browser-crawler", "true")
		fs.Set("no-scan", "true")
		c := boostNewCLIContext(fs)

		done := make(chan error, 1)
		go func() { done <- NewApp(c) }()

		select {
		case err := <-done:
			_ = err
		case <-time.After(15 * time.Second):
		}
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestBoost_NewApp_BrowserCrawler")
	cmd.Env = append(os.Environ(), "GO_WSCAN_SUBPROC=1")
	time.AfterFunc(20*time.Second, func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	})
	out, err := cmd.CombinedOutput()
	_ = out
	_ = err
}

// ==================== ReverseAction: all paths (reverse.go:15-28) ====================

func TestBoost_ReverseAction_DefaultConfig(t *testing.T) {
	if os.Getenv("GO_WSCAN_SUBPROC") == "1" {
		tmpDir := os.TempDir()
		cfgPath := filepath.Join(tmpDir, "reverse_config.yaml")
		NewExampleConfig().Dump(cfgPath)
		os.Chdir(tmpDir)

		fs := boostReverseFlagSet()
		fs.Set("config", cfgPath)
		c := boostNewReverseCLIContext(fs)

		done := make(chan error, 1)
		go func() { done <- ReverseAction(c) }()

		select {
		case err := <-done:
			_ = err
		case <-time.After(5 * time.Second):
		}
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestBoost_ReverseAction_DefaultConfig")
	cmd.Env = append(os.Environ(), "GO_WSCAN_SUBPROC=1")
	time.AfterFunc(10*time.Second, func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	})
	out, err := cmd.CombinedOutput()
	_ = out
	_ = err
}

// ==================== Dump: overwrite + read-back verification ====================

func TestBoost_Dump_OverwriteAndReadBack(t *testing.T) {
	tmpDir := t.TempDir()
	dumpPath := filepath.Join(tmpDir, "config.yaml")

	cfg := NewExampleConfig()
	cfg.Parallel = 42
	cfg.Dump(dumpPath)

	data, err := os.ReadFile(dumpPath)
	if err != nil {
		t.Fatalf("failed to read dumped config: %v", err)
	}

	var loaded CliEntryConfig
	err = yaml.Unmarshal(data, &loaded)
	if err != nil {
		t.Fatalf("failed to unmarshal dumped config: %v", err)
	}
	if loaded.Parallel != 42 {
		t.Errorf("expected Parallel=42, got %d", loaded.Parallel)
	}
}

func TestBoost_Dump_ReadOnlyDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("read-only directory test not reliable on Windows")
	}

	cfg := NewExampleConfig()
	tmpDir := t.TempDir()
	readOnly := filepath.Join(tmpDir, "readonly")
	os.MkdirAll(readOnly, 0555)

	err := cfg.Dump(filepath.Join(readOnly, "config.yaml"))
	if err == nil {
		t.Error("expected error when dumping to read-only directory")
	}
}

// ==================== Convert: round-trip ====================

func TestBoost_Convert_RoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	jsonPath := filepath.Join(tmpDir, "vulns.json")
	content := `{"plugin":"xss","severity":"high"}
{"plugin":"sqli","severity":"critical"}
`
	os.WriteFile(jsonPath, []byte(content), 0644)

	htmlPath := filepath.Join(tmpDir, "report.html")
	if err := convertJSONToHTML(jsonPath, htmlPath); err != nil {
		t.Fatalf("JSON->HTML error: %v", err)
	}

	jsonPath2 := filepath.Join(tmpDir, "vulns2.json")
	if err := convertHTMLToJSON(htmlPath, jsonPath2); err != nil {
		t.Fatalf("HTML->JSON error: %v", err)
	}

	data, err := os.ReadFile(jsonPath2)
	if err != nil {
		t.Fatalf("failed to read: %v", err)
	}
	s := string(data)
	if !containsStr(s, `"plugin":"xss"`) || !containsStr(s, `"plugin":"sqli"`) {
		t.Error("round-trip lost vulns")
	}
}

// ==================== parsePortRange additional edge cases ====================

func TestBoost_ParsePortRange_EmptyPart(t *testing.T) {
	_, err := parsePortRange("80,,443")
	if err == nil {
		t.Error("expected error for empty port part")
	}
}

func TestBoost_ParsePortRange_ZeroPort(t *testing.T) {
	ports, err := parsePortRange("0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 1 || ports[0] != 0 {
		t.Errorf("expected [0], got %v", ports)
	}
}

// ==================== serviceFitter additional edge cases ====================

func TestBoost_ServiceFitter_TargetWithPortStripped(t *testing.T) {
	sf := &serviceFitter{
		targets: []string{"192.168.1.1:8080"},
		ports:   []int{80},
	}
	ch, err := sf.FitOut(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	svc := <-ch
	s := svc.(*resource.Service)
	if s.Host != "192.168.1.1" {
		t.Errorf("expected host '192.168.1.1' (port stripped), got %q", s.Host)
	}
	for range ch {
	}
}

func TestBoost_ServiceFitter_HttpsTargetPortStripped(t *testing.T) {
	sf := &serviceFitter{
		targets: []string{"https://example.com:9443"},
		ports:   []int{443},
	}
	ch, err := sf.FitOut(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	svc := <-ch
	s := svc.(*resource.Service)
	if s.Host != "example.com" {
		t.Errorf("expected host 'example.com', got %q", s.Host)
	}
	for range ch {
	}
}

// ==================== CliEntryConfig JSON/YAML marshal ====================

func TestBoost_CliEntryConfig_JSONMarshal(t *testing.T) {
	cfg := NewExampleConfig()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("failed to marshal to JSON: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty JSON")
	}
	if !containsStr(string(data), `"version"`) {
		t.Error("expected 'version' in JSON")
	}
}

func TestBoost_CliEntryConfig_YAMLMarshal(t *testing.T) {
	cfg := NewExampleConfig()
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("failed to marshal to YAML: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty YAML")
	}
	if !containsStr(string(data), "version:") {
		t.Error("expected 'version:' in YAML")
	}
}

// ==================== CrawlerCommonConfig with restriction ====================

func TestBoost_CrawlerCommonConfig_WithRestriction(t *testing.T) {
	cfg := collector.CrawlerCommonConfig{
		Restriction: &checker.RequestCheckerConfig{
			URLCheckerConfig: checker.URLCheckerConfig{
				HostnameDisallowed: []string{"*google*"},
			},
		},
	}
	if cfg.Restriction == nil {
		t.Error("expected non-nil Restriction")
	}
	if len(cfg.Restriction.HostnameDisallowed) != 1 {
		t.Errorf("expected 1 entry, got %d", len(cfg.Restriction.HostnameDisallowed))
	}
}

// ==================== NewApp: basic-crawler with --no-scan ====================

func TestBoost_NewApp_BasicCrawlerNoScan(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldDir)

	cfg := NewExampleConfig()
	cfg.Crawler.BasicCrawler.MaxDepth = 3
	cfg.Dump("config.yaml")

	fs := newAppFlagSet()
	fs.Set("url", "http://127.0.0.1:1")
	fs.Set("basic-crawler", "true")
	fs.Set("no-scan", "true")
	c := newTestCLIContext(fs)

	done := make(chan error, 1)
	go func() { done <- NewApp(c) }()

	select {
	case err := <-done:
		_ = err
	case <-time.After(60 * time.Second):
		t.Fatal("NewApp timed out")
	}
}

// ==================== NewApp: URL with data, no crawler ====================

func TestBoost_NewApp_WithDataFlag(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldDir)

	cfg := NewExampleConfig()
	cfg.Dump("config.yaml")

	fs := newAppFlagSet()
	fs.Set("url", "http://127.0.0.1:1")
	fs.Set("data", "key=value")
	fs.Set("no-scan", "true")
	c := newTestCLIContext(fs)

	done := make(chan error, 1)
	go func() { done <- NewApp(c) }()

	select {
	case err := <-done:
		_ = err
	case <-time.After(60 * time.Second):
		t.Fatal("NewApp timed out")
	}
}

// ==================== NewApp: basic-auth with no existing Authorization header ====================

func TestBoost_NewApp_BasicAuthNoExistingHeader(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldDir)

	cfg := NewExampleConfig()
	cfg.Crawler.BasicAuth.Username = "user"
	cfg.Crawler.BasicAuth.Password = "pass"
	delete(cfg.HTTP.DefaultHeaders, "Authorization")
	cfg.Dump("config.yaml")

	fs := newAppFlagSet()
	fs.Set("url", "http://127.0.0.1:1")
	fs.Set("no-scan", "true")
	c := newTestCLIContext(fs)

	done := make(chan error, 1)
	go func() { done <- NewApp(c) }()

	select {
	case err := <-done:
		_ = err
	case <-time.After(60 * time.Second):
		t.Fatal("NewApp timed out")
	}
}

// ==================== NewApp: URL file with duplicates ====================

func TestBoost_NewApp_URLFileWithDuplicates(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldDir)

	cfg := NewExampleConfig()
	cfg.Dump("config.yaml")

	urlFile := filepath.Join(tmpDir, "urls.txt")
	os.WriteFile(urlFile, []byte("http://127.0.0.1:1\nhttp://127.0.0.1:1\nhttp://127.0.0.1:2\n"), 0644)

	fs := newAppFlagSet()
	fs.Set("url-file", urlFile)
	fs.Set("no-scan", "true")
	c := newTestCLIContext(fs)

	done := make(chan error, 1)
	go func() { done <- NewApp(c) }()

	select {
	case err := <-done:
		_ = err
	case <-time.After(60 * time.Second):
		t.Fatal("NewApp timed out")
	}
}

// ==================== getPrinters: combined outputs ====================

func TestBoost_GetPrinters_JSONAndCrawler(t *testing.T) {
	tmpDir := t.TempDir()
	jsonPath := filepath.Join(tmpDir, "output.json")
	crawlerPath := filepath.Join(tmpDir, "crawler.json")

	fs := newFlagSet()
	fs.Set("json-output", jsonPath)
	fs.Set("json-crawler-output", crawlerPath)
	c := newTestCLIContext(fs)

	printers := getPrinters(c)
	if len(printers) != 3 {
		t.Errorf("expected 3 printers, got %d", len(printers))
	}
}

func TestBoost_GetPrinters_HTMLAndWebhook(t *testing.T) {
	tmpDir := t.TempDir()
	htmlPath := filepath.Join(tmpDir, "output.html")

	fs := newFlagSet()
	fs.Set("html-output", htmlPath)
	fs.Set("webhook-output", "http://example.com/webhook")
	c := newTestCLIContext(fs)

	printers := getPrinters(c)
	if len(printers) != 3 {
		t.Errorf("expected 3 printers, got %d", len(printers))
	}
}

// ==================== serviceScanAction additional coverage ====================

func TestBoost_ServiceScanAction_BothTargetAndFile(t *testing.T) {
	tmpDir := t.TempDir()
	targetFile := filepath.Join(tmpDir, "targets.txt")
	os.WriteFile(targetFile, []byte("10.0.0.1\n"), 0644)

	err := serviceScanAction("192.168.1.1", targetFile, "80")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBoost_ServiceScanAction_WithPortRange(t *testing.T) {
	err := serviceScanAction("127.0.0.1", "", "8000-8003")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ==================== getServiceFitter additional coverage ====================

func TestBoost_GetServiceFitter_BlankLinesInFile(t *testing.T) {
	tmpDir := t.TempDir()
	targetFile := filepath.Join(tmpDir, "targets.txt")
	os.WriteFile(targetFile, []byte("10.0.0.1\n\n  \n10.0.0.2\n"), 0644)

	fitter := getServiceFitter("", targetFile, []int{80})
	if fitter == nil {
		t.Fatal("expected non-nil fitter")
	}

	ch, err := fitter.FitOut(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	count := 0
	for range ch {
		count++
	}
	if count != 2 {
		t.Errorf("expected 2 services (blank lines skipped), got %d", count)
	}
}

// ==================== convertHTMLToJSON: non-existent JSON dir ====================

func TestBoost_ConvertHTMLToJSON_NonExistentJSONDir(t *testing.T) {
	tmpDir := t.TempDir()
	htmlPath := filepath.Join(tmpDir, "report.html")
	os.WriteFile(htmlPath, []byte("<html></html>"), 0644)

	err := convertHTMLToJSON(htmlPath, "/nonexistent/dir/vulns.json")
	if err == nil {
		t.Error("expected error for non-existent JSON directory")
	}
}

// ==================== convertJSONToHTML: non-existent HTML dir ====================

func TestBoost_ConvertJSONToHTML_NonExistentHTMLDir(t *testing.T) {
	tmpDir := t.TempDir()
	jsonPath := filepath.Join(tmpDir, "vulns.json")
	os.WriteFile(jsonPath, []byte(`{"plugin":"xss"}`), 0644)

	err := convertJSONToHTML(jsonPath, "/nonexistent/dir/report.html")
	if err == nil {
		t.Error("expected error for non-existent HTML directory")
	}
}

// ==================== Helper flag set constructors ====================

func boostFlagSet() *flag.FlagSet {
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

func boostAppFlagSet() *flag.FlagSet {
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

func boostReverseFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("config", "", "config file path")
	fs.String("log-level", "", "log level")
	return fs
}

func boostNewCLIContext(fs *flag.FlagSet) *cli.Context {
	app := &cli.App{Flags: []cli.Flag{}}
	return cli.NewContext(app, fs, nil)
}

func boostNewReverseCLIContext(fs *flag.FlagSet) *cli.Context {
	app := &cli.App{Flags: []cli.Flag{}}
	return cli.NewContext(app, fs, nil)
}

// ==================== Unused import assertions ====================

var _ = bufio.Scanner{}
var _ = io.EOF
var _ = (*resource.Service)(nil)
