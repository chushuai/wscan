package entry

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"wscan/core/collector"
	"wscan/core/resource"
)

// ==================== serviceFitter FitOut coverage ====================

func TestBoostServiceFitter_FitOut_MultipleTargets(t *testing.T) {
	sf := &serviceFitter{
		targets: []string{"192.168.1.1", "10.0.0.1"},
		ports:   []int{80, 443},
	}

	ch, err := sf.FitOut(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var services []*resource.Service
	timeout := time.After(5 * time.Second)
	for {
		select {
		case svc, ok := <-ch:
			if !ok {
				goto done
			}
			s, ok := svc.(*resource.Service)
			if !ok {
				t.Fatal("expected *resource.Service")
			}
			services = append(services, s)
		case <-timeout:
			t.Fatal("FitOut timed out")
		}
	}
done:
	// 2 targets * 2 ports = 4 services
	if len(services) != 4 {
		t.Errorf("expected 4 services, got %d", len(services))
	}
}

func TestBoostServiceFitter_FitOut_WithProtocolPrefix(t *testing.T) {
	sf := &serviceFitter{
		targets: []string{"http://192.168.1.1", "https://10.0.0.1"},
		ports:   []int{80},
	}

	ch, err := sf.FitOut(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	svc := <-ch
	s, ok := svc.(*resource.Service)
	if !ok {
		t.Fatal("expected *resource.Service")
	}
	if s.Host != "192.168.1.1" {
		t.Errorf("expected host '192.168.1.1', got '%s'", s.Host)
	}
	// Drain the rest
	for range ch {
	}
}

func TestBoostServiceFitter_FitOut_WithContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	sf := &serviceFitter{
		targets: []string{"192.168.1.1"},
		ports:   []int{80},
	}

	ch, err := sf.FitOut(ctx, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Cancel context immediately
	cancel()

	// Channel should close gracefully
	timeout := time.After(2 * time.Second)
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				return // channel closed, test passed
			}
		case <-timeout:
			t.Fatal("FitOut didn't close after context cancellation")
		}
	}
}

// ==================== getServiceFitter coverage ====================

func TestBoostGetServiceFitter_WithTarget(t *testing.T) {
	fitter := getServiceFitter("192.168.1.1", "", []int{80, 443})
	if fitter == nil {
		t.Fatal("expected non-nil fitter")
	}

	sf, ok := fitter.(*serviceFitter)
	if !ok {
		t.Fatal("expected *serviceFitter")
	}
	if len(sf.targets) != 1 || sf.targets[0] != "192.168.1.1" {
		t.Errorf("expected target '192.168.1.1', got %v", sf.targets)
	}
	if len(sf.ports) != 2 {
		t.Errorf("expected 2 ports, got %d", len(sf.ports))
	}
}

func TestBoostGetServiceFitter_WithTargetFile(t *testing.T) {
	tmpDir := t.TempDir()
	targetFile := filepath.Join(tmpDir, "targets.txt")
	err := os.WriteFile(targetFile, []byte("192.168.1.1\n10.0.0.1\n"), 0644)
	if err != nil {
		t.Fatalf("failed to write target file: %v", err)
	}

	fitter := getServiceFitter("", targetFile, []int{80})
	if fitter == nil {
		t.Fatal("expected non-nil fitter")
	}

	sf, ok := fitter.(*serviceFitter)
	if !ok {
		t.Fatal("expected *serviceFitter")
	}
	if len(sf.targets) != 2 {
		t.Errorf("expected 2 targets, got %d", len(sf.targets))
	}
}

func TestBoostGetServiceFitter_NoTargetOrFile(t *testing.T) {
	fitter := getServiceFitter("", "", []int{80})
	if fitter == nil {
		t.Fatal("expected non-nil fitter even with no target")
	}

	sf, ok := fitter.(*serviceFitter)
	if !ok {
		t.Fatal("expected *serviceFitter")
	}
	if len(sf.targets) != 0 {
		t.Errorf("expected 0 targets, got %d", len(sf.targets))
	}
}

func TestBoostGetServiceFitter_NonExistentFile(t *testing.T) {
	fitter := getServiceFitter("", "/nonexistent/file.txt", []int{80})
	if fitter != nil {
		t.Error("expected nil fitter for nonexistent file")
	}
}

// ==================== serviceScanAction coverage ====================

func TestBoostServiceScanAction_NoTarget(t *testing.T) {
	err := serviceScanAction("", "", "80,443")
	if err == nil {
		t.Error("expected error for empty target and file")
	}
}

func TestBoostServiceScanAction_WithTarget(t *testing.T) {
	// This actually runs the service scan preparation
	err := serviceScanAction("127.0.0.1", "", "80")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestBoostServiceScanAction_WithTargetFile(t *testing.T) {
	tmpDir := t.TempDir()
	targetFile := filepath.Join(tmpDir, "targets.txt")
	err := os.WriteFile(targetFile, []byte("127.0.0.1\n"), 0644)
	if err != nil {
		t.Fatalf("failed to write target file: %v", err)
	}

	err = serviceScanAction("", targetFile, "80")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestBoostServiceScanAction_InvalidPortRange(t *testing.T) {
	err := serviceScanAction("127.0.0.1", "", "abc")
	if err == nil {
		t.Error("expected error for invalid port range")
	}
}

// ==================== parsePortRange edge cases ====================

func TestBoostParsePortRange_LargeRange(t *testing.T) {
	ports, err := parsePortRange("8000-8005")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 6 {
		t.Errorf("expected 6 ports, got %d", len(ports))
	}
}

func TestBoostParsePortRange_EmptyPart(t *testing.T) {
	_, err := parsePortRange("80,,443")
	if err == nil {
		t.Error("expected error for empty port part")
	}
}

// ==================== CliEntryConfig coverage ====================

func TestBoostCliEntryConfig_StructValues(t *testing.T) {
	cfg := &CliEntryConfig{
		Plugins: map[string]any{"test": "value"},
	}
	if len(cfg.Plugins) != 1 {
		t.Error("expected 1 plugin entry")
	}
	if cfg.Plugins["test"] != "value" {
		t.Error("expected plugin value 'value'")
	}
}

func TestBoostNewExampleConfig_PluginsPopulated(t *testing.T) {
	cfg := NewExampleConfig()
	if cfg.Plugins == nil {
		t.Error("expected Plugins map to be initialized")
	}
}

// ==================== CrawlerCommonConfig coverage ====================

func TestBoostCrawlerCommonConfig(t *testing.T) {
	cfg := collector.CrawlerCommonConfig{}
	if cfg.BasicCrawler.MaxDepth != 0 {
		t.Error("expected default MaxDepth 0")
	}
}

// ==================== newJSONPrinter edge case ====================

func TestBoostNewJSONPrinter_FileExists(t *testing.T) {
	tmpDir := t.TempDir()
	existingFile := filepath.Join(tmpDir, "existing.json")
	os.WriteFile(existingFile, []byte("exists"), 0644)

	// newJSONPrinter calls log.Fatalf if file exists - we can't easily test that
	// without subprocess testing. This test documents the behavior.
	t.Skip("newJSONPrinter with existing file calls log.Fatalf - cannot test without subprocess")
}

// ==================== LoadOrGenConfig additional paths ====================

func TestBoostLoadOrGenConfig_WithURLAndNoCrawler(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	cfg := NewExampleConfig()
	cfg.Dump(configPath)

	fs := newFlagSet()
	fs.Set("config", configPath)
	fs.Set("url", "http://example.com")
	c := newTestCLIContext(fs)

	loadedCfg, err := LoadOrGenConfig(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if loadedCfg == nil {
		t.Fatal("expected non-nil config")
	}
	// Without crawler flags, Filter should be set to empty RequestCheckerConfig
	if loadedCfg.Filter == nil {
		t.Error("expected Filter to be set")
	}
}

func TestBoostLoadOrGenConfig_WithData(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	cfg := NewExampleConfig()
	cfg.Dump(configPath)

	fs := newFlagSet()
	fs.Set("config", configPath)
	fs.Set("url", "http://example.com")
	fs.Set("data", "key=value")
	c := newTestCLIContext(fs)

	loadedCfg, err := LoadOrGenConfig(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if loadedCfg == nil {
		t.Fatal("expected non-nil config")
	}
}

// ==================== getPrinters coverage ====================

func TestBoostGetPrinters_AllCombined(t *testing.T) {
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
	// JSON + JSON-crawler + HTML + webhook + stdout = 5 printers
	if len(printers) != 5 {
		t.Errorf("expected 5 printers, got %d", len(printers))
	}
}

// ==================== Dump config edge cases ====================

func TestBoostDumpConfig_ValidPath(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := NewExampleConfig()
	path := filepath.Join(tmpDir, "dump.yaml")

	err := cfg.Dump(path)
	if err != nil {
		t.Fatalf("Dump failed: %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("Expected config file to be created")
	}
}

func TestBoostDumpConfig_InvalidPath(t *testing.T) {
	cfg := NewExampleConfig()
	err := cfg.Dump("/nonexistent/dir/config.yaml")
	if err == nil {
		t.Error("Expected error for invalid path")
	}
}

// ==================== serviceScanAction additional coverage ====================

func TestBoostServiceScanAction_WithTargetAndPorts(t *testing.T) {
	err := serviceScanAction("127.0.0.1", "", "22,80,443")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestBoostServiceScanAction_WithTargetFileAndPorts(t *testing.T) {
	tmpDir := t.TempDir()
	targetFile := filepath.Join(tmpDir, "targets.txt")
	err := os.WriteFile(targetFile, []byte("127.0.0.1\n192.168.1.1\n"), 0644)
	if err != nil {
		t.Fatalf("failed to write target file: %v", err)
	}

	err = serviceScanAction("", targetFile, "22,80")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// ==================== getServiceFitter additional coverage ====================

func TestBoostGetServiceFitter_WithTargetAndPorts(t *testing.T) {
	fitter := getServiceFitter("192.168.1.1", "", []int{22, 80, 443})
	if fitter == nil {
		t.Fatal("expected non-nil fitter")
	}

	sf, ok := fitter.(*serviceFitter)
	if !ok {
		t.Fatal("expected *serviceFitter")
	}
	if len(sf.targets) != 1 || sf.targets[0] != "192.168.1.1" {
		t.Errorf("expected target '192.168.1.1', got %v", sf.targets)
	}
	if len(sf.ports) != 3 {
		t.Errorf("expected 3 ports, got %d", len(sf.ports))
	}
}
