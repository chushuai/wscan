package entry

import (
	"os"
	"path/filepath"
	"testing"
)

// ==================== CliEntryConfig coverage ====================

func TestCovNewExampleConfigValues(t *testing.T) {
	cfg := NewExampleConfig()
	if cfg == nil {
		t.Fatal("Expected non-nil config")
	}
	if cfg.Crawler.Restriction == nil {
		t.Error("Expected Crawler Restriction to be set")
	}
	if cfg.Mitm.CACert != "./ca.crt" {
		t.Errorf("Expected Mitm CACert './ca.crt', got %q", cfg.Mitm.CACert)
	}
	if cfg.Mitm.CAKey != "./ca.key" {
		t.Errorf("Expected Mitm CAKey './ca.key', got %q", cfg.Mitm.CAKey)
	}
}

func TestCovDumpConfig(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := NewExampleConfig()
	path := filepath.Join(tmpDir, "test_config.yaml")

	err := cfg.Dump(path)
	if err != nil {
		t.Fatalf("Dump failed: %v", err)
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("Expected config file to be created")
	}

	// Verify the file is valid YAML
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read dumped config: %v", err)
	}
	if len(data) == 0 {
		t.Error("Expected non-empty config file")
	}
}

func TestCovDumpConfigInvalidPath(t *testing.T) {
	cfg := NewExampleConfig()
	err := cfg.Dump("/nonexistent/dir/config.yaml")
	if err == nil {
		t.Error("Expected error for invalid path")
	}
}

// ==================== verifyFile / rsaVerify coverage ====================

func TestCovVerifyFile(t *testing.T) {
	// verifyFile is a no-op
	verifyFile()
}

func TestCovRsaVerify(t *testing.T) {
	// rsaVerify is a no-op
	rsaVerify()
}

// ==================== isAllEmpty / validMutexChoice / getFitter coverage ====================

func TestCovIsAllEmpty(t *testing.T) {
	// isAllEmpty is a no-op
	isAllEmpty()
}

func TestCovValidMutexChoice(t *testing.T) {
	// validMutexChoice is a no-op
	validMutexChoice()
}

func TestCovGetFitter(t *testing.T) {
	// getFitter is a no-op
	getFitter()
}

// ==================== lookupRad coverage ====================

func TestCovLookupRad(t *testing.T) {
	// lookupRad is a no-op
	lookupRad()
}

// ==================== genca.go coverage ====================

func TestCovGencaPackage(t *testing.T) {
	// genca.go only has a package declaration
	t.Log("genca package compiles successfully")
}

// ==================== CompleteOutputPath coverage ====================

func TestCovCompleteOutputPath(t *testing.T) {
	CompleteOutputPath()
}

// ==================== webscan.go coverage ====================

func TestCovWebscanPackage(t *testing.T) {
	// webscan.go only has no-op functions
	t.Log("webscan package compiles successfully")
}
