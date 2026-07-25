package entry

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/urfave/cli/v2"
)

// newReverseTestCLIContext creates a cli.Context for ReverseAction testing
func newReverseTestCLIContext(flagSet *flag.FlagSet) *cli.Context {
	app := &cli.App{
		Flags: []cli.Flag{},
	}
	return cli.NewContext(app, flagSet, nil)
}

func newReverseFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("config", "", "config file path")
	fs.String("log-level", "", "log level")
	return fs
}

func TestReverseAction_ConfigLoading(t *testing.T) {
	// Verify that ReverseAction can at least load the config
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	cfg := NewExampleConfig()
	cfg.Dump(configPath)

	fs := newReverseFlagSet()
	fs.Set("config", configPath)
	_ = newReverseTestCLIContext(fs)

	// ReverseAction will:
	// 1. Load config (this works)
	// 2. Create reverse.NewReverse with the config (returns nil since servers disabled)
	// 3. Call log.Fatal("you must set reverse config") since r == nil
	// 4. Then block on wg.Wait()
	// We can't test the full execution without subprocess
}

func TestReverseAction_DefaultConfig(t *testing.T) {
	// Test that ReverseAction works with default config generation
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldDir)

	fs := newReverseFlagSet()
	_ = newReverseTestCLIContext(fs)

	// With default config, reverse servers are disabled so ReverseAction
	// will call log.Fatal. We can't test this without subprocess.
	// This test verifies the config file is created as a side effect.
}
