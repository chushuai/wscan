package log

import (
	"bytes"
	"os"
	"os/exec"
	"testing"

	"github.com/kataras/golog"
)

func TestNewDefaultConfig(t *testing.T) {
	cfg := NewDefaultConfig()
	if cfg.Level != "info" {
		t.Errorf("NewDefaultConfig Level = %q, expected 'info'", cfg.Level)
	}
}

func TestConfig_Clone(t *testing.T) {
	cfg := &Config{Level: "debug"}
	cloned := cfg.Clone()
	if cloned != nil {
		t.Error("Clone currently returns nil")
	}
}

func TestSetConfig_ValidLevel(t *testing.T) {
	// Test valid levels don't panic
	levels := []string{"debug", "info", "warn", "error"}
	for _, level := range levels {
		cfg := &Config{Level: level}
		SetConfig(cfg)
	}
}

func TestSetConfig_InvalidLevel(t *testing.T) {
	// SetConfig with invalid level calls Fatal, which will os.Exit.
	// Test via subprocess to verify it exits.
	if os.Getenv("TEST_FATAL") == "1" {
		SetConfig(&Config{Level: "invalid_level"})
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestSetConfig_InvalidLevel")
	cmd.Env = append(os.Environ(), "TEST_FATAL=1")
	err := cmd.Run()
	if e, ok := err.(*exec.ExitError); ok && !e.Success() {
		// Expected: process exited with non-zero status
		return
	}
	t.Error("SetConfig with invalid level should have caused Fatal/exit")
}

func TestFatal(t *testing.T) {
	// Fatal calls os.Exit(1) - test via subprocess
	if os.Getenv("TEST_FATAL") == "1" {
		Fatal("fatal message")
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestFatal")
	cmd.Env = append(os.Environ(), "TEST_FATAL=1")
	err := cmd.Run()
	if e, ok := err.(*exec.ExitError); ok && !e.Success() {
		return
	}
	t.Error("Fatal should have caused process exit")
}

func TestFatalf(t *testing.T) {
	// Fatalf calls os.Exit(1) - test via subprocess
	if os.Getenv("TEST_FATAL") == "1" {
		Fatalf("fatalf %s", "message")
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestFatalf")
	cmd.Env = append(os.Environ(), "TEST_FATAL=1")
	err := cmd.Run()
	if e, ok := err.(*exec.ExitError); ok && !e.Success() {
		return
	}
	t.Error("Fatalf should have caused process exit")
}

func TestDebug(t *testing.T) {
	Debug("debug message")
}

func TestInfo(t *testing.T) {
	Info("info message")
}

func TestWarning(t *testing.T) {
	Warning("warning message")
}

func TestWarn(t *testing.T) {
	Warn("warn message")
}

func TestError(t *testing.T) {
	Error("error message")
}

func TestPrintln(t *testing.T) {
	Println("println message")
}

func TestPrint(t *testing.T) {
	Print("print message")
}

func TestPrintf(t *testing.T) {
	Printf("printf %s", "message")
}

func TestInfof(t *testing.T) {
	Infof("infof %s", "message")
}

func TestDebugf(t *testing.T) {
	Debugf("debugf %s", "message")
}

func TestWarningf(t *testing.T) {
	Warningf("warningf %s", "message")
}

func TestWarnf(t *testing.T) {
	Warnf("warnf %s", "message")
}

func TestErrorf(t *testing.T) {
	Errorf("errorf %s", "message")
}

func TestGetLogger(t *testing.T) {
	logger := GetLogger("test")
	if logger == nil {
		t.Fatal("GetLogger returned nil")
	}
	if logger.name != "test" {
		t.Errorf("GetLogger name = %q, expected 'test'", logger.name)
	}
}

func TestGetLogger_Output(t *testing.T) {
	logger := GetLogger("test_output")
	// Set level to debug to ensure output
	logger.SetLevel("debug")
	logger.Debug("test debug output")
	logger.Info("test info output")
}

func TestDefaultLogger(t *testing.T) {
	// Verify defaultLogger was initialized
	if defaultLogger == nil {
		t.Fatal("defaultLogger should be initialized by init()")
	}
}

func TestLogger_SetLevel(t *testing.T) {
	logger := golog.New()
	logger.SetLevel("debug")
	logger.Debug("should be visible at debug level")
	logger.SetLevel("error")
	logger.Debug("should not be visible at error level")
}

func TestFileConfig(t *testing.T) {
	fc := FileConfig{
		Dir:        "/tmp/logs",
		MaxSize:    100,
		MaxBackUps: 5,
		MaxAge:     30,
		Compress:   true,
	}
	if fc.Dir != "/tmp/logs" {
		t.Errorf("Dir = %q, expected '/tmp/logs'", fc.Dir)
	}
	if fc.MaxSize != 100 {
		t.Errorf("MaxSize = %d, expected 100", fc.MaxSize)
	}
	if !fc.Compress {
		t.Error("Compress should be true")
	}
}

func TestLogMultipleArgs(t *testing.T) {
	// Test with multiple arguments
	Info("message", "arg1", "arg2")
	Debug("debug", 1, 2)
	Warning("warning", "arg")
	Warn("warn", "arg")
	Error("error", "arg")
	Println("println", "arg1", "arg2")
	Print("print", "arg1", "arg2")
}

func TestLogFormatted(t *testing.T) {
	Infof("infof %d %s", 42, "test")
	Debugf("debugf %d %s", 42, "test")
	Warningf("warningf %d %s", 42, "test")
	Warnf("warnf %d %s", 42, "test")
	Errorf("errorf %d %s", 42, "test")
	Printf("printf %d %s", 42, "test")
}

func TestLogToBuffer(t *testing.T) {
	var buf bytes.Buffer
	logger := golog.New()
	logger.SetOutput(&buf)
	logger.SetLevel("info")
	logger.Info("test buffer output")
	if buf.Len() == 0 {
		t.Error("expected output in buffer")
	}
}
