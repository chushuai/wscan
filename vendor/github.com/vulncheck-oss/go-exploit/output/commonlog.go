// Package output handles structured logging for the framework and exploits.
//
// Our goals for logging in go-exploit were something like this:
//
//   - Structured logging for easy parsing (text and JSON).
//   - The option to log to the CLI or directly to a file.
//   - Program output to stdout, and errors to stderr
//   - Different log level controls for the framework and the exploits implementation.
//
// To achieve all of the above, we split the implementation into two logging APIs:
// exploitlog.go and frameworklog.go. Exploit should use exploitlog.go API such as
// output.PrintFrameworkSuccess(), output.PrintFrameworkError(), etc. Framework should use frameworklog.go
// API such as output.PrintFrameworkSuccess(), output.PrintFrameworkError(), etc.
package output

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
)

// The exploit framework can use multiple threads so logging should acquire this lock.
var logMutex sync.Mutex

// The standard output logging descriptor (can be replaced by a file descriptor).
var stdOutputDesc io.Writer = os.Stdout

// The standard error logging descriptor (can be replaced by a file descriptor).
var stdErrDesc io.Writer = os.Stderr

// FormatJSON indicates if we should use TextHandler or NJSONHandler for logging.
var FormatJSON = false

// If logging to a file, function will create/append the file and assign the
// file as output for all log types.
func SetOutputFile(file string) bool {
	logFile, err := os.OpenFile(file, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		PrintError(err.Error())

		return false
	}

	stdOutputDesc = logFile
	stdErrDesc = logFile

	return true
}

const (
	// Extreme debugging that shows executions.
	LevelTrace = slog.Level(-8)
	// Useful tidbits for debugging potential problems.
	LevelDebug = slog.LevelDebug
	// A hihg-level status updat.
	LevelStatus = slog.LevelInfo
	// A non-critical issue that is bubbled up to the user.
	LevelWarning = slog.LevelWarn
	// A special message for outputing software versions.
	LevelVersion = slog.Level(5)
	// An important status message.
	LevelSuccess = slog.Level(6)
	// An important error message.
	LevelError = slog.LevelError
)

// LogLevels is a mapping of the log names to slog level.
var LogLevels = map[string]slog.Level{
	"TRACE":   LevelTrace,
	"DEBUG":   LevelDebug,
	"STATUS":  LevelStatus,
	"WARNING": LevelWarning,
	"VERSION": LevelVersion,
	"SUCCESS": LevelSuccess,
	"ERROR":   LevelError,
}

func customLogLevels(_ []string, a slog.Attr) slog.Attr {
	if a.Key == slog.LevelKey {
		switch a.Value.Any().(slog.Level) {
		case LevelTrace:
			a.Value = slog.StringValue("TRACE")
		case LevelDebug:
			a.Value = slog.StringValue("DEBUG")
		case LevelStatus:
			a.Value = slog.StringValue("STATUS")
		case LevelWarning:
			a.Value = slog.StringValue("WARNING")
		case LevelVersion:
			a.Value = slog.StringValue("VERSION")
		case LevelSuccess:
			a.Value = slog.StringValue("SUCCESS")
		case LevelError:
			a.Value = slog.StringValue("ERROR")
		}
	}

	return a
}

// This is a bit icky. We wanted to be able to use slog but also send error messages
// to stderr and program messages to stdout. This.
func resetLogger(descriptor io.Writer, minLevel slog.Level) *slog.Logger {
	if FormatJSON {
		return slog.New(slog.NewJSONHandler(descriptor, &slog.HandlerOptions{
			Level:       minLevel,
			ReplaceAttr: customLogLevels,
		}))
	}

	return slog.New(slog.NewTextHandler(descriptor, &slog.HandlerOptions{
		Level:       minLevel,
		ReplaceAttr: customLogLevels,
	}))
}

// Displaying content on our fake shell. Need to hold the log mutex for
// writing to stdout. In theory we could log here too if wanted?
func PrintShell(msg string) {
	logMutex.Lock()
	defer logMutex.Unlock()

	fmt.Print(msg)
	os.Stdout.Sync()
}
