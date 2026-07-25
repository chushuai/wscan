package output

import (
	"context"
	"fmt"
	"io"
	"log/slog"
)

// The log level for the framework.
var frameworkLevel = LevelStatus

// Sets the log level for framework logging. Anything below the provided value will not get logged.
func SetFrameworkLogLevel(level slog.Level) {
	frameworkLevel = level
}

// reset logger to the appropriate level / output location and write the log.
func doFrameworkLog(descriptor io.Writer, level slog.Level, msg string, keys ...any) {
	logMutex.Lock()
	defer logMutex.Unlock()

	if level >= frameworkLevel {
		logger := resetLogger(descriptor, frameworkLevel)

		ctx := context.Background()
		logger.Log(ctx, level, msg, keys...)
	}
}

// PrintfFrameworkTrace formats according to a format specifier and logs as TRACE
// If the framework is not logging to file, this will go to standard error.
func PrintfFrameworkTrace(format string, msg ...interface{}) {
	PrintFrameworkTrace(fmt.Sprintf(format, msg...))
}

// PrintFrameworkTrace logs a string as TRACE
// If the framework is not logging to file, this will go to standard error.
func PrintFrameworkTrace(msg string, keys ...any) {
	doFrameworkLog(stdErrDesc, LevelTrace, msg, keys...)
}

// PrintfFrameworkDebug formats according to a format specifier and logs as DEBUG
// If the framework is not logging to file, this will go to standard error.
func PrintfFrameworkDebug(format string, msg ...interface{}) {
	PrintFrameworkDebug(fmt.Sprintf(format, msg...))
}

// PrintFrameworkDebug logs a string as TRACE
// If the framework is not logging to file, this will go to standard error.
func PrintFrameworkDebug(msg string, keys ...any) {
	doFrameworkLog(stdErrDesc, LevelDebug, msg, keys...)
}

// PrintfFrameworkStatus formats according to a format specifier and logs as STATUS (aka INFO)
// If the framework is not logging to file, this will go to standard out.
func PrintfFrameworkStatus(format string, msg ...interface{}) {
	PrintFrameworkStatus(fmt.Sprintf(format, msg...))
}

// PrintFrameworkStatus logs a string as STATUS (aka INFO)
// If the framework is not logging to file, this will go to standard out.
func PrintFrameworkStatus(msg string, keys ...any) {
	doFrameworkLog(stdOutputDesc, LevelStatus, msg, keys...)
}

// PrintfFrameworkWarn formats according to a format specifier and logs as WARN
// If the framework is not logging to file, this will go to standard error.
func PrintfFrameworkWarn(format string, msg ...interface{}) {
	PrintFrameworkWarn(fmt.Sprintf(format, msg...))
}

// PrintFrameworkWarn logs a string as WARN
// If the framework is not logging to file, this will go to standard error.
func PrintFrameworkWarn(msg string, keys ...any) {
	doFrameworkLog(stdErrDesc, LevelStatus, msg, keys...)
}

// PrintfFrameworkSuccess formats according to a format specifier and logs as SUCCESS
// If the framework is not logging to file, this will go to standard out.
func PrintfFrameworkSuccess(format string, msg ...interface{}) {
	PrintFrameworkSuccess(fmt.Sprintf(format, msg...))
}

// PrintFrameworkSuccess logs a string as SUCCESS
// If the framework is not logging to file, this will go to standard out.
func PrintFrameworkSuccess(msg string, keys ...any) {
	doFrameworkLog(stdOutputDesc, LevelSuccess, msg, keys...)
}

// PrintfFrameworkError formats according to a format specifier and logs as ERROR
// If the framework is not logging to file, this will go to standard error.
func PrintfFrameworkError(format string, msg ...interface{}) {
	PrintFrameworkError(fmt.Sprintf(format, msg...))
}

// PrintFrameworkError logs a string as ERROR
// If the framework is not logging to file, this will go to standard error.
func PrintFrameworkError(msg string, keys ...any) {
	doFrameworkLog(stdErrDesc, LevelError, msg, keys...)
}
