/**
2 * @Author: shaochuyu
3 * @Date: 9/4/22
4 */

package log

import (
	"github.com/kataras/golog"
)

type Logger struct {
	*golog.Logger
	name string
}

var defaultLogger *Logger

func GetLogger(name string) *Logger {
	return &Logger{name: name, Logger: golog.New()}
}

func Debug(v ...interface{}) {
	defaultLogger.Debug(v...)
}

func Info(v ...interface{}) {
	defaultLogger.Info(v...)
}

func Warning(v ...interface{}) {
	defaultLogger.Warn(v...)
}

func Warn(v ...interface{}) {
	defaultLogger.Warn(v...)
}

func Error(v ...interface{}) {
	defaultLogger.Error(v...)
}

func Fatal(v ...interface{}) {
	defaultLogger.Fatal(v...)
}

func Println(v ...interface{}) {
	defaultLogger.Println(v...)
}

func Print(v ...interface{}) {
	defaultLogger.Print(v...)
}

func Printf(format string, args ...interface{}) {
	defaultLogger.Printf(format, args...)
}

func Infof(format string, args ...interface{}) {
	defaultLogger.Infof(format, args...)
}

func Debugf(format string, args ...interface{}) {
	defaultLogger.Debugf(format, args...)
}

func Warningf(format string, args ...interface{}) {
	defaultLogger.Warningf(format, args...)
}

func Warnf(format string, args ...interface{}) {
	defaultLogger.Warnf(format, args...)
}

func Errorf(format string, args ...interface{}) {
	defaultLogger.Errorf(format, args...)
}

func Fatalf(format string, args ...interface{}) {
	defaultLogger.Fatalf(format, args...)
}

func init() {
	defaultLogger = GetLogger("default")
}
