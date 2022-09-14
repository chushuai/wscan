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

func Infof(format string, args ...interface{}) {
	defaultLogger.Logf(golog.InfoLevel, format, args...)
}

func Debugf(format string, args ...interface{}) {
	defaultLogger.Logf(golog.InfoLevel, format, args...)
}

func init() {
	defaultLogger = GetLogger("default")
	golog.New()

}
