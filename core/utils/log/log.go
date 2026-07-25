/**
2 * @Author: shaochuyu
3 * @Date: 9/4/22
4 */

package log

import (
	"fmt"
	"runtime"
	"strings"

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

// ================= 辅助函数 =================

// getCallStack 获取当前的函数调用栈
func getCallStack(skip int) string {
	var pcs [32]uintptr
	n := runtime.Callers(skip+1, pcs[:])
	if n == 0 {
		return ""
	}

	frames := runtime.CallersFrames(pcs[:n])
	var sb strings.Builder
	for {
		frame, more := frames.Next()
		if strings.Contains(frame.Function, "runtime.") {
			if !more {
				break
			}
			continue
		}
		sb.WriteString(fmt.Sprintf("  at %s (%s:%d)\n", frame.Function, frame.File, frame.Line))
		if !more {
			break
		}
	}
	return sb.String()
}

// extractErrorStack 尝试从参数中提取 error 自带的原始堆栈
func extractErrorStack(args ...any) string {
	for _, arg := range args {
		if err, ok := arg.(error); ok {
			// 使用 %+v 打印详细堆栈 (兼容 pkg/errors 等库)
			verbose := fmt.Sprintf("%+v", err)
			// 关键优化：如果 %+v 的输出和 err.Error() 完全一样，说明它没有堆栈（如标准库 errors.New）
			// 这样可以避免在日志中重复打印一遍错误文本
			if verbose != err.Error() {
				return verbose
			}
		}
	}
	return ""
}

// buildStackMessage 将当前调用栈和错误原始堆栈拼接成易读的格式
func buildStackMessage(runtimeStack, errorStack string) string {
	var sb strings.Builder

	if runtimeStack != "" {
		sb.WriteString("Current Call Stack:\n")
		sb.WriteString(runtimeStack)
	}

	if errorStack != "" {
		if sb.Len() > 0 {
			sb.WriteString("\n")
		}
		sb.WriteString("Original Error Stack:\n")
		sb.WriteString(errorStack)
	}

	return sb.String()
}

func Debug(v ...any) {
	defaultLogger.Debug(v...)
}

func Info(v ...any) {
	defaultLogger.Info(v...)
}

func Warning(v ...any) {
	defaultLogger.Warn(v...)
}

func Warn(v ...any) {
	defaultLogger.Warn(v...)
}

func Error(v ...any) {
	msg := fmt.Sprint(v...)

	// 同时获取两种堆栈
	runtimeStack := getCallStack(2)
	errorStack := extractErrorStack(v...)

	stackMsg := buildStackMessage(runtimeStack, errorStack)
	if stackMsg != "" {
		msg = fmt.Sprintf("%s\n%s", msg, stackMsg)
	}

	defaultLogger.Error(msg)
}

func Fatal(v ...any) {
	defaultLogger.Fatal(v...)
}

func Println(v ...any) {
	defaultLogger.Println(v...)
}

func Print(v ...any) {
	defaultLogger.Print(v...)
}

func Printf(format string, args ...any) {
	defaultLogger.Printf(format, args...)
}

func Infof(format string, args ...any) {
	defaultLogger.Infof(format, args...)
}

func Debugf(format string, args ...any) {
	defaultLogger.Debugf(format, args...)
}

func Warningf(format string, args ...any) {
	defaultLogger.Warningf(format, args...)
}

func Warnf(format string, args ...any) {
	defaultLogger.Warnf(format, args...)
}

func Errorf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)

	// 同时获取两种堆栈
	runtimeStack := getCallStack(2)
	errorStack := extractErrorStack(args...)

	stackMsg := buildStackMessage(runtimeStack, errorStack)
	if stackMsg != "" {
		msg = fmt.Sprintf("%s\n%s", msg, stackMsg)
	}

	// ⚠️ 注意：这里必须调用 Error 而不是 Errorf！
	// 因为 msg 中包含了堆栈信息（可能含有 % 字符），调用 Errorf 会导致二次格式化 panic。
	defaultLogger.Error(msg)
}

func Fatalf(format string, args ...any) {
	defaultLogger.Fatalf(format, args...)
}

func init() {
	defaultLogger = GetLogger("default")
	defaultLogger.SetTimeFormat("2006-01-02 15:04:05")

}
