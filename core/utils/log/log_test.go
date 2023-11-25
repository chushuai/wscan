/**
2 * @Author: shaochuyu
3 * @Date: 9/11/22
4 */

package log

import (
	"github.com/kataras/golog"
	"github.com/sirupsen/logrus"
	"testing"
)

func TestLog(t *testing.T) {

	defaultLogger.Info("hello log")

}

func TestLog2(t *testing.T) {
	// 创建一个新的 Logger 实例
	logger := golog.New()
	golog.Install(logrus.StandardLogger())
	// 设置日志级别
	logger.SetLevel("debug")

	// 设置自定义的日志格式
	logger.SetFormat("[%lvl%] %time% [%file%:%line%] %msg%")

	// 设置时间格式
	logger.SetTimeFormat("2006-01-02 15:04:05")

	// 输出一条日志
	logger.Debug("GET http://testphp.vulnweb.com/images/s.jsp")

}
