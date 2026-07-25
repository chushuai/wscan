package global

import (
	"os"
	"strconv"

	"github.com/projectdiscovery/utils/sysutil"
)

const OS_MAX_THREADS_ENV = "OS_MAX_THREADS"

func init() {
	handleOSMaxThreads()
}

func handleOSMaxThreads() {
	osMaxThreads := os.Getenv(OS_MAX_THREADS_ENV)
	if osMaxThreads == "" {
		return
	}
	if value, err := strconv.Atoi(osMaxThreads); err == nil && value > 0 {
		_ = sysutil.SetMaxThreads(value)
	}
}
