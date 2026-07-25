/**
2 * @Author: shaochuyu
3 * @Date: 4/25/24
4 */

package utils

import (
	"fmt"
	"reflect"
	"runtime"
	logger "wscan/core/utils/log"
)

func PrintCurrentGoroutineRuntimeStack() {
	var buf [4096]byte
	n := runtime.Stack(buf[:], false)
	fmt.Printf("Current goroutine call stack:\n%s\n", buf[:n])
}

func TryWriteChannel[T any](c chan T, data T) (ret bool) {
	defer func() {
		if err := recover(); err != nil {
			logger.Errorf("write channel failed: %v", err)
			ret = false
		}
	}()
	c <- data
	return true
}

func TryCloseChannel(i any) {
	if i == nil {
		return
	}
	defer func() {
		if err := recover(); err != nil {
			logger.Errorf("close channel failed: %v", err)
		}
	}()

	if reflect.TypeOf(i).Kind() == reflect.Chan {
		reflect.ValueOf(i).Close()
	}
}
