/**
2 * @Author: shaochuyu
3 * @Date: 9/11/22
4 */

package main

import (
	"testing"
	"wscan/core/utils/log"
)

func TestLog(t *testing.T) {
	l := log.GetLogger("test")
	l.Info("test the logger")
}

func TestInfof(t *testing.T) {
	log.Infof("Test log %s", "info")
}

func TestDebugf(t *testing.T) {
	log.Debugf("Test log %s", "Debugf")
}
