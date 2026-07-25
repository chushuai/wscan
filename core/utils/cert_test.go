/**
2 * @Author: shaochuyu
3 * @Date: 9/8/22
4 */

package utils

import (
	"os"
	"testing"
)

func TestGenerateCA(t *testing.T) {
	crtBuff, keyBuff := GenerateCA()
	if crtBuff == nil {
		t.Fatal("crtBuff == nil")
	}
	if keyBuff == nil {
		t.Fatal("keyBuff == nil")
	}
}

func TestGenerateCAToPath(t *testing.T) {
	if err := GenerateCAToPath("." + string(os.PathSeparator)); err != nil {
		t.Error(err)
	}
}
