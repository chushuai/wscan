/**
2 * @Author: shaochuyu
3 * @Date: 3/13/23
4 */

package printer

import (
	"os"
	"testing"
)

func TestTextPrinter(t *testing.T) {
	// 创建 TextPrinter 实例
	p := NewTextPrinter(os.Stdout)

	// 向打印机打印内容
	err := p.Print("Hello, World!")
	if err != nil {
		t.Errorf("failed to print: %v", err)
	}

	// 关闭打印机
	err = p.Close()
	if err != nil {
		t.Errorf("failed to close: %v", err)
	}
}
