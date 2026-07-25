/**
2 * @Author: shaochuyu
 * @Date: 3/13/23
*/

package printer

import (
	"bytes"
	"testing"
)

// writeCloserWrapper wraps a bytes.Buffer to implement io.WriteCloser
type writeCloserWrapper struct {
	*bytes.Buffer
	closed bool
}

func (w *writeCloserWrapper) Close() error {
	w.closed = true
	return nil
}

func TestTextPrinter(t *testing.T) {
	buf := &writeCloserWrapper{Buffer: &bytes.Buffer{}}
	p := NewTextPrinter(buf)

	// 向打印机打印内容
	err := p.Print("Hello, World!")
	if err != nil {
		t.Errorf("failed to print: %v", err)
	}

	// 验证输出内容
	if buf.String() != "Hello, World!\n" {
		t.Errorf("expected 'Hello, World!\\n', got '%s'", buf.String())
	}

	// 关闭打印机
	err = p.Close()
	if err != nil {
		t.Errorf("failed to close: %v", err)
	}

	if !buf.closed {
		t.Error("expected buffer to be closed")
	}
}

func TestTextPrinterInterceptor(t *testing.T) {
	buf := &writeCloserWrapper{Buffer: &bytes.Buffer{}}
	p := NewTextPrinter(buf)

	// Add interceptor that transforms the data
	p.AddInterceptor(func(data any) (any, error) {
		s, ok := data.(string)
		if !ok {
			return data, nil
		}
		return "[" + s + "]", nil
	})

	err := p.Print("test")
	if err != nil {
		t.Errorf("failed to print: %v", err)
	}

	if buf.String() != "[test]\n" {
		t.Errorf("expected '[test]\\n', got '%s'", buf.String())
	}
}

func TestTextPrinterNonString(t *testing.T) {
	buf := &writeCloserWrapper{Buffer: &bytes.Buffer{}}
	p := NewTextPrinter(buf)

	// Print non-string data should return error
	err := p.Print(42)
	if err == nil {
		t.Error("expected error for non-string input")
	}
}
