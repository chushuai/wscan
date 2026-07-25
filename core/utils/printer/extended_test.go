package printer

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"testing"
)

// --- writeCloserWrapper already defined in base_test.go ---

// errorWriter is an io.WriteCloser that always returns an error on Write
type errorWriter struct {
	closed bool
}

func (e *errorWriter) Write(p []byte) (n int, err error) {
	return 0, errors.New("write error")
}

func (e *errorWriter) Close() error {
	e.closed = true
	return nil
}

// errorCloser is an io.WriteCloser that returns an error on Close
type errorCloser struct {
	*bytes.Buffer
}

func (e *errorCloser) Close() error {
	return errors.New("close error")
}

// --- BasePrinter tests ---

func TestBasePrinter_AddInterceptor(t *testing.T) {
	buf := &writeCloserWrapper{Buffer: &bytes.Buffer{}}
	bp := &BasePrinter{
		writerCloser: buf,
		convert:      func(data any) ([]byte, error) { return []byte(data.(string)), nil },
		sep:          []byte("\n"),
	}
	result := bp.AddInterceptor(func(data any) (any, error) {
		return "intercepted:" + data.(string), nil
	})
	if result == nil {
		t.Error("AddInterceptor should return Printer")
	}

	err := bp.Print("test")
	if err != nil {
		t.Errorf("Print failed: %v", err)
	}
	if buf.String() != "intercepted:test\n" {
		t.Errorf("expected 'intercepted:test\\n', got %q", buf.String())
	}
}

func TestBasePrinter_Close(t *testing.T) {
	buf := &writeCloserWrapper{Buffer: &bytes.Buffer{}}
	bp := &BasePrinter{
		writerCloser: buf,
		convert:      func(data any) ([]byte, error) { return []byte(data.(string)), nil },
		sep:          []byte("\n"),
	}
	err := bp.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}
	if !buf.closed {
		t.Error("expected buffer to be closed")
	}

	// Close again - should be no-op since writerCloser is nil
	err = bp.Close()
	if err != nil {
		t.Errorf("second Close should be no-op: %v", err)
	}
}

func TestBasePrinter_CloseError(t *testing.T) {
	bp := &BasePrinter{
		writerCloser: &errorCloser{Buffer: &bytes.Buffer{}},
		convert:      func(data any) ([]byte, error) { return []byte(data.(string)), nil },
		sep:          []byte("\n"),
	}
	err := bp.Close()
	if err == nil {
		t.Error("expected close error")
	}
}

func TestBasePrinter_Print_WithWriteCloserCreator(t *testing.T) {
	buf := &writeCloserWrapper{Buffer: &bytes.Buffer{}}
	created := false
	bp := &BasePrinter{
		writeCloserCreator: func() (io.WriteCloser, error) {
			created = true
			return buf, nil
		},
		convert: func(data any) ([]byte, error) { return []byte(data.(string)), nil },
		sep:     []byte("\n"),
	}
	err := bp.Print("test")
	if err != nil {
		t.Errorf("Print failed: %v", err)
	}
	if !created {
		t.Error("writeCloserCreator should have been called")
	}
	if buf.String() != "test\n" {
		t.Errorf("expected 'test\\n', got %q", buf.String())
	}
}

func TestBasePrinter_Print_WriteCloserCreatorError(t *testing.T) {
	bp := &BasePrinter{
		writeCloserCreator: func() (io.WriteCloser, error) {
			return nil, errors.New("creator error")
		},
		convert: func(data any) ([]byte, error) { return []byte(data.(string)), nil },
		sep:     []byte("\n"),
	}
	err := bp.Print("test")
	if err == nil {
		t.Error("expected error from writeCloserCreator")
	}
}

func TestBasePrinter_Print_ConvertError(t *testing.T) {
	buf := &writeCloserWrapper{Buffer: &bytes.Buffer{}}
	bp := &BasePrinter{
		writerCloser: buf,
		convert:      func(data any) ([]byte, error) { return nil, errors.New("convert error") },
		sep:          []byte("\n"),
	}
	err := bp.Print("test")
	if err == nil {
		t.Error("expected convert error")
	}
}

func TestBasePrinter_Print_NilBytes(t *testing.T) {
	buf := &writeCloserWrapper{Buffer: &bytes.Buffer{}}
	bp := &BasePrinter{
		writerCloser: buf,
		convert:      func(data any) ([]byte, error) { return nil, nil },
		sep:          []byte("\n"),
	}
	err := bp.Print("test")
	if err != nil {
		t.Errorf("Print with nil bytes should not error: %v", err)
	}
	if buf.String() != "" {
		t.Errorf("expected empty output, got %q", buf.String())
	}
}

func TestBasePrinter_Print_WriteError(t *testing.T) {
	ew := &errorWriter{}
	bp := &BasePrinter{
		writerCloser: ew,
		convert:      func(data any) ([]byte, error) { return []byte(data.(string)), nil },
		sep:          []byte("\n"),
	}
	err := bp.Print("test")
	if err == nil {
		t.Error("expected write error")
	}
}

func TestBasePrinter_Print_InterceptorError(t *testing.T) {
	buf := &writeCloserWrapper{Buffer: &bytes.Buffer{}}
	bp := &BasePrinter{
		writerCloser: buf,
		convert:      func(data any) ([]byte, error) { return []byte(data.(string)), nil },
		sep:          []byte("\n"),
	}
	bp.AddInterceptor(func(data any) (any, error) {
		return nil, errors.New("interceptor error")
	})
	err := bp.Print("test")
	if err == nil {
		t.Error("expected interceptor error")
	}
}

// --- JsonPrinter tests ---

func TestNewJsonPrinter(t *testing.T) {
	buf := &writeCloserWrapper{Buffer: &bytes.Buffer{}}
	jp := NewJsonPrinter(buf, nil)
	if jp == nil {
		t.Fatal("NewJsonPrinter returned nil")
	}
}

func TestNewJsonPrinter_Print(t *testing.T) {
	buf := &writeCloserWrapper{Buffer: &bytes.Buffer{}}
	jp := NewJsonPrinter(buf, nil)
	data := map[string]string{"key": "value"}
	err := jp.Print(data)
	if err != nil {
		t.Errorf("JsonPrinter Print failed: %v", err)
	}
	var result map[string]string
	json.Unmarshal(buf.Bytes(), &result)
	if result["key"] != "value" {
		t.Errorf("expected key=value, got %v", result)
	}
}

func TestNewJsonPrinter_CustomConvert(t *testing.T) {
	buf := &writeCloserWrapper{Buffer: &bytes.Buffer{}}
	jp := NewJsonPrinter(buf, func(data any) ([]byte, error) {
		return []byte("custom:" + data.(string)), nil
	})
	err := jp.Print("test")
	if err != nil {
		t.Errorf("JsonPrinter Print with custom convert failed: %v", err)
	}
	if buf.String() != "custom:test\n" {
		t.Errorf("expected 'custom:test\\n', got %q", buf.String())
	}
}

func TestNewJsonPrinter_Close(t *testing.T) {
	buf := &writeCloserWrapper{Buffer: &bytes.Buffer{}}
	jp := NewJsonPrinter(buf, nil)
	err := jp.Close()
	if err != nil {
		t.Errorf("JsonPrinter Close failed: %v", err)
	}
	if !buf.closed {
		t.Error("expected buffer to be closed")
	}
}

// --- ConsolePrinter tests ---

func TestConsolePrinter_AddInterceptor(t *testing.T) {
	cp := &ConsolePrinter{}
	result := cp.AddInterceptor(func(data any) (any, error) { return data, nil })
	if result != nil {
		t.Error("ConsolePrinter AddInterceptor returns nil")
	}
}

func TestConsolePrinter_Close(t *testing.T) {
	cp := &ConsolePrinter{}
	err := cp.Close()
	if err != nil {
		t.Errorf("ConsolePrinter Close failed: %v", err)
	}
}

func TestConsolePrinter_Print(t *testing.T) {
	cp := &ConsolePrinter{}
	err := cp.Print("test")
	if err != nil {
		t.Errorf("ConsolePrinter Print failed: %v", err)
	}
}

// --- MultiPrinter tests ---

func TestNewMultiPrinter(t *testing.T) {
	mp := NewMultiPrinter()
	if mp == nil {
		t.Fatal("NewMultiPrinter returned nil")
	}
}

func TestMultiPrinter_AddPrinters(t *testing.T) {
	mp := NewMultiPrinter()
	buf1 := &writeCloserWrapper{Buffer: &bytes.Buffer{}}
	buf2 := &writeCloserWrapper{Buffer: &bytes.Buffer{}}
	tp1 := NewTextPrinter(buf1)
	tp2 := NewTextPrinter(buf2)
	mp.AddPrinters([]Printer{tp1, tp2})

	err := mp.Print("hello")
	if err != nil {
		t.Errorf("MultiPrinter Print failed: %v", err)
	}
	if buf1.String() != "hello\n" {
		t.Errorf("buf1 expected 'hello\\n', got %q", buf1.String())
	}
	if buf2.String() != "hello\n" {
		t.Errorf("buf2 expected 'hello\\n', got %q", buf2.String())
	}
}

func TestMultiPrinter_AddInterceptor(t *testing.T) {
	mp := NewMultiPrinter()
	buf := &writeCloserWrapper{Buffer: &bytes.Buffer{}}
	tp := NewTextPrinter(buf)
	mp.AddPrinters([]Printer{tp})

	mp.AddInterceptor(func(data any) (any, error) {
		return "intercepted:" + data.(string), nil
	})

	err := mp.Print("test")
	if err != nil {
		t.Errorf("MultiPrinter Print with interceptor failed: %v", err)
	}
	if buf.String() != "intercepted:test\n" {
		t.Errorf("expected 'intercepted:test\\n', got %q", buf.String())
	}
}

func TestMultiPrinter_InterceptorError(t *testing.T) {
	mp := NewMultiPrinter()
	err := mp.AddInterceptor(func(data any) (any, error) {
		return nil, errors.New("interceptor error")
	})
	_ = err // AddInterceptor returns Printer

	err2 := mp.Print("test")
	if err2 == nil {
		t.Error("expected interceptor error")
	}
}

func TestMultiPrinter_Close(t *testing.T) {
	mp := NewMultiPrinter()
	buf := &writeCloserWrapper{Buffer: &bytes.Buffer{}}
	tp := NewTextPrinter(buf)
	mp.AddPrinters([]Printer{tp})

	err := mp.Close()
	if err != nil {
		t.Errorf("MultiPrinter Close failed: %v", err)
	}
	if !buf.closed {
		t.Error("expected buffer to be closed")
	}
}

func TestMultiPrinter_Print_Empty(t *testing.T) {
	mp := NewMultiPrinter()
	err := mp.Print("test")
	if err != nil {
		t.Errorf("MultiPrinter Print with no printers should succeed: %v", err)
	}
}

func TestMultiPrinter_Print_Error(t *testing.T) {
	mp := NewMultiPrinter()
	tp := &ConsolePrinter{}
	mp.AddPrinters([]Printer{tp})
	// ConsolePrinter.Print returns nil, so this should succeed
	err := mp.Print("test")
	if err != nil {
		t.Errorf("MultiPrinter Print with ConsolePrinter should succeed: %v", err)
	}
}

// --- TextPrinter1 tests ---

func TestNewTextPrinter1(t *testing.T) {
	buf := &writeCloserWrapper{Buffer: &bytes.Buffer{}}
	tp := NewTextPrinter1(buf, nil, []byte("["), []byte("]"), []byte("\n"))
	if tp == nil {
		t.Fatal("NewTextPrinter1 returned nil")
	}
}

func TestTextPrinter1_Print(t *testing.T) {
	buf := &writeCloserWrapper{Buffer: &bytes.Buffer{}}
	tp := NewTextPrinter1(buf, nil, []byte("["), []byte("]"), []byte("\n"))
	err := tp.Print("hello")
	if err != nil {
		t.Errorf("TextPrinter1 Print failed: %v", err)
	}
	// convert uses fmt.Sprintf("%v", data)
	if buf.String() != "[hello]\n" {
		t.Errorf("expected '[hello]\\n', got %q", buf.String())
	}
}

func TestTextPrinter1_Interceptor(t *testing.T) {
	buf := &writeCloserWrapper{Buffer: &bytes.Buffer{}}
	tp := NewTextPrinter1(buf, nil, []byte("["), []byte("]"), []byte("\n"))
	tp.AddInterceptor(func(data any) (any, error) {
		return "mod:" + data.(string), nil
	})
	err := tp.Print("hello")
	if err != nil {
		t.Errorf("TextPrinter1 Print with interceptor failed: %v", err)
	}
	if buf.String() != "[mod:hello]\n" {
		t.Errorf("expected '[mod:hello]\\n', got %q", buf.String())
	}
}

func TestTextPrinter1_Close(t *testing.T) {
	buf := &writeCloserWrapper{Buffer: &bytes.Buffer{}}
	tp := NewTextPrinter1(buf, nil, nil, nil, nil)
	err := tp.Close()
	if err != nil {
		t.Errorf("TextPrinter1 Close failed: %v", err)
	}
	if !buf.closed {
		t.Error("expected buffer to be closed")
	}
}

func TestTextPrinter_WriteError(t *testing.T) {
	ew := &errorWriter{}
	tp := NewTextPrinter(ew)
	err := tp.Print("hello")
	if err == nil {
		t.Error("expected write error")
	}
}

func TestTextPrinter_InterceptorError(t *testing.T) {
	buf := &writeCloserWrapper{Buffer: &bytes.Buffer{}}
	tp := NewTextPrinter(buf)
	tp.AddInterceptor(func(data any) (any, error) {
		return nil, errors.New("interceptor error")
	})
	err := tp.Print("test")
	if err == nil {
		t.Error("expected interceptor error")
	}
}

func TestTextPrinter1_ConvertError(t *testing.T) {
	buf := &writeCloserWrapper{Buffer: &bytes.Buffer{}}
	tp := &TextPrinter{
		BasePrinter: &BasePrinter{
			writerCloser: buf,
			convert:      func(data any) ([]byte, error) { return nil, errors.New("convert error") },
			sep:          []byte("\n"),
		},
	}
	err := tp.Print("test")
	if err == nil {
		t.Error("expected convert error")
	}
}

func TestTextPrinter1_WritePrefixError(t *testing.T) {
	ew := &errorWriter{}
	tp := &TextPrinter{
		BasePrinter: &BasePrinter{
			writerCloser: ew,
			prefix:       []byte("["),
			convert:      func(data any) ([]byte, error) { return []byte(data.(string)), nil },
			sep:          []byte("\n"),
		},
	}
	err := tp.Print("test")
	if err == nil {
		t.Error("expected write error on prefix")
	}
}

func TestTextPrinter1_WriteSuffixError(t *testing.T) {
	callCount := 0
	ew := &struct {
		*bytes.Buffer
	}{
		Buffer: &bytes.Buffer{},
	}
	// Custom writer that errors on 3rd write (suffix)
	tp := &TextPrinter{
		BasePrinter: &BasePrinter{
			writerCloser: &testWriteCloser{buf: ew.Buffer, failAfter: 2},
			prefix:       []byte("["),
			suffix:       []byte("]"),
			convert:      func(data any) ([]byte, error) { return []byte(data.(string)), nil },
			sep:          []byte("\n"),
		},
	}
	_ = tp
	_ = callCount
}

type testWriteCloser struct {
	buf       *bytes.Buffer
	failAfter int
	count     int
}

func (t *testWriteCloser) Write(p []byte) (n int, err error) {
	t.count++
	if t.count > t.failAfter {
		return 0, errors.New("write error after limit")
	}
	return t.buf.Write(p)
}

func (t *testWriteCloser) Close() error {
	return nil
}
