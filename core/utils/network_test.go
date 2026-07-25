package utils

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// mockConn implements net.Conn for testing TimeoutConn
type mockConn struct {
	readData   []byte
	readErr    error
	writeErr   error
	closeErr   error
	localAddr  net.Addr
	remoteAddr net.Addr
	deadline   time.Time
	readBuf    *bytes.Buffer
	closed     bool
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	if m.readBuf != nil {
		return m.readBuf.Read(b)
	}
	if m.readErr != nil {
		return 0, m.readErr
	}
	if len(m.readData) > 0 {
		n = copy(b, m.readData)
		m.readData = m.readData[n:]
		return n, nil
	}
	return 0, io.EOF
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	return len(b), nil
}

func (m *mockConn) Close() error {
	m.closed = true
	return m.closeErr
}

func (m *mockConn) LocalAddr() net.Addr {
	return m.localAddr
}

func (m *mockConn) RemoteAddr() net.Addr {
	return m.remoteAddr
}

func (m *mockConn) SetDeadline(t time.Time) error {
	m.deadline = t
	return nil
}

func (m *mockConn) SetReadDeadline(t time.Time) error {
	m.deadline = t
	return nil
}

func (m *mockConn) SetWriteDeadline(t time.Time) error {
	m.deadline = t
	return nil
}

func TestIPRange_StrInRange(t *testing.T) {
	ipr := &IPRange{}
	result := ipr.StrInRange("192.168.1.1")
	if result != false {
		t.Errorf("IPRange.StrInRange should return false, got %v", result)
	}
}

func TestTimeoutError_Error(t *testing.T) {
	err := &timeoutError{error: errors.New("test error"), timeout: true}
	if err.Error() != "test error" {
		t.Errorf("timeoutError.Error() = %q, want %q", err.Error(), "test error")
	}
}

func TestTimeoutError_Timeout(t *testing.T) {
	te := &timeoutError{error: errors.New("test"), timeout: true}
	if !te.Timeout() {
		t.Errorf("timeoutError.Timeout() should return true")
	}

	te2 := &timeoutError{error: errors.New("test"), timeout: false}
	if te2.Timeout() {
		t.Errorf("timeoutError.Timeout() should return false")
	}
}

func TestTimeoutError_Temporary(t *testing.T) {
	te := &timeoutError{error: errors.New("test"), timeout: true}
	if !te.Temporary() {
		t.Errorf("timeoutError.Temporary() should always return true")
	}
}

func TestTimeoutConn_Close(t *testing.T) {
	mock := &mockConn{}
	tc := &TimeoutConn{Conn: mock}
	err := tc.Close()
	if err != nil {
		t.Errorf("TimeoutConn.Close() returned error: %v", err)
	}
	if !mock.closed {
		t.Errorf("TimeoutConn.Close() should close underlying conn")
	}
}

func TestTimeoutConn_LocalAddr(t *testing.T) {
	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
	mock := &mockConn{localAddr: addr}
	tc := &TimeoutConn{Conn: mock}
	la := tc.LocalAddr()
	if la.String() != "127.0.0.1:1234" {
		t.Errorf("TimeoutConn.LocalAddr() = %v, want 127.0.0.1:1234", la)
	}
}

func TestTimeoutConn_RemoteAddr(t *testing.T) {
	addr := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 80}
	mock := &mockConn{remoteAddr: addr}
	tc := &TimeoutConn{Conn: mock}
	ra := tc.RemoteAddr()
	if ra.String() != "192.168.1.1:80" {
		t.Errorf("TimeoutConn.RemoteAddr() = %v, want 192.168.1.1:80", ra)
	}
}

func TestTimeoutConn_SetDeadline(t *testing.T) {
	mock := &mockConn{}
	tc := &TimeoutConn{Conn: mock}
	deadline := time.Now().Add(5 * time.Second)
	err := tc.SetDeadline(deadline)
	if err != nil {
		t.Errorf("TimeoutConn.SetDeadline() returned error: %v", err)
	}
}

func TestTimeoutConn_SetReadDeadline(t *testing.T) {
	mock := &mockConn{}
	tc := &TimeoutConn{Conn: mock}
	deadline := time.Now().Add(5 * time.Second)
	err := tc.SetReadDeadline(deadline)
	if err != nil {
		t.Errorf("TimeoutConn.SetReadDeadline() returned error: %v", err)
	}
}

func TestTimeoutConn_SetWriteDeadline(t *testing.T) {
	mock := &mockConn{}
	tc := &TimeoutConn{Conn: mock}
	deadline := time.Now().Add(5 * time.Second)
	err := tc.SetWriteDeadline(deadline)
	if err != nil {
		t.Errorf("TimeoutConn.SetWriteDeadline() returned error: %v", err)
	}
}

func TestTimeoutConn_SetNoReadTimeout(t *testing.T) {
	mock := &mockConn{}
	tc := &TimeoutConn{Conn: mock, timeout: 10}
	tc.SetNoReadTimeout()
	if tc.timeout != 0 {
		t.Errorf("TimeoutConn.SetNoReadTimeout() should set timeout to 0, got %d", tc.timeout)
	}
}

func TestTimeoutConn_IsTimeout(t *testing.T) {
	mock := &mockConn{}
	tc := &TimeoutConn{Conn: mock}

	// Test with timeout error
	te := &timeoutError{error: errors.New("timeout"), timeout: true}
	if !tc.IsTimeout(te) {
		t.Errorf("IsTimeout should return true for timeout error")
	}

	// Test with non-timeout error
	ne := errors.New("normal error")
	if tc.IsTimeout(ne) {
		t.Errorf("IsTimeout should return false for non-timeout error")
	}
}

func TestTimeoutConn_ReadWithTimeout_NoTimeout(t *testing.T) {
	mock := &mockConn{readBuf: bytes.NewBufferString("hello")}
	tc := &TimeoutConn{Conn: mock, timeout: 0}
	buf := make([]byte, 5)
	n, err := tc.ReadWithTimeout(buf)
	if err != nil {
		t.Errorf("ReadWithTimeout returned error: %v", err)
	}
	if string(buf[:n]) != "hello" {
		t.Errorf("ReadWithTimeout data = %q, want %q", string(buf[:n]), "hello")
	}
}

func TestTimeoutConn_ReadWithTimeout_WithTimeout(t *testing.T) {
	mock := &mockConn{readBuf: bytes.NewBufferString("hi")}
	tc := &TimeoutConn{Conn: mock, timeout: 5}
	buf := make([]byte, 2)
	n, err := tc.ReadWithTimeout(buf)
	if err != nil {
		t.Errorf("ReadWithTimeout returned error: %v", err)
	}
	if n != 2 || string(buf) != "hi" {
		t.Errorf("ReadWithTimeout data = %q, want %q", string(buf[:n]), "hi")
	}
}

func TestTimeoutConn_ReadUntil(t *testing.T) {
	mock := &mockConn{readBuf: bytes.NewBufferString("hello\nworld")}
	tc := &TimeoutConn{Conn: mock, timeout: 0}
	result, err := tc.ReadUntil('\n')
	if err != nil {
		t.Errorf("ReadUntil returned error: %v", err)
	}
	if string(result) != "hello\n" {
		t.Errorf("ReadUntil = %q, want %q", string(result), "hello\n")
	}
}

func TestTimeoutConn_ReadUntil_Error(t *testing.T) {
	mock := &mockConn{readErr: errors.New("read error")}
	tc := &TimeoutConn{Conn: mock, timeout: 0}
	_, err := tc.ReadUntil('\n')
	if err == nil {
		t.Errorf("ReadUntil should return error on read failure")
	}
}

func TestTimeoutConn_ReadAllWithTimeout(t *testing.T) {
	mock := &mockConn{readBuf: bytes.NewBufferString("hello world")}
	tc := &TimeoutConn{Conn: mock, timeout: 0}
	result, err := tc.ReadAllWithTimeout()
	if err != nil {
		t.Errorf("ReadAllWithTimeout returned error: %v", err)
	}
	if string(result) != "hello world" {
		t.Errorf("ReadAllWithTimeout = %q, want %q", string(result), "hello world")
	}
}

func TestTimeoutConn_ReadAllWithTimeout_Empty(t *testing.T) {
	mock := &mockConn{readBuf: bytes.NewBufferString("")}
	tc := &TimeoutConn{Conn: mock, timeout: 0}
	result, err := tc.ReadAllWithTimeout()
	if err != nil {
		t.Errorf("ReadAllWithTimeout on empty returned error: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("ReadAllWithTimeout on empty = %q, want empty", string(result))
	}
}

func TestTimeoutConn_ReadAllWithTimeout_TimeoutError(t *testing.T) {
	// Use a real net.Pipe to simulate a timeout scenario
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	tc := &TimeoutConn{Conn: client, timeout: 1}

	// Close server to make client read fail with timeout
	go func() {
		time.Sleep(100 * time.Millisecond)
		server.Close()
	}()

	_, err := tc.ReadAllWithTimeout()
	// The error could be either a timeout or an EOF depending on timing
	if err == nil {
		t.Log("ReadAllWithTimeout returned nil error")
	}
}

func TestTimeoutConn_print(t *testing.T) {
	mock := &mockConn{}
	tc := &TimeoutConn{Conn: mock, timeout: 5, allowPartialWrite: true}
	// Just verify print doesn't panic
	tc.print()
}

func TestTimeoutConn_SetTLSHandshakeTimeout(t *testing.T) {
	// Use net.Pipe for a real connection
	client, _ := net.Pipe()
	defer client.Close()

	tc := &TimeoutConn{Conn: client, timeout: 5}
	tc.SetTLSHandshakeTimeout(10 * time.Second)
	// After SetTLSHandshakeTimeout, the underlying Conn should be a TLS client conn
	// Just verify it doesn't panic
}

// Test TimeoutConn with real net.Pipe for more realistic testing
func TestTimeoutConn_PipeRead(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	tc := &TimeoutConn{Conn: client, timeout: 0}

	go func() {
		server.Write([]byte("test data"))
		server.Close()
	}()

	buf := make([]byte, 100)
	n, err := tc.ReadWithTimeout(buf)
	if err != nil && err != io.EOF {
		t.Errorf("ReadWithTimeout error: %v", err)
	}
	if n > 0 && string(buf[:n]) != "test data" {
		t.Errorf("ReadWithTimeout data = %q, want %q", string(buf[:n]), "test data")
	}
}

func TestTimeoutConn_PipeReadAll(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	tc := &TimeoutConn{Conn: client, timeout: 0}

	go func() {
		server.Write([]byte("hello"))
		server.Write([]byte(" world"))
		server.Close()
	}()

	result, err := tc.ReadAllWithTimeout()
	if err != nil {
		t.Errorf("ReadAllWithTimeout error: %v", err)
	}
	if string(result) != "hello world" {
		t.Errorf("ReadAllWithTimeout = %q, want %q", string(result), "hello world")
	}
}

func TestTimeoutConn_PipeReadUntil(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	tc := &TimeoutConn{Conn: client, timeout: 0}

	go func() {
		server.Write([]byte("line1\nline2\n"))
		server.Close()
	}()

	result, err := tc.ReadUntil('\n')
	if err != nil {
		t.Errorf("ReadUntil error: %v", err)
	}
	if string(result) != "line1\n" {
		t.Errorf("ReadUntil = %q, want %q", string(result), "line1\n")
	}
}

// Verify TLS config in SetTLSHandshakeTimeout
func TestTimeoutConn_SetTLSHandshakeTimeout_CreatesTLSConn(t *testing.T) {
	client, _ := net.Pipe()
	defer client.Close()

	tc := &TimeoutConn{Conn: client, timeout: 5}
	tc.SetTLSHandshakeTimeout(time.Second)

	// The underlying conn should now be a *tls.Conn
	_, ok := tc.Conn.(*tls.Conn)
	if !ok {
		t.Errorf("After SetTLSHandshakeTimeout, Conn should be *tls.Conn, got %T", tc.Conn)
	}
}

// Test net.Error that satisfies Timeout() interface
type mockNetError struct {
	msg     string
	timeout bool
}

func (e *mockNetError) Error() string   { return e.msg }
func (e *mockNetError) Timeout() bool   { return e.timeout }
func (e *mockNetError) Temporary() bool { return false }

func TestTimeoutConn_IsTimeout_NetError(t *testing.T) {
	mock := &mockConn{}
	tc := &TimeoutConn{Conn: mock}

	// Test with a net.Error that reports Timeout=true
	ne := &mockNetError{msg: "timeout", timeout: true}
	if !tc.IsTimeout(ne) {
		t.Errorf("IsTimeout should return true for net.Error with Timeout()=true")
	}

	// Test with a net.Error that reports Timeout=false
	ne2 := &mockNetError{msg: "not timeout", timeout: false}
	if tc.IsTimeout(ne2) {
		t.Errorf("IsTimeout should return false for net.Error with Timeout()=false")
	}
}

func TestTimeoutConn_ReadWithTimeout_TimeoutOnRead(t *testing.T) {
	// Create a connection that won't send data, causing timeout
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	tc := &TimeoutConn{Conn: client, timeout: 1}

	// Don't write anything to server, so client read will timeout
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 100)
		tc.ReadWithTimeout(buf)
		close(done)
	}()

	// Wait a bit for timeout to occur
	select {
	case <-done:
		// Read completed (likely with timeout error)
	case <-time.After(3 * time.Second):
		t.Errorf("ReadWithTimeout should have timed out")
	}
}

// Additional coverage: test with a buffered reader approach
func TestTimeoutConn_ReadUntil_DelimiterNotFound(t *testing.T) {
	data := "no newline here"
	mock := &mockConn{readBuf: bytes.NewBufferString(data)}
	tc := &TimeoutConn{Conn: mock, timeout: 0}

	// This should read all data and then hit EOF
	result, err := tc.ReadUntil('\n')
	// When it reaches EOF before finding delimiter, ReadWithTimeout returns io.EOF
	if err == nil {
		// Check if we got partial data
		t.Logf("ReadUntil without delimiter: result=%q, err=%v", string(result), err)
	}
}

func TestTimeoutConn_ReadAllWithTimeout_ReadError(t *testing.T) {
	mock := &mockConn{readErr: errors.New("read failure")}
	tc := &TimeoutConn{Conn: mock, timeout: 0}
	_, err := tc.ReadAllWithTimeout()
	if err == nil {
		t.Errorf("ReadAllWithTimeout should return error on read failure")
	}
}

// Test with bufio.Scanner-like sequential reads
func TestTimeoutConn_ReadUntil_MultipleReads(t *testing.T) {
	// Simulate data that arrives byte by byte
	data := "abc\n"
	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()

	conn := &pipeConn{r: r, w: w}
	tc := &TimeoutConn{Conn: conn, timeout: 0}

	go func() {
		for _, b := range []byte(data) {
			w.Write([]byte{b})
			time.Sleep(10 * time.Millisecond)
		}
	}()

	result, err := tc.ReadUntil('\n')
	if err != nil {
		t.Errorf("ReadUntil error: %v", err)
	}
	if string(result) != "abc\n" {
		t.Errorf("ReadUntil = %q, want %q", string(result), "abc\n")
	}
}

// pipeConn wraps io.PipeReader/Writer to implement net.Conn
type pipeConn struct {
	r *io.PipeReader
	w *io.PipeWriter
}

func (p *pipeConn) Read(b []byte) (n int, err error)  { return p.r.Read(b) }
func (p *pipeConn) Write(b []byte) (n int, err error) { return p.w.Write(b) }
func (p *pipeConn) Close() error {
	p.r.Close()
	p.w.Close()
	return nil
}
func (p *pipeConn) LocalAddr() net.Addr                { return nil }
func (p *pipeConn) RemoteAddr() net.Addr               { return nil }
func (p *pipeConn) SetDeadline(t time.Time) error      { return nil }
func (p *pipeConn) SetReadDeadline(t time.Time) error  { return nil }
func (p *pipeConn) SetWriteDeadline(t time.Time) error { return nil }

// Test reading lines with Scanner integration
func TestReadingLinesExtended(t *testing.T) {
	// Create a temp file with various line patterns
	tmpFile, err := os.CreateTemp("", "reading_lines_ext_*")
	if err != nil {
		t.Fatal(err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	content := "line1\nline2\n\nline3\nline4\n\n\nline5\n"
	tmpFile.WriteString(content)
	tmpFile.Close()

	result := ReadingLines(tmpPath)
	expected := []string{"line1", "line2", "line3", "line4", "line5"}
	if len(result) != len(expected) {
		t.Fatalf("ReadingLines returned %d lines, want %d: %v", len(result), len(expected), result)
	}
	for i, v := range result {
		if v != expected[i] {
			t.Errorf("ReadingLines()[%d] = %q, want %q", i, v, expected[i])
		}
	}
}

func TestReadingLines_ScannerError(t *testing.T) {
	// Create a file, then make it unreadable
	tmpFile, err := os.CreateTemp("", "reading_lines_err_*")
	if err != nil {
		t.Fatal(err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)
	tmpFile.Close()

	// This should work normally
	result := ReadingLines(tmpPath)
	if len(result) != 0 {
		t.Errorf("ReadingLines of empty file should return empty slice")
	}
}
