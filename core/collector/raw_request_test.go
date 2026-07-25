package collector

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	stdhttp "net/http"
	vhttp "wscan/core/http"
)

// ==================== 构造函数测试 ====================

func TestNewFromRawRequestFile(t *testing.T) {
	rawData := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	opts := &vhttp.ClientOptions{}
	rc := NewFromRawRequestFile(rawData, false, opts)
	if rc == nil {
		t.Fatal("expected non-nil rawRequestCollector")
	}
	if rc.client == nil {
		t.Error("expected client to be initialized")
	}
	if rc.pool == nil {
		t.Error("expected pool to be initialized")
	}
	if rc.opts == nil {
		t.Error("expected opts to be set")
	}
	if rc.forceSSL != false {
		t.Error("expected forceSSL to be false")
	}
	if string(rc.fileData) != string(rawData) {
		t.Error("expected fileData to be set")
	}
}

func TestNewFromRawRequestFile_WithForceSSL(t *testing.T) {
	rawData := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	opts := &vhttp.ClientOptions{}
	rc := NewFromRawRequestFile(rawData, true, opts)
	if rc.forceSSL != true {
		t.Error("expected forceSSL to be true")
	}
}

func TestRawRequestCollector_ImplementsFitter(t *testing.T) {
	var _ Fitter = (*rawRequestCollector)(nil)
}

// ==================== parseRawRequest 单元测试 ====================

func TestParseRawRequest_GET(t *testing.T) {
	rawData := []byte("GET /path HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n")
	opts := &vhttp.ClientOptions{}
	rc := NewFromRawRequestFile(rawData, false, opts)

	req, err := rc.parseRawRequest(rawData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Method != "GET" {
		t.Errorf("expected method GET, got %q", req.Method)
	}
	if req.URL().Host != "example.com" {
		t.Errorf("expected host example.com, got %q", req.URL().Host)
	}
	if req.URL().Path != "/path" {
		t.Errorf("expected path /path, got %q", req.URL().Path)
	}
	if req.URL().Scheme != "http" {
		t.Errorf("expected scheme http, got %q", req.URL().Scheme)
	}
}

func TestParseRawRequest_POST(t *testing.T) {
	rawData := []byte("POST /login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 28\r\n\r\nusername=admin&password=secret")
	opts := &vhttp.ClientOptions{}
	rc := NewFromRawRequestFile(rawData, false, opts)

	req, err := rc.parseRawRequest(rawData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Method != "POST" {
		t.Errorf("expected method POST, got %q", req.Method)
	}
	if req.URL().Path != "/login" {
		t.Errorf("expected path /login, got %q", req.URL().Path)
	}
	ct := req.ContentType()
	if ct != "application/x-www-form-urlencoded" {
		t.Errorf("expected Content-Type application/x-www-form-urlencoded, got %q", ct)
	}
}

func TestParseRawRequest_WithCookies(t *testing.T) {
	rawData := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nCookie: session=abc123; user=test\r\n\r\n")
	opts := &vhttp.ClientOptions{}
	rc := NewFromRawRequestFile(rawData, false, opts)

	req, err := rc.parseRawRequest(rawData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cookie := req.Header.Get("Cookie")
	if cookie == "" {
		t.Error("expected Cookie header to be present")
	}
	if !strings.Contains(cookie, "session=abc123") {
		t.Errorf("expected cookie to contain session=abc123, got %q", cookie)
	}
}

func TestParseRawRequest_WithMultipleHeaders(t *testing.T) {
	rawData := []byte("GET /api HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer token123\r\nX-Api-Key: mykey\r\nAccept: application/json\r\n\r\n")
	opts := &vhttp.ClientOptions{}
	rc := NewFromRawRequestFile(rawData, false, opts)

	req, err := rc.parseRawRequest(rawData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Header.Get("Authorization") != "Bearer token123" {
		t.Errorf("expected Authorization header, got %q", req.Header.Get("Authorization"))
	}
	if req.Header.Get("X-Api-Key") != "mykey" {
		t.Errorf("expected X-Api-Key header, got %q", req.Header.Get("X-Api-Key"))
	}
	if req.Header.Get("Accept") != "application/json" {
		t.Errorf("expected Accept header, got %q", req.Header.Get("Accept"))
	}
}

func TestParseRawRequest_ForceSSL(t *testing.T) {
	rawData := []byte("GET /secure HTTP/1.1\r\nHost: example.com\r\n\r\n")
	opts := &vhttp.ClientOptions{}
	rc := NewFromRawRequestFile(rawData, true, opts)

	req, err := rc.parseRawRequest(rawData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.URL().Scheme != "https" {
		t.Errorf("expected scheme https with forceSSL=true, got %q", req.URL().Scheme)
	}
}

func TestParseRawRequest_NoForceSSL(t *testing.T) {
	rawData := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	opts := &vhttp.ClientOptions{}
	rc := NewFromRawRequestFile(rawData, false, opts)

	req, err := rc.parseRawRequest(rawData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.URL().Scheme != "http" {
		t.Errorf("expected scheme http with forceSSL=false, got %q", req.URL().Scheme)
	}
}

func TestParseRawRequest_HostHeaderRespected(t *testing.T) {
	rawData := []byte("GET /path HTTP/1.1\r\nHost: custom.example.com:8080\r\n\r\n")
	opts := &vhttp.ClientOptions{}
	rc := NewFromRawRequestFile(rawData, false, opts)

	req, err := rc.parseRawRequest(rawData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.URL().Host != "custom.example.com:8080" {
		t.Errorf("expected host custom.example.com:8080, got %q", req.URL().Host)
	}
}

func TestParseRawRequest_QueryParameters(t *testing.T) {
	rawData := []byte("GET /search?q=test&page=2 HTTP/1.1\r\nHost: example.com\r\n\r\n")
	opts := &vhttp.ClientOptions{}
	rc := NewFromRawRequestFile(rawData, false, opts)

	req, err := rc.parseRawRequest(rawData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.URL().RawQuery != "q=test&page=2" {
		t.Errorf("expected query q=test&page=2, got %q", req.URL().RawQuery)
	}
}

func TestParseRawRequest_InvalidData(t *testing.T) {
	rawData := []byte("this is not a valid http request")
	opts := &vhttp.ClientOptions{}
	rc := NewFromRawRequestFile(rawData, false, opts)

	_, err := rc.parseRawRequest(rawData)
	if err == nil {
		t.Error("expected error for invalid request data")
	}
}

func TestParseRawRequest_EmptyBody(t *testing.T) {
	rawData := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	opts := &vhttp.ClientOptions{}
	rc := NewFromRawRequestFile(rawData, false, opts)

	req, err := rc.parseRawRequest(rawData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Method != "GET" {
		t.Errorf("expected GET method, got %q", req.Method)
	}
}

// ==================== FitOut 集成测试 ====================

func TestRawRequestCollector_FitOut_GETRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	rawData := []byte("GET /test HTTP/1.1\r\nHost: " + server.Listener.Addr().String() + "\r\n\r\n")
	opts := &vhttp.ClientOptions{}
	rc := NewFromRawRequestFile(rawData, false, opts)

	ch, err := rc.FitOut(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error from FitOut: %v", err)
	}
	if ch == nil {
		t.Fatal("expected non-nil channel")
	}

	select {
	case res, ok := <-ch:
		if !ok {
			t.Error("channel closed without receiving result")
		} else if res == nil {
			t.Error("expected non-nil resource")
		}
	case <-time.After(15 * time.Second):
		t.Error("timed out waiting for result")
	}
}

func TestRawRequestCollector_FitOut_POSTRequest(t *testing.T) {
	var receivedMethod string
	var receivedBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	postBody := "username=admin&password=secret"
	rawData := []byte(fmt.Sprintf("POST /login HTTP/1.1\r\nHost: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n%s", server.Listener.Addr().String(), len(postBody), postBody))
	opts := &vhttp.ClientOptions{}
	rc := NewFromRawRequestFile(rawData, false, opts)

	ch, err := rc.FitOut(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error from FitOut: %v", err)
	}

	select {
	case <-ch:
		if receivedMethod != "POST" {
			t.Errorf("expected POST method, got %q", receivedMethod)
		}
		if receivedBody != postBody {
			t.Errorf("expected body %q, got %q", postBody, receivedBody)
		}
	case <-time.After(15 * time.Second):
		t.Error("timed out waiting for result")
	}
}

func TestRawRequestCollector_FitOut_WithHeaders(t *testing.T) {
	receivedHeaders := make(chan http.Header, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders <- r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	rawData := []byte("GET / HTTP/1.1\r\nHost: " + server.Listener.Addr().String() + "\r\n\r\n")
	opts := &vhttp.ClientOptions{
		DefaultHeaders: map[string]string{
			"X-Custom-Header": "custom-value",
			"User-Agent":      "TestAgent/1.0",
		},
	}
	opts.WroteBack()

	rc := NewFromRawRequestFile(rawData, false, opts)

	ch, err := rc.FitOut(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error from FitOut: %v", err)
	}

	select {
	case <-ch:
		select {
		case h := <-receivedHeaders:
			if h.Get("X-Custom-Header") != "custom-value" {
				t.Errorf("expected X-Custom-Header 'custom-value', got %q", h.Get("X-Custom-Header"))
			}
		default:
		}
	case <-time.After(15 * time.Second):
		t.Error("timed out waiting for result")
	}
}

func TestRawRequestCollector_FitOut_HeadersPriority(t *testing.T) {
	receivedHeaders := make(chan http.Header, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders <- r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	rawData := []byte("GET / HTTP/1.1\r\nHost: " + server.Listener.Addr().String() + "\r\n\r\n")
	opts := &vhttp.ClientOptions{
		Headers: map[string][]string{
			"X-Custom-Header": {"from-headers-map"},
		},
		DefaultHeaders: map[string]string{
			"X-Custom-Header": "from-default-headers",
			"X-Only-Default":  "default-value",
		},
	}

	rc := NewFromRawRequestFile(rawData, false, opts)

	ch, err := rc.FitOut(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error from FitOut: %v", err)
	}

	select {
	case <-ch:
		select {
		case h := <-receivedHeaders:
			// Headers map should take priority
			if h.Get("X-Custom-Header") != "from-headers-map" {
				t.Errorf("expected X-Custom-Header 'from-headers-map', got %q", h.Get("X-Custom-Header"))
			}
			// DefaultHeaders should be used for keys not in Headers
			if h.Get("X-Only-Default") != "default-value" {
				t.Errorf("expected X-Only-Default 'default-value', got %q", h.Get("X-Only-Default"))
			}
		default:
		}
	case <-time.After(15 * time.Second):
		t.Error("timed out waiting for result")
	}
}

func TestRawRequestCollector_FitOut_InvalidRequestData(t *testing.T) {
	rawData := []byte("this is not valid http")
	opts := &vhttp.ClientOptions{}
	rc := NewFromRawRequestFile(rawData, false, opts)

	ch, err := rc.FitOut(context.Background(), nil)
	if err == nil {
		t.Error("expected error for invalid request data")
	}
	if ch == nil {
		t.Fatal("expected non-nil channel even on error")
	}
	// Channel should be closed
	_, ok := <-ch
	if ok {
		t.Error("expected channel to be closed after parse error")
	}
}

func TestRawRequestCollector_FitOut_CancelledContext(t *testing.T) {
	rawData := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	opts := &vhttp.ClientOptions{}
	rc := NewFromRawRequestFile(rawData, false, opts)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ch, err := rc.FitOut(ctx, nil)
	if err != nil {
		t.Fatalf("unexpected error from FitOut: %v", err)
	}
	if ch == nil {
		t.Fatal("expected non-nil channel even with cancelled context")
	}
}

func TestRawRequestCollector_ChannelCapacity(t *testing.T) {
	rawData := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	opts := &vhttp.ClientOptions{}
	rc := NewFromRawRequestFile(rawData, false, opts)

	ch, err := rc.FitOut(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error from FitOut: %v", err)
	}
	if cap(ch) != 100 {
		t.Errorf("expected channel capacity 100, got %d", cap(ch))
	}
}

func TestRawRequestCollector_FitOut_RawRequestHeadersPreserved(t *testing.T) {
	receivedHeaders := make(chan http.Header, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders <- r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	rawData := []byte("GET /api HTTP/1.1\r\nHost: " + server.Listener.Addr().String() + "\r\nAuthorization: Bearer mytoken\r\nX-Custom: value123\r\n\r\n")
	opts := &vhttp.ClientOptions{}

	rc := NewFromRawRequestFile(rawData, false, opts)

	ch, err := rc.FitOut(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error from FitOut: %v", err)
	}

	select {
	case <-ch:
		select {
		case h := <-receivedHeaders:
			if h.Get("Authorization") != "Bearer mytoken" {
				t.Errorf("expected Authorization 'Bearer mytoken', got %q", h.Get("Authorization"))
			}
			if h.Get("X-Custom") != "value123" {
				t.Errorf("expected X-Custom 'value123', got %q", h.Get("X-Custom"))
			}
		default:
		}
	case <-time.After(15 * time.Second):
		t.Error("timed out waiting for result")
	}
}

// ==================== 辅助测试 ====================

func TestParseRawRequest_WithReadRequest(t *testing.T) {
	// 验证 net/http.ReadRequest 对原始请求的解析行为
	rawData := []byte("POST /submit HTTP/1.1\r\nHost: target.local\r\nContent-Type: application/json\r\nContent-Length: 25\r\n\r\n{\"key\":\"value\",\"num\":42}")

	hReq, err := stdhttp.ReadRequest(bufio.NewReader(bytes.NewReader(rawData)))
	if err != nil {
		t.Fatalf("ReadRequest failed: %v", err)
	}
	if hReq.Method != "POST" {
		t.Errorf("expected POST, got %q", hReq.Method)
	}
	if hReq.Host != "target.local" {
		t.Errorf("expected host target.local, got %q", hReq.Host)
	}
	if hReq.URL.Path != "/submit" {
		t.Errorf("expected path /submit, got %q", hReq.URL.Path)
	}
	// ReadRequest 后 URL.Host 应为空（Host 在 hReq.Host 字段中）
	if hReq.URL.Host != "" {
		t.Errorf("expected empty URL.Host after ReadRequest, got %q", hReq.URL.Host)
	}
}
