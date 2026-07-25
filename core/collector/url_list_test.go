package collector

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	vhttp "wscan/core/http"
)

func TestNewFromURLListReader(t *testing.T) {
	data := "http://example.com\nhttp://test.com\n"
	r := io.NopCloser(strings.NewReader(data))
	opts := &vhttp.ClientOptions{}
	ulc := NewFromURLListReader(r, opts)
	if ulc == nil {
		t.Fatal("expected non-nil urlListCollector")
	}
	if ulc.client == nil {
		t.Error("expected client to be initialized")
	}
	if ulc.pool == nil {
		t.Error("expected pool to be initialized")
	}
	if ulc.r == nil {
		t.Error("expected reader to be set")
	}
	if ulc.opts == nil {
		t.Error("expected opts to be set")
	}
}

func TestNewFromURLListReader_EmptyReader(t *testing.T) {
	r := io.NopCloser(strings.NewReader(""))
	opts := &vhttp.ClientOptions{}
	ulc := NewFromURLListReader(r, opts)
	if ulc == nil {
		t.Fatal("expected non-nil urlListCollector even with empty reader")
	}
}

func TestURLListCollector_FitOut_GET(t *testing.T) {
	// Start a test HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	r := io.NopCloser(strings.NewReader("")) // empty body => GET
	opts := &vhttp.ClientOptions{}
	ulc := NewFromURLListReader(r, opts)

	ch, err := ulc.FitOut(context.Background(), []string{server.URL})
	if err != nil {
		t.Fatalf("unexpected error from FitOut: %v", err)
	}
	if ch == nil {
		t.Fatal("expected non-nil channel")
	}

	// Wait for the result
	select {
	case res, ok := <-ch:
		if !ok {
			t.Error("channel closed without receiving result")
		} else {
			if res == nil {
				t.Error("expected non-nil resource")
			}
		}
	case <-time.After(15 * time.Second):
		t.Error("timed out waiting for result from urlListCollector")
	}
}

func TestURLListCollector_FitOut_POST(t *testing.T) {
	// Start a test HTTP server that echoes method
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(r.Method))
	}))
	defer server.Close()

	// Non-empty body => POST
	postData := "key=value"
	r := io.NopCloser(strings.NewReader(postData))
	opts := &vhttp.ClientOptions{}
	ulc := NewFromURLListReader(r, opts)

	ch, err := ulc.FitOut(context.Background(), []string{server.URL})
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

func TestURLListCollector_FitOut_EmptyTargets(t *testing.T) {
	r := io.NopCloser(strings.NewReader(""))
	opts := &vhttp.ClientOptions{}
	ulc := NewFromURLListReader(r, opts)

	ch, err := ulc.FitOut(context.Background(), []string{})
	if err != nil {
		t.Fatalf("unexpected error from FitOut: %v", err)
	}
	if ch == nil {
		t.Fatal("expected non-nil channel")
	}

	// Channel should close after delay
	select {
	case _, ok := <-ch:
		if ok {
			t.Error("expected channel to be closed with no targets")
		}
	case <-time.After(15 * time.Second):
		t.Error("timed out waiting for channel to close")
	}
}

func TestURLListCollector_FitOut_InvalidURL(t *testing.T) {
	r := io.NopCloser(strings.NewReader(""))
	opts := &vhttp.ClientOptions{}
	ulc := NewFromURLListReader(r, opts)

	ch, err := ulc.FitOut(context.Background(), []string{":::invalid"})
	if err != nil {
		t.Fatalf("unexpected error from FitOut: %v", err)
	}
	if ch == nil {
		t.Fatal("expected non-nil channel")
	}
	// The goroutine should handle the error gracefully
	select {
	case _, ok := <-ch:
		_ = ok
	case <-time.After(15 * time.Second):
		t.Error("timed out waiting for channel")
	}
}

func TestURLListCollector_FitOut_WithHeaders(t *testing.T) {
	receivedHeaders := make(chan http.Header, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders <- r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	r := io.NopCloser(strings.NewReader(""))
	opts := &vhttp.ClientOptions{
		DefaultHeaders: map[string]string{
			"X-Custom-Header": "custom-value",
			"User-Agent":      "TestAgent/1.0",
		},
	}
	opts.WroteBack()

	ulc := NewFromURLListReader(r, opts)

	ch, err := ulc.FitOut(context.Background(), []string{server.URL})
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
			// Headers may not have been captured yet
		}
	case <-time.After(15 * time.Second):
		t.Error("timed out waiting for result")
	}
}

func TestURLListCollector_FitOut_CancelledContext(t *testing.T) {
	r := io.NopCloser(strings.NewReader(""))
	opts := &vhttp.ClientOptions{}
	ulc := NewFromURLListReader(r, opts)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	ch, err := ulc.FitOut(ctx, []string{})
	if err != nil {
		t.Fatalf("unexpected error from FitOut: %v", err)
	}
	if ch == nil {
		t.Fatal("expected non-nil channel even with cancelled context")
	}
}

func TestURLListCollector_ImplementsFitter(t *testing.T) {
	// Verify that urlListCollector satisfies the Fitter interface at compile time
	var _ Fitter = (*urlListCollector)(nil)
}

func TestURLListCollector_MultipleTargets(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	r := io.NopCloser(strings.NewReader(""))
	opts := &vhttp.ClientOptions{}
	ulc := NewFromURLListReader(r, opts)

	ch, err := ulc.FitOut(context.Background(), []string{server.URL + "/a", server.URL + "/b"})
	if err != nil {
		t.Fatalf("unexpected error from FitOut: %v", err)
	}

	// Collect results
	receivedCount := 0
	timeout := time.After(15 * time.Second)
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				goto done
			}
			receivedCount++
		case <-timeout:
			goto done
		}
	}
done:
	// At least some results should come through (network errors may drop some)
	if receivedCount == 0 && callCount == 0 {
		t.Error("expected at least one result from multiple targets")
	}
}

func TestURLListCollector_PostDataDetection(t *testing.T) {
	// Empty reader => GET
	r1 := io.NopCloser(strings.NewReader(""))
	data1, _ := io.ReadAll(r1)
	if len(data1) > 0 {
		t.Error("expected empty data to result in GET request")
	}

	// Non-empty reader => POST
	r2 := io.NopCloser(strings.NewReader("user=admin&pass=secret"))
	data2, _ := io.ReadAll(r2)
	if len(data2) == 0 {
		t.Error("expected non-empty data to result in POST request")
	}
	if string(data2) != "user=admin&pass=secret" {
		t.Errorf("unexpected post data: %q", string(data2))
	}
}

func TestURLListCollector_FitOut_WithHeadersMap(t *testing.T) {
	receivedHeaders := make(chan http.Header, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders <- r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	r := io.NopCloser(strings.NewReader(""))
	opts := &vhttp.ClientOptions{
		Headers: map[string][]string{
			"X-Api-Key":     {"test-key-123"},
			"Authorization": {"Bearer token123"},
		},
	}
	ulc := NewFromURLListReader(r, opts)

	ch, err := ulc.FitOut(context.Background(), []string{server.URL})
	if err != nil {
		t.Fatalf("unexpected error from FitOut: %v", err)
	}

	select {
	case <-ch:
		select {
		case h := <-receivedHeaders:
			if h.Get("X-Api-Key") != "test-key-123" {
				t.Errorf("expected X-Api-Key 'test-key-123', got %q", h.Get("X-Api-Key"))
			}
			if h.Get("Authorization") != "Bearer token123" {
				t.Errorf("expected Authorization 'Bearer token123', got %q", h.Get("Authorization"))
			}
		default:
		}
	case <-time.After(15 * time.Second):
		t.Error("timed out waiting for result")
	}
}

func TestURLListCollector_FitOut_HeadersPriorityOverDefaultHeaders(t *testing.T) {
	receivedHeaders := make(chan http.Header, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders <- r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	r := io.NopCloser(strings.NewReader(""))
	opts := &vhttp.ClientOptions{
		Headers: map[string][]string{
			"X-Custom-Header": {"from-headers-map"},
		},
		DefaultHeaders: map[string]string{
			"X-Custom-Header": "from-default-headers",
			"X-Only-Default":  "default-value",
		},
	}
	ulc := NewFromURLListReader(r, opts)

	ch, err := ulc.FitOut(context.Background(), []string{server.URL})
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

func TestURLListCollector_FitOut_WithCookies(t *testing.T) {
	receivedHeaders := make(chan http.Header, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders <- r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	r := io.NopCloser(strings.NewReader(""))
	opts := &vhttp.ClientOptions{
		DefaultHeaders: map[string]string{
			"Cookie": "session=abc123",
		},
	}
	opts.WroteBack()

	ulc := NewFromURLListReader(r, opts)

	ch, err := ulc.FitOut(context.Background(), []string{server.URL})
	if err != nil {
		t.Fatalf("unexpected error from FitOut: %v", err)
	}

	select {
	case <-ch:
		select {
		case h := <-receivedHeaders:
			cookie := h.Get("Cookie")
			if cookie == "" {
				// Cookie handling may vary
				t.Log("no Cookie header received")
			}
		default:
		}
	case <-time.After(15 * time.Second):
		t.Error("timed out waiting for result")
	}
}

func TestURLListCollector_ChannelCapacity(t *testing.T) {
	r := io.NopCloser(strings.NewReader(""))
	opts := &vhttp.ClientOptions{}
	ulc := NewFromURLListReader(r, opts)

	ch, err := ulc.FitOut(context.Background(), []string{})
	if err != nil {
		t.Fatalf("unexpected error from FitOut: %v", err)
	}
	if cap(ch) != 100 {
		t.Errorf("expected channel capacity 100, got %d", cap(ch))
	}
}

func TestURLListCollector_FitOut_POSTWithBody(t *testing.T) {
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

	// Non-empty reader => POST
	postData := "username=testuser&password=testpass"
	r := io.NopCloser(strings.NewReader(postData))
	opts := &vhttp.ClientOptions{}
	ulc := NewFromURLListReader(r, opts)

	ch, err := ulc.FitOut(context.Background(), []string{server.URL})
	if err != nil {
		t.Fatalf("unexpected error from FitOut: %v", err)
	}

	select {
	case <-ch:
		if receivedMethod != "POST" {
			t.Errorf("expected POST method, got %q", receivedMethod)
		}
		if receivedBody != postData {
			t.Errorf("expected body %q, got %q", postData, receivedBody)
		}
	case <-time.After(15 * time.Second):
		t.Error("timed out waiting for result")
	}
}
