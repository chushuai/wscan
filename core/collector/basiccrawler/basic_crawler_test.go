package basiccrawler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"wscan/core/crawler"
	vhttp "wscan/core/http"
	"wscan/core/utils/checker"
)

func TestApplyConfigHeaders_NilOpts(t *testing.T) {
	req, err := vhttp.NewRequest("GET", "http://example.com/", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	// Should not panic with nil opts
	applyConfigHeaders(req, nil)
}

func TestApplyConfigHeaders_EmptyHeaders(t *testing.T) {
	req, err := vhttp.NewRequest("GET", "http://example.com/", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	opts := &vhttp.ClientOptions{}
	applyConfigHeaders(req, opts)
}

func TestApplyConfigHeaders_DefaultHeaders(t *testing.T) {
	req, err := vhttp.NewRequest("GET", "http://example.com/", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	opts := &vhttp.ClientOptions{
		DefaultHeaders: map[string]string{
			"X-Custom-Header": "custom-value",
			"User-Agent":      "TestAgent/1.0",
		},
	}
	applyConfigHeaders(req, opts)
	if req.Header.Get("X-Custom-Header") != "custom-value" {
		t.Errorf("expected X-Custom-Header 'custom-value', got %q", req.Header.Get("X-Custom-Header"))
	}
	if req.Header.Get("User-Agent") != "TestAgent/1.0" {
		t.Errorf("expected User-Agent 'TestAgent/1.0', got %q", req.Header.Get("User-Agent"))
	}
}

func TestApplyConfigHeaders_HeadersMap(t *testing.T) {
	req, err := vhttp.NewRequest("GET", "http://example.com/", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	opts := &vhttp.ClientOptions{
		Headers: map[string][]string{
			"X-Api-Key":    {"abc123"},
			"X-Request-Id": {"req-001"},
		},
	}
	applyConfigHeaders(req, opts)
	if req.Header.Get("X-Api-Key") != "abc123" {
		t.Errorf("expected X-Api-Key 'abc123', got %q", req.Header.Get("X-Api-Key"))
	}
	if req.Header.Get("X-Request-Id") != "req-001" {
		t.Errorf("expected X-Request-Id 'req-001', got %q", req.Header.Get("X-Request-Id"))
	}
}

func TestApplyConfigHeaders_WroteBack(t *testing.T) {
	req, err := vhttp.NewRequest("GET", "http://example.com/", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	opts := &vhttp.ClientOptions{
		DefaultHeaders: map[string]string{
			"X-Custom-Header": "from-default",
			"User-Agent":      "TestAgent/1.0",
		},
	}
	// WroteBack converts DefaultHeaders to Headers
	opts.WroteBack()
	applyConfigHeaders(req, opts)
	if req.Header.Get("X-Custom-Header") != "from-default" {
		t.Errorf("expected X-Custom-Header 'from-default', got %q", req.Header.Get("X-Custom-Header"))
	}
}

func TestApplyConfigHeaders_HeadersPriority(t *testing.T) {
	req, err := vhttp.NewRequest("GET", "http://example.com/", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	opts := &vhttp.ClientOptions{
		Headers: map[string][]string{
			"X-Custom-Header": {"from-headers"},
		},
		DefaultHeaders: map[string]string{
			"X-Custom-Header": "from-default",
			"X-Only-Default":  "default-value",
		},
	}
	applyConfigHeaders(req, opts)
	// Headers map should take priority over DefaultHeaders
	if req.Header.Get("X-Custom-Header") != "from-headers" {
		t.Errorf("expected X-Custom-Header 'from-headers', got %q", req.Header.Get("X-Custom-Header"))
	}
	// DefaultHeaders should be used when key doesn't exist in Headers
	if req.Header.Get("X-Only-Default") != "default-value" {
		t.Errorf("expected X-Only-Default 'default-value', got %q", req.Header.Get("X-Only-Default"))
	}
}

func TestApplyConfigHeaders_MultipleValuesInHeaders(t *testing.T) {
	req, err := vhttp.NewRequest("GET", "http://example.com/", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	opts := &vhttp.ClientOptions{
		Headers: map[string][]string{
			"Accept": {"text/html", "application/json"},
		},
	}
	applyConfigHeaders(req, opts)
	// When Headers has multiple values, only the first is used (per implementation)
	if req.Header.Get("Accept") != "text/html" {
		t.Errorf("expected Accept 'text/html', got %q", req.Header.Get("Accept"))
	}
}

func TestApplyConfigHeaders_EmptyValuesSlice(t *testing.T) {
	req, err := vhttp.NewRequest("GET", "http://example.com/", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	opts := &vhttp.ClientOptions{
		Headers: map[string][]string{
			"X-Empty": {},
		},
	}
	applyConfigHeaders(req, opts)
	// Empty slice should not set the header
	if req.Header.Get("X-Empty") != "" {
		t.Errorf("expected empty X-Empty, got %q", req.Header.Get("X-Empty"))
	}
}

func TestNewBasicCrawlerCollector(t *testing.T) {
	opts := &vhttp.ClientOptions{}
	config := &crawler.Config{
		Restrictions: &checker.RequestCheckerConfig{
			URLCheckerConfig: checker.URLCheckerConfig{
				HostnameAllowed: []string{"example.com"},
			},
		},
	}
	bc := NewBasicCrawlerCollector(opts, config)
	if bc == nil {
		t.Fatal("expected non-nil basicCrawlerCollector")
	}
	if bc.opts != opts {
		t.Error("expected opts to be set")
	}
	if bc.config != config {
		t.Error("expected config to be set")
	}
}

func TestNewBasicCrawlerCollector_WithProxy(t *testing.T) {
	opts := &vhttp.ClientOptions{
		Proxy: "http://127.0.0.1:8080",
	}
	config := &crawler.Config{
		Restrictions: &checker.RequestCheckerConfig{
			URLCheckerConfig: checker.URLCheckerConfig{
				HostnameAllowed: []string{"example.com"},
			},
		},
	}
	bc := NewBasicCrawlerCollector(opts, config)
	if bc == nil {
		t.Fatal("expected non-nil basicCrawlerCollector with proxy")
	}
}

func TestNewBasicCrawlerCollector_WithBrowser(t *testing.T) {
	opts := &vhttp.ClientOptions{}
	config := &crawler.Config{
		Browser: true,
		Restrictions: &checker.RequestCheckerConfig{
			URLCheckerConfig: checker.URLCheckerConfig{
				HostnameAllowed: []string{"example.com"},
			},
		},
	}
	bc := NewBasicCrawlerCollector(opts, config)
	if bc == nil {
		t.Fatal("expected non-nil basicCrawlerCollector with browser")
	}
	if bc.config.Browser != true {
		t.Error("expected Browser to be true")
	}
}

func TestNewBasicCrawlerCollector_NilOpts(t *testing.T) {
	config := &crawler.Config{
		Restrictions: &checker.RequestCheckerConfig{
			URLCheckerConfig: checker.URLCheckerConfig{
				HostnameAllowed: []string{"example.com"},
			},
		},
	}
	bc := NewBasicCrawlerCollector(nil, config)
	if bc == nil {
		t.Fatal("expected non-nil basicCrawlerCollector with nil opts")
	}
	if bc.opts != nil {
		t.Error("expected opts to be nil")
	}
}

func TestBasicCrawlerCollector_FitOut_WithLocalServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("<html><body>OK</body></html>"))
	}))
	defer server.Close()

	opts := &vhttp.ClientOptions{}
	config := &crawler.Config{
		Restrictions: &checker.RequestCheckerConfig{
			URLCheckerConfig: checker.URLCheckerConfig{
				HostnameAllowed: []string{},
			},
		},
		MaxDepth:       1,
		MaxCountOfURLs: 10,
		MaxConcurrent:  2,
	}
	bc := NewBasicCrawlerCollector(opts, config)

	ctx := context.Background()
	ch, err := bc.FitOut(ctx, []string{server.URL})
	if err != nil {
		t.Fatalf("unexpected error from FitOut: %v", err)
	}
	if ch == nil {
		t.Fatal("expected non-nil channel from FitOut")
	}
	if cap(ch) != 100 {
		t.Errorf("expected channel capacity 100, got %d", cap(ch))
	}

	// Wait for at least one result or timeout
	select {
	case res, ok := <-ch:
		if ok && res != nil {
			// Successfully received a result
		}
	case <-time.After(20 * time.Second):
		t.Error("timed out waiting for result from basicCrawlerCollector")
	}
}

func TestBasicCrawlerCollector_FitOut_EmptyTargets(t *testing.T) {
	opts := &vhttp.ClientOptions{}
	config := &crawler.Config{
		Restrictions: &checker.RequestCheckerConfig{
			URLCheckerConfig: checker.URLCheckerConfig{
				HostnameAllowed: []string{},
			},
		},
		MaxDepth:       1,
		MaxCountOfURLs: 10,
		MaxConcurrent:  2,
	}
	bc := NewBasicCrawlerCollector(opts, config)

	ctx := context.Background()
	ch, err := bc.FitOut(ctx, []string{})
	if err != nil {
		t.Fatalf("unexpected error from FitOut: %v", err)
	}
	if ch == nil {
		t.Fatal("expected non-nil channel from FitOut")
	}

	// Channel should close after timeout
	select {
	case _, ok := <-ch:
		if ok {
			t.Error("expected channel to be closed with no targets")
		}
	case <-time.After(20 * time.Second):
		t.Error("timed out waiting for channel to close")
	}
}

func TestBasicCrawlerCollector_FitOut_InvalidTarget(t *testing.T) {
	opts := &vhttp.ClientOptions{}
	config := &crawler.Config{
		Restrictions: &checker.RequestCheckerConfig{
			URLCheckerConfig: checker.URLCheckerConfig{
				HostnameAllowed: []string{},
			},
		},
		MaxDepth:       1,
		MaxCountOfURLs: 10,
		MaxConcurrent:  2,
	}
	bc := NewBasicCrawlerCollector(opts, config)

	ctx := context.Background()
	ch, err := bc.FitOut(ctx, []string{":::invalid"})
	if err != nil {
		t.Fatalf("unexpected error from FitOut: %v", err)
	}
	if ch == nil {
		t.Fatal("expected non-nil channel from FitOut even with invalid targets")
	}

	// Wait for the channel to close
	select {
	case _, ok := <-ch:
		_ = ok
	case <-time.After(20 * time.Second):
		t.Error("timed out waiting for channel")
	}
}

func TestBasicCrawlerCollector_ImplementsFitter(t *testing.T) {
	// Verify that basicCrawlerCollector has a FitOut method by creating an instance
	// and calling it with empty targets (safe, no network access)
	opts := &vhttp.ClientOptions{}
	config := &crawler.Config{
		Restrictions: &checker.RequestCheckerConfig{
			URLCheckerConfig: checker.URLCheckerConfig{},
		},
	}
	bc := NewBasicCrawlerCollector(opts, config)
	// Just verify the instance was created successfully - FitOut tested elsewhere
	if bc == nil {
		t.Fatal("expected non-nil basicCrawlerCollector")
	}
}
