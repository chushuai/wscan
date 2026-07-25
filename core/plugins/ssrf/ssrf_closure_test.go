package ssrf

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	wscan_http "wscan/core/http"
	"wscan/core/plugins/base"
	"wscan/core/reverse"
	"wscan/core/utils/printer"
)

// ==================== Mock printer ====================

type ssrfCovTestPrinter struct{}

func (p *ssrfCovTestPrinter) Print(v any) error { return nil }
func (p *ssrfCovTestPrinter) Close() error      { return nil }
func (p *ssrfCovTestPrinter) AddInterceptor(func(any) (any, error)) printer.Printer {
	return p
}
func (p *ssrfCovTestPrinter) LogSubdomain(any) error { return nil }
func (p *ssrfCovTestPrinter) LogVuln(any) error      { return nil }

// ==================== ssrfReflectFinger CheckAction ====================

func TestSSRFReflectFinger_CheckAction_WithURLParam(t *testing.T) {
	f := ssrfReflectFinger()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "OK")
	}))
	defer ts.Close()

	tsURL, _ := url.Parse(ts.URL)
	testURL := fmt.Sprintf("http://%s/page?url=http://example.com", tsURL.Host)
	req, _ := wscan_http.NewRequest("GET", testURL, nil)
	flow := &wscan_http.Flow{Request: req, Response: &wscan_http.Response{StatusCode: 200}}

	ab := base.NewApollo(flow)
	ab.ApolloBase.Output = &ssrfCovTestPrinter{}
	ab.ApolloBase.HTTPClient = wscan_http.NewClient()
	ab.ApolloBase.Reverse = reverse.NewReverse(&reverse.Config{
		Token:      "test-token",
		DBFilePath: t.TempDir() + "/reverse.db",
		HTTPServerConfig: reverse.HTTPServerConfig{
			Enabled:    true,
			ListenIP:   "127.0.0.1",
			ListenPort: "0",
		},
		DNSServerConfig: reverse.DNSServerConfig{Enabled: false},
	})

	if ab.Reverse == nil {
		t.Skip("Reverse server not available, skipping test")
	}

	err := f.CheckAction(context.Background(), ab)
	_ = err
}

func TestSSRFReflectFinger_CheckAction_NoURLParams(t *testing.T) {
	f := ssrfReflectFinger()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "OK")
	}))
	defer ts.Close()

	tsURL, _ := url.Parse(ts.URL)
	testURL := fmt.Sprintf("http://%s/page?id=123", tsURL.Host)
	req, _ := wscan_http.NewRequest("GET", testURL, nil)
	flow := &wscan_http.Flow{Request: req, Response: &wscan_http.Response{StatusCode: 200}}

	ab := base.NewApollo(flow)
	ab.ApolloBase.Output = &ssrfCovTestPrinter{}
	ab.ApolloBase.HTTPClient = wscan_http.NewClient()
	ab.ApolloBase.Reverse = reverse.NewReverse(&reverse.Config{
		Token:      "test-token",
		DBFilePath: t.TempDir() + "/reverse.db",
		HTTPServerConfig: reverse.HTTPServerConfig{
			Enabled:    true,
			ListenIP:   "127.0.0.1",
			ListenPort: "0",
		},
		DNSServerConfig: reverse.DNSServerConfig{Enabled: false},
	})

	if ab.Reverse == nil {
		t.Skip("Reverse server not available, skipping test")
	}

	err := f.CheckAction(context.Background(), ab)
	_ = err
}

func TestSSRFReflectFinger_CheckAction_MultipleURLParams(t *testing.T) {
	f := ssrfReflectFinger()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "OK")
	}))
	defer ts.Close()

	tsURL, _ := url.Parse(ts.URL)
	testURL := fmt.Sprintf("http://%s/page?url=http://a.com&redirect=http://b.com", tsURL.Host)
	req, _ := wscan_http.NewRequest("GET", testURL, nil)
	flow := &wscan_http.Flow{Request: req, Response: &wscan_http.Response{StatusCode: 200}}

	ab := base.NewApollo(flow)
	ab.ApolloBase.Output = &ssrfCovTestPrinter{}
	ab.ApolloBase.HTTPClient = wscan_http.NewClient()
	ab.ApolloBase.Reverse = reverse.NewReverse(&reverse.Config{
		Token:      "test-token",
		DBFilePath: t.TempDir() + "/reverse.db",
		HTTPServerConfig: reverse.HTTPServerConfig{
			Enabled:    true,
			ListenIP:   "127.0.0.1",
			ListenPort: "0",
		},
		DNSServerConfig: reverse.DNSServerConfig{Enabled: false},
	})

	if ab.Reverse == nil {
		t.Skip("Reverse server not available, skipping test")
	}

	err := f.CheckAction(context.Background(), ab)
	_ = err
}

func TestSSRFReflectFinger_CheckAction_HTTPError(t *testing.T) {
	f := ssrfReflectFinger()

	// Use unreachable port
	testURL := "http://127.0.0.1:1/page?url=http://example.com"
	req, _ := wscan_http.NewRequest("GET", testURL, nil)
	flow := &wscan_http.Flow{Request: req, Response: &wscan_http.Response{StatusCode: 200}}

	ab := base.NewApollo(flow)
	ab.ApolloBase.Output = &ssrfCovTestPrinter{}
	ab.ApolloBase.HTTPClient = wscan_http.NewClient()
	ab.ApolloBase.Reverse = reverse.NewReverse(&reverse.Config{
		Token:      "test-token",
		DBFilePath: t.TempDir() + "/reverse.db",
		HTTPServerConfig: reverse.HTTPServerConfig{
			Enabled:    true,
			ListenIP:   "127.0.0.1",
			ListenPort: "0",
		},
		DNSServerConfig: reverse.DNSServerConfig{Enabled: false},
	})

	if ab.Reverse == nil {
		t.Skip("Reverse server not available, skipping test")
	}

	err := f.CheckAction(context.Background(), ab)
	_ = err
}

// ==================== internalServiceFinger CheckAction ====================

func TestInternalServiceFinger_CheckAction_WithURLParam(t *testing.T) {
	f := internalServiceFinger()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, `{"cluster_name":"test","lucene_version":"8.0"}`)
	}))
	defer ts.Close()

	tsURL, _ := url.Parse(ts.URL)
	testURL := fmt.Sprintf("http://%s/page?url=http://example.com", tsURL.Host)
	req, _ := wscan_http.NewRequest("GET", testURL, nil)
	flow := &wscan_http.Flow{Request: req, Response: &wscan_http.Response{StatusCode: 200}}

	ab := base.NewApollo(flow)
	ab.ApolloBase.Output = &ssrfCovTestPrinter{}
	ab.ApolloBase.HTTPClient = wscan_http.NewClient()

	err := f.CheckAction(context.Background(), ab)
	_ = err
}

func TestInternalServiceFinger_CheckAction_NoURLParams(t *testing.T) {
	f := internalServiceFinger()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "OK")
	}))
	defer ts.Close()

	tsURL, _ := url.Parse(ts.URL)
	testURL := fmt.Sprintf("http://%s/page?id=123", tsURL.Host)
	req, _ := wscan_http.NewRequest("GET", testURL, nil)
	flow := &wscan_http.Flow{Request: req, Response: &wscan_http.Response{StatusCode: 200}}

	ab := base.NewApollo(flow)
	ab.ApolloBase.Output = &ssrfCovTestPrinter{}
	ab.ApolloBase.HTTPClient = wscan_http.NewClient()

	err := f.CheckAction(context.Background(), ab)
	_ = err
}

func TestInternalServiceFinger_CheckAction_HTTPError(t *testing.T) {
	f := internalServiceFinger()

	testURL := "http://127.0.0.1:1/page?url=http://example.com"
	req, _ := wscan_http.NewRequest("GET", testURL, nil)
	flow := &wscan_http.Flow{Request: req, Response: &wscan_http.Response{StatusCode: 200}}

	ab := base.NewApollo(flow)
	ab.ApolloBase.Output = &ssrfCovTestPrinter{}
	ab.ApolloBase.HTTPClient = wscan_http.NewClient()

	err := f.CheckAction(context.Background(), ab)
	_ = err
}

func TestInternalServiceFinger_CheckAction_NoMatch(t *testing.T) {
	f := internalServiceFinger()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "Normal page content")
	}))
	defer ts.Close()

	tsURL, _ := url.Parse(ts.URL)
	testURL := fmt.Sprintf("http://%s/page?url=http://example.com", tsURL.Host)
	req, _ := wscan_http.NewRequest("GET", testURL, nil)
	flow := &wscan_http.Flow{Request: req, Response: &wscan_http.Response{StatusCode: 200}}

	ab := base.NewApollo(flow)
	ab.ApolloBase.Output = &ssrfCovTestPrinter{}
	ab.ApolloBase.HTTPClient = wscan_http.NewClient()

	err := f.CheckAction(context.Background(), ab)
	_ = err
}
