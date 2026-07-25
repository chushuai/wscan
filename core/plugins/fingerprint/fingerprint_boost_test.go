package fingerprint

import (
	"context"
	nethttp "net/http"
	"net/http/httptest"
	"os"
	"testing"

	whttp "wscan/core/http"
	"wscan/core/plugins/base"
	"wscan/core/plugins/helper/knowledge"
	"wscan/core/utils/printer"
)

// ==================== ProcessFingerprint with context ====================

func TestBoostProcessFingerprint_WithCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ProcessFingerprint(ctx, nil)
}

// ==================== readDir with embedded FS ====================

func TestBoostReadDir_ValidDir(t *testing.T) {
	rules, err := readDir("technologies/wscan", template)
	if err != nil {
		t.Fatalf("readDir failed: %v", err)
	}
	if len(rules) == 0 {
		t.Error("expected at least one fingerprint rule")
	}
}

func TestBoostReadDir_InvalidDir(t *testing.T) {
	rules, err := readDir("nonexistent/path", template)
	if err == nil {
		t.Error("expected error for nonexistent directory")
	}
	if len(rules) != 0 {
		t.Errorf("expected empty rules for nonexistent dir, got %d", len(rules))
	}
}

// ==================== Fingerprint plugin interface ====================

func TestBoostFingerprint_PluginInterface(t *testing.T) {
	var _ base.Plugin = &Fingerprint{}
}

// ==================== execAction with real HTTP servers ====================

func TestBoostFingerprint_ExecAction_NonHTMLResponse(t *testing.T) {
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	p := &Fingerprint{}
	apollo := boostMakeTestApollo(t, server.URL)

	err := p.execAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error (may be expected for JSON): %v", err)
	}
}

func TestBoostFingerprint_ExecAction_NginxResponse(t *testing.T) {
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Server", "nginx/1.18.0")
		w.WriteHeader(200)
		w.Write([]byte(`<html><body>Welcome to nginx!</body></html>`))
	}))
	defer server.Close()

	p := &Fingerprint{}
	apollo := boostMakeTestApollo(t, server.URL)

	err := p.execAction(context.Background(), apollo)
	_ = err
}

func TestBoostFingerprint_ExecAction_ApacheResponse(t *testing.T) {
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Server", "Apache/2.4.41")
		w.WriteHeader(200)
		w.Write([]byte(`<html><body>Apache2 default page</body></html>`))
	}))
	defer server.Close()

	p := &Fingerprint{}
	apollo := boostMakeTestApollo(t, server.URL)

	err := p.execAction(context.Background(), apollo)
	_ = err
}

func TestBoostFingerprint_ExecAction_EmptyResponse(t *testing.T) {
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.WriteHeader(204)
	}))
	defer server.Close()

	p := &Fingerprint{}
	apollo := boostMakeTestApollo(t, server.URL)

	err := p.execAction(context.Background(), apollo)
	_ = err
}

// boostMakeTestApollo creates an Apollo with real HTTP response from test server
func boostMakeTestApollo(t *testing.T, serverURL string) *base.Apollo {
	t.Helper()
	req, err := whttp.NewRequest("GET", serverURL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	client := whttp.NewClient()
	resp, err := client.Respond(context.Background(), req)
	if err != nil {
		t.Fatalf("Failed to get response: %v", err)
	}

	flow := &whttp.Flow{Request: req, Response: resp}
	ab := &base.ApolloBase{
		HTTPClient: client,
		Output:     printer.NewTextPrinter(os.Stdout),
		KDB:        knowledge.NewKnowledgeDB(nil),
	}
	apollo := base.NewApollo(flow)
	apollo.ApolloBase = ab
	return apollo
}
