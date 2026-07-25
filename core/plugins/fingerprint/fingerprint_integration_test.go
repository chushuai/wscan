package fingerprint

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	whttp "wscan/core/http"
	"wscan/core/plugins/base"
	"wscan/core/plugins/helper/knowledge"
	"wscan/core/utils/printer"
)

func makeFingerprintTestApollo(t *testing.T, serverURL string) *base.Apollo {
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

func TestFingerprintExecAction_Basic(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		w.WriteHeader(200)
		w.Write([]byte("<html>normal page</html>"))
	}))
	defer server.Close()

	p := &Fingerprint{}
	apollo := makeFingerprintTestApollo(t, server.URL)

	err := p.execAction(context.Background(), apollo)
	if err != nil {
		t.Errorf("execAction() returned error: %v", err)
	}
}

func TestFingerprintExecAction_WithFingerprintMatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache-Coyote/1.1")
		w.WriteHeader(200)
		w.Write([]byte("<html><title>Apache Tomcat</title></html>"))
	}))
	defer server.Close()

	p := &Fingerprint{}
	apollo := makeFingerprintTestApollo(t, server.URL)

	err := p.execAction(context.Background(), apollo)
	if err != nil {
		t.Errorf("execAction() returned error: %v", err)
	}
}

func TestFingerprintExecAction_NoMatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("<html>generic response</html>"))
	}))
	defer server.Close()

	p := &Fingerprint{}
	apollo := makeFingerprintTestApollo(t, server.URL)

	err := p.execAction(context.Background(), apollo)
	if err != nil {
		t.Errorf("execAction() returned error: %v", err)
	}
}
