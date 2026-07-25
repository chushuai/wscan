package path_traversal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	whttp "wscan/core/http"
	"wscan/core/plugins/base"
	"wscan/core/utils/printer"
)

func makeTestApollo(t *testing.T, serverURL string, queryParams string) *base.Apollo {
	t.Helper()
	req, err := whttp.NewRequest("GET", serverURL+queryParams, nil)
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
	}
	apollo := base.NewApollo(flow)
	apollo.ApolloBase = ab
	return apollo
}

func TestPathTraversalExecAction_Basic(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("<html>normal page</html>"))
	}))
	defer server.Close()

	pt := &PathTraversal{}
	apollo := makeTestApollo(t, server.URL, "?file=test.txt")

	err := pt.execAction(context.Background(), apollo)
	if err != nil {
		t.Errorf("execAction() returned error: %v", err)
	}
}

func TestPathTraversalExecAction_VulnerableResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fileParam := r.URL.Query().Get("file")
		if fileParam != "" && fileParam != "test.txt" {
			w.WriteHeader(200)
			w.Write([]byte("root:x:0:0:root:/root:/bin/bash"))
			return
		}
		w.WriteHeader(200)
		w.Write([]byte("<html>normal page</html>"))
	}))
	defer server.Close()

	pt := &PathTraversal{}
	apollo := makeTestApollo(t, server.URL, "?file=test.txt")

	err := pt.execAction(context.Background(), apollo)
	if err != nil {
		t.Errorf("execAction() returned error: %v", err)
	}
}

func TestPathTraversalExecAction_NoParams(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("<html>normal page</html>"))
	}))
	defer server.Close()

	pt := &PathTraversal{}
	apollo := makeTestApollo(t, server.URL, "/")

	err := pt.execAction(context.Background(), apollo)
	if err != nil {
		t.Errorf("execAction() with no params returned error: %v", err)
	}
}
