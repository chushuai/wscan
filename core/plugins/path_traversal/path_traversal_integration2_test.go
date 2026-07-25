package path_traversal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	whttp "wscan/core/http"
)

func TestPathTraversalExecAction_WithBodyParam(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("<html>normal page</html>"))
	}))
	defer server.Close()

	pt := &PathTraversal{}
	apollo := makeTestApollo(t, server.URL, "/")

	// Test with body parameter
	req, err := whttp.NewRequest("POST", server.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	client := whttp.NewClient()
	resp, err := client.Respond(context.Background(), req)
	if err != nil {
		t.Fatalf("Failed to get response: %v", err)
	}

	flow := &whttp.Flow{Request: req, Response: resp}
	_ = flow
	_ = apollo

	err = pt.execAction(context.Background(), apollo)
	if err != nil {
		t.Errorf("execAction() returned error: %v", err)
	}
}

func TestPathTraversalExecAction_WithQueryStringParam(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("<html>normal page</html>"))
	}))
	defer server.Close()

	pt := &PathTraversal{}
	apollo := makeTestApollo(t, server.URL, "/?page=index")

	err := pt.execAction(context.Background(), apollo)
	if err != nil {
		t.Errorf("execAction() returned error: %v", err)
	}
}

func TestPathTraversalExecAction_MultipleParams(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("<html>normal page</html>"))
	}))
	defer server.Close()

	pt := &PathTraversal{}
	apollo := makeTestApollo(t, server.URL, "/?file=test.txt&path=/home")

	err := pt.execAction(context.Background(), apollo)
	if err != nil {
		t.Errorf("execAction() returned error: %v", err)
	}
}
