package redirect

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

func makeRedirectTestApollo(t *testing.T, serverURL string, queryParams string) *base.Apollo {
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

func TestRedirectExecAction_NoRedirectParam(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("<html>normal page</html>"))
	}))
	defer server.Close()

	p := &Redirect{}
	apollo := makeRedirectTestApollo(t, server.URL, "/?id=123")

	err := p.execAction(context.Background(), apollo)
	if err != nil {
		t.Errorf("execAction() returned error: %v", err)
	}
}

func TestRedirectExecAction_WithRedirectParam(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		urlParam := r.URL.Query().Get("url")
		if urlParam != "" {
			w.Header().Set("Location", urlParam)
			w.WriteHeader(302)
			return
		}
		w.WriteHeader(200)
		w.Write([]byte("<html>normal page</html>"))
	}))
	defer server.Close()

	p := &Redirect{}
	apollo := makeRedirectTestApollo(t, server.URL, "/?url=http://original.com")

	err := p.execAction(context.Background(), apollo)
	if err != nil {
		t.Errorf("execAction() returned error: %v", err)
	}
}

func TestRedirectExecAction_NoParams(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("<html>normal page</html>"))
	}))
	defer server.Close()

	p := &Redirect{}
	apollo := makeRedirectTestApollo(t, server.URL, "/")

	err := p.execAction(context.Background(), apollo)
	if err != nil {
		t.Errorf("execAction() with no params returned error: %v", err)
	}
}

func TestRedirectExecAction_NextParam(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextParam := r.URL.Query().Get("next")
		if nextParam != "" {
			w.Header().Set("Location", nextParam)
			w.WriteHeader(301)
			return
		}
		w.WriteHeader(200)
		w.Write([]byte("<html>normal page</html>"))
	}))
	defer server.Close()

	p := &Redirect{}
	apollo := makeRedirectTestApollo(t, server.URL, "/?next=/home")

	err := p.execAction(context.Background(), apollo)
	if err != nil {
		t.Errorf("execAction() returned error: %v", err)
	}
}
