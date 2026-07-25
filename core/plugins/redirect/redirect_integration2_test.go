package redirect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRedirectExecAction_WithGoToParam(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotoParam := r.URL.Query().Get("goto")
		if gotoParam != "" {
			w.Header().Set("Location", gotoParam)
			w.WriteHeader(303)
			return
		}
		w.WriteHeader(200)
		w.Write([]byte("<html>normal page</html>"))
	}))
	defer server.Close()

	p := &Redirect{}
	apollo := makeRedirectTestApollo(t, server.URL, "/?goto=/dashboard")

	err := p.execAction(context.Background(), apollo)
	if err != nil {
		t.Errorf("execAction() returned error: %v", err)
	}
}

func TestRedirectExecAction_NoRedirectResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always return 200, even for URL params
		w.WriteHeader(200)
		w.Write([]byte("<html>normal page</html>"))
	}))
	defer server.Close()

	p := &Redirect{}
	apollo := makeRedirectTestApollo(t, server.URL, "/?url=http://example.com")

	err := p.execAction(context.Background(), apollo)
	if err != nil {
		t.Errorf("execAction() returned error: %v", err)
	}
}

func TestRedirectExecAction_307Redirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		urlParam := r.URL.Query().Get("url")
		if urlParam != "" {
			w.Header().Set("Location", urlParam)
			w.WriteHeader(307)
			return
		}
		w.WriteHeader(200)
		w.Write([]byte("<html>normal page</html>"))
	}))
	defer server.Close()

	p := &Redirect{}
	apollo := makeRedirectTestApollo(t, server.URL, "/?url=http://example.com")

	err := p.execAction(context.Background(), apollo)
	if err != nil {
		t.Errorf("execAction() returned error: %v", err)
	}
}
