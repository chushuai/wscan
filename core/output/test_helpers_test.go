package output

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// mustParseURL is a test helper that parses a URL or fails the test.
func mustParseURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic("mustParseURL: " + err.Error())
	}
	return u
}

// containsSubstring checks if s contains substr.
func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && contains(s, substr))
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// newTestServer creates an httptest.Server that captures POST body.
func newTestServer(t *testing.T, onBody func([]byte)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		body := make([]byte, r.ContentLength)
		if r.ContentLength > 0 {
			n, err := r.Body.Read(body)
			if err != nil && n == 0 {
				t.Errorf("failed to read body: %v", err)
			}
			body = body[:n]
		}
		onBody(body)
		w.WriteHeader(http.StatusOK)
	}))
}
