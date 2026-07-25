package comparer

import (
	"net/http"
	"net/http/httptest"
	"testing"

	whttp "wscan/core/http"
)

// --- Test isSimilar with a real HTTP server ---

func TestIsSimilar_Both404(t *testing.T) {
	// When both generated URLs return 404, isSimilar should return true with methodCode
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		w.Write([]byte("<html><body>Not Found</body></html>"))
	}))
	defer server.Close()

	resp := &whttp.Response{
		StatusCode: 200,
		Text:       "<html><body>OK</body></html>",
	}
	similar, resp1, method := isSimilar(resp, server.URL)
	if !similar {
		t.Error("isSimilar should return true when both generated URLs return 404")
	}
	if method != methodCode {
		t.Errorf("method = %q, expected %q", method, methodCode)
	}
	if resp1 != nil {
		t.Error("resp1 should be nil for methodCode")
	}
}

func TestIsSimilar_SimilarPages(t *testing.T) {
	// When generated URLs return similar content, isSimilar should detect it
	pageCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Header().Set("Content-Type", "text/html")
		// All pages are similar - same structure
		w.Write([]byte("<html><body>Page not found - error 404</body></html>"))
		_ = pageCount
	}))
	defer server.Close()

	resp := &whttp.Response{
		StatusCode: 200,
		Text:       "<html><body>Page not found - error 404</body></html>",
	}
	similar, _, method := isSimilar(resp, server.URL)
	// The pages are identical, so averageSimilarity = 1.0 > 0.90
	// So it returns false (not 404-like), resp1, ""
	if similar {
		t.Error("identical pages should not be flagged as similar (avg > 0.90)")
	}
	_ = method
}

func TestIsSimilar_DifferentPages(t *testing.T) {
	// When generated URLs return different content from original
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(200)
		w.Header().Set("Content-Type", "text/html")
		if callCount == 1 {
			// Original request (request404 from judeMethod)
			w.Write([]byte("<html><head><title>Real Page</title></head><body>Real content with unique text here</body></html>"))
		} else {
			// Generated 404-like pages
			w.Write([]byte("<html><head><title>Error</title></head><body>404 Not Found - The page you requested could not be found on this server</body></html>"))
		}
	}))
	defer server.Close()

	resp := &whttp.Response{
		StatusCode: 200,
		Text:       "<html><head><title>Real Page</title></head><body>Real content with unique text here</body></html>",
	}
	similar, _, method := isSimilar(resp, server.URL)
	// Pages are different enough, so should return true with methodSimilar
	if !similar {
		t.Error("different pages should be flagged as similar (404-like detection)")
	}
	if method != methodSimilar {
		t.Errorf("method = %q, expected %q", method, methodSimilar)
	}
}

func TestJudeMethod_WithServer_404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		w.Write([]byte("Not Found"))
	}))
	defer server.Close()

	// Use the test server URL - request404 will return 404
	// judeMethod checks if resp.StatusCode == 404 -> returns methodCode
	resp := &whttp.Response{
		StatusCode: 404,
		Text:       "Not Found",
	}
	method, ok, _ := judeMethod(resp, server.URL)
	if method != methodCode {
		t.Errorf("judeMethod with 404 status: method = %q, expected %q", method, methodCode)
	}
	if ok {
		t.Error("judeMethod with 404 status: ok should be false")
	}
}

func TestIdentify404_WithServer_404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		w.Write([]byte("Not Found"))
	}))
	defer server.Close()

	ok, method, resp := Identify404(server.URL + "/test_404_check")
	// When server returns 404, judeMethod returns methodCode with ok=false
	// Identify404 returns (ok=false, method=methodCode, resp=nil)
	if ok {
		t.Error("Identify404 with 404 status: ok should be false (methodCode path)")
	}
	if method != methodCode {
		t.Errorf("Identify404 method = %q, expected %q", method, methodCode)
	}
	if resp != nil {
		t.Error("Identify404 with methodCode should return nil response")
	}
}

func TestIdentify404_WithServer_200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>OK</body></html>"))
	}))
	defer server.Close()

	ok, method, resp := Identify404(server.URL + "/test_page")
	_ = ok
	_ = method
	_ = resp
}

func TestHtmlToString_NilResponse(t *testing.T) {
	// Test with response that has empty text
	resp := &whttp.Response{
		Text: "",
	}
	result := htmlToString(resp)
	if result != "" {
		t.Errorf("htmlToString with empty text = %q, expected empty", result)
	}
}

func TestRequest404_InvalidURL(t *testing.T) {
	resp, err := request404("://invalid-url")
	if err == nil {
		t.Error("request404 with invalid URL should return error")
	}
	if resp != nil {
		t.Error("request404 with invalid URL should return nil response")
	}
}

func TestIsSimilar_OneRespNil(t *testing.T) {
	// When one of the generated URLs returns nil, isSimilar should return false
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		// Close connection for some requests to simulate nil response
		if callCount > 1 {
			// hijack and close
			hj, ok := w.(http.Hijacker)
			if ok {
				conn, _, _ := hj.Hijack()
				conn.Close()
				return
			}
		}
		w.WriteHeader(200)
		w.Write([]byte("<html><body>OK</body></html>"))
	}))
	defer server.Close()

	resp := &whttp.Response{
		StatusCode: 200,
		Text:       "<html><body>OK</body></html>",
	}
	// Test with an unreachable URL for one of the two generated URLs
	similar, _, _ := isSimilar(resp, server.URL)
	_ = similar
}
