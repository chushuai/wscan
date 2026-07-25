package comparer

import (
	"net/http"
	"testing"

	whttp "wscan/core/http"
)

// --- getSetCookieKey and filterBody are empty stubs, just call them for coverage ---

func TestGetSetCookieKey(t *testing.T) {
	getSetCookieKey()
}

func TestFilterBody(t *testing.T) {
	filterBody()
}

// --- CompareResponse additional cases ---

func TestCompareResponse_SameContentType(t *testing.T) {
	resp1 := &whttp.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Text:       "<html><body>Hello</body></html>",
	}
	resp2 := &whttp.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Text:       "<html><body>World</body></html>",
	}
	ratio := CompareResponse(resp1, resp2)
	if ratio <= 0 || ratio > 1.0 {
		t.Errorf("CompareResponse for same type different body = %v, expected 0-1", ratio)
	}
}

func TestCompareResponse_SameStatusDifferentContentType(t *testing.T) {
	resp1 := &whttp.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Text:       "<html><body>Hello</body></html>",
	}
	resp2 := &whttp.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Text:       `{"key":"value"}`,
	}
	ratio := CompareResponse(resp1, resp2)
	if ratio != 0 {
		t.Errorf("CompareResponse with different content types should return 0, got %v", ratio)
	}
}

// --- judeMethod additional branches ---

func TestJudeMethod_Non404_TitleBranch(t *testing.T) {
	// StatusCode != 404, bodyTitle returns false, then isSimilar is called
	// With invalid URL, isSimilar will fail and return false
	resp := &whttp.Response{
		StatusCode: 200,
		Text:       "<html><head><title>404 Not Found</title></head><body>Not found</body></html>",
	}
	method, ok, resp1 := judeMethod(resp, "http://nonexistent.invalid/path")
	if ok {
		t.Error("judeMethod with invalid URL should return ok=false")
	}
	if method != "" {
		t.Errorf("judeMethod method=%q, expected empty since isSimilar fails", method)
	}
	if resp1 != nil {
		t.Error("judeMethod should return nil response when isSimilar fails")
	}
}

func TestJudeMethod_200Status(t *testing.T) {
	resp := &whttp.Response{
		StatusCode: 200,
		Text:       "<html><body>OK</body></html>",
	}
	_, ok, _ := judeMethod(resp, "http://nonexistent.invalid/path")
	if ok {
		t.Error("judeMethod with 200 status and bad URL should return ok=false")
	}
}

// --- isSimilar with invalid URL ---

func TestIsSimilar_InvalidURL(t *testing.T) {
	resp := &whttp.Response{
		StatusCode: 200,
		Text:       "<html><body>OK</body></html>",
	}
	similar, resp1, method := isSimilar(resp, "://invalid-url")
	if similar {
		t.Error("isSimilar with invalid URL should return false")
	}
	if resp1 != nil {
		t.Error("isSimilar should return nil response for invalid URL")
	}
	if method != "" {
		t.Errorf("isSimilar method=%q, expected empty for invalid URL", method)
	}
}

// --- Identify404 additional cases ---

func TestIdentify404_ValidURL_404(t *testing.T) {
	// This will make a real HTTP request, so we test with a URL that will likely fail
	// The function should handle errors gracefully
	ok, method, resp := Identify404("http://127.0.0.1:1/nonexistent_path_test")
	// Can't assert much since it depends on network, just ensure no panic
	_ = ok
	_ = method
	_ = resp
}
