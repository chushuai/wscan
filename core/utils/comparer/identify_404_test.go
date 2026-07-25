package comparer

import (
	"net/http"
	"strings"
	"testing"

	whttp "wscan/core/http"
)

func TestHtmlToString(t *testing.T) {
	resp := &whttp.Response{
		Text: "<html><body>Hello World</body></html>",
	}
	result := htmlToString(resp)
	if result != "<html><body>Hello World</body></html>" {
		t.Errorf("htmlToString() = %q, expected original text", result)
	}
}

func TestHtmlToString_Empty(t *testing.T) {
	resp := &whttp.Response{
		Text: "",
	}
	result := htmlToString(resp)
	if result != "" {
		t.Errorf("htmlToString() = %q, expected empty string", result)
	}
}

func TestHtmlToString_LargeContent(t *testing.T) {
	largeText := strings.Repeat("a", 10000)
	resp := &whttp.Response{
		Text: largeText,
	}
	result := htmlToString(resp)
	if len(result) != 10000 {
		t.Errorf("htmlToString() returned %d bytes, expected 10000", len(result))
	}
}

func TestBodyTitle(t *testing.T) {
	// bodyTitle currently always returns false (hardcoded)
	result := bodyTitle(nil)
	if result != false {
		t.Error("bodyTitle() should return false (currently hardcoded)")
	}
}

func TestBodyTitle_WithResponse(t *testing.T) {
	resp := &whttp.Response{
		Text: "<html><head><title>Test Title</title></head><body>Content</body></html>",
	}
	result := bodyTitle(resp)
	if result != false {
		t.Error("bodyTitle() should return false (currently hardcoded)")
	}
}

func TestIs3xx(t *testing.T) {
	if is3xx() != false {
		t.Error("is3xx() should return false")
	}
}

func TestIdentify404_InvalidURL(t *testing.T) {
	ok, method, resp := Identify404("not-a-valid-url-format")
	if ok {
		t.Error("Identify404 with invalid URL should return ok=false")
	}
	if method != "" {
		t.Errorf("Identify404 with invalid URL method = %q, expected empty", method)
	}
	if resp != nil {
		t.Error("Identify404 with invalid URL should return nil response")
	}
}

func TestJudeMethod_404Status(t *testing.T) {
	// When response has 404 status code
	resp := &whttp.Response{
		StatusCode: 404,
	}
	method, ok, _ := judeMethod(resp, "http://example.com")
	if method != methodCode {
		t.Errorf("judeMethod with 404 status: method = %q, expected %q", method, methodCode)
	}
	if ok {
		t.Error("judeMethod with 404 status: ok should be false")
	}
}

func TestJudeMethod_Non404Status(t *testing.T) {
	// When response has non-404 status code, it goes to bodyTitle (returns false)
	// then tries isSimilar (which makes HTTP requests, will fail with bad URL)
	resp := &whttp.Response{
		StatusCode: 200,
		Text:       "<html><body>Some content</body></html>",
	}
	_, ok, _ := judeMethod(resp, "http://nonexistent.invalid/path")
	// Since isSimilar will fail to request, it returns false, "", nil
	if ok {
		t.Error("judeMethod should return ok=false when isSimilar fails")
	}
}

func TestCompareResponse_DifferentContentType(t *testing.T) {
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
		t.Errorf("CompareResponse with different content types = %v, expected 0", ratio)
	}
}

func TestCompareResponse_DifferentStatusCode(t *testing.T) {
	resp1 := &whttp.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Text:       "<html><body>Hello</body></html>",
	}
	resp2 := &whttp.Response{
		StatusCode: 404,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Text:       "<html><body>Not Found</body></html>",
	}

	ratio := CompareResponse(resp1, resp2)
	if ratio != 0 {
		t.Errorf("CompareResponse with different status codes = %v, expected 0", ratio)
	}
}

func TestCompareResponse_Identical(t *testing.T) {
	html := "<html><head><title>Test</title></head><body><p>Hello</p></body></html>"
	resp1 := &whttp.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Text:       html,
	}
	resp2 := &whttp.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Text:       html,
	}

	ratio := CompareResponse(resp1, resp2)
	if ratio != 1.0 {
		t.Errorf("CompareResponse for identical = %v, expected 1.0", ratio)
	}
}

func TestCompareResponse_Similar(t *testing.T) {
	resp1 := &whttp.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Text:       "<html><head><title>Page</title></head><body><div>A</div><p>Shared</p></body></html>",
	}
	resp2 := &whttp.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Text:       "<html><head><title>Page</title></head><body><div>B</div><p>Shared</p></body></html>",
	}

	ratio := CompareResponse(resp1, resp2)
	if ratio <= 0 || ratio > 1.0 {
		t.Errorf("CompareResponse for similar = %v, expected between 0 and 1", ratio)
	}
}

func TestCompareResponse_EmptyBodies(t *testing.T) {
	resp1 := &whttp.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Text:       "",
	}
	resp2 := &whttp.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Text:       "",
	}

	ratio := CompareResponse(resp1, resp2)
	if ratio != 1.0 {
		t.Errorf("CompareResponse for empty bodies = %v, expected 1.0", ratio)
	}
}
