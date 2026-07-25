package http

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestResponse_IsImage(t *testing.T) {
	tests := []struct {
		contentType string
		expected    bool
	}{
		{"image/png", true},
		{"image/jpeg", true},
		{"Image/GIF", true}, // case insensitive
		{"text/html", false},
		{"", false},
	}

	for _, tt := range tests {
		r := &Response{
			Header: http.Header{"Content-Type": {tt.contentType}},
		}
		result := r.IsImage()
		if result != tt.expected {
			t.Errorf("IsImage() with Content-Type %q = %v, want %v", tt.contentType, result, tt.expected)
		}
	}
}

func TestResponse_IsText(t *testing.T) {
	tests := []struct {
		contentType string
		expected    bool
	}{
		{"text/html", true},
		{"text/plain", true},
		{"TEXT/XML", true}, // case insensitive
		{"application/json", false},
		{"", false},
	}

	for _, tt := range tests {
		r := &Response{
			Header: http.Header{"Content-Type": {tt.contentType}},
		}
		result := r.IsText()
		if result != tt.expected {
			t.Errorf("IsText() with Content-Type %q = %v, want %v", tt.contentType, result, tt.expected)
		}
	}
}

func TestResponse_GetEncoding(t *testing.T) {
	r := &Response{encoding: "utf-8"}
	if r.GetEncoding() != "utf-8" {
		t.Errorf("GetEncoding() = %q, want %q", r.GetEncoding(), "utf-8")
	}
}

func TestResponse_GetContentType(t *testing.T) {
	r := &Response{
		Header: http.Header{"Content-Type": {"text/html; charset=utf-8"}},
	}
	if r.GetContentType() != "text/html; charset=utf-8" {
		t.Errorf("GetContentType() = %q, want %q", r.GetContentType(), "text/html; charset=utf-8")
	}
}

func TestResponse_GetHeader(t *testing.T) {
	r := &Response{
		Header: http.Header{"X-Custom": {"test-value"}},
	}
	if r.GetHeader("X-Custom") != "test-value" {
		t.Errorf("GetHeader() = %q, want %q", r.GetHeader("X-Custom"), "test-value")
	}
	if r.GetHeader("Non-Existent") != "" {
		t.Errorf("GetHeader() for missing key should return empty string")
	}
}

func TestResponse_GetHeaderMap(t *testing.T) {
	r := &Response{
		Header: http.Header{
			"Content-Type": {"text/html"},
			"X-Custom":     {"value1"},
		},
		NativeResponse: &http.Response{
			Header: http.Header{
				"Content-Type": {"text/html"},
				"X-Custom":     {"value1"},
				"Set-Cookie":   {"session=abc123"},
			},
		},
	}

	hm := r.GetHeaderMap()
	if hm["Content-Type"] != "text/html" {
		t.Errorf("GetHeaderMap()[Content-Type] = %q, want %q", hm["Content-Type"], "text/html")
	}
	if hm["X-Custom"] != "value1" {
		t.Errorf("GetHeaderMap()[X-Custom] = %q, want %q", hm["X-Custom"], "value1")
	}
}

func TestResponse_GetRawBody(t *testing.T) {
	// When rawBody is set
	r := &Response{rawBody: []byte("hello")}
	if string(r.GetRawBody()) != "hello" {
		t.Errorf("GetRawBody() = %q, want %q", string(r.GetRawBody()), "hello")
	}

	// When rawBody is nil
	r2 := &Response{}
	if r2.GetRawBody() != nil {
		t.Errorf("GetRawBody() with nil rawBody should return nil")
	}
}

func TestResponse_GetServerProcessingTime(t *testing.T) {
	r := &Response{}
	if r.GetServerProcessingTime() != 0 {
		t.Errorf("GetServerProcessingTime() should return 0")
	}
}

func TestResponse_GetUTF8Body(t *testing.T) {
	r := &Response{utf8Body: []byte("utf8 content")}
	body, err := r.GetUTF8Body()
	if err != nil {
		t.Errorf("GetUTF8Body() returned error: %v", err)
	}
	if string(body) != "utf8 content" {
		t.Errorf("GetUTF8Body() = %q, want %q", string(body), "utf8 content")
	}
}

func TestResponse_ResetBody(t *testing.T) {
	r := &Response{rawBody: []byte("original")}
	r.ResetBody([]byte("reset"))
	if string(r.rawBody) != "reset" {
		t.Errorf("ResetBody() = %q, want %q", string(r.rawBody), "reset")
	}
}

func TestResponse_URL(t *testing.T) {
	u, _ := url.Parse("http://example.com/path")
	r := &Response{url: u}
	if r.URL().String() != "http://example.com/path" {
		t.Errorf("URL() = %q, want %q", r.URL().String(), "http://example.com/path")
	}
}

func TestResponse_IsHTML(t *testing.T) {
	tests := []struct {
		contentType string
		expected    bool
	}{
		{"text/html", true},
		{"application/xhtml+xml", true},
		{"application/xhtml", true},
		{"text/html; charset=utf-8", true},
		{"application/json", false},
		{"", false},
	}

	for _, tt := range tests {
		r := &Response{
			Header: http.Header{"Content-Type": {tt.contentType}},
		}
		result := r.IsHTML()
		if result != tt.expected {
			t.Errorf("IsHTML() with Content-Type %q = %v, want %v", tt.contentType, result, tt.expected)
		}
	}
}

func TestResponse_IsCss(t *testing.T) {
	tests := []struct {
		contentType string
		expected    bool
	}{
		{"text/css", true},
		{"text/css; charset=utf-8", true},
		{"text/html", false},
	}

	for _, tt := range tests {
		r := &Response{
			Header: http.Header{"Content-Type": {tt.contentType}},
		}
		result := r.IsCss()
		if result != tt.expected {
			t.Errorf("IsCss() with Content-Type %q = %v, want %v", tt.contentType, result, tt.expected)
		}
	}
}

func TestResponse_IsImages(t *testing.T) {
	tests := []struct {
		contentType string
		expected    bool
	}{
		{"image/png", true},
		{"image/jpeg", true},
		{"text/html", false},
	}

	for _, tt := range tests {
		r := &Response{
			Header: http.Header{"Content-Type": {tt.contentType}},
		}
		result := r.IsImages()
		if result != tt.expected {
			t.Errorf("IsImages() with Content-Type %q = %v, want %v", tt.contentType, result, tt.expected)
		}
	}
}

func TestResponse_IsApplicationWasm(t *testing.T) {
	r := &Response{
		Header: http.Header{"Content-Type": {"application/wasm"}},
	}
	if !r.IsApplicationWasm() {
		t.Error("IsApplicationWasm() should return true for application/wasm")
	}

	r2 := &Response{
		Header: http.Header{"Content-Type": {"text/html"}},
	}
	if r2.IsApplicationWasm() {
		t.Error("IsApplicationWasm() should return false for text/html")
	}
}

func TestResponse_IsJavaScript(t *testing.T) {
	u, _ := url.Parse("http://example.com/app.js")
	r := &Response{
		url:    u,
		Header: http.Header{"Content-Type": {"text/html"}},
	}
	if !r.IsJavaScript() {
		t.Error("IsJavaScript() should return true for .js path")
	}

	u2, _ := url.Parse("http://example.com/app.html")
	r2 := &Response{
		url:    u2,
		Header: http.Header{"Content-Type": {"application/javascript"}},
	}
	if !r2.IsJavaScript() {
		t.Error("IsJavaScript() should return true for application/javascript content type")
	}

	u3, _ := url.Parse("http://example.com/app.html")
	r3 := &Response{
		url:    u3,
		Header: http.Header{"Content-Type": {"text/javascript"}},
	}
	if !r3.IsJavaScript() {
		t.Error("IsJavaScript() should return true for text/javascript content type")
	}

	u4, _ := url.Parse("http://example.com/app.html")
	r4 := &Response{
		url:    u4,
		Header: http.Header{"Content-Type": {"text/html"}},
	}
	if r4.IsJavaScript() {
		t.Error("IsJavaScript() should return false for non-JS content")
	}
}

func TestResponse_GetURL(t *testing.T) {
	u, _ := url.Parse("http://example.com/path?q=1")
	r := &Response{url: u}
	result := r.GetURL()
	if result.String() != "http://example.com/path?q=1" {
		t.Errorf("GetURL() = %q, want %q", result.String(), "http://example.com/path?q=1")
	}
}

func TestResponse_Dump(t *testing.T) {
	r := &Response{
		Text: "body content",
	}
	result := r.Dump()
	if len(result) == 0 {
		t.Error("Dump() should return non-empty bytes")
	}
	// Should contain the body text
	if !strings.Contains(string(result), "body content") {
		t.Errorf("Dump() result should contain body text, got: %q", string(result))
	}
}

func TestRequest_Hostname(t *testing.T) {
	u, _ := url.Parse("http://example.com/path")
	r := &Request{url: u}
	if r.Hostname() != "example.com" {
		t.Errorf("Hostname() = %q, want %q", r.Hostname(), "example.com")
	}
}

func TestResponse_GetTitle(t *testing.T) {
	r := &Response{
		rawBody: []byte("<html><head><title>Test Page</title></head><body></body></html>"),
	}
	title := r.GetTitile()
	if title != "Test Page" {
		t.Errorf("GetTitile() = %q, want %q", title, "Test Page")
	}
}

func TestResponse_GetTitle_Empty(t *testing.T) {
	r := &Response{
		rawBody: []byte("<html><body></body></html>"),
	}
	title := r.GetTitile()
	if title != "" {
		t.Errorf("GetTitile() with no title = %q, want empty", title)
	}
}
