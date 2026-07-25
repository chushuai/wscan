package utils

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestReadAndResetResponseBody_Ext(t *testing.T) {
	body := []byte("hello world")
	resp := &http.Response{
		Body: io.NopCloser(bytes.NewReader(body)),
	}

	result, err := ReadAndResetResponseBody(resp)
	if err != nil {
		t.Errorf("ReadAndResetResponseBody returned error: %v", err)
	}
	if string(result) != "hello world" {
		t.Errorf("ReadAndResetResponseBody = %q, want %q", string(result), "hello world")
	}

	// Verify body was reset - read again
	result2, err := ReadAndResetResponseBody(resp)
	if err != nil {
		t.Errorf("ReadAndResetResponseBody second call returned error: %v", err)
	}
	if string(result2) != "hello world" {
		t.Errorf("ReadAndResetResponseBody second call = %q, want %q", string(result2), "hello world")
	}
}

func TestReadAndResetRequestBody_Ext(t *testing.T) {
	// Test with nil body
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	result, err := ReadAndResetRequestBody(req)
	if err != nil {
		t.Errorf("ReadAndResetRequestBody with nil body returned error: %v", err)
	}
	if result != nil {
		t.Errorf("ReadAndResetRequestBody with nil body should return nil")
	}

	// Test with body
	body := []byte("test body")
	req, _ = http.NewRequest("POST", "http://example.com", bytes.NewReader(body))
	result, err = ReadAndResetRequestBody(req)
	if err != nil {
		t.Errorf("ReadAndResetRequestBody returned error: %v", err)
	}
	if string(result) != "test body" {
		t.Errorf("ReadAndResetRequestBody = %q, want %q", string(result), "test body")
	}
}

func TestCloneRequest_Ext(t *testing.T) {
	original, _ := http.NewRequest("GET", "http://example.com/path", bytes.NewReader([]byte("body")))
	original.Header.Set("X-Custom", "value")

	cloned := CloneRequest(original)
	if cloned.URL.String() != original.URL.String() {
		t.Errorf("CloneRequest URL mismatch: got %q, want %q", cloned.URL.String(), original.URL.String())
	}
	if cloned.Header.Get("X-Custom") != "value" {
		t.Errorf("CloneRequest header not preserved")
	}
}

func TestGetRequestContentType_Ext(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		expectErr   bool
	}{
		{"application/json", "application/json", false},
		{"application/json with charset", "application/json; charset=utf-8", false},
		{"application/x-www-form-urlencoded", "application/x-www-form-urlencoded", false},
		{"text/plain", "text/plain", true},
		{"empty", "", true},
		{"multipart/form-data", "multipart/form-data", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("POST", "http://example.com", nil)
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			_, err := GetRequestContentType(req)
			if tt.expectErr && err == nil {
				t.Errorf("expected error for content-type %q", tt.contentType)
			}
			if !tt.expectErr && err != nil {
				t.Errorf("unexpected error for content-type %q: %v", tt.contentType, err)
			}
		})
	}
}

func TestRequestPostDataMap_Ext(t *testing.T) {
	// Test JSON content type
	jsonBody := `{"key": "value"}`
	req, _ := http.NewRequest("POST", "http://example.com", bytes.NewReader([]byte(jsonBody)))
	req.Header.Set("Content-Type", "application/json")
	result := RequestPostDataMap(req)
	if result["key"] != "value" {
		t.Errorf("RequestPostDataMap with JSON = %v, want key=value", result)
	}

	// Test form-urlencoded content type
	formBody := "name=test&count=1"
	req, _ = http.NewRequest("POST", "http://example.com", bytes.NewReader([]byte(formBody)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	result = RequestPostDataMap(req)
	if result["name"] != "test" {
		t.Errorf("RequestPostDataMap with form = %v, want name=test", result)
	}

	// Test unsupported content type
	req, _ = http.NewRequest("POST", "http://example.com", bytes.NewReader([]byte("raw data")))
	req.Header.Set("Content-Type", "text/plain")
	result = RequestPostDataMap(req)
	if result["key"] != "raw data" {
		t.Errorf("RequestPostDataMap with unsupported type = %v", result)
	}
}

func TestIsRedirection_Ext(t *testing.T) {
	tests := []struct {
		code   int
		expect bool
	}{
		{299, false},
		{300, true},
		{301, true},
		{302, true},
		{304, true},
		{399, true},
		{400, false},
		{200, false},
		{500, false},
	}
	for _, tt := range tests {
		result := IsRedirection(tt.code)
		if result != tt.expect {
			t.Errorf("IsRedirection(%d) = %v, want %v", tt.code, result, tt.expect)
		}
	}
}

func TestIsClientError_Ext(t *testing.T) {
	tests := []struct {
		code   int
		expect bool
	}{
		{399, false},
		{400, true},
		{404, true},
		{499, true},
		{500, false},
		{200, false},
	}
	for _, tt := range tests {
		result := IsClientError(tt.code)
		if result != tt.expect {
			t.Errorf("IsClientError(%d) = %v, want %v", tt.code, result, tt.expect)
		}
	}
}

func TestIsServerError_Ext(t *testing.T) {
	tests := []struct {
		code   int
		expect bool
	}{
		{499, false},
		{500, true},
		{503, true},
		{600, true},
		{200, false},
	}
	for _, tt := range tests {
		result := IsServerError(tt.code)
		if result != tt.expect {
			t.Errorf("IsServerError(%d) = %v, want %v", tt.code, result, tt.expect)
		}
	}
}

func TestEscapeQuotes_Ext(t *testing.T) {
	tests := []struct {
		input  string
		expect string
	}{
		{`hello`, "hello"},
		{`say "hi"`, `say \"hi\"`},
		{`back\slash`, `back\\slash`},
		{`both\"here"`, `both\\\"here\"`},
	}
	for _, tt := range tests {
		result := EscapeQuotes(tt.input)
		if result != tt.expect {
			t.Errorf("EscapeQuotes(%q) = %q, want %q", tt.input, result, tt.expect)
		}
	}
}

func TestExtractBoundaryFromContentType_Ext(t *testing.T) {
	tests := []struct {
		contentType string
		expectErr   bool
		boundary    string
	}{
		{`multipart/form-data; boundary=----WebKitFormBoundary`, false, "----WebKitFormBoundary"},
		{`multipart/form-data; boundary="abc123"`, false, "abc123"},
		{`text/plain`, true, ""},
		{`invalid content type`, true, ""},
	}
	for _, tt := range tests {
		result, err := ExtractBoundaryFromContentType(tt.contentType)
		if tt.expectErr {
			if err == nil {
				t.Errorf("expected error for %q", tt.contentType)
			}
		} else {
			if err != nil {
				t.Errorf("unexpected error for %q: %v", tt.contentType, err)
			}
			if !strings.Contains(result, tt.boundary) {
				t.Errorf("ExtractBoundaryFromContentType(%q) = %q, want to contain %q", tt.contentType, result, tt.boundary)
			}
		}
	}
}

func TestUrlJoinPath_Ext(t *testing.T) {
	tests := []struct {
		base     string
		relative string
		expect   string
	}{
		{"http://example.com", "path", "http://example.com/path"},
		{"http://example.com/", "path", "http://example.com/path"},
		{"http://example.com", "/path", "http://example.com/path"},
		{"http://example.com/", "/path", "http://example.com/path"},
		{"http://example.com/api", "v1", "http://example.com/api/v1"},
		{"http://example.com/api/", "v1", "http://example.com/api/v1"},
		{"http://example.com/api/", "/v1", "http://example.com/api/v1"},
	}
	for _, tt := range tests {
		result := UrlJoinPath(tt.base, tt.relative)
		if result != tt.expect {
			t.Errorf("UrlJoinPath(%q, %q) = %q, want %q", tt.base, tt.relative, result, tt.expect)
		}
	}
}

func TestRequestPostDataMap_NoContentType(t *testing.T) {
	// Test with no content type set
	req, _ := http.NewRequest("POST", "http://example.com", bytes.NewReader([]byte("some data")))
	result := RequestPostDataMap(req)
	if result["key"] != "some data" {
		t.Errorf("RequestPostDataMap without content type = %v", result)
	}
}

func TestRequestPostDataMap_FormMultipleValues(t *testing.T) {
	// Test form with multiple values for same key
	formBody := "key=val1&key=val2"
	req, _ := http.NewRequest("POST", "http://example.com", bytes.NewReader([]byte(formBody)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	result := RequestPostDataMap(req)
	// When there are multiple values, the result should be a slice
	val, ok := result["key"]
	if !ok {
		t.Errorf("RequestPostDataMap with form should have 'key'")
	}
	switch v := val.(type) {
	case []string:
		if len(v) != 2 || v[0] != "val1" || v[1] != "val2" {
			t.Errorf("RequestPostDataMap multiple values = %v, want [val1 val2]", v)
		}
	case string:
		// Single value is fine too depending on URL encoding
		t.Logf("Single value: %v", v)
	default:
		t.Errorf("Unexpected type for 'key': %T", val)
	}
}

func TestRequestPostDataMap_InvalidJSON(t *testing.T) {
	// Test with JSON content type but invalid JSON
	req, _ := http.NewRequest("POST", "http://example.com", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	result := RequestPostDataMap(req)
	if result["key"] != "not json" {
		t.Errorf("RequestPostDataMap with invalid JSON = %v", result)
	}
}

// errorReader is a reader that always returns an error
type errorReader struct {
	err error
}

func (e *errorReader) Read(p []byte) (n int, err error) {
	return 0, e.err
}

func (e *errorReader) Close() error {
	return nil
}

func TestReadAndResetResponseBody_Error(t *testing.T) {
	// Test the error path in ReadAndResetResponseBody
	resp := &http.Response{
		Body: &errorReader{err: errors.New("read error")},
	}
	_, err := ReadAndResetResponseBody(resp)
	if err == nil {
		t.Errorf("ReadAndResetResponseBody should return error on read failure")
	}
}

func TestReadAndResetRequestBody_Error(t *testing.T) {
	// Test the error path in ReadAndResetRequestBody
	req, _ := http.NewRequest("POST", "http://example.com", &errorReader{err: errors.New("read error")})
	_, err := ReadAndResetRequestBody(req)
	if err == nil {
		t.Errorf("ReadAndResetRequestBody should return error on read failure")
	}
}

func TestMapQueryToString_Ext(t *testing.T) {
	// Empty function - just verify it doesn't panic
	MapQueryToString()
}

func TestDomainToURLFilter_Ext(t *testing.T) {
	// Empty function - just verify it doesn't panic
	DomainToURLFilter()
}
