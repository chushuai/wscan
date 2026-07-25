package placeholder

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// ==================== CreateRequest with invalid URL ====================

func TestCovURLParamInvalidURL(t *testing.T) {
	_, err := DefaultURLParam.CreateRequest("://invalid", "payload", nil)
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

func TestCovURLPathInvalidURL(t *testing.T) {
	_, err := DefaultURLPath.CreateRequest("://invalid", "payload", nil)
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

func TestCovUserAgentInvalidURL(t *testing.T) {
	_, err := DefaultUserAgent.CreateRequest("://invalid", "payload", nil)
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

func TestCovHeaderInvalidURL(t *testing.T) {
	_, err := DefaultHeader.CreateRequest("://invalid", "payload", nil)
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

func TestCovRequestBodyInvalidURL(t *testing.T) {
	_, err := DefaultRequestBody.CreateRequest("://invalid", "payload", nil)
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

func TestCovJSONBodyInvalidURL(t *testing.T) {
	_, err := DefaultJSONBody.CreateRequest("://invalid", "payload", nil)
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

func TestCovXMLBodyInvalidURL(t *testing.T) {
	_, err := DefaultXMLBody.CreateRequest("://invalid", "payload", nil)
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

func TestCovHTMLFormInvalidURL(t *testing.T) {
	_, err := DefaultHTMLForm.CreateRequest("://invalid", "payload", nil)
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

func TestCovHTMLMultipartFormInvalidURL(t *testing.T) {
	_, err := DefaultHTMLMultipartForm.CreateRequest("://invalid", "payload", nil)
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

func TestCovNonCrudUrlPathInvalidURL(t *testing.T) {
	_, err := DefaultNonCrudUrlPath.CreateRequest("://invalid", "payload", nil)
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

func TestCovNonCrudUrlParamInvalidURL(t *testing.T) {
	_, err := DefaultNonCrudUrlParam.CreateRequest("://invalid", "payload", nil)
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

func TestCovNonCRUDHeaderInvalidURL(t *testing.T) {
	_, err := DefaultNonCRUDHeader.CreateRequest("://invalid", "payload", nil)
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

func TestCovNonCRUDRequestBodyInvalidURL(t *testing.T) {
	_, err := DefaultNonCRUDRequestBody.CreateRequest("://invalid", "payload", nil)
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

// ==================== Detailed CreateRequest tests ====================

func TestCovURLParamWithExistingQuery(t *testing.T) {
	req, err := DefaultURLParam.CreateRequest("http://example.com/path?existing=1", "payload", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if req.Method != "GET" {
		t.Errorf("Expected GET, got %s", req.Method)
	}
	// Should append to existing query
	if !strings.Contains(req.URL.RawQuery, "existing=1") {
		t.Error("Expected existing query param to be preserved")
	}
	// Should add new param with payload
	found := false
	for _, vals := range req.URL.Query() {
		for _, v := range vals {
			if v == "payload" {
				found = true
			}
		}
	}
	if !found {
		t.Error("Expected payload in query params")
	}
}

func TestCovURLParamNoExistingQuery(t *testing.T) {
	req, err := DefaultURLParam.CreateRequest("http://example.com/path", "payload", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if req.Method != "GET" {
		t.Errorf("Expected GET, got %s", req.Method)
	}
}

func TestCovURLPathWithTrailingSlash(t *testing.T) {
	req, err := DefaultURLPath.CreateRequest("http://example.com/path/", "payload", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !strings.Contains(req.URL.Path, "payload") {
		t.Errorf("Expected path to contain payload, got %s", req.URL.Path)
	}
}

func TestCovURLPathNoTrailingSlash(t *testing.T) {
	req, err := DefaultURLPath.CreateRequest("http://example.com/path", "payload", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !strings.HasSuffix(req.URL.Path, "payload") {
		t.Errorf("Expected path to end with payload, got %s", req.URL.Path)
	}
}

func TestCovHeaderCreateRequestDetails(t *testing.T) {
	req, err := DefaultHeader.CreateRequest("http://example.com/", "payload-value", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if req.Method != "GET" {
		t.Errorf("Expected GET, got %s", req.Method)
	}
	// Should have an X- header with the payload
	found := false
	for k, v := range req.Header {
		if strings.HasPrefix(k, "X-") && len(v) > 0 && v[0] == "payload-value" {
			found = true
		}
	}
	if !found {
		t.Error("Expected X- header with payload value")
	}
}

func TestCovHTMLFormCreateRequestDetails(t *testing.T) {
	req, err := DefaultHTMLForm.CreateRequest("http://example.com/", "payload-value", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if req.Method != "POST" {
		t.Errorf("Expected POST, got %s", req.Method)
	}
	if ct := req.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
		t.Errorf("Expected application/x-www-form-urlencoded, got %s", ct)
	}
	body, _ := io.ReadAll(req.Body)
	if !strings.Contains(string(body), "payload-value") {
		t.Errorf("Expected body to contain payload, got %s", string(body))
	}
}

func TestCovJSONBodyCreateRequestDetails(t *testing.T) {
	req, err := DefaultJSONBody.CreateRequest("http://example.com/", `{"key":"val"}`, nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if req.Method != "POST" {
		t.Errorf("Expected POST, got %s", req.Method)
	}
	if ct := req.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Expected application/json, got %s", ct)
	}
	body, _ := io.ReadAll(req.Body)
	if string(body) != `{"key":"val"}` {
		t.Errorf("Expected body '{\"key\":\"val\"}', got '%s'", string(body))
	}
}

func TestCovXMLBodyCreateRequestDetails(t *testing.T) {
	req, err := DefaultXMLBody.CreateRequest("http://example.com/", "<root>test</root>", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if req.Method != "POST" {
		t.Errorf("Expected POST, got %s", req.Method)
	}
	if ct := req.Header.Get("Content-Type"); ct != "text/xml" {
		t.Errorf("Expected text/xml, got %s", ct)
	}
	body, _ := io.ReadAll(req.Body)
	if string(body) != "<root>test</root>" {
		t.Errorf("Expected body '<root>test</root>', got '%s'", string(body))
	}
}

func TestCovRequestBodyCreateRequestDetails(t *testing.T) {
	req, err := DefaultRequestBody.CreateRequest("http://example.com/", "test-body", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if req.Method != "POST" {
		t.Errorf("Expected POST, got %s", req.Method)
	}
	body, _ := io.ReadAll(req.Body)
	if string(body) != "test-body" {
		t.Errorf("Expected body 'test-body', got '%s'", string(body))
	}
}

func TestCovSOAPBodyCreateRequestDetails(t *testing.T) {
	req, err := DefaultSOAPBody.CreateRequest("http://example.com/", "payload-val", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if req.Method != "POST" {
		t.Errorf("Expected POST, got %s", req.Method)
	}
	if ct := req.Header.Get("Content-Type"); ct != "text/xml" {
		t.Errorf("Expected text/xml, got %s", ct)
	}
	sa := req.Header.Get("SOAPAction")
	if sa == "" {
		t.Error("Expected non-empty SOAPAction")
	}
	body, _ := io.ReadAll(req.Body)
	if !strings.Contains(string(body), "payload-val") {
		t.Error("Expected body to contain payload")
	}
	if !strings.Contains(string(body), "soapenv:Envelope") {
		t.Error("Expected SOAP envelope in body")
	}
}

func TestCovNonCrudUrlPathDetails(t *testing.T) {
	req, err := DefaultNonCrudUrlPath.CreateRequest("http://example.com/path", "payload", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if req.Method != "CUST" {
		t.Errorf("Expected CUST method, got %s", req.Method)
	}
	if !strings.HasSuffix(req.URL.Path, "payload") {
		t.Errorf("Expected path ending with payload, got %s", req.URL.Path)
	}
}

func TestCovNonCrudUrlParamDetails(t *testing.T) {
	req, err := DefaultNonCrudUrlParam.CreateRequest("http://example.com/path?existing=1", "payload", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if req.Method != "CUST" {
		t.Errorf("Expected CUST method, got %s", req.Method)
	}
}

func TestCovNonCRUDHeaderDetails(t *testing.T) {
	req, err := DefaultNonCRUDHeader.CreateRequest("http://example.com/", "payload-val", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if req.Method != "CUST" {
		t.Errorf("Expected CUST method, got %s", req.Method)
	}
}

func TestCovNonCRUDRequestBodyDetails(t *testing.T) {
	req, err := DefaultNonCRUDRequestBody.CreateRequest("http://example.com/", "test-body", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if req.Method != "CUST" {
		t.Errorf("Expected CUST method, got %s", req.Method)
	}
	body, _ := io.ReadAll(req.Body)
	if string(body) != "test-body" {
		t.Errorf("Expected body 'test-body', got '%s'", string(body))
	}
}

// ==================== RawRequest config tests ====================

func TestCovRawRequestNewConfigBodyType(t *testing.T) {
	conf, err := DefaultRawRequest.newConfig(map[any]any{
		"method": "POST",
		"path":   "/api",
		"body":   "test body",
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	rc := conf.(*RawRequestConfig)
	if rc.Body != "test body" {
		t.Errorf("Expected body 'test body', got '%s'", rc.Body)
	}
}

func TestCovRawRequestNewConfigBodyBadType(t *testing.T) {
	_, err := DefaultRawRequest.newConfig(map[any]any{
		"method": "POST",
		"body":   123,
	})
	if err == nil {
		t.Error("Expected error for bad body type")
	}
}

func TestCovRawRequestNewConfigPathBadType(t *testing.T) {
	_, err := DefaultRawRequest.newConfig(map[any]any{
		"method": "POST",
		"path":   123,
	})
	if err == nil {
		t.Error("Expected error for bad path type")
	}
}

func TestCovRawRequestNewConfigHeadersBadType(t *testing.T) {
	_, err := DefaultRawRequest.newConfig(map[any]any{
		"method":  "POST",
		"headers": "not-a-map",
	})
	if err == nil {
		t.Error("Expected error for bad headers type")
	}
}

func TestCovRawRequestNewConfigHeadersBadKV(t *testing.T) {
	_, err := DefaultRawRequest.newConfig(map[any]any{
		"method":  "POST",
		"headers": map[any]any{123: "value"},
	})
	if err == nil {
		t.Error("Expected error for non-string header key")
	}

	_, err = DefaultRawRequest.newConfig(map[any]any{
		"method":  "POST",
		"headers": map[any]any{"X-Test": 123},
	})
	if err == nil {
		t.Error("Expected error for non-string header value")
	}
}

func TestCovRawRequestNewConfigEmptyPath(t *testing.T) {
	conf, err := DefaultRawRequest.newConfig(map[any]any{
		"method": "POST",
		"path":   "",
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	rc := conf.(*RawRequestConfig)
	if rc.Path != "/" {
		t.Errorf("Expected path '/' for empty path, got '%s'", rc.Path)
	}
}

func TestCovRawRequestCreateRequestBadConfig(t *testing.T) {
	_, err := DefaultRawRequest.CreateRequest("http://example.com/", "payload", "bad-config")
	if err == nil {
		t.Error("Expected error for bad config type")
	}
}

func TestCovRawRequestCreateRequestWithPayload(t *testing.T) {
	conf := &RawRequestConfig{
		Method:  "POST",
		Path:    "/api/{{payload}}",
		Headers: map[string]string{"X-Custom": "{{payload}}"},
		Body:    "data={{payload}}",
	}
	req, err := DefaultRawRequest.CreateRequest("http://example.com/", "INJECT", conf)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !strings.Contains(req.URL.Path, "INJECT") {
		t.Errorf("Expected path to contain INJECT, got %s", req.URL.Path)
	}
	if req.Header.Get("X-Custom") != "INJECT" {
		t.Errorf("Expected X-Custom=INJECT, got %s", req.Header.Get("X-Custom"))
	}
	body, _ := io.ReadAll(req.Body)
	if !strings.Contains(string(body), "INJECT") {
		t.Errorf("Expected body to contain INJECT, got %s", string(body))
	}
}

// ==================== Apply function coverage ====================

func TestCovApplyAllPlaceholders(t *testing.T) {
	tests := []struct {
		name    string
		ph      string
		wantErr bool
	}{
		{"URLParam", "URLParam", false},
		{"URLPath", "URLPath", false},
		{"Header", "Header", false},
		{"UserAgent", "UserAgent", false},
		{"HTMLForm", "HTMLForm", false},
		{"HTMLMultipartForm", "HTMLMultipartForm", false},
		{"JSONBody", "JSONBody", false},
		{"JSONRequest", "JSONRequest", false},
		{"RequestBody", "RequestBody", false},
		{"SOAPBody", "SOAPBody", false},
		{"XMLBody", "XMLBody", false},
		{"NonCrudUrlPath", "NonCrudUrlPath", false},
		{"NonCrudUrlParam", "NonCrudUrlParam", false},
		{"NonCRUDHeader", "NonCRUDHeader", false},
		{"NonCRUDRequestBody", "NonCRUDRequestBody", false},
		{"gRPC", "gRPC", false},
		{"Unknown", "Unknown", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := Apply("http://example.com/", "payload", tt.ph, nil)
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				_ = req
			}
		})
	}
}

// ==================== Error type coverage ====================

func TestCovUnknownPlaceholderError(t *testing.T) {
	err := &UnknownPlaceholderError{name: "test"}
	if err.Error() != "unknown placeholder: test" {
		t.Errorf("Unexpected error message: %s", err.Error())
	}
}

func TestCovBadPlaceholderConfigErrorWithInner(t *testing.T) {
	innerErr := fmt.Errorf("inner error")
	err := &BadPlaceholderConfigError{name: "test", err: innerErr}
	expected := "bad config for test placeholder: inner error"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestCovBadPlaceholderConfigErrorNil(t *testing.T) {
	err := &BadPlaceholderConfigError{name: "test", err: nil}
	if err.Error() != "bad config for test placeholder" {
		t.Errorf("Unexpected error message: %s", err.Error())
	}
}

func TestCovGetPlaceholderConfigErrors(t *testing.T) {
	// Unknown placeholder
	_, err := GetPlaceholderConfig("NonExistent", map[any]any{})
	if _, ok := err.(*UnknownPlaceholderError); !ok {
		t.Errorf("Expected UnknownPlaceholderError, got %T", err)
	}

	// Bad config type
	_, err = GetPlaceholderConfig("URLParam", "not-a-map")
	if _, ok := err.(*BadPlaceholderConfigError); !ok {
		t.Errorf("Expected BadPlaceholderConfigError, got %T", err)
	}

	// Valid config
	conf, err := GetPlaceholderConfig("RawRequest", map[any]any{
		"method": "POST",
		"path":   "/api",
	})
	if err != nil || conf == nil {
		t.Errorf("Expected valid config, got err=%v conf=%v", err, conf)
	}
}

// ==================== RandomHex edge cases ====================

func TestCovRandomHexZero(t *testing.T) {
	result, err := RandomHex(0)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result != "" {
		t.Errorf("Expected empty string for 0 bytes, got %q", result)
	}
}

func TestCovRandomHexVariousSizes(t *testing.T) {
	for _, n := range []int{1, 5, 10, 32} {
		result, err := RandomHex(n)
		if err != nil {
			t.Errorf("RandomHex(%d) error: %v", n, err)
		}
		if len(result) != n*2 {
			t.Errorf("RandomHex(%d) length: expected %d, got %d", n, n*2, len(result))
		}
	}
}

// ==================== URLParam with path ending in non-slash char ====================

func TestCovURLParamPathEndChar(t *testing.T) {
	// Test when URL path ends with a non-slash character and no existing query
	// This exercises the inner loop in URLParam.CreateRequest that builds the query string
	req, err := DefaultURLParam.CreateRequest("http://example.com/path", "payload", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !strings.Contains(req.URL.String(), "payload") {
		t.Errorf("Expected URL to contain payload, got %s", req.URL.String())
	}
}

func TestCovURLParamPathEndWithSlash(t *testing.T) {
	req, err := DefaultURLParam.CreateRequest("http://example.com/path/", "payload", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !strings.Contains(req.URL.String(), "payload") {
		t.Errorf("Expected URL to contain payload, got %s", req.URL.String())
	}
}

// ==================== NonCrudUrlParam path variations ====================

func TestCovNonCrudUrlParamPathEndChar(t *testing.T) {
	req, err := DefaultNonCrudUrlParam.CreateRequest("http://example.com/path", "payload", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if req.Method != "CUST" {
		t.Errorf("Expected CUST method, got %s", req.Method)
	}
}

func TestCovNonCrudUrlParamWithExistingQuery(t *testing.T) {
	req, err := DefaultNonCrudUrlParam.CreateRequest("http://example.com/path?existing=1", "payload", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !strings.Contains(req.URL.RawQuery, "existing=1") {
		t.Error("Expected existing query to be preserved")
	}
}

// ==================== HTMLMultipartForm detailed ====================

func TestCovHTMLMultipartFormBody(t *testing.T) {
	req, err := DefaultHTMLMultipartForm.CreateRequest("http://example.com/", "multipart-payload", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if req.Method != "POST" {
		t.Errorf("Expected POST, got %s", req.Method)
	}
	ct := req.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "multipart/form-data") {
		t.Errorf("Expected multipart/form-data content type, got %s", ct)
	}
}

// ==================== JSONRequest detailed ====================

func TestCovJSONRequestDetails(t *testing.T) {
	req, err := DefaultJSONRequest.CreateRequest("http://example.com/", "payload-val", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if req.Method != "POST" {
		t.Errorf("Expected POST, got %s", req.Method)
	}
	ct := req.Header.Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Expected application/json, got %s", ct)
	}
	// JSONRequest encodes the payload using JSUnicode encoder
	// so the body contains unicode-escaped version of the payload
	body, _ := io.ReadAll(req.Body)
	if len(body) == 0 {
		t.Error("Expected non-empty body")
	}
}

// ==================== RawRequest with path prefix ====================

func TestCovRawRequestPathPrefix(t *testing.T) {
	conf := &RawRequestConfig{
		Method:  "GET",
		Path:    "api/test", // no leading slash
		Headers: map[string]string{},
	}
	req, err := DefaultRawRequest.CreateRequest("http://example.com", "payload", conf)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !strings.Contains(req.URL.Path, "api/test") {
		t.Errorf("Expected path to contain api/test, got %s", req.URL.Path)
	}
}

func TestCovRawRequestPathWithLeadingSlash(t *testing.T) {
	conf := &RawRequestConfig{
		Method:  "GET",
		Path:    "/api/test", // with leading slash
		Headers: map[string]string{},
	}
	req, err := DefaultRawRequest.CreateRequest("http://example.com", "payload", conf)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !strings.Contains(req.URL.Path, "api/test") {
		t.Errorf("Expected path to contain api/test, got %s", req.URL.Path)
	}
}

func TestCovRawRequestWithEmptyBody(t *testing.T) {
	conf := &RawRequestConfig{
		Method:  "GET",
		Path:    "/",
		Headers: map[string]string{},
		Body:    "", // empty body
	}
	req, err := DefaultRawRequest.CreateRequest("http://example.com/", "payload", conf)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if req.Body != nil {
		// Empty body should result in nil body reader
		body, _ := io.ReadAll(req.Body)
		if len(body) != 0 {
			t.Errorf("Expected empty body, got %q", string(body))
		}
	}
}

// ==================== GRPC coverage ====================

func TestCovGRPCNewConfig(t *testing.T) {
	conf, err := DefaultGRPC.newConfig(nil)
	if conf != nil || err != nil {
		t.Errorf("Expected nil config and nil error, got conf=%v err=%v", conf, err)
	}
}

// ==================== Constants coverage ====================

func TestCovConstants(t *testing.T) {
	if Seed != 5 {
		t.Errorf("Expected Seed=5, got %d", Seed)
	}
	if payloadPlaceholder != "{{payload}}" {
		t.Errorf("Expected {{payload}}, got %s", payloadPlaceholder)
	}
	if nonCRUDMethod != "CUST" {
		t.Errorf("Expected CUST, got %s", nonCRUDMethod)
	}
	if UAHeader != "User-Agent" {
		t.Errorf("Expected User-Agent, got %s", UAHeader)
	}
}

// ==================== newConfig coverage for all placeholders ====================

func TestCovAllNewConfigNil(t *testing.T) {
	placeholders := map[string]Placeholder{
		"Header":             DefaultHeader,
		"UserAgent":          DefaultUserAgent,
		"HTMLForm":           DefaultHTMLForm,
		"HTMLMultipartForm":  DefaultHTMLMultipartForm,
		"JSONBody":           DefaultJSONBody,
		"JSONRequest":        DefaultJSONRequest,
		"RequestBody":        DefaultRequestBody,
		"SOAPBody":           DefaultSOAPBody,
		"URLParam":           DefaultURLParam,
		"URLPath":            DefaultURLPath,
		"XMLBody":            DefaultXMLBody,
		"NonCrudUrlPath":     DefaultNonCrudUrlPath,
		"NonCrudUrlParam":    DefaultNonCrudUrlParam,
		"NonCRUDHeader":      DefaultNonCRUDHeader,
		"NonCRUDRequestBody": DefaultNonCRUDRequestBody,
		"gRPC":               DefaultGRPC,
	}
	for name, ph := range placeholders {
		conf, err := ph.newConfig(nil)
		_ = name
		_ = conf
		_ = err
	}
}

// ==================== JSONRequest coverage ====================

func TestCovJSONRequestInvalidURL(t *testing.T) {
	_, err := DefaultJSONRequest.CreateRequest("://invalid", "payload", nil)
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

// ==================== SOAPBody coverage ====================

func TestCovSOAPBodyInvalidURL(t *testing.T) {
	_, err := DefaultSOAPBody.CreateRequest("://invalid", "payload", nil)
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

// Suppress unused imports
var (
	_ = url.Parse
	_ = http.Request{}
	_ = fmt.Errorf
)
