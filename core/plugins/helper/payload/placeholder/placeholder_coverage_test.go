package placeholder

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"
)

func TestPlaceholder_MapInitialized(t *testing.T) {
	if Placeholders == nil {
		t.Fatal("Placeholders map should be initialized")
	}
	expectedPlaceholders := []string{
		"gRPC", "Header", "UserAgent", "HTMLForm", "HTMLMultipartForm",
		"JSONBody", "JSONRequest", "RequestBody", "SOAPBody",
		"URLParam", "URLPath", "XMLBody", "NonCrudUrlPath",
		"NonCrudUrlParam", "NonCRUDHeader", "NonCRUDRequestBody",
		"RawRequest",
	}
	for _, name := range expectedPlaceholders {
		if _, ok := Placeholders[name]; !ok {
			t.Errorf("expected placeholder '%s' to be registered", name)
		}
	}
}

func TestApply_UnknownPlaceholder(t *testing.T) {
	_, err := Apply("http://example.com", "payload", "UnknownPlaceholder", nil)
	if err == nil {
		t.Error("expected error for unknown placeholder")
	}
	var ue *UnknownPlaceholderError
	if !isErrorType(err, &ue) {
		t.Errorf("expected UnknownPlaceholderError, got %T", err)
	}
}

func TestApply_URLParam(t *testing.T) {
	req, err := Apply("http://example.com", "test-payload", "URLParam", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req == nil {
		t.Fatal("expected non-nil request")
	}
	if req.Method != "GET" {
		t.Errorf("expected GET method, got %s", req.Method)
	}
}

func TestApply_URLPath(t *testing.T) {
	req, err := Apply("http://example.com", "test-payload", "URLPath", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req == nil {
		t.Fatal("expected non-nil request")
	}
	if req.Method != "GET" {
		t.Errorf("expected GET method, got %s", req.Method)
	}
}

func TestApply_Header(t *testing.T) {
	req, err := Apply("http://example.com", "test-payload", "Header", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req == nil {
		t.Fatal("expected non-nil request")
	}
}

func TestApply_UserAgent(t *testing.T) {
	req, err := Apply("http://example.com", "custom-ua", "UserAgent", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.UserAgent() != "custom-ua" {
		t.Errorf("expected User-Agent 'custom-ua', got '%s'", req.UserAgent())
	}
}

func TestApply_JSONBody(t *testing.T) {
	req, err := Apply("http://example.com", `{"key":"value"}`, "JSONBody", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Method != "POST" {
		t.Errorf("expected POST method, got %s", req.Method)
	}
	ct := req.Header.Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got '%s'", ct)
	}
}

func TestApply_XMLBody(t *testing.T) {
	req, err := Apply("http://example.com", "<xml>test</xml>", "XMLBody", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Method != "POST" {
		t.Errorf("expected POST method, got %s", req.Method)
	}
	ct := req.Header.Get("Content-Type")
	if ct != "text/xml" {
		t.Errorf("expected Content-Type 'text/xml', got '%s'", ct)
	}
}

func TestApply_RequestBody(t *testing.T) {
	req, err := Apply("http://example.com", "test-body", "RequestBody", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Method != "POST" {
		t.Errorf("expected POST method, got %s", req.Method)
	}
}

func TestApply_HTMLForm(t *testing.T) {
	req, err := Apply("http://example.com", "test-payload", "HTMLForm", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Method != "POST" {
		t.Errorf("expected POST method, got %s", req.Method)
	}
	ct := req.Header.Get("Content-Type")
	if ct != "application/x-www-form-urlencoded" {
		t.Errorf("expected Content-Type 'application/x-www-form-urlencoded', got '%s'", ct)
	}
}

func TestApply_HTMLMultipartForm(t *testing.T) {
	req, err := Apply("http://example.com", "test-payload", "HTMLMultipartForm", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Method != "POST" {
		t.Errorf("expected POST method, got %s", req.Method)
	}
	ct := req.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "multipart/form-data") {
		t.Errorf("expected Content-Type starting with 'multipart/form-data', got '%s'", ct)
	}
}

func TestApply_SOAPBody(t *testing.T) {
	req, err := Apply("http://example.com", "test-payload", "SOAPBody", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Method != "POST" {
		t.Errorf("expected POST method, got %s", req.Method)
	}
	ct := req.Header.Get("Content-Type")
	if ct != "text/xml" {
		t.Errorf("expected Content-Type 'text/xml', got '%s'", ct)
	}
	sa := req.Header.Get("SOAPAction")
	if sa == "" {
		t.Error("expected non-empty SOAPAction header")
	}
}

func TestApply_JSONRequest(t *testing.T) {
	req, err := Apply("http://example.com", "test-payload", "JSONRequest", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Method != "POST" {
		t.Errorf("expected POST method, got %s", req.Method)
	}
	ct := req.Header.Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got '%s'", ct)
	}
}

func TestApply_NonCrudUrlPath(t *testing.T) {
	req, err := Apply("http://example.com", "test-payload", "NonCrudUrlPath", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Method != "CUST" {
		t.Errorf("expected CUST method, got %s", req.Method)
	}
}

func TestApply_NonCrudUrlParam(t *testing.T) {
	req, err := Apply("http://example.com", "test-payload", "NonCrudUrlParam", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Method != "CUST" {
		t.Errorf("expected CUST method, got %s", req.Method)
	}
}

func TestApply_NonCRUDHeader(t *testing.T) {
	req, err := Apply("http://example.com", "test-payload", "NonCRUDHeader", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Method != "CUST" {
		t.Errorf("expected CUST method, got %s", req.Method)
	}
}

func TestApply_NonCRUDRequestBody(t *testing.T) {
	req, err := Apply("http://example.com", "test-payload", "NonCRUDRequestBody", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Method != "CUST" {
		t.Errorf("expected CUST method, got %s", req.Method)
	}
}

func TestApply_GRPC(t *testing.T) {
	req, err := Apply("http://example.com", "test-payload", "gRPC", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// gRPC returns nil request
	if req != nil {
		t.Error("expected nil request for gRPC placeholder")
	}
}

func TestGetPlaceholderConfig_UnknownPlaceholder(t *testing.T) {
	_, err := GetPlaceholderConfig("UnknownPlaceholder", map[any]any{})
	if err == nil {
		t.Error("expected error for unknown placeholder")
	}
}

func TestGetPlaceholderConfig_BadConfigType(t *testing.T) {
	_, err := GetPlaceholderConfig("URLParam", "not a map")
	if err == nil {
		t.Error("expected error for bad config type")
	}
	var be *BadPlaceholderConfigError
	if !isErrorType(err, &be) {
		t.Errorf("expected BadPlaceholderConfigError, got %T", err)
	}
}

func TestGetPlaceholderConfig_ValidRawRequest(t *testing.T) {
	conf, err := GetPlaceholderConfig("RawRequest", map[any]any{
		"method": "POST",
		"path":   "/test",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conf == nil {
		t.Error("expected non-nil config")
	}
}

func TestUnknownPlaceholderError(t *testing.T) {
	err := &UnknownPlaceholderError{name: "test"}
	expected := "unknown placeholder: test"
	if err.Error() != expected {
		t.Errorf("expected '%s', got '%s'", expected, err.Error())
	}
}

func TestBadPlaceholderConfigError_WithErr(t *testing.T) {
	err := &BadPlaceholderConfigError{name: "test", err: fmt.Errorf("inner error")}
	expected := "bad config for test placeholder: inner error"
	if err.Error() != expected {
		t.Errorf("expected '%s', got '%s'", expected, err.Error())
	}
}

func TestBadPlaceholderConfigError_WithoutErr(t *testing.T) {
	err := &BadPlaceholderConfigError{name: "test"}
	expected := "bad config for test placeholder"
	if err.Error() != expected {
		t.Errorf("expected '%s', got '%s'", expected, err.Error())
	}
}

func TestBadPlaceholderConfigError_Unwrap(t *testing.T) {
	innerErr := fmt.Errorf("inner error")
	err := &BadPlaceholderConfigError{name: "test", err: innerErr}
	if err.Unwrap() != innerErr {
		t.Error("expected Unwrap to return inner error")
	}
}

func TestRandomHex(t *testing.T) {
	result, err := RandomHex(5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 5 bytes = 10 hex characters
	if len(result) != 10 {
		t.Errorf("expected 10 hex chars, got %d", len(result))
	}
	matched, _ := regexp.MatchString(`^[a-f0-9]+$`, result)
	if !matched {
		t.Errorf("expected hex string, got %s", result)
	}
}

func TestRandomHex_DifferentValues(t *testing.T) {
	results := make(map[string]bool)
	for i := 0; i < 10; i++ {
		r, _ := RandomHex(8)
		results[r] = true
	}
	if len(results) < 2 {
		t.Error("expected different random hex values")
	}
}

func TestHeader_CreateRequest(t *testing.T) {
	req, err := DefaultHeader.CreateRequest("http://example.com", "test-value", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Method != "GET" {
		t.Errorf("expected GET method, got %s", req.Method)
	}
	// Should have an X- header
	found := false
	for k, v := range req.Header {
		if strings.HasPrefix(k, "X-") && v[0] == "test-value" {
			found = true
		}
	}
	if !found {
		t.Error("expected X- header with test-value")
	}
}

func TestJSONBody_CreateRequest(t *testing.T) {
	req, err := DefaultJSONBody.CreateRequest("http://example.com", `{"test":true}`, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Method != "POST" {
		t.Errorf("expected POST, got %s", req.Method)
	}
	body, _ := io.ReadAll(req.Body)
	if string(body) != `{"test":true}` {
		t.Errorf("expected body '{\"test\":true}', got '%s'", string(body))
	}
}

func TestRequestBody_CreateRequest(t *testing.T) {
	req, err := DefaultRequestBody.CreateRequest("http://example.com", "test-body", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Method != "POST" {
		t.Errorf("expected POST, got %s", req.Method)
	}
	body, _ := io.ReadAll(req.Body)
	if string(body) != "test-body" {
		t.Errorf("expected body 'test-body', got '%s'", string(body))
	}
}

func TestXMLBody_CreateRequest(t *testing.T) {
	req, err := DefaultXMLBody.CreateRequest("http://example.com", "<root>test</root>", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Method != "POST" {
		t.Errorf("expected POST, got %s", req.Method)
	}
	body, _ := io.ReadAll(req.Body)
	if string(body) != "<root>test</root>" {
		t.Errorf("expected body '<root>test</root>', got '%s'", string(body))
	}
}

func TestGRPC_CreateRequest(t *testing.T) {
	req, err := DefaultGRPC.CreateRequest("http://example.com", "test", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req != nil {
		t.Error("expected nil request for gRPC")
	}
}

func TestGRPC_GetName(t *testing.T) {
	if DefaultGRPC.GetName() != "gRPC" {
		t.Errorf("expected name 'gRPC', got '%s'", DefaultGRPC.GetName())
	}
}

func TestNonCrudUrlPath_CreateRequest(t *testing.T) {
	req, err := DefaultNonCrudUrlPath.CreateRequest("http://example.com", "test-path", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Method != "CUST" {
		t.Errorf("expected CUST method, got %s", req.Method)
	}
	if !strings.HasSuffix(req.URL.Path, "test-path") {
		t.Errorf("expected URL path ending with 'test-path', got '%s'", req.URL.Path)
	}
}

func TestNonCRUDHeader_CreateRequest(t *testing.T) {
	req, err := DefaultNonCRUDHeader.CreateRequest("http://example.com", "test-value", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Method != "CUST" {
		t.Errorf("expected CUST method, got %s", req.Method)
	}
}

func TestNonCRUDRequestBody_CreateRequest(t *testing.T) {
	req, err := DefaultNonCRUDRequestBody.CreateRequest("http://example.com", "test-body", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Method != "CUST" {
		t.Errorf("expected CUST method, got %s", req.Method)
	}
	body, _ := io.ReadAll(req.Body)
	if string(body) != "test-body" {
		t.Errorf("expected body 'test-body', got '%s'", string(body))
	}
}

func TestRawRequest_CreateRequest_BadConfig(t *testing.T) {
	_, err := DefaultRawRequest.CreateRequest("http://example.com", "test", "bad config")
	if err == nil {
		t.Error("expected error for bad config type")
	}
}

func TestRawRequest_CreateRequest_WithBody(t *testing.T) {
	conf := &RawRequestConfig{
		Method:  "POST",
		Path:    "/api",
		Headers: map[string]string{"Content-Type": "application/json"},
		Body:    `{"data":"test"}`,
	}
	req, err := DefaultRawRequest.CreateRequest("http://example.com", "payload", conf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Method != "POST" {
		t.Errorf("expected POST, got %s", req.Method)
	}
	body, _ := io.ReadAll(req.Body)
	if string(body) != `{"data":"test"}` {
		t.Errorf("expected body '{\"data\":\"test\"}', got '%s'", string(body))
	}
}

func TestHTMLForm_CreateRequest(t *testing.T) {
	req, err := DefaultHTMLForm.CreateRequest("http://example.com", "test-value", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Method != "POST" {
		t.Errorf("expected POST, got %s", req.Method)
	}
	ct := req.Header.Get("Content-Type")
	if ct != "application/x-www-form-urlencoded" {
		t.Errorf("expected Content-Type 'application/x-www-form-urlencoded', got '%s'", ct)
	}
}

func TestHTMLMultipartForm_CreateRequest(t *testing.T) {
	req, err := DefaultHTMLMultipartForm.CreateRequest("http://example.com", "test-value", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Method != "POST" {
		t.Errorf("expected POST, got %s", req.Method)
	}
}

func TestSOAPBody_CreateRequest(t *testing.T) {
	req, err := DefaultSOAPBody.CreateRequest("http://example.com", "test-payload", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Method != "POST" {
		t.Errorf("expected POST, got %s", req.Method)
	}
	body, _ := io.ReadAll(req.Body)
	if !strings.Contains(string(body), "test-payload") {
		t.Error("expected body to contain the payload")
	}
	if !strings.Contains(string(body), "soapenv:Envelope") {
		t.Error("expected body to contain SOAP envelope")
	}
}

func TestJSONRequest_CreateRequest(t *testing.T) {
	req, err := DefaultJSONRequest.CreateRequest("http://example.com", "test-payload", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Method != "POST" {
		t.Errorf("expected POST, got %s", req.Method)
	}
}

// Helper to check error types using errors.As
func isErrorType(err error, target interface{}) bool {
	return errors.As(err, target)
}

// Suppress unused import warning
var _ = http.Request{}
