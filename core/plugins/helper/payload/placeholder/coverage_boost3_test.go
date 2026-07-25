package placeholder

import (
	"errors"
	"strings"
	"testing"
)

// ==================== Apply with CreateRequest error path ====================
// Covers placeholder.go:77-79 (Apply returning error from CreateRequest)

func TestBoost3_Apply_CreateRequestError(t *testing.T) {
	// Use an invalid URL with a valid placeholder name to trigger
	// CreateRequest error inside Apply (not the UnknownPlaceholderError path)
	_, err := Apply("://invalid", "payload", "Header", nil)
	if err == nil {
		t.Error("Expected error when Apply calls CreateRequest with invalid URL")
	}
	// Should NOT be UnknownPlaceholderError since "Header" is valid
	var unknownErr *UnknownPlaceholderError
	if errors.As(err, &unknownErr) {
		t.Error("Error should come from CreateRequest, not from unknown placeholder lookup")
	}
}

func TestBoost3_Apply_URLParamCreateRequestError(t *testing.T) {
	_, err := Apply("://invalid", "payload", "URLParam", nil)
	if err == nil {
		t.Error("Expected error from URLParam.CreateRequest")
	}
}

func TestBoost3_Apply_URLPathCreateRequestError(t *testing.T) {
	_, err := Apply("://invalid", "payload", "URLPath", nil)
	if err == nil {
		t.Error("Expected error from URLPath.CreateRequest")
	}
}

func TestBoost3_Apply_RequestBodyCreateRequestError(t *testing.T) {
	_, err := Apply("://invalid", "payload", "RequestBody", nil)
	if err == nil {
		t.Error("Expected error from RequestBody.CreateRequest")
	}
}

func TestBoost3_Apply_JSONBodyCreateRequestError(t *testing.T) {
	_, err := Apply("://invalid", "payload", "JSONBody", nil)
	if err == nil {
		t.Error("Expected error from JSONBody.CreateRequest")
	}
}

func TestBoost3_Apply_XMLBodyCreateRequestError(t *testing.T) {
	_, err := Apply("://invalid", "payload", "XMLBody", nil)
	if err == nil {
		t.Error("Expected error from XMLBody.CreateRequest")
	}
}

func TestBoost3_Apply_UserAgentCreateRequestError(t *testing.T) {
	_, err := Apply("://invalid", "payload", "UserAgent", nil)
	if err == nil {
		t.Error("Expected error from UserAgent.CreateRequest")
	}
}

func TestBoost3_Apply_HTMLFormCreateRequestError(t *testing.T) {
	_, err := Apply("://invalid", "payload", "HTMLForm", nil)
	if err == nil {
		t.Error("Expected error from HTMLForm.CreateRequest")
	}
}

func TestBoost3_Apply_HTMLMultipartFormCreateRequestError(t *testing.T) {
	_, err := Apply("://invalid", "payload", "HTMLMultipartForm", nil)
	if err == nil {
		t.Error("Expected error from HTMLMultipartForm.CreateRequest")
	}
}

func TestBoost3_Apply_SOAPBodyCreateRequestError(t *testing.T) {
	_, err := Apply("://invalid", "payload", "SOAPBody", nil)
	if err == nil {
		t.Error("Expected error from SOAPBody.CreateRequest")
	}
}

func TestBoost3_Apply_JSONRequestCreateRequestError(t *testing.T) {
	_, err := Apply("://invalid", "payload", "JSONRequest", nil)
	if err == nil {
		t.Error("Expected error from JSONRequest.CreateRequest")
	}
}

func TestBoost3_Apply_NonCrudUrlPathCreateRequestError(t *testing.T) {
	_, err := Apply("://invalid", "payload", "NonCrudUrlPath", nil)
	if err == nil {
		t.Error("Expected error from NonCrudUrlPath.CreateRequest")
	}
}

func TestBoost3_Apply_NonCrudUrlParamCreateRequestError(t *testing.T) {
	_, err := Apply("://invalid", "payload", "NonCrudUrlParam", nil)
	if err == nil {
		t.Error("Expected error from NonCrudUrlParam.CreateRequest")
	}
}

func TestBoost3_Apply_NonCRUDHeaderCreateRequestError(t *testing.T) {
	_, err := Apply("://invalid", "payload", "NonCRUDHeader", nil)
	if err == nil {
		t.Error("Expected error from NonCRUDHeader.CreateRequest")
	}
}

func TestBoost3_Apply_NonCRUDRequestBodyCreateRequestError(t *testing.T) {
	_, err := Apply("://invalid", "payload", "NonCRUDRequestBody", nil)
	if err == nil {
		t.Error("Expected error from NonCRUDRequestBody.CreateRequest")
	}
}

// ==================== GetPlaceholderConfig with newConfig error ====================
// Covers placeholder.go:60-65 (newConfig returning error)

func TestBoost3_GetPlaceholderConfig_NewConfigError(t *testing.T) {
	// RawRequest.newConfig returns error when "method" key is missing
	_, err := GetPlaceholderConfig("RawRequest", map[any]any{})
	if err == nil {
		t.Error("Expected error when RawRequest.newConfig is missing 'method' field")
	}
	var badErr *BadPlaceholderConfigError
	if !errors.As(err, &badErr) {
		t.Errorf("Expected BadPlaceholderConfigError, got %T", err)
	}
}

func TestBoost3_GetPlaceholderConfig_RawRequestBadMethod(t *testing.T) {
	_, err := GetPlaceholderConfig("RawRequest", map[any]any{
		"method": 123, // not a string
	})
	if err == nil {
		t.Error("Expected error for non-string method")
	}
}

// ==================== RawRequest.CreateRequest with invalid HTTP method ====================
// Covers rawrequest.go:135-137 (http.NewRequest returning error)

func TestBoost3_RawRequest_CreateRequest_InvalidMethod(t *testing.T) {
	conf := &RawRequestConfig{
		Method:  "INVALID METHOD", // spaces make this an invalid HTTP method
		Path:    "/api",
		Headers: map[string]string{},
	}
	_, err := DefaultRawRequest.CreateRequest("http://example.com/", "payload", conf)
	if err == nil {
		t.Error("Expected error for invalid HTTP method containing space")
	}
}

// ==================== URLParam and NonCrudUrlParam edge cases ====================

func TestBoost3_URLParam_URLWithOnlySlashes(t *testing.T) {
	req, err := DefaultURLParam.CreateRequest("http://example.com/", "payload", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !strings.Contains(req.URL.String(), "payload") {
		t.Errorf("Expected URL to contain payload, got %s", req.URL.String())
	}
}

func TestBoost3_NonCrudUrlParam_URLWithOnlySlashes(t *testing.T) {
	req, err := DefaultNonCrudUrlParam.CreateRequest("http://example.com/", "payload", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if req.Method != "CUST" {
		t.Errorf("Expected CUST method, got %s", req.Method)
	}
}

func TestBoost3_URLPath_URLWithOnlySlashes(t *testing.T) {
	req, err := DefaultURLPath.CreateRequest("http://example.com/", "payload", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !strings.Contains(req.URL.Path, "payload") {
		t.Errorf("Expected path to contain payload, got %s", req.URL.Path)
	}
}

// ==================== Additional NonCrudUrlParam path variations ====================

func TestBoost3_NonCrudUrlParam_HasSuffixBranch(t *testing.T) {
	req, err := DefaultNonCrudUrlParam.CreateRequest("http://example.com/test", "payload", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if req.Method != "CUST" {
		t.Errorf("Expected CUST method, got %s", req.Method)
	}
}
