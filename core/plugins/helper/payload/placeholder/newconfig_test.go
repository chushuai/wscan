package placeholder

import (
	"io"
	"strings"
	"testing"
)

// ==================== newConfig method tests ====================

func TestHelperGRPC_newConfig(t *testing.T) {
	conf, err := DefaultGRPC.newConfig(map[any]any{})
	if err != nil {
		t.Errorf("newConfig() error: %v", err)
	}
	if conf != nil {
		t.Errorf("GRPC newConfig returns nil, got %v", conf)
	}
}

func TestHelperHeader_newConfig2(t *testing.T) {
	conf, err := DefaultHeader.newConfig(map[any]any{})
	if err != nil {
		t.Errorf("newConfig() error: %v", err)
	}
	if conf != nil {
		t.Errorf("Header newConfig returns nil, got %v", conf)
	}
}

func TestHelperHTMLForm_newConfig2(t *testing.T) {
	conf, err := DefaultHTMLForm.newConfig(map[any]any{})
	if err != nil {
		t.Errorf("newConfig() error: %v", err)
	}
	if conf != nil {
		t.Errorf("HTMLForm newConfig returns nil, got %v", conf)
	}
}

func TestHelperURLParam_newConfig2(t *testing.T) {
	conf, err := DefaultURLParam.newConfig(map[any]any{})
	if err != nil {
		t.Errorf("newConfig() error: %v", err)
	}
	if conf != nil {
		t.Errorf("URLParam newConfig returns nil, got %v", conf)
	}
}

func TestHelperURLPath_newConfig2(t *testing.T) {
	conf, err := DefaultURLPath.newConfig(map[any]any{})
	if err != nil {
		t.Errorf("newConfig() error: %v", err)
	}
	if conf != nil {
		t.Errorf("URLPath newConfig returns nil, got %v", conf)
	}
}

func TestHelperHTMLMultipartForm_newConfig(t *testing.T) {
	conf, err := DefaultHTMLMultipartForm.newConfig(map[any]any{})
	if err != nil {
		t.Errorf("newConfig() error: %v", err)
	}
	if conf != nil {
		t.Errorf("HTMLMultipartForm newConfig returns nil, got %v", conf)
	}
}

func TestHelperJSONBody_newConfig(t *testing.T) {
	conf, err := DefaultJSONBody.newConfig(map[any]any{})
	if err != nil {
		t.Errorf("newConfig() error: %v", err)
	}
	if conf != nil {
		t.Errorf("JSONBody newConfig returns nil, got %v", conf)
	}
}

func TestHelperJSONRequest_newConfig(t *testing.T) {
	conf, err := DefaultJSONRequest.newConfig(map[any]any{})
	if err != nil {
		t.Errorf("newConfig() error: %v", err)
	}
	if conf != nil {
		t.Errorf("JSONRequest newConfig returns nil, got %v", conf)
	}
}

func TestHelperRequestBody_newConfig(t *testing.T) {
	conf, err := DefaultRequestBody.newConfig(map[any]any{})
	if err != nil {
		t.Errorf("newConfig() error: %v", err)
	}
	if conf != nil {
		t.Errorf("RequestBody newConfig returns nil, got %v", conf)
	}
}

func TestHelperSOAPBody_newConfig(t *testing.T) {
	conf, err := DefaultSOAPBody.newConfig(map[any]any{})
	if err != nil {
		t.Errorf("newConfig() error: %v", err)
	}
	if conf != nil {
		t.Errorf("SOAPBody newConfig returns nil, got %v", conf)
	}
}

func TestHelperXMLBody_newConfig(t *testing.T) {
	conf, err := DefaultXMLBody.newConfig(map[any]any{})
	if err != nil {
		t.Errorf("newConfig() error: %v", err)
	}
	if conf != nil {
		t.Errorf("XMLBody newConfig returns nil, got %v", conf)
	}
}

func TestHelperUserAgent_newConfig(t *testing.T) {
	conf, err := DefaultUserAgent.newConfig(map[any]any{})
	if err != nil {
		t.Errorf("newConfig() error: %v", err)
	}
	if conf != nil {
		t.Errorf("UserAgent newConfig returns nil, got %v", conf)
	}
}

func TestHelperNonCrudUrlPath_newConfig(t *testing.T) {
	conf, err := DefaultNonCrudUrlPath.newConfig(map[any]any{})
	if err != nil {
		t.Errorf("newConfig() error: %v", err)
	}
	if conf != nil {
		t.Errorf("NonCrudUrlPath newConfig returns nil, got %v", conf)
	}
}

func TestHelperNonCrudUrlParam_newConfig(t *testing.T) {
	conf, err := DefaultNonCrudUrlParam.newConfig(map[any]any{})
	if err != nil {
		t.Errorf("newConfig() error: %v", err)
	}
	if conf != nil {
		t.Errorf("NonCrudUrlParam newConfig returns nil, got %v", conf)
	}
}

func TestHelperNonCRUDHeader_newConfig(t *testing.T) {
	conf, err := DefaultNonCRUDHeader.newConfig(map[any]any{})
	if err != nil {
		t.Errorf("newConfig() error: %v", err)
	}
	if conf != nil {
		t.Errorf("NonCRUDHeader newConfig returns nil, got %v", conf)
	}
}

func TestHelperNonCRUDRequestBody_newConfig(t *testing.T) {
	conf, err := DefaultNonCRUDRequestBody.newConfig(map[any]any{})
	if err != nil {
		t.Errorf("newConfig() error: %v", err)
	}
	if conf != nil {
		t.Errorf("NonCRUDRequestBody newConfig returns nil, got %v", conf)
	}
}

// ==================== CreateRequest edge cases ====================

func TestHelperJSONRequest_CreateRequest_BodyContent(t *testing.T) {
	req, err := DefaultJSONRequest.CreateRequest("http://example.com", "test-value", nil)
	if err != nil {
		t.Fatalf("CreateRequest() error: %v", err)
	}
	body, _ := io.ReadAll(req.Body)
	// JSONRequest applies JSUnicode encoding, so the payload will be unicode-encoded
	if len(body) == 0 {
		t.Error("Body should not be empty")
	}
}

func TestHelperSOAPBody_CreateRequest_BodyContent(t *testing.T) {
	req, err := DefaultSOAPBody.CreateRequest("http://example.com", "test-payload", nil)
	if err != nil {
		t.Fatalf("CreateRequest() error: %v", err)
	}
	body, _ := io.ReadAll(req.Body)
	if !strings.Contains(string(body), "test-payload") {
		t.Errorf("Body should contain 'test-payload', got %q", string(body))
	}
	if !strings.Contains(string(body), "soapenv:Envelope") {
		t.Errorf("Body should contain SOAP envelope, got %q", string(body))
	}
}

func TestHelperHTMLMultipartForm_CreateRequest_BodyContainsPayload(t *testing.T) {
	req, err := DefaultHTMLMultipartForm.CreateRequest("http://example.com", "form-payload", nil)
	if err != nil {
		t.Fatalf("CreateRequest() error: %v", err)
	}
	body, _ := io.ReadAll(req.Body)
	if !strings.Contains(string(body), "form-payload") {
		t.Errorf("Body should contain 'form-payload', got %q", string(body))
	}
}

// ==================== CreateRequest with invalid URLs ====================

func TestHelperNonCrudUrlPath_CreateRequest_InvalidURL(t *testing.T) {
	_, err := DefaultNonCrudUrlPath.CreateRequest("://invalid", "payload", nil)
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

func TestHelperNonCrudUrlParam_CreateRequest_InvalidURL(t *testing.T) {
	_, err := DefaultNonCrudUrlParam.CreateRequest("://invalid", "payload", nil)
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

func TestHelperNonCRUDHeader_CreateRequest_InvalidURL(t *testing.T) {
	_, err := DefaultNonCRUDHeader.CreateRequest("://invalid", "payload", nil)
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

func TestHelperNonCRUDRequestBody_CreateRequest_InvalidURL(t *testing.T) {
	_, err := DefaultNonCRUDRequestBody.CreateRequest("://invalid", "payload", nil)
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

func TestHelperJSONBody_CreateRequest_InvalidURL(t *testing.T) {
	_, err := DefaultJSONBody.CreateRequest("://invalid", "payload", nil)
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

func TestHelperRequestBody_CreateRequest_InvalidURL(t *testing.T) {
	_, err := DefaultRequestBody.CreateRequest("://invalid", "payload", nil)
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

func TestHelperXMLBody_CreateRequest_InvalidURL(t *testing.T) {
	_, err := DefaultXMLBody.CreateRequest("://invalid", "payload", nil)
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

func TestHelperSOAPBody_CreateRequest_InvalidURL(t *testing.T) {
	_, err := DefaultSOAPBody.CreateRequest("://invalid", "payload", nil)
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

func TestHelperHTMLMultipartForm_CreateRequest_InvalidURL(t *testing.T) {
	_, err := DefaultHTMLMultipartForm.CreateRequest("://invalid", "payload", nil)
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

func TestHelperJSONRequest_CreateRequest_InvalidURL(t *testing.T) {
	_, err := DefaultJSONRequest.CreateRequest("://invalid", "payload", nil)
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}
