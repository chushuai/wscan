package placeholder

import (
	"io"
	"strings"
	"testing"
)

// ==================== Apply with various valid placeholders ====================

func TestHelperApply_AllSimplePlaceholders(t *testing.T) {
	testURL := "http://example.com/test"
	payload := "test-payload-data"

	placeholders := []string{
		"Header", "HTMLForm", "HTMLMultipartForm", "JSONBody",
		"RequestBody", "XMLBody", "SOAPBody", "JSONRequest",
		"URLParam", "URLPath", "UserAgent",
		"NonCrudUrlPath", "NonCrudUrlParam", "NonCRUDHeader", "NonCRUDRequestBody",
	}

	for _, name := range placeholders {
		t.Run(name, func(t *testing.T) {
			req, err := Apply(testURL, payload, name, nil)
			if err != nil {
				t.Errorf("Apply(%q) error: %v", name, err)
			}
			if req == nil {
				t.Errorf("Apply(%q) returned nil request", name)
			}
		})
	}
}

// ==================== GetPlaceholderConfig with RawRequest ====================

func TestHelperGetPlaceholderConfig_RawRequest_FullConfig(t *testing.T) {
	conf, err := GetPlaceholderConfig("RawRequest", map[any]any{
		"method":  "POST",
		"path":    "/api/test",
		"headers": map[any]any{"Content-Type": "application/json"},
		"body":    `{"data":"test"}`,
	})
	if err != nil {
		t.Fatalf("GetPlaceholderConfig() error: %v", err)
	}
	if conf == nil {
		t.Error("Expected non-nil config")
	}
}

// ==================== Body content verification ====================

func TestHelperRequestBody_BodyContent(t *testing.T) {
	req, err := Apply("http://example.com", "my-body-content", "RequestBody", nil)
	if err != nil {
		t.Fatalf("Apply() error: %v", err)
	}
	body, _ := io.ReadAll(req.Body)
	if string(body) != "my-body-content" {
		t.Errorf("Body = %q, want 'my-body-content'", string(body))
	}
}

func TestHelperXMLBody_BodyContent(t *testing.T) {
	payload := "<root><item>test</item></root>"
	req, err := Apply("http://example.com", payload, "XMLBody", nil)
	if err != nil {
		t.Fatalf("Apply() error: %v", err)
	}
	body, _ := io.ReadAll(req.Body)
	if string(body) != payload {
		t.Errorf("Body = %q, want %q", string(body), payload)
	}
}

func TestHelperJSONBody_BodyContent(t *testing.T) {
	payload := `{"key":"value"}`
	req, err := Apply("http://example.com", payload, "JSONBody", nil)
	if err != nil {
		t.Fatalf("Apply() error: %v", err)
	}
	body, _ := io.ReadAll(req.Body)
	if string(body) != payload {
		t.Errorf("Body = %q, want %q", string(body), payload)
	}
}

// ==================== Header placeholder verification ====================

func TestHelperHeader_CustomHeaderPresent(t *testing.T) {
	req, err := Apply("http://example.com", "my-payload", "Header", nil)
	if err != nil {
		t.Fatalf("Apply() error: %v", err)
	}
	found := false
	for key, vals := range req.Header {
		if strings.HasPrefix(key, "X-") && len(vals) > 0 && vals[0] == "my-payload" {
			found = true
		}
	}
	if !found {
		t.Error("Expected custom X- header with payload value")
	}
}

// ==================== UserAgent verification ====================

func TestHelperUserAgent_HeaderSet(t *testing.T) {
	req, err := Apply("http://example.com", "custom-user-agent", "UserAgent", nil)
	if err != nil {
		t.Fatalf("Apply() error: %v", err)
	}
	ua := req.UserAgent()
	if ua != "custom-user-agent" {
		t.Errorf("User-Agent = %q, want 'custom-user-agent'", ua)
	}
}

// ==================== NonCRUD placeholders ====================

func TestHelperNonCrudUrlPath_URLContainsPayload(t *testing.T) {
	req, err := Apply("http://example.com/api", "injected-path", "NonCrudUrlPath", nil)
	if err != nil {
		t.Fatalf("Apply() error: %v", err)
	}
	if !strings.Contains(req.URL.String(), "injected-path") {
		t.Errorf("URL should contain 'injected-path', got %q", req.URL.String())
	}
}

func TestHelperNonCrudUrlParam_URLContainsPayload(t *testing.T) {
	req, err := Apply("http://example.com/api", "injected-param", "NonCrudUrlParam", nil)
	if err != nil {
		t.Fatalf("Apply() error: %v", err)
	}
	if !strings.Contains(req.URL.String(), "injected-param") {
		t.Errorf("URL should contain 'injected-param', got %q", req.URL.String())
	}
}

func TestHelperNonCRUDHeader_CustomHeaderPresent(t *testing.T) {
	req, err := Apply("http://example.com", "custom-value", "NonCRUDHeader", nil)
	if err != nil {
		t.Fatalf("Apply() error: %v", err)
	}
	found := false
	for key, vals := range req.Header {
		if strings.HasPrefix(key, "X-") && len(vals) > 0 && vals[0] == "custom-value" {
			found = true
		}
	}
	if !found {
		t.Error("Expected custom X- header with payload value for NonCRUDHeader")
	}
}

func TestHelperNonCRUDRequestBody_BodyContent(t *testing.T) {
	req, err := Apply("http://example.com", "body-content", "NonCRUDRequestBody", nil)
	if err != nil {
		t.Fatalf("Apply() error: %v", err)
	}
	body, _ := io.ReadAll(req.Body)
	if string(body) != "body-content" {
		t.Errorf("Body = %q, want 'body-content'", string(body))
	}
}

// ==================== SOAPBody verification ====================

func TestHelperSOAPBody_ContainsEnvelope(t *testing.T) {
	req, err := Apply("http://example.com", "test-payload", "SOAPBody", nil)
	if err != nil {
		t.Fatalf("Apply() error: %v", err)
	}
	body, _ := io.ReadAll(req.Body)
	if !strings.Contains(string(body), "soapenv:Envelope") {
		t.Error("Expected SOAP envelope in body")
	}
	if !strings.Contains(string(body), "test-payload") {
		t.Error("Expected payload in SOAP body")
	}
	sa := req.Header.Get("SOAPAction")
	if sa == "" {
		t.Error("Expected non-empty SOAPAction header")
	}
}

// ==================== HTMLForm verification ====================

func TestHelperHTMLForm_ContainsPayload(t *testing.T) {
	req, err := Apply("http://example.com", "form-data", "HTMLForm", nil)
	if err != nil {
		t.Fatalf("Apply() error: %v", err)
	}
	body, _ := io.ReadAll(req.Body)
	if !strings.Contains(string(body), "form-data") {
		t.Errorf("Body should contain 'form-data', got %q", string(body))
	}
}

// ==================== HTMLMultipartForm verification ====================

func TestHelperHTMLMultipartForm_ContainsPayload(t *testing.T) {
	req, err := Apply("http://example.com", "multipart-data", "HTMLMultipartForm", nil)
	if err != nil {
		t.Fatalf("Apply() error: %v", err)
	}
	body, _ := io.ReadAll(req.Body)
	if !strings.Contains(string(body), "multipart-data") {
		t.Errorf("Body should contain 'multipart-data', got %q", string(body))
	}
}
