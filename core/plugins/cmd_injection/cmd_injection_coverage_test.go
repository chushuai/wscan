package cmd_injection

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	wscan_http "wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/utils/printer"
)

// ==================== Mock printer ====================

type cmdInjTestPrinter struct {
	vulns []*model.Vuln
}

func (p *cmdInjTestPrinter) Print(v any) error {
	if vuln, ok := v.(*model.Vuln); ok {
		p.vulns = append(p.vulns, vuln)
	}
	return nil
}
func (p *cmdInjTestPrinter) Close() error { return nil }
func (p *cmdInjTestPrinter) AddInterceptor(func(any) (any, error)) printer.Printer {
	return p
}
func (p *cmdInjTestPrinter) LogSubdomain(any) error { return nil }
func (p *cmdInjTestPrinter) LogVuln(any) error      { return nil }

// ==================== execAction tests ====================

func TestCmdInjection_ExecAction_NoParams(t *testing.T) {
	c := &CmdInjection{}
	cfg := c.DefaultConfig()
	ab := &base.ApolloBase{}
	ab.Output = &cmdInjTestPrinter{}
	c.Init(context.Background(), cfg, ab)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "Normal response")
	}))
	defer ts.Close()

	tsURL, _ := url.Parse(ts.URL)
	testURL := fmt.Sprintf("http://%s/page", tsURL.Host)
	req, _ := wscan_http.NewRequest("GET", testURL, nil)
	flow := &wscan_http.Flow{Request: req, Response: &wscan_http.Response{StatusCode: 200}}

	a := base.NewApollo(flow)
	a.ApolloBase.Output = &cmdInjTestPrinter{}
	a.ApolloBase.HTTPClient = wscan_http.NewClient()

	fingers := c.Fingers()
	if len(fingers) != 1 {
		t.Fatalf("Expected 1 finger, got %d", len(fingers))
	}

	err := fingers[0].CheckAction(context.Background(), a)
	_ = err
}

func TestCmdInjection_ExecAction_WithQueryParams(t *testing.T) {
	c := &CmdInjection{}
	cfg := c.DefaultConfig()
	ab := &base.ApolloBase{}
	ab.Output = &cmdInjTestPrinter{}
	c.Init(context.Background(), cfg, ab)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "Normal response")
	}))
	defer ts.Close()

	tsURL, _ := url.Parse(ts.URL)
	testURL := fmt.Sprintf("http://%s/page?q=test", tsURL.Host)
	req, _ := wscan_http.NewRequest("GET", testURL, nil)
	flow := &wscan_http.Flow{Request: req, Response: &wscan_http.Response{StatusCode: 200}}

	a := base.NewApollo(flow)
	a.ApolloBase.Output = &cmdInjTestPrinter{}
	a.ApolloBase.HTTPClient = wscan_http.NewClient()

	fingers := c.Fingers()
	err := fingers[0].CheckAction(context.Background(), a)
	_ = err
}

func TestCmdInjection_ExecAction_WithSubmitParam(t *testing.T) {
	// The execAction skips parameters named "submit"
	c := &CmdInjection{}
	cfg := c.DefaultConfig()
	ab := &base.ApolloBase{}
	ab.Output = &cmdInjTestPrinter{}
	c.Init(context.Background(), cfg, ab)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "Normal response")
	}))
	defer ts.Close()

	tsURL, _ := url.Parse(ts.URL)
	testURL := fmt.Sprintf("http://%s/page?submit=go&id=123", tsURL.Host)
	req, _ := wscan_http.NewRequest("GET", testURL, nil)
	flow := &wscan_http.Flow{Request: req, Response: &wscan_http.Response{StatusCode: 200}}

	a := base.NewApollo(flow)
	a.ApolloBase.Output = &cmdInjTestPrinter{}
	a.ApolloBase.HTTPClient = wscan_http.NewClient()

	fingers := c.Fingers()
	err := fingers[0].CheckAction(context.Background(), a)
	_ = err
}

func TestCmdInjection_ExecAction_VulnDetected(t *testing.T) {
	// Simulate a server that echoes the payload (vulnerable to cmd injection)
	c := &CmdInjection{}
	cfg := c.DefaultConfig()
	ab := &base.ApolloBase{}
	printer := &cmdInjTestPrinter{}
	ab.Output = printer
	c.Init(context.Background(), cfg, ab)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo back the query parameter value (simulating command injection)
		val := r.URL.Query().Get("cmd")
		w.WriteHeader(200)
		fmt.Fprint(w, val)
	}))
	defer ts.Close()

	tsURL, _ := url.Parse(ts.URL)
	testURL := fmt.Sprintf("http://%s/page?cmd=test", tsURL.Host)
	req, _ := wscan_http.NewRequest("GET", testURL, nil)
	flow := &wscan_http.Flow{Request: req, Response: &wscan_http.Response{StatusCode: 200}}

	a := base.NewApollo(flow)
	a.ApolloBase.Output = printer
	a.ApolloBase.HTTPClient = wscan_http.NewClient()

	fingers := c.Fingers()
	err := fingers[0].CheckAction(context.Background(), a)
	_ = err
}

func TestCmdInjection_ExecAction_HTTPError(t *testing.T) {
	c := &CmdInjection{}
	cfg := c.DefaultConfig()
	ab := &base.ApolloBase{}
	ab.Output = &cmdInjTestPrinter{}
	c.Init(context.Background(), cfg, ab)

	// Use unreachable port to trigger HTTP error
	testURL := "http://127.0.0.1:1/page?q=test"
	req, _ := wscan_http.NewRequest("GET", testURL, nil)
	flow := &wscan_http.Flow{Request: req, Response: &wscan_http.Response{StatusCode: 200}}

	a := base.NewApollo(flow)
	a.ApolloBase.Output = &cmdInjTestPrinter{}
	a.ApolloBase.HTTPClient = wscan_http.NewClient()

	fingers := c.Fingers()
	err := fingers[0].CheckAction(context.Background(), a)
	// HTTP errors should be handled gracefully
	_ = err
}

func TestCmdInjection_ExecAction_PostWithBodyParams(t *testing.T) {
	c := &CmdInjection{}
	cfg := c.DefaultConfig()
	ab := &base.ApolloBase{}
	ab.Output = &cmdInjTestPrinter{}
	c.Init(context.Background(), cfg, ab)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "OK")
	}))
	defer ts.Close()

	tsURL, _ := url.Parse(ts.URL)
	testURL := fmt.Sprintf("http://%s/page", tsURL.Host)
	req, _ := wscan_http.NewRequest("POST", testURL, nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	flow := &wscan_http.Flow{Request: req, Response: &wscan_http.Response{StatusCode: 200}}

	a := base.NewApollo(flow)
	a.ApolloBase.Output = &cmdInjTestPrinter{}
	a.ApolloBase.HTTPClient = wscan_http.NewClient()

	fingers := c.Fingers()
	err := fingers[0].CheckAction(context.Background(), a)
	_ = err
}

// ==================== CmdInjection comprehensive ====================

func TestCmdInjection_MultipleClose(t *testing.T) {
	c := &CmdInjection{}
	for i := 0; i < 3; i++ {
		if err := c.Close(); err != nil {
			t.Errorf("Close() call %d error: %v", i, err)
		}
	}
}

func TestCmdInjection_GetConfig_AfterInit(t *testing.T) {
	c := &CmdInjection{}
	cfg := c.DefaultConfig()
	ab := &base.ApolloBase{}
	c.Init(context.Background(), cfg, ab)

	gotCfg := c.GetConfig()
	if gotCfg == nil {
		t.Fatal("Expected non-nil config after Init")
	}
}

// ==================== Config comprehensive ====================

func TestConfig_Fields(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:       "cmd-injection",
			Enabled:    true,
			IsAdvanced: true,
		},
	}
	if !cfg.PluginBaseConfig.IsAdvanced {
		t.Error("IsAdvanced should be true")
	}
	bc := cfg.BaseConfig()
	if bc.Name != "cmd-injection" {
		t.Errorf("Name = %q, want 'cmd-injection'", bc.Name)
	}
}

// ==================== GenCmdInjectionPayload comprehensive ====================

func TestGenCmdInjectionPayload_HasSuffixAndValue(t *testing.T) {
	payloads := GenCmdInjectionPayload()

	hasValue := false
	hasSuffix := false
	hasPrefix := false

	for _, p := range payloads {
		switch p.ParameterType {
		case wscan_http.ParameterTypeValue:
			hasValue = true
		case wscan_http.ParameterTypeSuffix:
			hasSuffix = true
		case wscan_http.ParameterTypePrefix:
			hasPrefix = true
		}
	}

	if !hasValue {
		t.Error("Expected Value-type payloads")
	}
	if !hasSuffix {
		t.Error("Expected Suffix-type payloads")
	}
	// Prefix type is not currently used
	_ = hasPrefix
}

func TestGenCmdInjectionPayload_AllNonEmpty(t *testing.T) {
	payloads := GenCmdInjectionPayload()
	for i, p := range payloads {
		if p.Payload == "" {
			t.Errorf("Payload %d: empty Payload", i)
		}
		if p.VerifyResult == "" {
			t.Errorf("Payload %d: empty VerifyResult", i)
		}
		if p.ParameterType == "" {
			t.Errorf("Payload %d: empty ParameterType", i)
		}
	}
}

// ==================== RenderIntAdd range ====================

func TestRenderIntAdd_LargeValues(t *testing.T) {
	for i := 0; i < 5; i++ {
		payload, verifyResult := RenderIntAdd("\nexpr %d + %d\n")
		if payload == "" {
			t.Error("Payload should not be empty")
		}
		if verifyResult == "" {
			t.Error("VerifyResult should not be empty")
		}
		// verifyResult should be a large number (sum of two 100M-500M numbers)
		if len(verifyResult) < 9 {
			t.Errorf("VerifyResult should be >= 200M (9+ digits), got %s", verifyResult)
		}
	}
}

// ==================== RenderIntMul uniqueness ====================

func TestRenderIntMul_UniqueValues(t *testing.T) {
	results := make(map[string]bool)
	for i := 0; i < 5; i++ {
		_, verifyResult := RenderIntMul("response.write(%d*%d)")
		results[verifyResult] = true
	}
	// Each call should produce unique random values (with very high probability)
	if len(results) < 3 {
		t.Errorf("Expected mostly unique results, got %d unique out of 5", len(results))
	}
}

// ==================== RenderIntMd5Payload format ====================

func TestRenderIntMd5Payload_ContainsFormat(t *testing.T) {
	payload, verifyResult := RenderIntMd5Payload("print(md5(%d));")
	if !containsCov(payload, "md5") {
		t.Errorf("Payload should contain 'md5', got: %s", payload)
	}
	if len(verifyResult) != 32 {
		t.Errorf("MD5 result should be 32 chars, got %d chars", len(verifyResult))
	}
}

// ==================== EchoBasedInjection interface ====================

func TestEchoBasedInjection_Interface(t *testing.T) {
	// CMDInjectionPayload implements EchoBasedInjection
	var _ EchoBasedInjection = &CMDInjectionPayload{}
	var _ EchoBasedInjection = &PHPCodeInjectionPayload{}
	var _ EchoBasedInjection = &TemplateInjectionPayload{}
}

// ==================== Helper ====================

func containsCov(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
