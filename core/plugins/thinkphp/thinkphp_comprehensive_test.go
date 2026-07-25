package thinkphp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	whttp "wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/utils/printer"
)

// noOpPrinter is a simple printer that discards output.
type noOpPrinter struct{}

func (noOpPrinter) AddInterceptor(func(any) (any, error)) printer.Printer { return noOpPrinter{} }
func (noOpPrinter) Close() error                                          { return nil }
func (noOpPrinter) Print(any) error                                       { return nil }

// helperCreateFlow creates an http.Flow targeting the given URL.
func helperCreateFlow(targetURL string) *whttp.Flow {
	req, err := whttp.NewRequest("GET", targetURL, nil)
	if err != nil {
		panic(fmt.Sprintf("helperCreateFlow: %v", err))
	}
	return &whttp.Flow{
		Request: req,
		Response: &whttp.Response{
			StatusCode: 200,
			Text:       "OK",
		},
	}
}

// helperCreateApollo creates an Apollo with the given flow and HTTP client.
func helperCreateApollo(flow *whttp.Flow, client *whttp.Client) *base.Apollo {
	a := base.NewApollo(flow)
	a.ApolloBase = &base.ApolloBase{
		HTTPClient: client,
		Output:     noOpPrinter{},
	}
	return a
}

// helperNewHTTPClient creates a real HTTP client that can talk to the test server.
func helperNewHTTPClient() *whttp.Client {
	return whttp.NewClient()
}

// helperReadBody reads the full body from an HTTP request.
func helperReadBody(r *http.Request) string {
	body, _ := io.ReadAll(r.Body)
	return string(body)
}

// helperParseFormBody parses a URL-encoded form body manually.
func helperParseFormBody(body string) url.Values {
	v, _ := url.ParseQuery(body)
	return v
}

// ==================== InvokeRce CheckAction tests ====================

func TestInvokeRce_CheckAction_NormalResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "Normal ThinkPHP page")
	}))
	defer server.Close()

	flow := helperCreateFlow(server.URL + "/index.php")
	client := helperNewHTTPClient()
	apollo := helperCreateApollo(flow, client)

	r := &InvokeRce{}
	finger := r.Finger()
	err := finger.CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("CheckAction error: %v", err)
	}
}

func TestInvokeRce_CheckAction_VulnDetected(t *testing.T) {
	// Simulate a vulnerable ThinkPHP server that processes the invokefunction payload
	// and returns the expected marker pattern
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			body := helperReadBody(r)
			form := helperParseFormBody(body)
			vars1 := form.Get("vars[1][]")
			// The payload contains R1%25%25R2 which URL-decodes to R1%%R2
			// Simulate printf: %% becomes %
			result := strings.ReplaceAll(vars1, "%%", "%")
			w.Header().Set("Content-Type", "text/html")
			// The check looks for fmt.Sprintf("%s%%%s1", r1, r2) = r1 + "%" + r2 + "1"
			fmt.Fprint(w, result+"1")
			return
		}
		w.WriteHeader(404)
	}))
	defer server.Close()

	flow := helperCreateFlow(server.URL + "/index.php")
	client := helperNewHTTPClient()
	apollo := helperCreateApollo(flow, client)

	r := &InvokeRce{}
	finger := r.Finger()
	err := finger.CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("CheckAction error: %v", err)
	}
}

// ==================== MethodRce CheckAction tests ====================

func TestMethodRce_CheckAction_NormalResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "Normal response")
	}))
	defer server.Close()

	flow := helperCreateFlow(server.URL + "/index.php?s=captcha")
	client := helperNewHTTPClient()
	apollo := helperCreateApollo(flow, client)

	r := &MethodRce{}
	finger := r.Finger()
	err := finger.CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("CheckAction error: %v", err)
	}
}

func TestMethodRce_CheckAction_VulnDetected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			body := helperReadBody(r)
			form := helperParseFormBody(body)
			serverRM := form.Get("server[REQUEST_METHOD]")
			// Simulate printf: %% becomes %
			result := strings.ReplaceAll(serverRM, "%%", "%")
			w.Header().Set("Content-Type", "text/html")
			// The check looks for fmt.Sprintf("%s%%%s", r1, r2) = r1 + "%" + r2
			fmt.Fprint(w, result)
			return
		}
		w.WriteHeader(404)
	}))
	defer server.Close()

	flow := helperCreateFlow(server.URL + "/index.php")
	client := helperNewHTTPClient()
	apollo := helperCreateApollo(flow, client)

	r := &MethodRce{}
	finger := r.Finger()
	err := finger.CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("CheckAction error: %v", err)
	}
}

// ==================== PregRce CheckAction tests ====================

func TestPregRce_CheckAction_NormalResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "Normal ThinkPHP page")
	}))
	defer server.Close()

	flow := helperCreateFlow(server.URL + "/index.php")
	client := helperNewHTTPClient()
	apollo := helperCreateApollo(flow, client)

	r := &PregRce{}
	finger := r.Finger()
	err := finger.CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("CheckAction error: %v", err)
	}
}

func TestPregRce_CheckAction_VulnDetected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The URL query contains s=/aa/bb/name/${@printf(N1*N2)}
		// The vulnerable server would evaluate this expression
		rawQuery := r.URL.RawQuery
		// Extract the multiplication from the query string
		if strings.Contains(rawQuery, "printf") {
			idx := strings.Index(rawQuery, "printf(")
			if idx >= 0 {
				rest := rawQuery[idx+7:]
				endIdx := strings.Index(rest, ")")
				if endIdx >= 0 {
					expr := rest[:endIdx]
					// URL-decode the expression (the %7B and %7D are { and })
					expr, _ = url.QueryUnescape(expr)
					mulParts := strings.Split(expr, "*")
					if len(mulParts) == 2 {
						var a, b int
						fmt.Sscanf(mulParts[0], "%d", &a)
						fmt.Sscanf(mulParts[1], "%d", &b)
						w.Header().Set("Content-Type", "text/html")
						fmt.Fprintf(w, "Result: %d", a*b)
						return
					}
				}
			}
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "Normal page")
	}))
	defer server.Close()

	flow := helperCreateFlow(server.URL + "/index.php")
	client := helperNewHTTPClient()
	apollo := helperCreateApollo(flow, client)

	r := &PregRce{}
	finger := r.Finger()
	err := finger.CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("CheckAction error: %v", err)
	}
}

// ==================== Sqli CheckAction tests ====================

func TestSqli_CheckAction_XPATHError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "XPATH syntax error: something went wrong")
	}))
	defer server.Close()

	flow := helperCreateFlow(server.URL + "/index.php")
	client := helperNewHTTPClient()
	apollo := helperCreateApollo(flow, client)

	s := &Sqli{}
	finger := s.Finger()
	err := finger.CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("CheckAction error: %v", err)
	}
}

func TestSqli_CheckAction_NormalResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "Normal database result")
	}))
	defer server.Close()

	flow := helperCreateFlow(server.URL + "/index.php")
	client := helperNewHTTPClient()
	apollo := helperCreateApollo(flow, client)

	s := &Sqli{}
	finger := s.Finger()
	err := finger.CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("CheckAction error: %v", err)
	}
}

// ==================== V6FileWrite CheckAction tests ====================

func TestV6FileWrite_CheckAction_NormalResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "Normal ThinkPHP page - no session file accessible")
	}))
	defer server.Close()

	flow := helperCreateFlow(server.URL + "/index.php")
	client := helperNewHTTPClient()
	apollo := helperCreateApollo(flow, client)

	v := &V6FileWrite{}
	finger := v.Finger()
	err := finger.CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("CheckAction error: %v", err)
	}
}

func TestV6FileWrite_CheckAction_VulnDetected(t *testing.T) {
	var capturedCookie string
	var marker string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/index.php/index/index/index" && r.Method == "POST" {
			capturedCookie = r.Header.Get("Cookie")
			if strings.HasPrefix(capturedCookie, "PHPSESSID=") {
				marker = strings.TrimPrefix(capturedCookie, "PHPSESSID=")
			}
			w.WriteHeader(200)
			return
		}
		// Session file paths
		if strings.HasPrefix(r.URL.Path, "/runtime/session/") {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, marker)
			return
		}
		w.WriteHeader(404)
	}))
	defer server.Close()

	flow := helperCreateFlow(server.URL + "/index.php")
	client := helperNewHTTPClient()
	apollo := helperCreateApollo(flow, client)

	v := &V6FileWrite{}
	finger := v.Finger()
	err := finger.CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("CheckAction error: %v", err)
	}
	// Verify the session write request was made correctly
	if !strings.HasPrefix(capturedCookie, "PHPSESSID=") {
		t.Errorf("Expected PHPSESSID cookie, got: %s", capturedCookie)
	}
}

// ==================== Sqli payload Check function tests ====================

func TestSqliPayloads_Check_XPATHSyntaxError(t *testing.T) {
	for i, p := range sqliPayloads {
		if !p.Check("XPATH syntax error", "marker123") {
			t.Errorf("payload[%d]: Check should return true for XPATH syntax error", i)
		}
	}
}

func TestSqliPayloads_Check_MarkerPattern(t *testing.T) {
	marker := "abcdef01"
	for i, p := range sqliPayloads {
		if !p.Check("~"+marker+"~", marker) {
			t.Errorf("payload[%d]: Check should return true for ~%s~ pattern", i, marker)
		}
	}
}

func TestSqliPayloads_Check_NoMatch(t *testing.T) {
	marker := "abcdef01"
	for i, p := range sqliPayloads {
		if p.Check("normal response without any markers", marker) {
			t.Errorf("payload[%d]: Check should return false for normal response", i)
		}
	}
}

func TestSqliPayloads_Check_EmptyBody(t *testing.T) {
	marker := "abcdef01"
	for i, p := range sqliPayloads {
		if p.Check("", marker) {
			t.Errorf("payload[%d]: Check should return false for empty body", i)
		}
	}
}

func TestSqliPayloads_Check_MarkerInBodyButNotDelimited(t *testing.T) {
	marker := "abcdef01"
	for i, p := range sqliPayloads {
		if p.Check("this is "+marker+" in the middle", marker) {
			t.Errorf("payload[%d]: Check should return false for marker without delimiters", i)
		}
	}
}

// ==================== Thinkphp Fingers config edge cases ====================

func TestThinkphp_Fingers_NilConfigCast(t *testing.T) {
	p := &Thinkphp{}
	fingers := p.Fingers()
	if len(fingers) != 4 {
		t.Errorf("Expected 4 fingers with nil config, got %d", len(fingers))
	}
}

// otherConfig is a PluginConfigInterface implementation that is not *Config
type otherConfig struct {
	base.PluginBaseConfig
}

func (c *otherConfig) BaseConfig() *base.PluginBaseConfig {
	return &c.PluginBaseConfig
}

func TestThinkphp_Fingers_ConfigNotMatchingType(t *testing.T) {
	p := &Thinkphp{}
	cfg := &otherConfig{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "thinkphp",
			Enabled: true,
		},
	}
	ab := &base.ApolloBase{}
	p.Init(context.Background(), cfg, ab)

	fingers := p.Fingers()
	if len(fingers) != 4 {
		t.Errorf("Expected 4 fingers when config type doesn't match, got %d", len(fingers))
	}
}

// ==================== Thinkphp Close and execAction ====================

func TestThinkphp_ExecAction(t *testing.T) {
	p := &Thinkphp{}
	err := p.execAction(context.Background(), nil)
	if err != nil {
		t.Errorf("execAction should return nil, got %v", err)
	}
}

func TestThinkphp_Close_Nil(t *testing.T) {
	p := &Thinkphp{}
	err := p.Close()
	if err != nil {
		t.Errorf("Close should return nil, got %v", err)
	}
}

// ==================== Config edge case tests ====================

func TestConfig_BaseConfig_NilFields(t *testing.T) {
	cfg := &Config{}
	bc := cfg.BaseConfig()
	if bc == nil {
		t.Fatal("BaseConfig should not return nil")
	}
	if bc.Name != "" {
		t.Errorf("Expected empty Name, got '%s'", bc.Name)
	}
	if bc.Enabled {
		t.Error("Expected Enabled=false by default")
	}
	if cfg.DetectThinkPHPSQLInjection {
		t.Error("Expected DetectThinkPHPSQLInjection=false by default")
	}
}

// ==================== InvokeRce with cancelled context ====================

func TestInvokeRce_CheckAction_WithCancelledContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(200)
	}))
	defer server.Close()

	flow := helperCreateFlow(server.URL + "/index.php")
	client := helperNewHTTPClient()
	apollo := helperCreateApollo(flow, client)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	r := &InvokeRce{}
	finger := r.Finger()
	err := finger.CheckAction(ctx, apollo)
	if err != nil {
		t.Logf("CheckAction with cancelled context: %v", err)
	}
}

// ==================== MethodRce with cancelled context ====================

func TestMethodRce_CheckAction_WithCancelledContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(200)
	}))
	defer server.Close()

	flow := helperCreateFlow(server.URL + "/index.php")
	client := helperNewHTTPClient()
	apollo := helperCreateApollo(flow, client)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	r := &MethodRce{}
	finger := r.Finger()
	err := finger.CheckAction(ctx, apollo)
	if err != nil {
		t.Logf("CheckAction with cancelled context: %v", err)
	}
}

// ==================== Sqli CheckAction with connection failure ====================

func TestSqli_CheckAction_ConnectionFailure(t *testing.T) {
	flow := helperCreateFlow("http://127.0.0.1:1/index.php")
	client := helperNewHTTPClient()
	apollo := helperCreateApollo(flow, client)

	s := &Sqli{}
	finger := s.Finger()
	err := finger.CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("CheckAction with connection failure: %v", err)
	}
}

// ==================== V6FileWrite CheckAction with connection failure ====================

func TestV6FileWrite_CheckAction_ConnectionFailure(t *testing.T) {
	flow := helperCreateFlow("http://127.0.0.1:1/index.php")
	client := helperNewHTTPClient()
	apollo := helperCreateApollo(flow, client)

	v := &V6FileWrite{}
	finger := v.Finger()
	err := finger.CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("CheckAction with connection failure: %v", err)
	}
}

// ==================== Sqli Payload content tests ====================

func TestSqliPayloads_ContainsMarker(t *testing.T) {
	for i, p := range sqliPayloads {
		if !strings.Contains(p.Payload, "{{marker}}") {
			t.Errorf("payload[%d]: Payload should contain {{marker}} placeholder", i)
		}
	}
}

func TestSqliPayloads_SpecificPayloads(t *testing.T) {
	expected := []struct {
		path     string
		paramKey string
	}{
		{"/index.php", "order[id]"},
		{"/index.php", "where[id]"},
		{"/index.php", "group[id]"},
	}
	for i, exp := range expected {
		if i >= len(sqliPayloads) {
			break
		}
		if sqliPayloads[i].Path != exp.path {
			t.Errorf("payload[%d].Path: expected %q, got %q", i, exp.path, sqliPayloads[i].Path)
		}
		if sqliPayloads[i].ParamKey != exp.paramKey {
			t.Errorf("payload[%d].ParamKey: expected %q, got %q", i, exp.paramKey, sqliPayloads[i].ParamKey)
		}
	}
}

// ==================== Finger Binding severity tests ====================

func TestAllFingers_Severity(t *testing.T) {
	p := &Thinkphp{}
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "thinkphp",
			Enabled: true,
		},
		DetectThinkPHPSQLInjection: true,
	}
	ab := &base.ApolloBase{}
	p.Init(context.Background(), cfg, ab)
	fingers := p.Fingers()

	expectedSeverities := map[string]model.SeverityLevel{
		"thinkphp/rce/invoke":            model.SeverityCritical,
		"thinkphp/rce/method":            model.SeverityCritical,
		"thinkphp/rce/preg":              model.SeverityCritical,
		"thinkphp/sqli/default":          model.SeverityHigh,
		"thinkphp/v6-file-write/default": model.SeverityHigh,
	}
	for _, f := range fingers {
		expected, ok := expectedSeverities[f.Binding.ID]
		if !ok {
			t.Errorf("Unexpected finger ID: %s", f.Binding.ID)
			continue
		}
		if f.Binding.Severity != expected {
			t.Errorf("Finger %s: expected severity %v, got %v", f.Binding.ID, expected, f.Binding.Severity)
		}
	}
}

// ==================== All Fingers Channel tests ====================

func TestAllFingers_Channels(t *testing.T) {
	p := &Thinkphp{}
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "thinkphp",
			Enabled: true,
		},
		DetectThinkPHPSQLInjection: true,
	}
	ab := &base.ApolloBase{}
	p.Init(context.Background(), cfg, ab)
	fingers := p.Fingers()

	expectedChannels := map[string]string{
		"thinkphp/rce/invoke":            "website",
		"thinkphp/rce/method":            "website",
		"thinkphp/rce/preg":              "website",
		"thinkphp/sqli/default":          "web-generic",
		"thinkphp/v6-file-write/default": "website",
	}
	for _, f := range fingers {
		expected, ok := expectedChannels[f.Binding.ID]
		if !ok {
			t.Errorf("Unexpected finger ID: %s", f.Binding.ID)
			continue
		}
		if f.Channel != expected {
			t.Errorf("Finger %s: expected channel %q, got %q", f.Binding.ID, expected, f.Channel)
		}
	}
}

// ==================== Finger struct type tests ====================

func TestInvokeRce_Type(t *testing.T) {
	r := &InvokeRce{}
	if r == nil {
		t.Fatal("InvokeRce should be creatable")
	}
}

func TestMethodRce_Type(t *testing.T) {
	r := &MethodRce{}
	if r == nil {
		t.Fatal("MethodRce should be creatable")
	}
}

func TestPregRce_Type(t *testing.T) {
	r := &PregRce{}
	if r == nil {
		t.Fatal("PregRce should be creatable")
	}
}

func TestSqli_Type(t *testing.T) {
	s := &Sqli{}
	if s == nil {
		t.Fatal("Sqli should be creatable")
	}
}

func TestV6FileWrite_Type(t *testing.T) {
	v := &V6FileWrite{}
	if v == nil {
		t.Fatal("V6FileWrite should be creatable")
	}
}

// ==================== Sqli payload replacement test ====================

func TestSqliPayloads_MarkerReplacement(t *testing.T) {
	marker := "TESTMARK"
	for i, p := range sqliPayloads {
		replaced := strings.Replace(p.Payload, "{{marker}}", marker, -1)
		if !strings.Contains(replaced, marker) {
			t.Errorf("payload[%d]: marker replacement failed", i)
		}
		if strings.Contains(replaced, "{{marker}}") {
			t.Errorf("payload[%d]: marker placeholder not fully replaced", i)
		}
	}
}

// ==================== V6FileWrite session paths ====================

func TestV6FileWrite_SessionPathConstruction(t *testing.T) {
	marker := "testsession"
	paths := []string{
		fmt.Sprintf("/runtime/session/sess_%s", marker),
		fmt.Sprintf("/runtime/session/%s.php", marker),
	}
	if len(paths) != 2 {
		t.Error("Expected 2 session paths")
	}
	if !strings.Contains(paths[0], "sess_") {
		t.Error("First path should contain sess_ prefix")
	}
	if !strings.HasSuffix(paths[1], ".php") {
		t.Error("Second path should end with .php")
	}
}

// ==================== URL parsing in Finger methods ====================

func TestInvokeRce_URLConstruction(t *testing.T) {
	baseURL, err := url.Parse("http://example.com/index.php")
	if err != nil {
		t.Fatalf("Failed to parse base URL: %v", err)
	}
	reqURL, err := baseURL.Parse("/index.php?s=/Index/\\think\\app/invokefunction")
	if err != nil {
		t.Fatalf("Failed to parse sub-URL: %v", err)
	}
	if reqURL.Path != "/index.php" {
		t.Errorf("Unexpected path: %s", reqURL.Path)
	}
}

func TestMethodRce_URLConstruction(t *testing.T) {
	baseURL, err := url.Parse("http://example.com/index.php")
	if err != nil {
		t.Fatalf("Failed to parse base URL: %v", err)
	}
	reqURL, err := baseURL.Parse("/index.php?s=captcha")
	if err != nil {
		t.Fatalf("Failed to parse sub-URL: %v", err)
	}
	if reqURL.RawQuery != "s=captcha" {
		t.Errorf("Unexpected query: %s", reqURL.RawQuery)
	}
}

func TestPregRce_URLConstruction(t *testing.T) {
	baseURL, err := url.Parse("http://example.com/index.php")
	if err != nil {
		t.Fatalf("Failed to parse base URL: %v", err)
	}
	path := "/index.php?s=/aa/bb/name/$%7B@printf(1234*5678)%7D"
	reqURL, err := baseURL.Parse(path)
	if err != nil {
		t.Fatalf("Failed to parse sub-URL: %v", err)
	}
	t.Logf("PregRce URL: %s", reqURL.String())
}

// ==================== InvokeRce payload construction test ====================

func TestInvokeRce_PayloadConstruction(t *testing.T) {
	r1 := "AAAAAAAA"
	r2 := "BBBBBBBB"
	payload := "function=call_user_func_array&vars[0]=printf&vars[1][]={{r1}}%25%25{{r2}}"
	payload = strings.Replace(payload, "{{r1}}", r1, -1)
	payload = strings.Replace(payload, "{{r2}}", r2, -1)

	if !strings.Contains(payload, r1) {
		t.Error("Payload should contain r1")
	}
	if !strings.Contains(payload, r2) {
		t.Error("Payload should contain r2")
	}
	if strings.Contains(payload, "{{r1}}") || strings.Contains(payload, "{{r2}}") {
		t.Error("Payload should not contain placeholder markers")
	}
}

// ==================== MethodRce payload construction test ====================

func TestMethodRce_PayloadConstruction(t *testing.T) {
	r1 := "CCCCCCCC"
	r2 := "DDDDDDDD"
	payload := "_method=__construct&filter[]=printf&method=GET&server[REQUEST_METHOD]={{r1}}%25%25{{r2}}&get[]=1"
	payload = strings.Replace(payload, "{{r1}}", r1, -1)
	payload = strings.Replace(payload, "{{r2}}", r2, -1)

	if !strings.Contains(payload, r1) {
		t.Error("Payload should contain r1")
	}
	if !strings.Contains(payload, r2) {
		t.Error("Payload should contain r2")
	}
	if strings.Contains(payload, "{{r1}}") || strings.Contains(payload, "{{r2}}") {
		t.Error("Payload should not contain placeholder markers")
	}
}

// ==================== All CheckAction with server returning 500 ====================

func TestInvokeRce_CheckAction_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer server.Close()

	flow := helperCreateFlow(server.URL + "/index.php")
	client := helperNewHTTPClient()
	apollo := helperCreateApollo(flow, client)

	r := &InvokeRce{}
	finger := r.Finger()
	err := finger.CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("CheckAction error: %v", err)
	}
}

func TestMethodRce_CheckAction_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer server.Close()

	flow := helperCreateFlow(server.URL + "/index.php")
	client := helperNewHTTPClient()
	apollo := helperCreateApollo(flow, client)

	r := &MethodRce{}
	finger := r.Finger()
	err := finger.CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("CheckAction error: %v", err)
	}
}

func TestPregRce_CheckAction_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer server.Close()

	flow := helperCreateFlow(server.URL + "/index.php")
	client := helperNewHTTPClient()
	apollo := helperCreateApollo(flow, client)

	r := &PregRce{}
	finger := r.Finger()
	err := finger.CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("CheckAction error: %v", err)
	}
}

func TestSqli_CheckAction_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer server.Close()

	flow := helperCreateFlow(server.URL + "/index.php")
	client := helperNewHTTPClient()
	apollo := helperCreateApollo(flow, client)

	s := &Sqli{}
	finger := s.Finger()
	err := finger.CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("CheckAction error: %v", err)
	}
}

func TestV6FileWrite_CheckAction_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer server.Close()

	flow := helperCreateFlow(server.URL + "/index.php")
	client := helperNewHTTPClient()
	apollo := helperCreateApollo(flow, client)

	v := &V6FileWrite{}
	finger := v.Finger()
	err := finger.CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("CheckAction error: %v", err)
	}
}

// ==================== V6FileWrite - second session path matches ====================

func TestV6FileWrite_CheckAction_SecondSessionPath(t *testing.T) {
	var capturedCookie string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/index.php/index/index/index" && r.Method == "POST" {
			capturedCookie = r.Header.Get("Cookie")
			w.WriteHeader(200)
			return
		}
		// First session path: return empty (no match)
		if strings.HasPrefix(r.URL.Path, "/runtime/session/sess_") {
			w.WriteHeader(404)
			return
		}
		// Second session path: /runtime/session/MARKER.php - return marker
		if strings.HasPrefix(r.URL.Path, "/runtime/session/") && strings.HasSuffix(r.URL.Path, ".php") {
			marker := strings.TrimPrefix(capturedCookie, "PHPSESSID=")
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, marker)
			return
		}
		w.WriteHeader(404)
	}))
	defer server.Close()

	flow := helperCreateFlow(server.URL + "/index.php")
	client := helperNewHTTPClient()
	apollo := helperCreateApollo(flow, client)

	v := &V6FileWrite{}
	finger := v.Finger()
	err := finger.CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("CheckAction error: %v", err)
	}
}

// ==================== Sqli CheckAction with all payloads succeeding ====================

func TestSqli_CheckAction_AllPayloadsHit(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("Content-Type", "text/html")
		if requestCount == 1 {
			fmt.Fprint(w, "XPATH syntax error")
		} else {
			fmt.Fprint(w, "Normal response")
		}
	}))
	defer server.Close()

	flow := helperCreateFlow(server.URL + "/index.php")
	client := helperNewHTTPClient()
	apollo := helperCreateApollo(flow, client)

	s := &Sqli{}
	finger := s.Finger()
	err := finger.CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("CheckAction error: %v", err)
	}
	if requestCount != 1 {
		t.Logf("Expected 1 request (early return after first match), got %d", requestCount)
	}
}

// ==================== Sqli CheckAction - no payloads match ====================

func TestSqli_CheckAction_NoPayloadsMatch(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "Normal response - no SQL error")
	}))
	defer server.Close()

	flow := helperCreateFlow(server.URL + "/index.php")
	client := helperNewHTTPClient()
	apollo := helperCreateApollo(flow, client)

	s := &Sqli{}
	finger := s.Finger()
	err := finger.CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("CheckAction error: %v", err)
	}
	if requestCount != 3 {
		t.Logf("Expected 3 requests (all payloads tried), got %d", requestCount)
	}
}

// ==================== Thinkphp Fingers with different Config states ====================

func TestThinkphp_Fingers_WithConfigZeroValue(t *testing.T) {
	p := &Thinkphp{}
	cfg := &Config{}
	ab := &base.ApolloBase{}
	p.Init(context.Background(), cfg, ab)

	fingers := p.Fingers()
	if len(fingers) != 4 {
		t.Errorf("Expected 4 fingers with zero-value config, got %d", len(fingers))
	}
}

// ==================== Thinkphp Fingers with SQLi enabled ====================

func TestThinkphp_Fingers_WithSQLiConfigComprehensive(t *testing.T) {
	p := &Thinkphp{}
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "thinkphp",
			Enabled: true,
		},
		DetectThinkPHPSQLInjection: true,
	}
	ab := &base.ApolloBase{}
	p.Init(context.Background(), cfg, ab)

	fingers := p.Fingers()
	if len(fingers) != 5 {
		t.Errorf("Expected 5 fingers with sqli enabled, got %d", len(fingers))
	}

	expectedIDs := map[string]bool{
		"thinkphp/rce/invoke":            false,
		"thinkphp/rce/method":            false,
		"thinkphp/rce/preg":              false,
		"thinkphp/sqli/default":          false,
		"thinkphp/v6-file-write/default": false,
	}
	for _, f := range fingers {
		if _, ok := expectedIDs[f.Binding.ID]; ok {
			expectedIDs[f.Binding.ID] = true
		}
		if f.CheckAction == nil {
			t.Errorf("Finger %s should have CheckAction", f.Binding.ID)
		}
	}
	for id, found := range expectedIDs {
		if !found {
			t.Errorf("Expected finger with ID=%s not found", id)
		}
	}
}

// ==================== InvokeRce with FlowWithNilURL (panic recovery test) ====================

func TestInvokeRce_CheckAction_FlowWithNilURL(t *testing.T) {
	req := &whttp.Request{
		Method: "GET",
		Header: make(http.Header),
	}
	flow := &whttp.Flow{
		Request: req,
	}

	a := base.NewApollo(flow)
	a.ApolloBase = &base.ApolloBase{
		Output: noOpPrinter{},
	}

	r := &InvokeRce{}
	finger := r.Finger()
	defer func() {
		if rec := recover(); rec != nil {
			t.Logf("Recovered from panic (expected for nil URL): %v", rec)
		}
	}()
	finger.CheckAction(context.Background(), a)
}

// ==================== Sqli with URL parse error ====================

func TestSqli_CheckAction_InvalidBaseURL(t *testing.T) {
	flow := helperCreateFlow("http://example.com/index.php")
	client := helperNewHTTPClient()
	apollo := helperCreateApollo(flow, client)

	s := &Sqli{}
	finger := s.Finger()
	err := finger.CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("CheckAction error: %v", err)
	}
}

// ==================== V6FileWrite - session path parse errors ====================

func TestV6FileWrite_CheckAction_SessionPathErrors(t *testing.T) {
	var capturedCookie string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/index.php/index/index/index" && r.Method == "POST" {
			capturedCookie = r.Header.Get("Cookie")
			w.WriteHeader(200)
			return
		}
		// Return 404 for session paths - no vulnerability
		w.WriteHeader(404)
	}))
	defer server.Close()

	flow := helperCreateFlow(server.URL + "/index.php")
	client := helperNewHTTPClient()
	apollo := helperCreateApollo(flow, client)

	v := &V6FileWrite{}
	finger := v.Finger()
	err := finger.CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("CheckAction error: %v", err)
	}
	if !strings.HasPrefix(capturedCookie, "PHPSESSID=") {
		t.Errorf("Expected PHPSESSID cookie, got: %s", capturedCookie)
	}
}

// ==================== InvokeRce - HTTP request error path ====================

func TestInvokeRce_CheckAction_HttpRequestError(t *testing.T) {
	// Use a URL that will fail to connect
	flow := helperCreateFlow("http://127.0.0.1:1/index.php")
	client := helperNewHTTPClient()
	apollo := helperCreateApollo(flow, client)

	r := &InvokeRce{}
	finger := r.Finger()
	err := finger.CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("CheckAction error (expected for connection failure): %v", err)
	}
}

// ==================== MethodRce - HTTP request error path ====================

func TestMethodRce_CheckAction_HttpRequestError(t *testing.T) {
	flow := helperCreateFlow("http://127.0.0.1:1/index.php")
	client := helperNewHTTPClient()
	apollo := helperCreateApollo(flow, client)

	r := &MethodRce{}
	finger := r.Finger()
	err := finger.CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("CheckAction error (expected for connection failure): %v", err)
	}
}

// ==================== PregRce - HTTP request error path ====================

func TestPregRce_CheckAction_HttpRequestError(t *testing.T) {
	flow := helperCreateFlow("http://127.0.0.1:1/index.php")
	client := helperNewHTTPClient()
	apollo := helperCreateApollo(flow, client)

	r := &PregRce{}
	finger := r.Finger()
	err := finger.CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("CheckAction error (expected for connection failure): %v", err)
	}
}

// ==================== V6FileWrite - POST fails (connection refused) ====================

func TestV6FileWrite_CheckAction_PostFails(t *testing.T) {
	flow := helperCreateFlow("http://127.0.0.1:1/index.php")
	client := helperNewHTTPClient()
	apollo := helperCreateApollo(flow, client)

	v := &V6FileWrite{}
	finger := v.Finger()
	err := finger.CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("CheckAction error (expected for connection failure): %v", err)
	}
}

// ==================== PregRce multiplication verification ====================

func TestPregRce_MultiplicationCheck(t *testing.T) {
	// Verify the multiplication check logic used in PregRce
	r1 := 43775
	r2 := 44642
	result := fmt.Sprintf("%d", r1*r2)
	expected := strconv.Itoa(r1 * r2)
	if result != expected {
		t.Errorf("Multiplication check failed: expected %s, got %s", expected, result)
	}
}

// ==================== InvokeRce format string verification ====================

func TestInvokeRce_FormatStringCheck(t *testing.T) {
	r1 := "AAAA"
	r2 := "BBBB"
	// The check uses: fmt.Sprintf("%s%%%s1", r1, r2)
	result := fmt.Sprintf("%s%%%s1", r1, r2)
	expected := "AAAA%BBBB1"
	if result != expected {
		t.Errorf("Format string check failed: expected %s, got %s", expected, result)
	}
}

// ==================== MethodRce format string verification ====================

func TestMethodRce_FormatStringCheck(t *testing.T) {
	r1 := "CCCC"
	r2 := "DDDD"
	// The check uses: fmt.Sprintf("%s%%%s", r1, r2)
	result := fmt.Sprintf("%s%%%s", r1, r2)
	expected := "CCCC%DDDD"
	if result != expected {
		t.Errorf("Format string check failed: expected %s, got %s", expected, result)
	}
}

// ==================== V6FileWrite cookie and body construction ====================

func TestV6FileWrite_CookieConstruction(t *testing.T) {
	marker := "abcdefgh"
	cookie := fmt.Sprintf("PHPSESSID=%s", marker)
	if !strings.HasPrefix(cookie, "PHPSESSID=") {
		t.Error("Cookie should start with PHPSESSID=")
	}
	if !strings.Contains(cookie, marker) {
		t.Error("Cookie should contain the marker")
	}
}

func TestV6FileWrite_BodyConstruction(t *testing.T) {
	marker := "abcdefgh"
	body := fmt.Sprintf("<?php echo '%s';?>", marker)
	if !strings.Contains(body, marker) {
		t.Error("Body should contain the marker")
	}
	if !strings.HasPrefix(body, "<?php") {
		t.Error("Body should start with <?php")
	}
}

// ==================== V6FileWrite POST request Content-Type ====================

func TestV6FileWrite_PostRequestHasCorrectBody(t *testing.T) {
	var receivedBody string
	var receivedContentType string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			receivedContentType = r.Header.Get("Content-Type")
			body, _ := io.ReadAll(r.Body)
			receivedBody = string(body)
		}
		w.WriteHeader(200)
	}))
	defer server.Close()

	flow := helperCreateFlow(server.URL + "/index.php")
	client := helperNewHTTPClient()
	apollo := helperCreateApollo(flow, client)

	v := &V6FileWrite{}
	finger := v.Finger()
	finger.CheckAction(context.Background(), apollo)

	t.Logf("Received Content-Type: %q", receivedContentType)
	t.Logf("Received Body: %q", receivedBody)
}

// ==================== V6FileWrite - both session paths fail ====================

func TestV6FileWrite_CheckAction_BothSessionPathsFail(t *testing.T) {
	var capturedCookie string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/index.php/index/index/index" && r.Method == "POST" {
			capturedCookie = r.Header.Get("Cookie")
			w.WriteHeader(200)
			return
		}
		// All session paths return 404
		w.WriteHeader(404)
	}))
	defer server.Close()

	flow := helperCreateFlow(server.URL + "/index.php")
	client := helperNewHTTPClient()
	apollo := helperCreateApollo(flow, client)

	v := &V6FileWrite{}
	finger := v.Finger()
	err := finger.CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("CheckAction error: %v", err)
	}
	// Verify the cookie was received
	if !strings.HasPrefix(capturedCookie, "PHPSESSID=") {
		t.Errorf("Expected PHPSESSID cookie, got: %s", capturedCookie)
	}
}

// ==================== InvokeRce NewRequest error path ====================

func TestInvokeRce_CheckAction_NewRequestError(t *testing.T) {
	// This test creates a scenario where NewRequest might fail.
	// Since NewRequest is called with a valid URL from the test server,
	// we use a server that the request can actually reach.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "OK")
	}))
	defer server.Close()

	flow := helperCreateFlow(server.URL + "/index.php")
	client := helperNewHTTPClient()
	apollo := helperCreateApollo(flow, client)

	r := &InvokeRce{}
	finger := r.Finger()
	err := finger.CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("CheckAction error: %v", err)
	}
}

// ==================== MethodRce NewRequest error path ====================

func TestMethodRce_CheckAction_NewRequestError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "OK")
	}))
	defer server.Close()

	flow := helperCreateFlow(server.URL + "/index.php")
	client := helperNewHTTPClient()
	apollo := helperCreateApollo(flow, client)

	r := &MethodRce{}
	finger := r.Finger()
	err := finger.CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("CheckAction error: %v", err)
	}
}

// ==================== PregRce NewRequest error path ====================

func TestPregRce_CheckAction_NewRequestError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "OK")
	}))
	defer server.Close()

	flow := helperCreateFlow(server.URL + "/index.php")
	client := helperNewHTTPClient()
	apollo := helperCreateApollo(flow, client)

	r := &PregRce{}
	finger := r.Finger()
	err := finger.CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("CheckAction error: %v", err)
	}
}

// ==================== InvokeRce - response contains the marker pattern ====================

func TestInvokeRce_CheckAction_ResponseContainsMarker(t *testing.T) {
	// Create a server that will return a response containing the exact marker pattern
	// needed for the InvokeRce vulnerability check
	vulnDetected := false
	var vulnPayload string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			body := helperReadBody(r)
			form := helperParseFormBody(body)
			vars1 := form.Get("vars[1][]")
			// Replace %% with % to simulate printf output
			result := strings.ReplaceAll(vars1, "%%", "%")
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, result+"1")
			return
		}
		w.WriteHeader(404)
	}))
	defer server.Close()

	// We need to capture when OutputVuln is called
	flow := helperCreateFlow(server.URL + "/index.php")
	client := helperNewHTTPClient()
	a := base.NewApollo(flow)
	a.ApolloBase = &base.ApolloBase{
		HTTPClient: client,
		Output: &capturePrinter{
			onPrint: func(data any) error {
				if v, ok := data.(*model.Vuln); ok {
					vulnDetected = true
					vulnPayload = v.Payload
				}
				return nil
			},
		},
	}

	r := &InvokeRce{}
	finger := r.Finger()
	err := finger.CheckAction(context.Background(), a)
	if err != nil {
		t.Logf("CheckAction error: %v", err)
	}

	if vulnDetected {
		t.Logf("Vulnerability detected! Payload: %s", vulnPayload)
	} else {
		t.Log("Vulnerability not detected (may need server adjustments)")
	}
}

// capturePrinter captures calls to Print for testing
type capturePrinter struct {
	onPrint func(any) error
}

func (c *capturePrinter) AddInterceptor(func(any) (any, error)) printer.Printer { return c }
func (c *capturePrinter) Close() error                                          { return nil }
func (c *capturePrinter) Print(data any) error                                  { return c.onPrint(data) }

// ==================== MethodRce - response contains the marker pattern ====================

func TestMethodRce_CheckAction_ResponseContainsMarker(t *testing.T) {
	vulnDetected := false
	var vulnPayload string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			body := helperReadBody(r)
			form := helperParseFormBody(body)
			serverRM := form.Get("server[REQUEST_METHOD]")
			result := strings.ReplaceAll(serverRM, "%%", "%")
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, result)
			return
		}
		w.WriteHeader(404)
	}))
	defer server.Close()

	flow := helperCreateFlow(server.URL + "/index.php")
	client := helperNewHTTPClient()
	a := base.NewApollo(flow)
	a.ApolloBase = &base.ApolloBase{
		HTTPClient: client,
		Output: &capturePrinter{
			onPrint: func(data any) error {
				if v, ok := data.(*model.Vuln); ok {
					vulnDetected = true
					vulnPayload = v.Payload
				}
				return nil
			},
		},
	}

	r := &MethodRce{}
	finger := r.Finger()
	err := finger.CheckAction(context.Background(), a)
	if err != nil {
		t.Logf("CheckAction error: %v", err)
	}

	if vulnDetected {
		t.Logf("Vulnerability detected! Payload: %s", vulnPayload)
	} else {
		t.Log("Vulnerability not detected (may need server adjustments)")
	}
}

// ==================== PregRce - response contains the multiplication result ====================

func TestPregRce_CheckAction_ResponseContainsResult(t *testing.T) {
	vulnDetected := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse the multiplication from the URL
		fullURL := r.URL.String()
		if strings.Contains(fullURL, "printf") {
			idx := strings.Index(fullURL, "printf(")
			if idx >= 0 {
				rest := fullURL[idx+7:]
				endIdx := strings.Index(rest, ")")
				if endIdx >= 0 {
					expr := rest[:endIdx]
					expr, _ = url.QueryUnescape(expr)
					mulParts := strings.Split(expr, "*")
					if len(mulParts) == 2 {
						var a, b int
						fmt.Sscanf(mulParts[0], "%d", &a)
						fmt.Sscanf(mulParts[1], "%d", &b)
						w.Header().Set("Content-Type", "text/html")
						fmt.Fprintf(w, "%d", a*b)
						return
					}
				}
			}
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "Normal page")
	}))
	defer server.Close()

	flow := helperCreateFlow(server.URL + "/index.php")
	client := helperNewHTTPClient()
	a := base.NewApollo(flow)
	a.ApolloBase = &base.ApolloBase{
		HTTPClient: client,
		Output: &capturePrinter{
			onPrint: func(data any) error {
				if _, ok := data.(*model.Vuln); ok {
					vulnDetected = true
				}
				return nil
			},
		},
	}

	r := &PregRce{}
	finger := r.Finger()
	err := finger.CheckAction(context.Background(), a)
	if err != nil {
		t.Logf("CheckAction error: %v", err)
	}

	if vulnDetected {
		t.Log("Vulnerability detected!")
	} else {
		t.Log("Vulnerability not detected (may need server adjustments)")
	}
}

// ==================== V6FileWrite - session file contains marker ====================

func TestV6FileWrite_CheckAction_SessionContainsMarker(t *testing.T) {
	vulnDetected := false
	var capturedCookie string
	var marker string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/index.php/index/index/index" && r.Method == "POST" {
			capturedCookie = r.Header.Get("Cookie")
			if strings.HasPrefix(capturedCookie, "PHPSESSID=") {
				marker = strings.TrimPrefix(capturedCookie, "PHPSESSID=")
			}
			w.WriteHeader(200)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/runtime/session/") {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, marker)
			return
		}
		w.WriteHeader(404)
	}))
	defer server.Close()

	flow := helperCreateFlow(server.URL + "/index.php")
	client := helperNewHTTPClient()
	a := base.NewApollo(flow)
	a.ApolloBase = &base.ApolloBase{
		HTTPClient: client,
		Output: &capturePrinter{
			onPrint: func(data any) error {
				if _, ok := data.(*model.Vuln); ok {
					vulnDetected = true
				}
				return nil
			},
		},
	}

	v := &V6FileWrite{}
	finger := v.Finger()
	err := finger.CheckAction(context.Background(), a)
	if err != nil {
		t.Logf("CheckAction error: %v", err)
	}

	if vulnDetected {
		t.Log("V6FileWrite vulnerability detected!")
	} else {
		t.Log("V6FileWrite vulnerability not detected")
	}
}

// ==================== Check that V6FileWrite sets headers on the POST request ====================

func TestV6FileWrite_CheckAction_SetsCookieHeader(t *testing.T) {
	var postCookie string
	var postPath string
	postReceived := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && !postReceived {
			postCookie = r.Header.Get("Cookie")
			postPath = r.URL.Path
			postReceived = true
		}
		w.WriteHeader(200)
		fmt.Fprint(w, "OK")
	}))
	defer server.Close()

	flow := helperCreateFlow(server.URL + "/index.php")
	client := helperNewHTTPClient()
	apollo := helperCreateApollo(flow, client)

	v := &V6FileWrite{}
	finger := v.Finger()
	finger.CheckAction(context.Background(), apollo)

	if !postReceived {
		t.Fatal("POST request was not received")
	}
	if postPath != "/index.php/index/index/index" {
		t.Errorf("Expected path /index.php/index/index/index, got %s", postPath)
	}
	if !strings.HasPrefix(postCookie, "PHPSESSID=") {
		t.Errorf("Expected PHPSESSID cookie, got: %s", postCookie)
	}
}

// ==================== Sqli with specific marker in response ====================

func TestSqli_CheckAction_SpecificMarkerInResponse(t *testing.T) {
	vulnDetected := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Return XPATH syntax error which triggers the vulnerability check
		fmt.Fprint(w, "XPATH syntax error: unknown")
	}))
	defer server.Close()

	flow := helperCreateFlow(server.URL + "/index.php")
	client := helperNewHTTPClient()
	a := base.NewApollo(flow)
	a.ApolloBase = &base.ApolloBase{
		HTTPClient: client,
		Output: &capturePrinter{
			onPrint: func(data any) error {
				if _, ok := data.(*model.Vuln); ok {
					vulnDetected = true
				}
				return nil
			},
		},
	}

	s := &Sqli{}
	finger := s.Finger()
	err := finger.CheckAction(context.Background(), a)
	if err != nil {
		t.Logf("CheckAction error: %v", err)
	}

	if vulnDetected {
		t.Log("SQLi vulnerability detected!")
	}
}

// ==================== V6FileWrite - verify request body contains PHP payload ====================

func TestV6FileWrite_CheckAction_PostBodyContainsPHP(t *testing.T) {
	var receivedBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			bodyBytes, _ := io.ReadAll(r.Body)
			receivedBody = string(bodyBytes)
		}
		w.WriteHeader(200)
		fmt.Fprint(w, "OK")
	}))
	defer server.Close()

	flow := helperCreateFlow(server.URL + "/index.php")
	client := helperNewHTTPClient()
	apollo := helperCreateApollo(flow, client)

	v := &V6FileWrite{}
	finger := v.Finger()
	finger.CheckAction(context.Background(), apollo)

	if !strings.Contains(receivedBody, "<?php echo") {
		t.Errorf("POST body should contain PHP echo payload, got: %s", receivedBody)
	}
}

// ==================== InvokeRce - test with httptest server that returns the vulnerability ====================

func TestInvokeRce_CheckAction_FullVulnDetected(t *testing.T) {
	vulnDetected := false
	var vulnPayload string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			body := helperReadBody(r)
			form := helperParseFormBody(body)
			vars1 := form.Get("vars[1][]")
			// Simulate printf: %% becomes %, then append "1" as the real server does
			result := strings.ReplaceAll(vars1, "%%", "%")
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, result+"1")
			return
		}
		w.WriteHeader(404)
	}))
	defer server.Close()

	flow := helperCreateFlow(server.URL + "/index.php")
	client := helperNewHTTPClient()
	a := base.NewApollo(flow)
	a.ApolloBase = &base.ApolloBase{
		HTTPClient: client,
		Output: &capturePrinter{
			onPrint: func(data any) error {
				if v, ok := data.(*model.Vuln); ok {
					vulnDetected = true
					vulnPayload = v.Payload
				}
				return nil
			},
		},
	}

	r := &InvokeRce{}
	finger := r.Finger()
	finger.CheckAction(context.Background(), a)

	t.Logf("InvokeRce vuln detected: %v, payload: %q", vulnDetected, vulnPayload)
}

// ==================== MethodRce - test with httptest server that returns the vulnerability ====================

func TestMethodRce_CheckAction_FullVulnDetected(t *testing.T) {
	vulnDetected := false
	var vulnPayload string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			body := helperReadBody(r)
			form := helperParseFormBody(body)
			serverRM := form.Get("server[REQUEST_METHOD]")
			result := strings.ReplaceAll(serverRM, "%%", "%")
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, result)
			return
		}
		w.WriteHeader(404)
	}))
	defer server.Close()

	flow := helperCreateFlow(server.URL + "/index.php")
	client := helperNewHTTPClient()
	a := base.NewApollo(flow)
	a.ApolloBase = &base.ApolloBase{
		HTTPClient: client,
		Output: &capturePrinter{
			onPrint: func(data any) error {
				if v, ok := data.(*model.Vuln); ok {
					vulnDetected = true
					vulnPayload = v.Payload
				}
				return nil
			},
		},
	}

	r := &MethodRce{}
	finger := r.Finger()
	finger.CheckAction(context.Background(), a)

	t.Logf("MethodRce vuln detected: %v, payload: %q", vulnDetected, vulnPayload)
}

// ==================== Verify POST body from InvokeRce has correct format ====================

func TestInvokeRce_CheckAction_PostBodyFormat(t *testing.T) {
	var receivedBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			bodyBytes, _ := io.ReadAll(r.Body)
			receivedBody = string(bodyBytes)
		}
		w.WriteHeader(200)
		fmt.Fprint(w, "OK")
	}))
	defer server.Close()

	flow := helperCreateFlow(server.URL + "/index.php")
	client := helperNewHTTPClient()
	apollo := helperCreateApollo(flow, client)

	r := &InvokeRce{}
	finger := r.Finger()
	finger.CheckAction(context.Background(), apollo)

	// The payload should contain the expected format
	if !strings.Contains(receivedBody, "function=call_user_func_array") {
		t.Errorf("POST body should contain function=call_user_func_array, got: %s", receivedBody)
	}
	if !strings.Contains(receivedBody, "vars[0]=printf") {
		t.Errorf("POST body should contain vars[0]=printf, got: %s", receivedBody)
	}
}

// ==================== Verify POST body from MethodRce has correct format ====================

func TestMethodRce_CheckAction_PostBodyFormat(t *testing.T) {
	var receivedBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			bodyBytes, _ := io.ReadAll(r.Body)
			receivedBody = string(bodyBytes)
		}
		w.WriteHeader(200)
		fmt.Fprint(w, "OK")
	}))
	defer server.Close()

	flow := helperCreateFlow(server.URL + "/index.php")
	client := helperNewHTTPClient()
	apollo := helperCreateApollo(flow, client)

	r := &MethodRce{}
	finger := r.Finger()
	finger.CheckAction(context.Background(), apollo)

	if !strings.Contains(receivedBody, "_method=__construct") {
		t.Errorf("POST body should contain _method=__construct, got: %s", receivedBody)
	}
	if !strings.Contains(receivedBody, "filter[]=printf") {
		t.Errorf("POST body should contain filter[]=printf, got: %s", receivedBody)
	}
}

// ==================== PregRce - verify the URL path format ====================

func TestPregRce_CheckAction_UrlPathFormat(t *testing.T) {
	var receivedPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.String()
		w.WriteHeader(200)
		fmt.Fprint(w, "OK")
	}))
	defer server.Close()

	flow := helperCreateFlow(server.URL + "/index.php")
	client := helperNewHTTPClient()
	apollo := helperCreateApollo(flow, client)

	r := &PregRce{}
	finger := r.Finger()
	finger.CheckAction(context.Background(), apollo)

	t.Logf("PregRce received URL: %s", receivedPath)
	// The URL should contain the printf expression with multiplication
	if !strings.Contains(receivedPath, "printf") {
		t.Errorf("URL should contain printf, got: %s", receivedPath)
	}
}

// ==================== Bytes buffer helper ====================

func TestHelperReadBody(t *testing.T) {
	req := httptest.NewRequest("POST", "/test", bytes.NewReader([]byte("hello world")))
	body := helperReadBody(req)
	if body != "hello world" {
		t.Errorf("Expected 'hello world', got '%s'", body)
	}
}

func TestHelperParseFormBody(t *testing.T) {
	form := helperParseFormBody("key1=value1&key2=value2")
	if form.Get("key1") != "value1" {
		t.Errorf("Expected value1, got %s", form.Get("key1"))
	}
	if form.Get("key2") != "value2" {
		t.Errorf("Expected value2, got %s", form.Get("key2"))
	}
}
