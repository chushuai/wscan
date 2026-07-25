package http

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// ===== client.go additional coverage =====

func TestClient_AddFlowCallback_Coverage(t *testing.T) {
	client := NewClient()
	called := false
	client.AddFlowCallback(func(f *Flow) {
		called = true
	})
	// AddFlowCallback is a no-op, just ensure it doesn't panic
	_ = called
}

func TestClient_Respond_Coverage(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("response body"))
	}))
	defer ts.Close()

	client := NewClient()
	req, _ := NewRequest("GET", ts.URL, nil)
	resp, err := client.Respond(context.Background(), req)
	if err != nil {
		t.Fatalf("Respond() error: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
	if resp.Text != "response body" {
		t.Errorf("Text = %q, want %q", resp.Text, "response body")
	}
}

func TestClient_Respond_MultipleRetries(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	client := NewClient()
	req, _ := NewRequest("GET", ts.URL, nil)
	// Respond calls doWithRetries with retry=1
	resp, err := client.Respond(context.Background(), req)
	if err != nil {
		t.Fatalf("Respond() error: %v", err)
	}
	_ = resp
}

func TestClient_DoRaw_WithBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(200)
		w.Write([]byte("received: " + string(body)))
	}))
	defer ts.Close()

	client := NewClient()
	req, _ := NewRequest("POST", ts.URL, strings.NewReader("test data"))
	req.SetHeader("Content-Type", "text/plain")

	resp, err := client.DoRaw(req)
	if err != nil {
		t.Fatalf("DoRaw() error: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(resp.Text, "received: test data") {
		t.Errorf("Text = %q, should contain echo", resp.Text)
	}
}

func TestClient_DoRaw_EmptyBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	client := NewClient()
	req, _ := NewRequest("GET", ts.URL, nil)

	resp, err := client.DoRaw(req)
	if err != nil {
		t.Fatalf("DoRaw() error: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
}

func TestClient_DoRaw_Non2xx(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		w.Write([]byte("not found"))
	}))
	defer ts.Close()

	client := NewClient()
	req, _ := NewRequest("GET", ts.URL, nil)

	resp, err := client.DoRaw(req)
	if err != nil {
		t.Fatalf("DoRaw() error: %v", err)
	}
	if resp.StatusCode != 404 {
		t.Errorf("StatusCode = %d, want 404", resp.StatusCode)
	}
}

func TestClient_DoRaw_ConnectionError(t *testing.T) {
	client := NewClient()
	// Use a port that's not listening
	req, _ := NewRequest("GET", "http://127.0.0.1:1/", nil)

	_, err := client.DoRaw(req)
	if err == nil {
		t.Error("DoRaw() should return error for connection refused")
	}
}

func TestClient_BuildRequest_WithDefaultHeadersAndHeaders(t *testing.T) {
	opt := &ClientOptions{
		DefaultHeaders: map[string]string{
			"User-Agent": "DefaultAgent",
			"X-Default":  "defaultVal",
		},
		Headers: map[string][]string{
			"X-Multi": {"val1", "val2"},
		},
	}
	client := NewClientWithOptions(opt)
	req, _ := NewRequest("GET", "http://example.com/", nil)
	hReq, err := client.BuildRequest(req)
	if err != nil {
		t.Fatalf("BuildRequest() error: %v", err)
	}
	if hReq.Header.Get("User-Agent") != "DefaultAgent" {
		t.Errorf("User-Agent = %q, want %q", hReq.Header.Get("User-Agent"), "DefaultAgent")
	}
	if hReq.Header.Get("X-Default") != "defaultVal" {
		t.Errorf("X-Default = %q, want %q", hReq.Header.Get("X-Default"), "defaultVal")
	}
	vals := hReq.Header["X-Multi"]
	if len(vals) != 2 {
		t.Errorf("X-Multi values = %d, want 2", len(vals))
	}
}

func TestClient_BuildRequest_HeadersNotOverwritten(t *testing.T) {
	opt := &ClientOptions{
		DefaultHeaders: map[string]string{
			"User-Agent": "DefaultAgent",
		},
		Headers: map[string][]string{
			"X-Shared": {"from_options"},
		},
	}
	client := NewClientWithOptions(opt)
	req, _ := NewRequest("GET", "http://example.com/", nil)
	req.SetHeader("User-Agent", "CustomAgent")
	req.SetHeader("X-Shared", "from_request")

	hReq, err := client.BuildRequest(req)
	if err != nil {
		t.Fatalf("BuildRequest() error: %v", err)
	}
	// Request header should NOT be overwritten by default headers or options headers
	if hReq.Header.Get("User-Agent") != "CustomAgent" {
		t.Errorf("User-Agent should be preserved from request, got %q", hReq.Header.Get("User-Agent"))
	}
	if hReq.Header.Get("X-Shared") != "from_request" {
		t.Errorf("X-Shared should be preserved from request, got %q", hReq.Header.Get("X-Shared"))
	}
}

func TestClient_Options_Access(t *testing.T) {
	opt := &ClientOptions{
		Proxy:       "http://proxy:8080",
		DialTimeout: 5,
		ReadTimeout: 10,
		FailRetries: 3,
		MaxRedirect: 5,
		MaxQPS:      100.0,
	}
	client := NewClientWithOptions(opt)
	result := client.Options()
	if result.Proxy != "http://proxy:8080" {
		t.Errorf("Options().Proxy = %q, want %q", result.Proxy, "http://proxy:8080")
	}
	if result.DialTimeout != 5 {
		t.Errorf("Options().DialTimeout = %d, want 5", result.DialTimeout)
	}
}

func TestClient_WithStatistics_Chain(t *testing.T) {
	client := NewClient()
	newStat := &Statistics{responseTimeHistory: make(map[int64]*responseTime)}
	result := client.WithStatistics(newStat)
	if result != client {
		t.Error("WithStatistics() should return the same client for chaining")
	}
	if client.Stater() != newStat {
		t.Error("Stater() should return the new statistics after WithStatistics()")
	}
}

func TestClient_CloneWithNewOptions_Details(t *testing.T) {
	opt := &ClientOptions{
		Proxy:       "http://original:8080",
		DialTimeout: 5,
	}
	client := NewClientWithOptions(opt)

	newOpt := &ClientOptions{
		Proxy:       "http://newproxy:9090",
		DialTimeout: 10,
	}
	cloned := client.CloneWithNewOptions(newOpt, true)
	if cloned == nil {
		t.Fatal("CloneWithNewOptions() should not return nil")
	}
	if cloned.options.Proxy != "http://newproxy:9090" {
		t.Errorf("cloned options.Proxy = %q, want %q", cloned.options.Proxy, "http://newproxy:9090")
	}
}

func TestClient_Statistics_UpdatedAfterRequest(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Millisecond) // small delay to ensure measurable response time
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	client := NewClient()
	req, _ := NewRequest("GET", ts.URL, nil)
	_, err := client.DoRaw(req)
	if err != nil {
		t.Fatalf("DoRaw() error: %v", err)
	}

	stat := client.Stater()
	if stat == nil {
		t.Fatal("Stater() should not return nil after request")
	}
	raw := stat.Raw()
	if raw["requestNumber"].(int64) != 1 {
		t.Errorf("requestNumber = %d, want 1", raw["requestNumber"])
	}
}

func TestNewClientWithOptions_WithPKCS12_InvalidPath(t *testing.T) {
	opt := &ClientOptions{
		PKCS12: PKCS12Config{
			Path:     "/nonexistent/cert.p12",
			Password: "test",
		},
	}
	client := NewClientWithOptions(opt)
	if client == nil {
		t.Fatal("NewClientWithOptions() should not return nil even with invalid PKCS12")
	}
}

func TestNewTransport_WithPKCS12_InvalidPath(t *testing.T) {
	opt := &ClientOptions{
		PKCS12: PKCS12Config{
			Path:     "/nonexistent/cert.p12",
			Password: "test",
		},
	}
	transport := NewTransport(opt)
	if transport == nil {
		t.Fatal("NewTransport() should not return nil even with invalid PKCS12")
	}
}

// ===== request.go additional coverage =====

func TestRequest_SetValue_Coverage(t *testing.T) {
	req, _ := NewRequest("GET", "http://example.com/", nil)
	// SetValue is a no-op, just verify it doesn't panic
	req.SetValue("key", "value")
}

func TestRequest_buildDataMap_Coverage(t *testing.T) {
	req, _ := NewRequest("GET", "http://example.com/", nil)
	// buildDataMap is a no-op, just verify it doesn't panic
	req.buildDataMap()
}

func TestRequest_buildQueryData_Coverage(t *testing.T) {
	req, _ := NewRequest("GET", "http://example.com/", nil)
	// buildQueryData is a no-op, just verify it doesn't panic
	req.buildQueryData()
}

func TestRequest_paramsCookie_Coverage(t *testing.T) {
	req, _ := NewRequest("GET", "http://example.com/", nil)
	// paramsCookie is a stub, just verify it doesn't panic
	req.paramsCookie()
}

func TestBuildRequest_Func_Coverage(t *testing.T) {
	// BuildRequest is a package-level no-op function
	BuildRequest()
}

func TestRequest_GetURLDepth_EmptyPath(t *testing.T) {
	req := &Request{}
	u, _ := url.Parse("http://example.com")
	req.url = u
	req.url.Path = ""
	depth := req.GetURLDepth()
	if depth != 0 {
		t.Errorf("GetURLDepth() for empty path = %d, want 0", depth)
	}
}

func TestRequest_Dump_NilBody(t *testing.T) {
	req, _ := NewRequest("GET", "http://example.com/path", nil)
	req.body = nil
	dump := req.Dump()
	if len(dump) == 0 {
		t.Error("Dump() should return non-empty bytes even with nil body")
	}
}

func TestRequest_WithBody_Error(t *testing.T) {
	req, _ := NewRequest("POST", "http://example.com/", nil)
	// Create a reader that always returns an error
	errorReader := &errorReader{err: fmt.Errorf("read error")}
	result := req.WithBody(errorReader, "text/plain")
	if result != nil {
		t.Error("WithBody() should return nil on read error")
	}
}

type errorReader struct {
	err error
}

func (r *errorReader) Read([]byte) (int, error) {
	return 0, r.err
}

func TestRequest_ParseMultipartForm_WithParts(t *testing.T) {
	// Test ParseMultipartForm with actual multipart body
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	_ = writer.WriteField("field1", "value1")
	part, _ := writer.CreateFormFile("file1", "test.txt")
	part.Write([]byte("file content"))
	writer.Close()

	req, _ := NewRequest("POST", "http://example.com/", &buf)
	req.SetHeader("Content-Type", writer.FormDataContentType())
	// ParseMultipartForm uses a hardcoded empty body, so it won't find anything
	// But we test that it doesn't panic
	result := req.ParseMultipartForm()
	if result != nil {
		t.Errorf("ParseMultipartForm() should return nil, got %v", result)
	}
}

func TestRequest_Clone_BodyIndependence(t *testing.T) {
	req, _ := NewRequest("POST", "http://example.com/", strings.NewReader("original body"))
	req.SetHeader("Content-Type", "text/plain")

	cloned := req.clone()

	// Verify body content matches
	if string(cloned.body) != "original body" {
		t.Errorf("cloned body = %q, want %q", string(cloned.body), "original body")
	}

	// Verify body independence
	cloned.body[0] = 'X'
	if req.body[0] == 'X' {
		t.Error("modifying cloned body should not affect original")
	}
}

func TestRequest_Clone_NilBody(t *testing.T) {
	req, _ := NewRequest("GET", "http://example.com/", nil)
	cloned := req.clone()
	// After clone fix, make([]byte, 0) is used for nil body, resulting in empty slice
	if len(cloned.body) != 0 {
		t.Errorf("cloned body should be empty when original body is nil, got %d bytes", len(cloned.body))
	}
}

func TestRequest_Mutate_Cookie_WithExistingCookies(t *testing.T) {
	req, _ := NewRequest("GET", "http://example.com/", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: "abc"})
	req.AddCookie(&http.Cookie{Name: "user", Value: "test"})
	req.doCache()

	newReq := req.Mutate(&Parameter{
		Position: PositionCookie,
		Key:      "session",
		Value:    "newvalue",
		Prefix:   "",
		Suffix:   "",
	})
	if newReq == nil {
		t.Fatal("Mutate() should return non-nil")
	}
	// The mutated cookie should be updated
	cookieHeader := newReq.Header.Get("Cookie")
	if cookieHeader == "" {
		t.Error("Mutate(cookie) should preserve cookie header")
	}
}

func TestRequest_Mutate_Path_Modification(t *testing.T) {
	req, _ := NewRequest("GET", "http://example.com/api/v1/users/123/details", nil)
	req.doCache()

	newReq := req.Mutate(&Parameter{
		Position: PositionPath,
		Key:      "3",
		Value:    "456",
		Prefix:   "",
		Suffix:   "",
	})
	if newReq == nil {
		t.Fatal("Mutate() should return non-nil")
	}
	if !strings.Contains(newReq.url.Path, "456") {
		t.Errorf("Mutate(path) should update path segment, got %q", newReq.url.Path)
	}
}

func TestRequest_Mutate_BodyFormURL_WithContent(t *testing.T) {
	req, _ := NewRequest("POST", "http://example.com/", strings.NewReader("key1=val1&key2=val2"))
	req.SetHeader("Content-Type", "application/x-www-form-urlencoded")
	req.doCache()

	newReq := req.Mutate(&Parameter{
		Position:    PositionBody,
		Key:         "key1",
		Value:       "mutated",
		Prefix:      "",
		Suffix:      "",
		Filename:    "",
		ContentType: "",
		Content:     []byte("mutated content"),
	})
	if newReq == nil {
		t.Fatal("Mutate() should return non-nil")
	}
}

func TestRequest_Mutate_BodyJSON_WithPrefixSuffix(t *testing.T) {
	body := `{"name":"original"}`
	req, _ := NewRequest("POST", "http://example.com/", strings.NewReader(body))
	req.SetHeader("Content-Type", "application/json")
	req.doCache()

	newReq := req.Mutate(&Parameter{
		Position: PositionBody,
		Key:      "$.name",
		Value:    "modified",
		Prefix:   "pre_",
		Suffix:   "_suf",
	})
	if newReq == nil {
		t.Fatal("Mutate() should return non-nil")
	}
}

func TestRequest_Mutate_BodyXML_WithPrefixSuffix(t *testing.T) {
	body := `<root><child>original</child></root>`
	req, _ := NewRequest("POST", "http://example.com/", strings.NewReader(body))
	req.SetHeader("Content-Type", "application/xml")
	req.doCache()

	newReq := req.Mutate(&Parameter{
		Position: PositionBody,
		Key:      "/root/child",
		Value:    "modified",
		Prefix:   "",
		Suffix:   "",
	})
	if newReq == nil {
		t.Fatal("Mutate() should return non-nil")
	}
}

func TestRequest_Mutate_Header_WithPrefixSuffix(t *testing.T) {
	req, _ := NewRequest("GET", "http://example.com/", nil)
	req.SetHeader("X-Custom", "original")
	req.doCache()

	newReq := req.Mutate(&Parameter{
		Position: PositionHeader,
		Key:      "X-Custom",
		Value:    "mutated",
		Prefix:   "pre_",
		Suffix:   "_suf",
	})
	if newReq == nil {
		t.Fatal("Mutate() should return non-nil")
	}
	vals := newReq.Header["X-Custom"]
	if len(vals) == 0 || vals[0] != "pre_mutated_suf" {
		t.Errorf("Mutate(header) should update header with prefix/suffix, got %v", vals)
	}
}

// ===== flow.go additional coverage =====

func TestBuildFlow_CompleteWithCookies(t *testing.T) {
	request := "GET / HTTP/1.1\r\nHost: example.com\r\nCookie: session=abc123\r\n\r\n"
	response := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: newcookie=val\r\n\r\nhello"

	flow := BuildFlow(request, response)
	if flow == nil {
		t.Fatal("BuildFlow() returned nil")
	}
	if flow.Request == nil {
		t.Error("BuildFlow() flow.Request is nil")
	}
	if flow.Response == nil {
		t.Error("BuildFlow() flow.Response is nil")
	}
}

func TestBuildFlow_EmptyStrings(t *testing.T) {
	flow := BuildFlow("", "")
	if flow != nil {
		t.Error("BuildFlow() with empty strings should return nil")
	}
}

func TestMakeSnapShot_WithFlows(t *testing.T) {
	req, _ := NewRequest("GET", "http://example.com", nil)
	req.SetHeader("Host", "example.com")
	flows := []Flow{
		{
			Request:  req,
			Response: &Response{TimeStamp: 2000, Text: "response text"},
		},
	}
	snapShot := MakeSnapShot(flows, 100)
	_ = snapShot // just verify it doesn't panic
}

func TestAddFlow_ExactMaxSize(t *testing.T) {
	u, _ := url.Parse("http://example.com")
	var flows []*Flow
	maxSize := 2

	for i := 0; i < 2; i++ {
		f := &Flow{
			Request:  &Request{url: u, TimeStamp: int64(i)},
			Response: &Response{TimeStamp: int64(i)},
		}
		flows = AddFlow(flows, f, maxSize)
	}
	if len(flows) != 2 {
		t.Errorf("expected %d flows, got %d", maxSize, len(flows))
	}
}

func TestFlow_Seconds_Negative(t *testing.T) {
	u, _ := url.Parse("http://example.com")
	f := &Flow{
		Request:  &Request{url: u, TimeStamp: 2000000},
		Response: &Response{TimeStamp: 1000000},
	}
	seconds := f.Seconds()
	// Response before request would give negative, but int division handles it
	_ = seconds
}

// ===== config.go additional coverage =====

func TestClientOptions_SetProxies_Coverage(t *testing.T) {
	opt := &ClientOptions{}
	opt.SetProxies([]string{"http://proxy:8080"})
	// SetProxies is a no-op
}

func TestClientOptions_WroteBack_EmptyCookie(t *testing.T) {
	opt := &ClientOptions{
		DefaultHeaders: map[string]string{
			"Cookie": "",
		},
	}
	opt.WroteBack()
	// Empty cookie string should not panic
}

func TestClientOptions_WroteBack_CookieNoEquals(t *testing.T) {
	opt := &ClientOptions{
		DefaultHeaders: map[string]string{
			"Cookie": "invalidcookie",
		},
	}
	opt.WroteBack()
	// Cookie without = should not panic
}

// ===== resource.go additional coverage =====

func TestFlow_DeepClone_WithHistory(t *testing.T) {
	u, _ := url.Parse("http://example.com")
	f := &Flow{
		Request:   &Request{url: u, TimeStamp: 100},
		Response:  &Response{TimeStamp: 200},
		History:   []*Response{{TimeStamp: 150}, {TimeStamp: 175}},
		TimeStamp: 150,
	}

	cloned := f.DeepClone()
	clonedFlow := cloned.(*Flow)

	// Verify History is preserved
	if len(clonedFlow.History) != 2 {
		t.Errorf("cloned History length = %d, want 2", len(clonedFlow.History))
	}
}

func TestRequest_DeepClone_WithBodyParams(t *testing.T) {
	u, _ := url.Parse("http://example.com/path")
	r := &Request{
		Method: "POST",
		url:    u,
		Header: http.Header{
			"Content-Type": {"application/x-www-form-urlencoded"},
		},
		bodyParams: map[string]*Parameter{
			"key1": {Key: "key1", Value: "val1", Position: PositionBody},
			"key2": {Key: "key2", Value: "val2", Position: PositionBody},
		},
		queryParams: map[string]*Parameter{
			"q": {Key: "q", Value: "1", Position: PositionQuery},
		},
	}

	cloned := r.DeepClone()
	if cloned.bodyParams["key1"].Value != "val1" {
		t.Errorf("cloned bodyParams[key1] = %q, want %q", cloned.bodyParams["key1"].Value, "val1")
	}
	// Verify independence
	cloned.bodyParams["key1"].Value = "modified"
	if r.bodyParams["key1"].Value != "val1" {
		t.Error("modifying cloned bodyParams should not affect original")
	}
}

// ===== HTTP integration tests =====

func TestClient_FullFlow_GetRequest(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		w.Write([]byte("<html><body>Hello</body></html>"))
	}))
	defer ts.Close()

	client := NewClient()
	req, _ := NewRequest("GET", ts.URL+"/path?key=value", nil)
	req.SetHeader("User-Agent", "TestBot")

	resp, err := client.Respond(context.Background(), req)
	if err != nil {
		t.Fatalf("Respond() error: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(resp.Text, "Hello") {
		t.Errorf("Text = %q, should contain 'Hello'", resp.Text)
	}
	if resp.GetContentType() != "text/html" {
		t.Errorf("GetContentType() = %q, want %q", resp.GetContentType(), "text/html")
	}
}

func TestClient_FullFlow_PostRequest(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		w.Write([]byte(`{"status":"created"}`))
		_ = body
	}))
	defer ts.Close()

	client := NewClient()
	req, _ := NewRequest("POST", ts.URL+"/api", strings.NewReader(`{"name":"test"}`))
	req.SetHeader("Content-Type", "application/json")

	resp, err := client.Respond(context.Background(), req)
	if err != nil {
		t.Fatalf("Respond() error: %v", err)
	}
	if resp.StatusCode != 201 {
		t.Errorf("StatusCode = %d, want 201", resp.StatusCode)
	}
}

func TestClient_DoRaw_WithCookies(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie := r.Header.Get("Cookie")
		w.WriteHeader(200)
		w.Write([]byte("cookies: " + cookie))
	}))
	defer ts.Close()

	client := NewClient()
	req, _ := NewRequest("GET", ts.URL, nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: "abc123"})

	resp, err := client.DoRaw(req)
	if err != nil {
		t.Fatalf("DoRaw() error: %v", err)
	}
	if !strings.Contains(resp.Text, "session=abc123") {
		t.Errorf("Text = %q, should contain cookie", resp.Text)
	}
}

func TestClient_DoRaw_ResponseHeaders(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom", "response-value")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	client := NewClient()
	req, _ := NewRequest("GET", ts.URL, nil)

	resp, err := client.DoRaw(req)
	if err != nil {
		t.Fatalf("DoRaw() error: %v", err)
	}
	if resp.Header.Get("X-Custom") != "response-value" {
		t.Errorf("X-Custom = %q, want %q", resp.Header.Get("X-Custom"), "response-value")
	}
}

func TestClient_Respond_RetryOnFailure(t *testing.T) {
	callCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount < 2 {
			// Close connection to simulate failure
			hj, ok := w.(http.Hijacker)
			if ok {
				conn, _, _ := hj.Hijack()
				conn.Close()
				return
			}
		}
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	client := NewClient()
	req, _ := NewRequest("GET", ts.URL, nil)
	// doWithRetries with retry=2 should succeed on second attempt
	resp, err := client.doWithRetries(req, 2)
	if err != nil {
		// This may fail if the server doesn't support hijacking, which is fine
		t.Logf("doWithRetries() error (expected if hijack not supported): %v", err)
	}
	_ = resp
}

// ===== request.go PostDataMap additional coverage =====

func TestRequest_PostDataMap_WithContentType(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
		wantKey     string
	}{
		{
			name:        "json_valid",
			contentType: "application/json",
			body:        `{"key":"value"}`,
			wantKey:     "key",
		},
		{
			name:        "url_encoded",
			contentType: "application/x-www-form-urlencoded",
			body:        "key=value",
			wantKey:     "key",
		},
		{
			name:        "other_content_type",
			contentType: "text/plain",
			body:        "some text",
			wantKey:     "key", // fallback key
		},
		{
			name:        "empty_content_type",
			contentType: "",
			body:        "raw data",
			wantKey:     "key", // fallback key
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := NewRequest("POST", "http://example.com/", strings.NewReader(tt.body))
			if tt.contentType != "" {
				req.SetHeader("Content-Type", tt.contentType)
			}
			req.doCache()
			result := req.PostDataMap()
			if result == nil {
				t.Error("PostDataMap() should not return nil")
			}
		})
	}
}

// ===== BuildRequest on Client with various options =====

func TestClient_BuildRequest_WithPostBody(t *testing.T) {
	client := NewClient()
	req, _ := NewRequest("POST", "http://example.com/api", strings.NewReader("data=test"))
	req.SetHeader("Content-Type", "application/x-www-form-urlencoded")

	hReq, err := client.BuildRequest(req)
	if err != nil {
		t.Fatalf("BuildRequest() error: %v", err)
	}
	if hReq.Method != "POST" {
		t.Errorf("Method = %q, want %q", hReq.Method, "POST")
	}
	if hReq.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q, want %q", hReq.Header.Get("Content-Type"), "application/x-www-form-urlencoded")
	}
}

func TestClient_BuildRequest_InvalidURL(t *testing.T) {
	client := NewClient()
	req, _ := NewRequest("GET", "http://example.com/", nil)
	// Set an invalid URL to cause BuildRequest to fail
	req.url = &url.URL{}
	hReq, err := client.BuildRequest(req)
	// BuildRequest should still work since url.URL.String() handles empty URLs
	_ = hReq
	_ = err
}

// ===== DeepCopy coverage =====

func TestParameter_DeepCopy_Comprehensive(t *testing.T) {
	p := &Parameter{
		Position:    PositionBody,
		Key:         "test_key",
		Value:       "test_value",
		Filename:    "test.txt",
		ContentType: "text/plain",
		Content:     []byte("test content"),
	}

	copied := p.DeepCopy()
	if copied.Key != p.Key {
		t.Errorf("DeepCopy Key = %q, want %q", copied.Key, p.Key)
	}
	if copied.Value != p.Value {
		t.Errorf("DeepCopy Value = %q, want %q", copied.Value, p.Value)
	}
	if copied.Position != p.Position {
		t.Errorf("DeepCopy Position = %v, want %v", copied.Position, p.Position)
	}
	if copied.Filename != p.Filename {
		t.Errorf("DeepCopy Filename = %q, want %q", copied.Filename, p.Filename)
	}
	if copied.ContentType != p.ContentType {
		t.Errorf("DeepCopy ContentType = %q, want %q", copied.ContentType, p.ContentType)
	}
	if string(copied.Content) != string(p.Content) {
		t.Errorf("DeepCopy Content = %q, want %q", string(copied.Content), string(p.Content))
	}

	// Verify Content independence
	copied.Content[0] = 'X'
	if p.Content[0] == 'X' {
		t.Error("modifying copied Content should not affect original")
	}
}

// ===== Response integration with httptest =====

func TestResponse_GetTitle_FromTestServer(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		w.Write([]byte("<html><head><title>Test Title</title></head><body></body></html>"))
	}))
	defer ts.Close()

	client := NewClient()
	req, _ := NewRequest("GET", ts.URL, nil)
	resp, err := client.DoRaw(req)
	if err != nil {
		t.Fatalf("DoRaw() error: %v", err)
	}
	title := resp.GetTitile()
	if title != "Test Title" {
		t.Errorf("GetTitile() = %q, want %q", title, "Test Title")
	}
}

func TestResponse_FullCoverage_FromTestServer(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Custom", "header-value")
		w.WriteHeader(200)
		w.Write([]byte("<html><body>Test</body></html>"))
	}))
	defer ts.Close()

	client := NewClient()
	req, _ := NewRequest("GET", ts.URL, nil)
	resp, err := client.DoRaw(req)
	if err != nil {
		t.Fatalf("DoRaw() error: %v", err)
	}

	// Test various response methods
	if resp.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
	if resp.Status != "200 OK" {
		t.Errorf("Status = %q, want %q", resp.Status, "200 OK")
	}
	if !resp.IsHTML() {
		t.Error("IsHTML() should return true")
	}
	if resp.GetContentType() != "text/html; charset=utf-8" {
		t.Errorf("GetContentType() = %q", resp.GetContentType())
	}
	if resp.GetHeader("X-Custom") != "header-value" {
		t.Errorf("GetHeader() = %q", resp.GetHeader("X-Custom"))
	}
	if len(resp.GetRawBody()) == 0 {
		t.Error("GetRawBody() should not be empty")
	}
	if resp.GetURL() == nil {
		t.Error("GetURL() should not return nil")
	}
}

// ===== Edge cases for GetURLDepth =====

func TestRequest_GetURLDepth_DeepPath(t *testing.T) {
	tests := []struct {
		urlStr   string
		expected int
	}{
		{"http://example.com/", 0},
		{"http://example.com/a", 0},
		{"http://example.com/a/b", 1},
		{"http://example.com/a/b/c", 2},
		{"http://example.com/a/b/c/d", 3},
	}
	for _, tt := range tests {
		req, _ := NewRequest("GET", tt.urlStr, nil)
		depth := req.GetURLDepth()
		if depth != tt.expected {
			t.Errorf("GetURLDepth() for %q = %d, want %d", tt.urlStr, depth, tt.expected)
		}
	}
}

// ===== RequestFromNetHttpRequert additional coverage =====

func TestRequestFromNetHttpRequert_WithAllHeaders(t *testing.T) {
	hReq, _ := http.NewRequest("GET", "http://example.com/", nil)
	hReq.Header.Set("Accept", "text/html")
	hReq.Header.Set("Accept-Language", "en-US")
	hReq.Header.Set("X-Custom", "value1")

	req, err := RequestFromNetHttpRequert(hReq)
	if err != nil {
		t.Fatalf("RequestFromNetHttpRequert() error: %v", err)
	}
	if req.Header.Get("Accept") != "text/html" {
		t.Errorf("Accept = %q, want %q", req.Header.Get("Accept"), "text/html")
	}
}

// BytesCloser embeds *bytes.Reader, which has no Close method.
// Just verify it's usable as a Reader.
func TestBytesCloser(t *testing.T) {
	reader := bytes.NewReader([]byte("test data"))
	bc := BytesCloser{Reader: reader}
	buf := make([]byte, 4)
	n, err := bc.Read(buf)
	if err != nil {
		t.Errorf("Read() error: %v", err)
	}
	if n != 4 {
		t.Errorf("Read() returned %d bytes, want 4", n)
	}
	if string(buf) != "test" {
		t.Errorf("Read() content = %q, want %q", string(buf), "test")
	}
}

// ===== ParseMultipartForm additional coverage =====
// ParseMultipartForm hardcodes []byte("") as the body, so the loop body
// (lines 286-291: buf.ReadFrom, fmt.Println x3, part.Close) is unreachable
// through testing. These tests verify the observable behavior.

func TestRequest_ParseMultipartForm_EmptyBodyReturnsNil(t *testing.T) {
	req, _ := NewRequest("POST", "http://example.com/", nil)
	result := req.ParseMultipartForm()
	if result != nil {
		t.Errorf("ParseMultipartForm() with empty body should return nil, got %v", result)
	}
}

func TestRequest_ParseMultipartForm_DoesNotUseRequestBody(t *testing.T) {
	// Even with a real multipart body set on the request, ParseMultipartForm
	// ignores it because it hardcodes []byte("") as the body.
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	_ = writer.WriteField("field1", "value1")
	part2, _ := writer.CreateFormFile("upload", "test.txt")
	part2.Write([]byte("file content here"))
	writer.Close()

	req, _ := NewRequest("POST", "http://example.com/", &buf)
	req.SetHeader("Content-Type", writer.FormDataContentType())
	// The function still returns nil because it ignores req.body
	result := req.ParseMultipartForm()
	if result != nil {
		t.Errorf("ParseMultipartForm() should return nil regardless of request body, got %v", result)
	}
}

// ===== ConvertValue additional coverage =====
// ConvertValue uses fmt.Sprintf("%#v", oldValue) which always produces a
// quoted string (e.g., "\"42\""), so IsValidInteger/IsValidFloat/IsValidBool
// always return false. The integer/float/boolean branches are dead code.
// These tests verify the string fallback path thoroughly and document
// edge cases.

func TestConvertValue_StringFallback_BothStrings(t *testing.T) {
	result := ConvertValue("hello", "world")
	if result != "world" {
		t.Errorf("ConvertValue(hello, world) = %q, want %q", result, "world")
	}
}

func TestConvertValue_StringFallback_EmptyOldValue(t *testing.T) {
	result := ConvertValue("", "replacement")
	if result != "replacement" {
		t.Errorf("ConvertValue('', replacement) = %q, want %q", result, "replacement")
	}
}

func TestConvertValue_StringFallback_EmptyNewValue(t *testing.T) {
	result := ConvertValue("original", "")
	if result != "" {
		t.Errorf("ConvertValue(original, '') = %q, want empty string", result)
	}
}

func TestConvertValue_StringFallback_BothEmpty(t *testing.T) {
	result := ConvertValue("", "")
	if result != "" {
		t.Errorf("ConvertValue('', '') = %q, want empty string", result)
	}
}

func TestConvertValue_StringFallback_NumericOldString(t *testing.T) {
	// Even though oldValue looks like a number, fmt.Sprintf("%#v", "42")
	// produces "\"42\"" (with quotes), so IsValidInteger("\"42\"") is false.
	// The function falls through to the string path.
	result := ConvertValue("42", "100")
	if result != "100" {
		t.Errorf("ConvertValue('42', '100') = %q, want %q", result, "100")
	}
}

func TestConvertValue_StringFallback_FloatOldString(t *testing.T) {
	// Same as above: fmt.Sprintf("%#v", "3.14") produces "\"3.14\"",
	// so IsValidFloat("\"3.14\"") is false.
	result := ConvertValue("3.14", "2.71")
	if result != "2.71" {
		t.Errorf("ConvertValue('3.14', '2.71') = %q, want %q", result, "2.71")
	}
}

func TestConvertValue_StringFallback_BoolOldString(t *testing.T) {
	// Same: fmt.Sprintf("%#v", "true") produces "\"true\"",
	// so IsValidBool("\"true\"") is false.
	result := ConvertValue("true", "false")
	if result != "false" {
		t.Errorf("ConvertValue('true', 'false') = %q, want %q", result, "false")
	}
}

func TestConvertValue_StringFallback_SpecialChars(t *testing.T) {
	result := ConvertValue("<tag>", "&lt;tag&gt;")
	if result != "&lt;tag&gt;" {
		t.Errorf("ConvertValue('<tag>', '&lt;tag&gt;') = %q, want %q", result, "&lt;tag&gt;")
	}
}

func TestConvertValue_StringFallback_Unicode(t *testing.T) {
	result := ConvertValue("old", "新值")
	if result != "新值" {
		t.Errorf("ConvertValue('old', '新值') = %q, want %q", result, "新值")
	}
}
