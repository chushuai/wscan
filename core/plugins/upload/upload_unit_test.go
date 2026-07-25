package upload

import (
	"bytes"
	"context"
	"fmt"
	"mime/multipart"
	nethttp "net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"wscan/core/http"
	"wscan/core/plugins/base"
)

func TestUpload_GetConfig(t *testing.T) {
	u := &Upload{}
	// Before Init
	cfg := u.GetConfig()
	if cfg != nil {
		t.Errorf("Expected nil config before Init, got %v", cfg)
	}

	// After Init
	expectedCfg := u.DefaultConfig()
	ab := &base.ApolloBase{}
	u.Init(context.Background(), expectedCfg, ab)

	cfg = u.GetConfig()
	if cfg == nil {
		t.Fatal("Expected non-nil config after Init")
	}
	bc := cfg.BaseConfig()
	if bc.Name != "upload" {
		t.Errorf("Expected Name='upload', got '%s'", bc.Name)
	}
}

func TestUpload_Init(t *testing.T) {
	u := &Upload{}
	cfg := u.DefaultConfig()
	ab := &base.ApolloBase{}

	err := u.Init(context.Background(), cfg, ab)
	if err != nil {
		t.Errorf("Init() returned error: %v", err)
	}
}

func TestUpload_Init_NilContext(t *testing.T) {
	u := &Upload{}
	cfg := u.DefaultConfig()
	ab := &base.ApolloBase{}

	err := u.Init(nil, cfg, ab)
	if err != nil {
		t.Errorf("Init() with nil context returned error: %v", err)
	}
}

func TestUpload_execAction(t *testing.T) {
	u := &Upload{}
	err := u.execAction(context.Background(), nil)
	if err != nil {
		t.Errorf("execAction() should return nil, got %v", err)
	}
}

func TestUpload_Fingers(t *testing.T) {
	u := &Upload{}
	fingers := u.Fingers()
	if len(fingers) == 0 {
		t.Error("Expected at least one finger")
	}
	for i, f := range fingers {
		if f.CheckAction == nil {
			t.Errorf("Finger[%d] CheckAction should not be nil", i)
		}
		if f.Channel != "web-generic" {
			t.Errorf("Finger[%d] Channel = %q, want 'web-generic'", i, f.Channel)
		}
		if f.Binding == nil {
			t.Errorf("Finger[%d] Binding should not be nil", i)
		}
		if f.Binding.ID != "upload/upload/default" {
			t.Errorf("Finger[%d] Binding.ID = %q, want 'upload/upload/default'", i, f.Binding.ID)
		}
	}
}

func TestUpload_Fingers_BindingDetails(t *testing.T) {
	u := &Upload{}
	fingers := u.Fingers()
	if len(fingers) == 0 {
		t.Fatal("Expected at least one finger")
	}
	f := fingers[0]
	if f.Binding.Plugin != "upload/upload/default" {
		t.Errorf("Binding.Plugin = %q, want 'upload/upload/default'", f.Binding.Plugin)
	}
	if f.Binding.Category != "upload" {
		t.Errorf("Binding.Category = %q, want 'upload'", f.Binding.Category)
	}
}

func TestGenerateWebshelldata(t *testing.T) {
	// No-op function, just verify it doesn't panic
	generateWebshelldata()
}

func TestGetServiceTypeFromURL(t *testing.T) {
	// No-op function, just verify it doesn't panic
	getServiceTypeFromURL()
}

func TestCleanupWebshell(t *testing.T) {
	ts := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.WriteHeader(nethttp.StatusOK)
	}))
	defer ts.Close()

	ctx := context.Background()
	httpClient := http.NewClient()
	cleanupWebshell(ctx, httpClient, ts.URL+"/shell.php")
}

func TestCleanupWebshell_InvalidURL(t *testing.T) {
	ctx := context.Background()
	httpClient := http.NewClient()
	cleanupWebshell(ctx, httpClient, "http://invalid-host-that-does-not-exist:99999/shell.php")
}

func TestResolveUploadPaths_RequestDir(t *testing.T) {
	baseURL, _ := url.Parse("http://example.com/upload/process.php")
	res := &http.Response{Text: ""}
	paths := resolveUploadPaths(baseURL, res, "shell.php")
	found := false
	for _, p := range paths {
		if p == "http://example.com/upload/shell.php" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected request-dir based path, got: %v", paths)
	}
}

func TestResolveUploadPaths_DuplicateDedup(t *testing.T) {
	baseURL, _ := url.Parse("http://example.com/upload/")
	res := &http.Response{Text: `{"url":"/upload/shell.php"}`}
	paths := resolveUploadPaths(baseURL, res, "shell.php")
	seen := make(map[string]int)
	for _, p := range paths {
		seen[p]++
	}
	for p, count := range seen {
		if count > 1 {
			t.Errorf("duplicate path %s appears %d times", p, count)
		}
	}
}

func TestExtractPathsFromResponse_HTMLAction(t *testing.T) {
	res := &http.Response{Text: `<form action="/upload/shell.php">`}
	paths := extractPathsFromResponse(res, "shell.php")
	if len(paths) == 0 {
		t.Error("expected to find path from HTML action attribute")
	}
}

func TestGenerateWebshells_AllTypes(t *testing.T) {
	shells := GenerateWebshells()
	if len(shells) < 5 {
		t.Errorf("expected at least 5 webshell types, got %d", len(shells))
	}
	for i, ws := range shells {
		if ws.CheckPattern == nil {
			t.Errorf("webshell[%d] has nil CheckPattern", i)
		}
	}
}

func TestFingers_NonMultipart(t *testing.T) {
	u := &Upload{}
	fingers := u.Fingers()
	if len(fingers) == 0 {
		t.Fatal("expected at least one finger")
	}
	// Test the CheckAction with a non-multipart request - should return nil (skip)
	f := fingers[0]
	req, _ := http.NewRequest("GET", "http://example.com/page", nil)
	flow := &http.Flow{
		Request:  req,
		Response: &http.Response{StatusCode: 200},
	}
	apollo := base.NewApollo(flow)
	ab := &base.ApolloBase{
		HTTPClient: http.NewClient(),
	}
	apollo.ApolloBase = ab

	err := f.CheckAction(context.Background(), apollo)
	if err != nil {
		t.Errorf("expected nil error for non-multipart request, got %v", err)
	}
}

func TestFingers_MultipartUpload(t *testing.T) {
	var uploadedFilename string
	var lastWebshellContent string
	var serverURL string
	var uploadCount int
	ts := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if r.Method == "DELETE" {
			w.WriteHeader(nethttp.StatusOK)
			return
		}
		if r.URL.Path == "/upload/" && r.Method == "POST" {
			r.ParseMultipartForm(10 << 20)
			file, handler, err := r.FormFile("file")
			if err == nil {
				content := make([]byte, handler.Size)
				n, _ := file.Read(content)
				lastWebshellContent = string(content[:n])
				uploadedFilename = handler.Filename
				uploadCount++
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(nethttp.StatusOK)
				fmt.Fprintf(w, `{"url":"%s/files/%s"}`, serverURL, uploadedFilename)
				return
			}
		}
		if len(uploadedFilename) > 0 && strings.HasSuffix(r.URL.Path, uploadedFilename) {
			w.WriteHeader(nethttp.StatusOK)
			w.Write([]byte(lastWebshellContent))
			return
		}
		w.WriteHeader(nethttp.StatusNotFound)
	}))
	defer ts.Close()
	serverURL = ts.URL

	u := &Upload{}
	fingers := u.Fingers()
	if len(fingers) == 0 {
		t.Fatal("expected at least one finger")
	}
	f := fingers[0]

	// Build a proper multipart request using net/http, then convert
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", "test.txt")
	if err != nil {
		t.Fatal(err)
	}
	part.Write([]byte("original content"))
	writer.Close()

	netReq, _ := nethttp.NewRequest("POST", ts.URL+"/upload/", body)
	netReq.Header.Set("Content-Type", writer.FormDataContentType())
	req, err := http.RequestFromNetHttpRequert(netReq)
	if err != nil {
		t.Fatal(err)
	}

	// Verify multipart params are parsed correctly
	params := req.ParamsQueryAndBody()
	t.Logf("Number of params: %d", len(params))
	for i, p := range params {
		t.Logf("Param[%d]: Key=%s, Filename=%s", i, p.Key, p.Filename)
	}

	flow := &http.Flow{
		Request:  req,
		Response: &http.Response{StatusCode: 200},
	}
	apollo := base.NewApollo(flow)
	ab := &base.ApolloBase{
		HTTPClient: http.NewClient(),
	}
	apollo.ApolloBase = ab

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	f.CheckAction(ctx, apollo)

	if uploadCount > 0 {
		t.Logf("Upload was attempted %d time(s)", uploadCount)
	}
}

func TestFingers_UploadSuccessStatusNotMatch(t *testing.T) {
	ts := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.WriteHeader(nethttp.StatusForbidden)
	}))
	defer ts.Close()

	u := &Upload{}
	fingers := u.Fingers()
	f := fingers[0]

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("file", "test.txt")
	part.Write([]byte("content"))
	writer.Close()

	netReq, _ := nethttp.NewRequest("POST", ts.URL+"/upload/", body)
	netReq.Header.Set("Content-Type", writer.FormDataContentType())
	req, _ := http.RequestFromNetHttpRequert(netReq)

	flow := &http.Flow{
		Request:  req,
		Response: &http.Response{StatusCode: 200},
	}
	apollo := base.NewApollo(flow)
	ab := &base.ApolloBase{HTTPClient: http.NewClient()}
	apollo.ApolloBase = ab

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := f.CheckAction(ctx, apollo)
	if err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

func TestFingers_UploadErrRespond(t *testing.T) {
	ts := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		hj, ok := w.(nethttp.Hijacker)
		if ok {
			conn, _, _ := hj.Hijack()
			conn.Close()
			return
		}
		w.WriteHeader(nethttp.StatusInternalServerError)
	}))
	defer ts.Close()

	u := &Upload{}
	fingers := u.Fingers()
	f := fingers[0]

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("file", "test.txt")
	part.Write([]byte("content"))
	writer.Close()

	netReq, _ := nethttp.NewRequest("POST", ts.URL+"/upload/", body)
	netReq.Header.Set("Content-Type", writer.FormDataContentType())
	req, _ := http.RequestFromNetHttpRequert(netReq)

	flow := &http.Flow{
		Request:  req,
		Response: &http.Response{StatusCode: 200},
	}
	apollo := base.NewApollo(flow)
	ab := &base.ApolloBase{HTTPClient: http.NewClient()}
	apollo.ApolloBase = ab

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	f.CheckAction(ctx, apollo)
}

func TestFingers_MultipartNoFileParam(t *testing.T) {
	u := &Upload{}
	fingers := u.Fingers()
	f := fingers[0]

	// Create a multipart request without a file parameter
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	writer.WriteField("name", "test")
	writer.Close()

	req, _ := http.NewRequest("POST", "http://example.com/upload", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	flow := &http.Flow{
		Request:  req,
		Response: &http.Response{StatusCode: 200},
	}
	apollo := base.NewApollo(flow)
	ab := &base.ApolloBase{
		HTTPClient: http.NewClient(),
	}
	apollo.ApolloBase = ab

	err := f.CheckAction(context.Background(), apollo)
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}
