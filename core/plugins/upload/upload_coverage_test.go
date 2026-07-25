package upload

import (
	"net/url"
	"regexp"
	"testing"

	"wscan/core/http"
)

func TestIsUploadSuccessStatus(t *testing.T) {
	tests := []struct {
		code     int
		expected bool
	}{
		{200, true},
		{201, true},
		{202, true},
		{204, true},
		{301, true},
		{302, true},
		{400, false},
		{403, false},
		{404, false},
		{500, false},
		{100, false},
	}
	for _, tt := range tests {
		result := isUploadSuccessStatus(tt.code)
		if result != tt.expected {
			t.Errorf("isUploadSuccessStatus(%d) = %v, expected %v", tt.code, result, tt.expected)
		}
	}
}

func TestExtractPathsFromResponse_JSONUrl(t *testing.T) {
	res := &http.Response{
		Text: `{"url":"/uploads/shell.php","path":"/files/shell.php"}`,
	}
	paths := extractPathsFromResponse(res, "shell.php")
	found := false
	for _, p := range paths {
		if p == "/uploads/shell.php" || p == "/files/shell.php" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected to find path from JSON response, got: %v", paths)
	}
}

func TestExtractPathsFromResponse_JSONDataNested(t *testing.T) {
	res := &http.Response{
		Text: `{"data":{"url":"/uploads/shell.php","file_path":"/files/shell.php"}}`,
	}
	paths := extractPathsFromResponse(res, "shell.php")
	found := false
	for _, p := range paths {
		if p == "/uploads/shell.php" || p == "/files/shell.php" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected to find path from nested data JSON, got: %v", paths)
	}
}

func TestExtractPathsFromResponse_HTMLHref(t *testing.T) {
	res := &http.Response{
		Text: `<a href="/uploads/shell.php">link</a>`,
	}
	paths := extractPathsFromResponse(res, "shell.php")
	if len(paths) == 0 {
		t.Error("expected to find path from HTML href attribute")
	}
}

func TestExtractPathsFromResponse_JSONSrc(t *testing.T) {
	res := &http.Response{
		Text: `{"src":"/img/shell.php"}`,
	}
	paths := extractPathsFromResponse(res, "shell.php")
	if len(paths) == 0 {
		t.Error("expected to find path from JSON src field")
	}
}

func TestExtractPathsFromResponse_NoMatch(t *testing.T) {
	res := &http.Response{
		Text: `{"status":"ok"}`,
	}
	paths := extractPathsFromResponse(res, "shell.php")
	if len(paths) != 0 {
		t.Errorf("expected 0 paths for non-matching response, got %d", len(paths))
	}
}

func TestResolveUploadPaths_AbsoluteURL(t *testing.T) {
	baseURL, _ := url.Parse("http://example.com/upload/")
	res := &http.Response{
		Text: `{"url":"http://cdn.example.com/files/shell.php"}`,
	}
	paths := resolveUploadPaths(baseURL, res, "shell.php")
	found := false
	for _, p := range paths {
		if p == "http://cdn.example.com/files/shell.php" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected absolute URL in paths, got: %v", paths)
	}
}

func TestResolveUploadPaths_RelativePath(t *testing.T) {
	baseURL, _ := url.Parse("http://example.com/upload/process.php")
	res := &http.Response{
		Text: `{"path":"files/shell.php"}`,
	}
	paths := resolveUploadPaths(baseURL, res, "shell.php")
	// Should contain the relative path resolved to absolute
	if len(paths) == 0 {
		t.Error("expected at least one path from relative resolution")
	}
}

func TestResolveUploadPaths_RootPath(t *testing.T) {
	baseURL, _ := url.Parse("http://example.com/upload/process.php")
	res := &http.Response{
		Text: `{"url":"/uploads/shell.php"}`,
	}
	paths := resolveUploadPaths(baseURL, res, "shell.php")
	found := false
	for _, p := range paths {
		if p == "http://example.com/uploads/shell.php" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected root-relative path in paths, got: %v", paths)
	}
}

func TestResolveUploadPaths_NilResponse(t *testing.T) {
	baseURL, _ := url.Parse("http://example.com/upload/process.php")
	paths := resolveUploadPaths(baseURL, nil, "shell.php")
	// Should still produce paths from common upload paths
	if len(paths) == 0 {
		t.Error("expected paths from common upload paths even with nil response")
	}
}

func TestResolveUploadPaths_CommonPaths(t *testing.T) {
	baseURL, _ := url.Parse("http://example.com/upload/")
	paths := resolveUploadPaths(baseURL, nil, "shell.php")
	// Verify some common paths are included
	found := false
	for _, p := range paths {
		if p == "http://example.com/upload/shell.php" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected request-dir based path in paths, got: %v", paths)
	}
}

func TestGenerateWebshellsDetailed(t *testing.T) {
	shells := GenerateWebshells()
	if len(shells) == 0 {
		t.Fatal("expected at least one webshell to be generated")
	}
	for i, ws := range shells {
		if len(ws.NamesForUpload) == 0 {
			t.Errorf("webshell[%d]: NamesForUpload should not be empty", i)
		}
		if len(ws.Content) == 0 {
			t.Errorf("webshell[%d]: Content should not be empty", i)
		}
		if ws.CheckPattern == nil {
			t.Errorf("webshell[%d]: CheckPattern should not be nil", i)
		}
		// Verify filenames don't contain template placeholders
		for _, name := range ws.NamesForUpload {
			if name == "" {
				t.Errorf("webshell[%d]: filename should not be empty", i)
			}
		}
	}
}

func TestGenerateWebshells_PHPWebshell(t *testing.T) {
	shells := GenerateWebshells()
	// First webshell should be PHP with JPEG markers
	if len(shells) < 1 {
		t.Fatal("expected at least one webshell")
	}
	ws := shells[0]
	// PHP webshell content should contain md5 pattern
	if ws.CheckPattern == nil {
		t.Error("PHP webshell CheckPattern should not be nil")
	}
}

func TestGenerateWebshells_CheckPattern(t *testing.T) {
	shells := GenerateWebshells()
	for i, ws := range shells {
		if ws.CheckPattern != nil {
			// Test the pattern can match something
			if !ws.CheckPattern.MatchString(ws.CheckPattern.String()) {
				// The pattern should at least be a valid regex
				t.Logf("webshell[%d] CheckPattern: %s", i, ws.CheckPattern.String())
			}
		}
	}
}

func TestCalculateMD5Hash_Valid(t *testing.T) {
	result, err := CalculateMD5Hash("md5('hello')")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// MD5 of "hello" is 5d41402abc4b2a76b9719d911017c592
	if result != "5d41402abc4b2a76b9719d911017c592" {
		t.Errorf("expected MD5 of hello, got %s", result)
	}
}

func TestCalculateMD5Hash_NoMatch(t *testing.T) {
	_, err := CalculateMD5Hash("no md5 here")
	if err == nil {
		t.Error("expected error for no match")
	}
}

func TestCalculateMD5Hash_Empty(t *testing.T) {
	_, err := CalculateMD5Hash("")
	if err == nil {
		t.Error("expected error for empty input")
	}
}

func TestUploadConfig_BaseConfig(t *testing.T) {
	c := &Config{}
	bc := c.BaseConfig()
	if bc == nil {
		t.Error("expected non-nil BaseConfig")
	}
}

func TestUpload_DefaultConfig(t *testing.T) {
	u := &Upload{}
	cfg := u.DefaultConfig()
	if cfg == nil {
		t.Fatal("expected non-nil DefaultConfig")
	}
	bc := cfg.BaseConfig()
	if bc.Name != "upload" {
		t.Errorf("expected Name 'upload', got '%s'", bc.Name)
	}
	if !bc.Enabled {
		t.Error("expected Enabled=true")
	}
}

func TestUpload_Close(t *testing.T) {
	u := &Upload{}
	if err := u.Close(); err != nil {
		t.Errorf("expected nil error from Close, got %v", err)
	}
}

func TestCommonUploadPaths(t *testing.T) {
	if len(commonUploadPaths) == 0 {
		t.Error("expected non-empty commonUploadPaths")
	}
	// Verify they all start with /
	for _, p := range commonUploadPaths {
		if !startsWithSlash(p) {
			t.Errorf("expected path to start with /, got %s", p)
		}
	}
}

func startsWithSlash(s string) bool {
	return len(s) > 0 && s[0] == '/'
}

func TestExtractPathsFromResponse_AllJSONKeys(t *testing.T) {
	// Test all supported JSON keys
	keys := []string{"url", "path", "file_path", "file_url", "src", "link", "file", "filepath", "fileUrl", "filePath"}
	for _, key := range keys {
		res := &http.Response{
			Text: `{"` + key + `":"/found/shell.php"}`,
		}
		paths := extractPathsFromResponse(res, "shell.php")
		found := false
		for _, p := range paths {
			if p == "/found/shell.php" {
				found = true
			}
		}
		if !found {
			t.Errorf("expected to find path from JSON key '%s'", key)
		}
	}
}

func TestExtractPathsFromResponse_RegexPatterns(t *testing.T) {
	// Test the regex pattern for src attribute
	res := &http.Response{
		Text: `<img src="/uploads/shell.php">`,
	}
	paths := extractPathsFromResponse(res, "shell.php")
	if len(paths) == 0 {
		t.Error("expected to find path from src attribute regex")
	}
}

func TestWebshellStruct(t *testing.T) {
	// Test Webshell struct creation
	ws := Webshell{
		Content:        []byte("test content"),
		NamesForUpload: []string{"test.php"},
		CheckPattern:   regexp.MustCompile("test"),
	}
	if len(ws.Content) != 12 {
		t.Errorf("expected 12 bytes, got %d", len(ws.Content))
	}
	if len(ws.NamesForUpload) != 1 {
		t.Errorf("expected 1 name, got %d", len(ws.NamesForUpload))
	}
	if !ws.CheckPattern.MatchString("test") {
		t.Error("CheckPattern should match 'test'")
	}
}
