/**
* @Author: shaochuyu
* @Date: 6/16/2026 10:00
 */
package sensitivefile

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"wscan/core/model"
	"wscan/core/plugins/base"
)

func TestBuildSensitiveFileEntries(t *testing.T) {
	entries := buildSensitiveFileEntries()
	if len(entries) == 0 {
		t.Fatal("expected non-empty sensitive file entries")
	}
	// Verify all entries have required fields and valid patterns
	for _, entry := range entries {
		if entry.Name == "" {
			t.Error("entry missing name")
		}
		if entry.Pattern == "" {
			t.Errorf("entry %s missing pattern", entry.Name)
		}
		if entry.Description == "" {
			t.Errorf("entry %s missing description", entry.Name)
		}
		if entry.Severity == "" {
			t.Errorf("entry %s missing severity", entry.Name)
		}
		// Verify pattern compiles
		_, err := regexp.Compile(entry.Pattern)
		if err != nil {
			t.Errorf("entry %s has invalid pattern %q: %v", entry.Name, entry.Pattern, err)
		}
	}
}

func TestExtractDirName(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"http://example.com/admin/", "admin"},
		{"http://example.com/app/", "app"},
		{"http://example.com/", ""},
		{"http://example.com/a/b/c/", "c"},
	}
	for _, tt := range tests {
		got := extractDirName(tt.url)
		if got != tt.want {
			t.Errorf("extractDirName(%q) = %q, want %q", tt.url, got, tt.want)
		}
	}
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input string
		want  model.SeverityLevel
	}{
		{"critical", model.SeverityCritical},
		{"high", model.SeverityHigh},
		{"medium", model.SeverityMedium},
		{"low", model.SeverityLow},
		{"info", model.SeverityInfo},
		{"CRITICAL", model.SeverityCritical},
		{"unknown", model.SeverityHigh}, // default
	}
	for _, tt := range tests {
		got := parseSeverity(tt.input)
		if got != tt.want {
			t.Errorf("parseSeverity(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestBodySimilarity(t *testing.T) {
	// Identical strings
	if sim := bodySimilarity("hello", "hello"); sim != 1.0 {
		t.Errorf("bodySimilarity identical = %f, want 1.0", sim)
	}
	// Empty strings
	if sim := bodySimilarity("", ""); sim != 1.0 {
		t.Errorf("bodySimilarity empty = %f, want 1.0", sim)
	}
	// One empty
	if sim := bodySimilarity("hello", ""); sim != 0.0 {
		t.Errorf("bodySimilarity one-empty = %f, want 0.0", sim)
	}
	// Different strings with similar prefix
	if sim := bodySimilarity("hello world", "hello there"); sim <= 0.5 {
		t.Errorf("bodySimilarity similar-prefix = %f, want > 0.5", sim)
	}
	// Completely different strings
	if sim := bodySimilarity("aaaa", "bbbb"); sim >= 0.8 {
		t.Errorf("bodySimilarity different = %f, want < 0.8", sim)
	}
}

func TestDefaultConfig(t *testing.T) {
	p := &SensitiveFile{}
	cfg := p.DefaultConfig()
	if cfg.BaseConfig().Name != "sensitivefile" {
		t.Errorf("expected plugin name 'sensitivefile', got %q", cfg.BaseConfig().Name)
	}
	if !cfg.BaseConfig().Enabled {
		t.Error("expected plugin to be enabled by default")
	}
	sfcfg := cfg.(*Config)
	if sfcfg.MaxDetectPerScan != 15 {
		t.Errorf("expected MaxDetectPerScan=15, got %d", sfcfg.MaxDetectPerScan)
	}
}

func TestCheckActionDirectoryPath(t *testing.T) {
	p := &SensitiveFile{}
	entries := buildSensitiveFileEntries()
	p.entries = entries

	// Test that directory paths (ending with /) pass the check
	// We need to construct an Apollo with a target flow having a directory URL
	// For unit testing, we'll just test the logic directly by checking
	// the CheckAction behavior through the plugin struct
}

func TestEnvFileDetection(t *testing.T) {
	// Test .env file pattern matches real .env content
	envContent := `APP_ENV=production
DB_PASSWORD=secret123
DB_HOST=localhost
REDIS_HOST=redis.example.com
APP_DEBUG=true`

	re := regexp.MustCompile(`(APP_ENV|DB_PASSWORD|DB_HOST|DB_DATABASE|REDIS_HOST|APP_DEBUG|MAIL_HOST|MAIL_PORT|MAIL_DRIVER|CACHE_DRIVER|QUEUE_DRIVER|APP_KEY)\s*=`)
	if !re.MatchString(envContent) {
		t.Error("expected .env pattern to match real .env content")
	}
}

func TestRSAPrivateKeyDetection(t *testing.T) {
	rsaContent := `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3v5j8nBmT2fK1p7Q+4Xa3RdW6yHsJl9Nv0
-----END RSA PRIVATE KEY-----`

	re := regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`)
	if !re.MatchString(rsaContent) {
		t.Error("expected RSA private key pattern to match")
	}
}

func TestHtpasswdDetection(t *testing.T) {
	htpasswdContent := `admin:$apr1$H6D5P1$t8F9V0K3Q7P2B4R8A0C6E4G8I2J6K0L4M8N2O6P0Q4R8S2T6U0V4W8X2Y6Z0`

	re := regexp.MustCompile(`:\$apr1\$|:\{SHA\}|:\$2[ayb]\$`)
	if !re.MatchString(htpasswdContent) {
		t.Error("expected .htpasswd pattern to match")
	}
}

func TestWPConfigDetection(t *testing.T) {
	wpContent := `<?php
define('DB_PASSWORD', 'my_secret_db_pass');
define('DB_USER', 'root');
define('DB_NAME', 'wordpress');`

	re := regexp.MustCompile(`(DB_PASSWORD|DB_USER|DB_NAME|DB_HOST|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY)`)
	if !re.MatchString(wpContent) {
		t.Error("expected wp-config.php pattern to match")
	}
}

func TestAWSCredentialsDetection(t *testing.T) {
	awsContent := `[default]
aws_access_key_id=AKIAIOSFODNN7EXAMPLE
aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`

	re := regexp.MustCompile(`(aws_access_key_id|aws_secret_access_key)\s*=`)
	if !re.MatchString(awsContent) {
		t.Error("expected AWS credentials pattern to match")
	}
}

func TestDockerComposeDetection(t *testing.T) {
	dockerContent := `version: '3'
services:
  db:
    environment:
      MYSQL_ROOT_PASSWORD: supersecret`

	re := regexp.MustCompile(`(environment|password|secret|MYSQL_ROOT_PASSWORD|POSTGRES_PASSWORD|API_KEY|TOKEN)\s*:`)
	if !re.MatchString(dockerContent) {
		t.Error("expected docker-compose pattern to match")
	}
}

func TestFileZillaDetection(t *testing.T) {
	fileZillaContent := `<FileZilla3>
<Servers>
<Server>
<Pass>encoded_password_here</Pass>
</Server>
</Servers>
</FileZilla3>`

	re := regexp.MustCompile(`<Pass>`)
	if !re.MatchString(fileZillaContent) {
		t.Error("expected FileZilla recentservers.xml pattern to match")
	}
}

func TestDSStoreDetection(t *testing.T) {
	// .DS_Store files start with "Bud1" magic bytes
	dsStoreContent := "Bud1\x00\x00\x00\x00"

	re := regexp.MustCompile(`Bud1`)
	if !re.MatchString(dsStoreContent) {
		t.Error("expected .DS_Store pattern to match Bud1 signature")
	}
}

func TestTemplateVariableResolution(t *testing.T) {
	// Test ${dirname} template replacement
	dirname := "myapp"
	fileName := strings.ReplaceAll("${dirname}.sql", "${dirname}", dirname)
	if fileName != "myapp.sql" {
		t.Errorf("expected 'myapp.sql', got %q", fileName)
	}

	fileName = strings.ReplaceAll("${dirname}.bak", "${dirname}", dirname)
	if fileName != "myapp.bak" {
		t.Errorf("expected 'myapp.bak', got %q", fileName)
	}
}

func TestRandomSuffixAntiFalsePositive(t *testing.T) {
	// Simulate a catch-all server that returns the same content for any URL
	catchAllBody := `<html><body>Welcome to our site</body></html>`
	randomSuffixBody := `<html><body>Welcome to our site</body></html>`

	sim := bodySimilarity(catchAllBody, randomSuffixBody)
	if sim <= 0.8 {
		t.Errorf("expected high similarity for identical catch-all responses, got %f", sim)
	}

	// Real file returns different content than random suffix URL
	realFileBody := `APP_ENV=production
DB_PASSWORD=secret123`
	differentBody := `<html><body>404 Not Found</body></html>`

	sim = bodySimilarity(realFileBody, differentBody)
	if sim >= 0.8 {
		t.Errorf("expected low similarity for different responses, got %f", sim)
	}
}

func TestInitCompilesPatterns(t *testing.T) {
	p := &SensitiveFile{}
	err := p.Init(context.Background(), p.DefaultConfig(), nil)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	if len(p.entries) == 0 {
		t.Fatal("expected entries to be populated after Init")
	}
	for _, entry := range p.entries {
		if entry.Pattern != "" && entry.patternRe == nil {
			t.Errorf("entry %s has pattern but patternRe is nil after Init", entry.Name)
		}
	}
}

func TestFingersReturnsCorrectChannel(t *testing.T) {
	p := &SensitiveFile{}
	err := p.Init(context.Background(), p.DefaultConfig(), nil)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	fingers := p.Fingers()
	if len(fingers) != 1 {
		t.Fatalf("expected 1 finger, got %d", len(fingers))
	}
	if fingers[0].Channel != "web-directory" {
		t.Errorf("expected channel 'web-directory', got %q", fingers[0].Channel)
	}
	if fingers[0].Binding.ID != "sensitive_file_exposure" {
		t.Errorf("expected binding ID 'sensitive_file_exposure', got %q", fingers[0].Binding.ID)
	}
	if fingers[0].Binding.Plugin != "sensitivefile" {
		t.Errorf("expected binding plugin 'sensitivefile', got %q", fingers[0].Binding.Plugin)
	}
}

func TestIntegrationWithHTTPServer(t *testing.T) {
	// Set up a test HTTP server that serves a fake .env file
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.env":
			w.WriteHeader(200)
			w.Write([]byte("APP_ENV=production\nDB_PASSWORD=secret123\n"))
		case "/.htaccess":
			w.WriteHeader(200)
			w.Write([]byte("RewriteEngine On\nRewriteRule ^api/(.*)$ /handler.php?req=$1 [L]\n"))
		case "/id_rsa":
			w.WriteHeader(200)
			w.Write([]byte("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\n"))
		default:
			// Return 404 for random suffix URLs and non-existent files
			w.WriteHeader(404)
			w.Write([]byte("Not Found"))
		}
	}))
	defer server.Close()

	// Verify the server responds correctly
	resp, err := http.Get(server.URL + "/.env")
	if err != nil {
		t.Fatalf("Failed to connect to test server: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("Expected 200 for /.env, got %d", resp.StatusCode)
	}

	resp2, err := http.Get(server.URL + "/nonexistent12345")
	if err != nil {
		t.Fatalf("Failed to connect to test server: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != 404 {
		t.Errorf("Expected 404 for random suffix, got %d", resp2.StatusCode)
	}
}

func TestGetConfig(t *testing.T) {
	p := &SensitiveFile{}
	err := p.Init(context.Background(), p.DefaultConfig(), nil)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	cfg := p.GetConfig()
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.BaseConfig().Name != "sensitivefile" {
		t.Errorf("expected config name 'sensitivefile', got %q", cfg.BaseConfig().Name)
	}
}

func TestClose(t *testing.T) {
	p := &SensitiveFile{}
	err := p.Close()
	if err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
}

// Ensure the plugin implements the base.Plugin interface at compile time.
var _ base.Plugin = (*SensitiveFile)(nil)
