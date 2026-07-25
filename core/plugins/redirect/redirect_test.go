/**
2 * @Author: shaochuyu
 * @Date: 12/31/23
*/

package redirect

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"wscan/core/plugins/base"
)

// --log-level=debug ws  --plug redirect  --url http://localhost:8080/listproducts.php?ab=http://wscan.cool --json-output=redirect.json
func TestRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		location := ""
		if r.URL != nil {
			for _, v := range r.URL.Query() {
				if strings.Contains(v[0], "http") || strings.Contains(v[0], "com") {
					location = v[0]
				}
			}
		}

		// 设置响应头
		w.Header().Set("Server", "Apache-Coyote/1.1")
		w.Header().Set("Content-Type", "text/html;charset=ISO-8859-1")
		// 设置响应体
		body := "<html>1111111111</html>"
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))

		if location != "" {
			w.Header().Set("Location", location)
			w.WriteHeader(http.StatusMovedPermanently)

		}
		// 发送响应体
		fmt.Fprint(w, body)
	}))
	defer server.Close()

	// Test normal request
	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("Failed to connect to test server: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Test redirect request - use client that doesn't follow redirects
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp2, err := client.Get(server.URL + "?url=http://example.com")
	if err != nil {
		t.Fatalf("Failed to connect to test server: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusMovedPermanently {
		t.Errorf("Expected status 301, got %d", resp2.StatusCode)
	}
}

func TestDefaultConfig(t *testing.T) {
	r := &Redirect{}
	cfg := r.DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig should not return nil")
	}

	baseCfg := cfg.BaseConfig()
	if baseCfg.Name != "redirect" {
		t.Errorf("Expected name 'redirect', got '%s'", baseCfg.Name)
	}
	if !baseCfg.Enabled {
		t.Error("Expected Enabled to be true")
	}
}

func TestClose(t *testing.T) {
	r := &Redirect{}
	if err := r.Close(); err != nil {
		t.Errorf("Close should not return error, got %v", err)
	}
}

func TestFingers(t *testing.T) {
	r := &Redirect{}
	r.PluginMixinInitConfig.Config = r.DefaultConfig()
	fingers := r.Fingers()
	if len(fingers) == 0 {
		t.Error("Expected at least one finger")
	}

	for _, f := range fingers {
		if f.CheckAction == nil {
			t.Error("CheckAction should not be nil")
		}
		if f.Binding == nil {
			t.Error("Binding should not be nil")
		}
		if f.Channel != "web-generic" {
			t.Errorf("Expected channel 'web-generic', got '%s'", f.Channel)
		}
	}
}

func TestConfigBaseConfig(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "redirect",
			Enabled: true,
		},
	}

	baseCfg := cfg.BaseConfig()
	if baseCfg.Name != "redirect" {
		t.Errorf("Expected name 'redirect', got '%s'", baseCfg.Name)
	}
}
