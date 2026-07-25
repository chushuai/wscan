/**
2 * @Author: shaochuyu
 * @Date: 12/31/23
*/

package xxe

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"wscan/core/plugins/base"
)

func TestXEE(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 设置响应头
		w.Header().Set("Server", "Apache-Coyote/1.1")
		w.Header().Set("Content-Type", "text/html;charset=ISO-8859-1")

		// 设置响应体
		body := "<html>1111111111</html>"
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))

		// 发送响应体
		fmt.Fprint(w, body)
	}))
	defer server.Close()

	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("Failed to connect to test server: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

func extractURLFromXML(xmlStr string) string {
	// 正则表达式匹配SYSTEM关键字后面的URL
	re := regexp.MustCompile(`SYSTEM.*(http[^"]+)"`)
	match := re.FindStringSubmatch(xmlStr)
	if len(match) > 1 {
		return match[1] // 返回第一个捕获组，即URL本身
	}
	return "" // 没有找到匹配项时返回空字符串
}

func TestExtractURLFromXML(t *testing.T) {
	// [<?xml+version="1.0"?><!DOCTYPE+ANY+[<!ENTITY+content+SYSTEM+"http://0.0.0.0:49297/1416638653/sxdwnufw">]><a>&content;</a>]
	xmlStr := `<?xml+version="1.0"?><!DOCTYPE+ANY+[<!ENTITY+content+SYSTEM+"http://0.0.0.0:8003/i/5d4d3c/4f4q/6ngx/">]><a>&content;</a>`
	url := extractURLFromXML(xmlStr)
	if url == "" {
		t.Error("Expected non-empty URL from XML extraction")
	}
	fmt.Println(url)

	// Test with no URL
	xmlStr2 := `<?xml version="1.0"?><root>hello</root>`
	url2 := extractURLFromXML(xmlStr2)
	if url2 != "" {
		t.Errorf("Expected empty URL for non-XXE XML, got '%s'", url2)
	}
}

func TestDefaultConfig(t *testing.T) {
	p := &XXE{}
	cfg := p.DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig should not return nil")
	}

	baseCfg := cfg.BaseConfig()
	if baseCfg.Name != "xxe" {
		t.Errorf("Expected name 'xxe', got '%s'", baseCfg.Name)
	}
	if !baseCfg.Enabled {
		t.Error("Expected Enabled to be true")
	}
}

func TestClose(t *testing.T) {
	p := &XXE{}
	if err := p.Close(); err != nil {
		t.Errorf("Close should not return error, got %v", err)
	}
}

func TestFingers(t *testing.T) {
	p := &XXE{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()
	fingers := p.Fingers()
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
		if !f.NeedReverse {
			t.Error("XXE finger should need reverse")
		}
	}
}

func TestConfigBaseConfig(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "xxe",
			Enabled: true,
		},
	}

	baseCfg := cfg.BaseConfig()
	if baseCfg.Name != "xxe" {
		t.Errorf("Expected name 'xxe', got '%s'", baseCfg.Name)
	}
}
