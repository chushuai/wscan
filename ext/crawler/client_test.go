/**
2 * @Author: shaochuyu
3 * @Date: 3/19/23
4 */

package crawler

import (
	"crypto/tls"
	"net/http"
	"testing"
)

func TestClient_Do(t *testing.T) {
	// 创建一个带有自定义配置的 Client
	config := &ClientConfig{
		Proxies:             []string{"http://localhost:8888"},
		DialTimeout:         10,
		TLSHandshakeTimeout: 10,
		ReadTimeout:         30,
		IdleConnTimeout:     90,
		MaxConnsPerHost:     100,
		MaxIdleConns:        10,
		TLSSkipVerify:       true,
		TLSMinVersion:       tls.VersionTLS12,
		TLSMaxVersion:       tls.VersionTLS13,
		MaxRetryTimes:       3,
		MaxRedirectTimes:    10,
		MaxRequestPerSecond: 10,
		MaxRespBodySize:     1024 * 1024,
		AllowedMethods:      []string{"GET", "POST", "PUT"},
	}
	client, _ := NewClient(config)

	// 准备一个 GET 请求
	req, err := http.NewRequest("GET", "http://httpbin.org/get", nil)
	if err != nil {
		t.Fatal(err)
	}

	// 发送请求并检查响应
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status %d; got %d", http.StatusOK, resp.StatusCode)
	}
}
