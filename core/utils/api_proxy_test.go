/**
2 * @Author: shaochuyu
3 * @Date: 12/22/23
4 */

package utils

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestAPIProxy(t *testing.T) {
	// 创建一个模拟的目标服务器
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 模拟目标服务器的响应
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello, this is the target server response!"))
	}))
	defer targetServer.Close()

	// 启动代理服务器
	proxyURL, err := url.Parse(targetServer.URL)
	if err != nil {
		t.Fatal("Error parsing proxy URL:", err)
	}

	proxyServer := httptest.NewServer(APIProxy(proxyURL))
	defer proxyServer.Close()

	// 创建一个模拟的客户端
	client := &http.Client{}

	// 发送请求到代理服务器
	req, err := http.NewRequest("GET", proxyServer.URL+"/path", nil)
	if err != nil {
		t.Fatal("Error creating request:", err)
	}

	// 执行请求
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal("Error sending request:", err)
	}
	defer resp.Body.Close()

	// 验证代理服务器的响应
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}

	// 读取代理服务器的响应内容
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal("Error reading response body:", err)
	}

	expectedResponse := "Hello, this is the target server response!"
	if string(responseBody) != expectedResponse {
		t.Errorf("Expected response '%s', got '%s'", expectedResponse, string(responseBody))
	}
}

func Test2Api(t *testing.T) {
	// 设置代理目标的地址
	targetURL, err := url.Parse("http://testphp.vulnweb.com")
	if err != nil {
		fmt.Println("Error parsing target URL:", err)
		return
	}

	// 创建代理处理程序
	proxyHandler := APIProxy(targetURL)

	// 设置HTTP处理函数，所有请求都将通过代理处理
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		proxyHandler.ServeHTTP(w, r)
	})

	// 启动代理服务器
	port := 188
	fmt.Printf("Proxy server is running on port %d...\n", port)
	err = http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
	if err != nil {
		fmt.Println("Error starting proxy server:", err)
	}
}

//
