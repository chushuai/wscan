/**
2 * @Author: shaochuyu
3 * @Date: 12/24/23
4 */

package reverse

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
	"wscan/core/http"
)

func TestReverse(t *testing.T) {
	urlPath := "/652027834/xx" // 替换为你要查询的URL
	// 构建请求体
	body := QueryInfo{Query: urlPath}
	requestBody, err := json.Marshal(body)
	if err != nil {
		fmt.Println("Failed to marshal request body:", err)
		return
	}
	// 发送POST请求
	req, err := http.NewRequest("POST", "http://0.0.0.0:8003/api/verifyHttp", bytes.NewBuffer(requestBody))
	if err != nil {
		fmt.Println("Failed to send HTTP request:", err)
		return
	}
	req.SetHeader("token", "NiJu2jPz")
	req.SetValue("Content-Type", "application/json")

	client := http.NewClient()
	resp, err := client.DoRaw(req)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(resp.GetRawBody())
	rd := RespData{}
	err = json.Unmarshal([]byte(resp.Text), &rd)
	if err == nil {
		fmt.Println(rd)
	}

}

func TestReverseDNS(t *testing.T) {
	config := &Config{
		Token: "xxxx",
		HTTPServerConfig: HTTPServerConfig{
			Enabled:    true,
			ListenIP:   "0.0.0.0",
			ListenPort: "8003",
		},
		DNSServerConfig: DNSServerConfig{
			Enabled:  true,
			ListenIP: "0.0.0.0",
			Domain:   "xxx.com",
		},
		ClientConfig: ClientConfig{
			HTTPBaseURL: "http://0.0.0.0:8003",
		},
	}
	fmt.Println(CheckReverse(config, "cxy.xxx.com", "dns", 10))
}
