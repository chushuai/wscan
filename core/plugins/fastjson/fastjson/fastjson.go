/**
2 * @Author: shaochuyu
3 * @Date: 1/6/24
4 */

package main

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// 设置响应头
		body := "<html>1111111111</html>"
		w.Header().Set("Server", "Apache-Coyote/1.1")
		fmt.Println(r.URL.String())
		if strings.Contains(r.URL.String(), ".php") {
			w.WriteHeader(404)
			return
		}
		if strings.Contains(r.URL.String(), "fastjson") {
			w.Header().Set("Content-Type", "application/json")
			body = `{"code":200, "data": {"rx" : "xxx"}}`
		} else {
			w.Header().Set("Content-Type", "text/html;charset=ISO-8859-1")
		}
		// 设置响应体
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))

		if r.Body != nil {
			if data, err := io.ReadAll(r.Body); err == nil {
				fmt.Println(string(data))
				re := regexp.MustCompile(`"url": "([^"]+)"`)
				matches := re.FindStringSubmatch(string(data))
				// 检查是否找到匹配项
				if len(matches) > 1 {
					url := matches[1]
					fmt.Println(url) // 输出提取到的URL
				} else {
					fmt.Println("No URL found")
				}
			}
		}
		// 发送响应体
		fmt.Fprint(w, body)
	})
	// 启动HTTP服务器
	fmt.Println("Server is running at http://127.0.0.1:8080")
	http.ListenAndServe(":8080", nil)
}

// .\xray.exe --log-level=debug ws --plug fastjson --rr .\raw.txt
// new knowledge for http://127.0.0.1:8080, is_struts: fingerprint_found
