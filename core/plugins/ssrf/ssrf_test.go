/**
2 * @Author: shaochuyu
3 * @Date: 12/31/23
4 */

package ssrf

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// --log-level=debug ws  --plug ssrf --url http://localhost:8080/listproducts.php?ab=https://www.baidu.com  --json-output=ssrf.json
func TestSSRF(t *testing.T) {
	t.Skip("Manual test - requires interactive server, skipping in automated tests")
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// 设置响应头
		w.Header().Set("Server", "Apache-Coyote/1.1")
		//w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Type", "text/html;charset=ISO-8859-1")

		// 设置响应体
		body := "<html>1111111111</html>"
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		fmt.Println(r.Header)
		if r.URL != nil {
			for k, v := range r.URL.Query() {
				fmt.Println(k, v)
				if strings.HasPrefix(v[0], "http") {
					http.Get(v[0])
				}
			}
		}
		// 发送响应体
		fmt.Fprint(w, body)
	})
	// 启动HTTP服务器
	fmt.Println("Server is running at http://127.0.01:8080")
	http.ListenAndServe(":8080", nil)
}

//  [reverse:http_server.go:179] starting reverse http server
//[INFO] 2024-01-01 17:36:50 [reverse:reverse.go:169] reverse server base url: http://0.0.0.0:40490, token: NiJu2jPz
//[INFO] 2024-01-01 17:36:50 [reverse:reverse.go:170] reverse server webUI: http://0.0.0.0:40490/cland/

// http://localhost:8080/listproducts.php?ab=http://127.0.0.1:22#@www.baidu.com/
// http://localhost:8080/listproducts.php?ab=http://127.0.0.1:6379#@www.baidu.com/
// http://localhost:8080/listproducts.php?ab=http://0.0.0.0:8003/i/6729e4/qxqc/07gg/
// http://localhost:8080/listproducts.php?ab=http://0.0.0.0:8003#@www.baidu.com/i/e5058d/qxqc/t5l2/
