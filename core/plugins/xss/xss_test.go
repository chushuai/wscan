/**
2 * @Author: shaochuyu
3 * @Date: 11/25/22
4 */

package xss

import (
	"fmt"
	"net/http"
	"testing"
)

// http://127.0.0.1:8080/?a=b
func TestScriptXSS(t *testing.T) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		a := r.URL.Query().Get("a")

		// 设置响应头
		w.Header().Set("Server", "Apache-Coyote/1.1")
		//w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Type", "text/html;charset=ISO-8859-1")

		// 设置响应体
		body := `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>XSS Injection Demo</title>
</head>
<body>

<h1>XSS Injection Demo</h1>

<!-- 潜在的 XSS 注入点 -->
<script>
    // 这里是潜在的 XSS 注入点，展示用户输入的内容
    var userInput = ` + a + `;
    document.getElementById("result").innerHTML += "<p>通过脚本获取的输入内容: " + userInput + "</p>";
</script>

</body>
</html>`
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		// 发送响应体
		fmt.Fprint(w, body)
	})
	// 启动HTTP服务器
	fmt.Println("Server is running at http://127.0.01:8080")
	http.ListenAndServe(":8080", nil)
}

// http://127.0.0.1:8080/?a=--!%3E%3Csvg%20onload=alert`1`
func TestCommentXSS(t *testing.T) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		a := r.URL.Query().Get("a")

		// 设置响应头
		w.Header().Set("Server", "Apache-Coyote/1.1")
		//w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Type", "text/html;charset=ISO-8859-1")

		// 设置响应体
		body := `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>XSS Injection Demo</title>
</head>
<body>

<h1>XSS Injection Demo</h1>

<!-- ` + a + `  -->
</body>
</html> `
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		// 发送响应体
		fmt.Fprint(w, body)
	})
	// 启动HTTP服务器
	fmt.Println("Server is running at http://127.0.01:8080")
	http.ListenAndServe(":8080", nil)
}

// http://127.0.0.1:8080/?a=%22%20onmousemove=prompt(1)%20%22
func TestAttibuteValueXSS(t *testing.T) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		a := r.URL.Query().Get("a")

		// 设置响应头
		w.Header().Set("Server", "Apache-Coyote/1.1")
		//w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Type", "text/html;charset=ISO-8859-1")

		// 设置响应体
		body := `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>XSS Injection Demo</title>
</head>
<body>

<h1>XSS Injection Demo</h1>

 
<a  a="111` + a + `">iiiii</a>
</body>
</html> `
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		// 发送响应体
		fmt.Fprint(w, body)
	})
	// 启动HTTP服务器
	fmt.Println("Server is running at http://127.0.01:8080")
	http.ListenAndServe(":8080", nil)
}

func TestAttibuteKeyXSS(t *testing.T) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		a := r.URL.Query().Get("a")

		// 设置响应头
		w.Header().Set("Server", "Apache-Coyote/1.1")
		//w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Type", "text/html;charset=ISO-8859-1")

		// 设置响应体
		body := `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>XSS Injection Demo</title>
</head>
<body>

<h1>XSS Injection Demo</h1>
<input type="hidden" name="langue" value="\"ozmhl=\"\"">
 
<a  ` + a + `="111">iiiii</a>
</body>
</html> `
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		// 发送响应体
		fmt.Fprint(w, body)
	})
	// 启动HTTP服务器
	fmt.Println("Server is running at http://127.0.01:8080")
	http.ListenAndServe(":8080", nil)
}
