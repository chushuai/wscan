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
	"strconv"
	"strings"
)

func extractValueFromURL(url string) (string, error) {
	// 正则表达式模式
	pattern := `(\d+)\*(\d+)`

	// 编译正则表达式
	re := regexp.MustCompile(pattern)

	// 查找匹配的字符串
	matches := re.FindStringSubmatch(url)

	// 提取值
	if len(matches) == 3 {
		i2, _ := strconv.Atoi(matches[1])
		i3, _ := strconv.Atoi(matches[2])
		fmt.Println(i2 * i3)
		return fmt.Sprintf("%d", i2*i3), nil
	} else {
		return "", fmt.Errorf("未找到匹配的值")
	}
}

func isRandomPhp(url string) bool {
	// 正则表达式模式
	pattern := `^/(\d+).php$`

	// 编译正则表达式
	re := regexp.MustCompile(pattern)

	return re.MatchString(url)
}

// GOOS=windows GOARCH=amd64 go build
func main() {
	count := 0
	PHPSESSID := ""
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// 设置响应头
		fmt.Println("-----------------")
		body := "<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n<meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge,chrome=1\">\n<meta name=\"viewport\" content=\"width=device-width, maximum-scale=1, initial-scale=1, user-scalable=yes\">\n<link href=\"/favicon.ico\" rel=\"shortcut icon\"/>\n<title>Hello</title>\n<link rel=\"stylesheet\" href=\"/Public/theme/view4/css/qietu.css\">\n<link rel=\"stylesheet\" href=\"/Public/theme/view4/css/iconfont.css\">\n<link rel=\"stylesheet\" href=\"/Public/theme/view4/css/animate.min.css\" />\n<link rel=\"stylesheet\" href=\"/Public/theme/view4/css/style.css\">\n<link rel=\"stylesheet\" href=\"/Public/theme/view4/css/responsive.css\">\n<meta name=\"__hash__\" content=\"6666cd76f96956469e7be39d750cc7d9_acaf784e8b1c28becb1c93ec8643133b\" /></head>\n\n<body>\nHello\n</body>\n</html>"
		w.Header().Set("Server", "Apache-Coyote/1.1")
		fmt.Println(r.Method, r.URL.String(), r.Header)
		if isRandomPhp(r.URL.String()) {
			count += 1
			fmt.Println("found RandomPhp", count)
			if count == 1 {
				w.WriteHeader(http.StatusNotFound)
				return
			} else if count == 2 {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(200)
				return
			}
		}

		if r.URL.String() == "/" {
			PHPSESSID = r.Header.Get("Cookie")
			fmt.Println(PHPSESSID)
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.URL.String() == "/" && PHPSESSID != "" {
			w.Header().Set("Set-Cookie", PHPSESSID)
		} else {
			w.Header().Set("Set-Cookie", "PHPSESSID=5d99c9cb0580e199234b63b5375975a1; path=/; HttpOnly")
		}

		w.Header().Set("X-Powered-By", "ThinkPHP")

		if data, err := extractValueFromURL(r.URL.String()); err == nil {
			body += data
		}

		if r.Body != nil {
			if data, err := io.ReadAll(r.Body); err == nil {
				fmt.Println(string(data))
				body += strings.ReplaceAll(string(data), "%25%25", "%")
				body += "1"
			}
		}
		fmt.Println("-----------------")
		// 设置响应体
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		// 发送响应体
		fmt.Fprint(w, body)
	})
	// 启动HTTP服务器
	fmt.Println("Server is running at http://127.0.0.1:8080")
	http.ListenAndServe(":8080", nil)
}
