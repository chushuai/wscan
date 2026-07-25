/**
2 * @Author: shaochuyu
 * @Date: 12/10/23
*/

package dirscan

import (
	"bufio"
	"fmt"
	"gopkg.in/yaml.v2"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	logger "wscan/core/utils/log"
)

func TestSvnEntries(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 设置响应头
		w.Header().Set("Server", "Apache-Coyote/1.1")
		w.Header().Set("Content-Type", "text/html;charset=ISO-8859-1")

		// 设置响应体
		responseBody := "<html>dir123svn://example.com/repository  \ndir456https://example.org/svn/project\n</html>"
		w.Header().Set("Content-Length", fmt.Sprint(len(responseBody)))

		// 发送响应体
		fmt.Fprint(w, responseBody)
	}))
	defer server.Close()

	// 验证服务器正常响应
	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("Failed to connect to test server: %v", err)
	}
	defer resp.Body.Close()

	if resp.Header.Get("Server") != "Apache-Coyote/1.1" {
		t.Errorf("Expected Server header 'Apache-Coyote/1.1', got '%s'", resp.Header.Get("Server"))
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

func TestLoad(t *testing.T) {

	var ruleSet RuleSet
	err := yaml.Unmarshal(ruleYaml, &ruleSet)
	if err != nil {
		logger.Fatal(err)
	}
	seen := make(map[string]bool)
	for _, i := range ruleSet.Rules {
		p := i.Paths[0]
		if strings.HasPrefix(p, "/") {
			p = p[1:]
		}
		seen[p] = true
	}
	urlFile, err := os.Open("url_list.txt")
	if err != nil {
		logger.Error(err)
	}
	defer urlFile.Close()
	scanner := bufio.NewScanner(urlFile)

	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if strings.Contains(url, ".gz") && strings.Contains(url, ".rar") &&
			strings.Contains(url, ".zip") && strings.Contains(url, ".7z") &&
			strings.Contains(url, ".tgz") && strings.Contains(url, ".tar") {
			if strings.HasPrefix(url, "/") {
				url = url[1:]
			}

			if _, exist := seen[url]; exist {
				ruleSet.Rules = append(ruleSet.Rules, &Rule{Paths: []string{url},
					Expression: "response.status == 200", Category: "dirscan/default"})
				seen[url] = true
			}

		}
	}

	out, err := yaml.Marshal(ruleSet)
	if err != nil {
		logger.Fatal(err)
	}
	fmt.Println(string(out))

}
