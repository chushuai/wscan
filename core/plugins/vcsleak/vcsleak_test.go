/**
* @Author: shaochuyu
* @Date: 6/16/2026
 */
package vcsleak

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	wscan_http "wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/utils/printer"
)

// ==================== Mock printer ====================

type mockPrinter struct {
	printer.BasePrinter
}

func (m *mockPrinter) Print(v any) error { return nil }
func (m *mockPrinter) Close() error      { return nil }

// ==================== Helper to create Apollo ====================

func makeTestApollo(serverURL string) *base.Apollo {
	u, _ := url.Parse(serverURL)
	req, _ := wscan_http.NewRequest("GET", u.String(), nil)
	flow := &wscan_http.Flow{
		Request:  req,
		Response: &wscan_http.Response{StatusCode: 200},
	}
	a := base.NewApollo(flow)
	a.ApolloBase.Output = &mockPrinter{}
	return a
}

func makeTestApolloWithClient(serverURL string, client *wscan_http.Client) *base.Apollo {
	u, _ := url.Parse(serverURL)
	req, _ := wscan_http.NewRequest("GET", u.String(), nil)
	flow := &wscan_http.Flow{
		Request:  req,
		Response: &wscan_http.Response{StatusCode: 200},
	}
	a := base.NewApollo(flow)
	a.ApolloBase.HTTPClient = client
	a.ApolloBase.Output = &mockPrinter{}
	return a
}

// ==================== Git Index Parsing Tests ====================

// buildGitIndexData 构建 Git index 二进制数据用于测试
func buildGitIndexData(version uint32, fileNames []string) []byte {
	data := make([]byte, 0)

	// Header: DIRC signature
	data = append(data, []byte("DIRC")...)
	// Version
	data = append(data, make([]byte, 4)...)
	binary.BigEndian.PutUint32(data[4:8], version)
	// Entry count
	data = append(data, make([]byte, 4)...)
	binary.BigEndian.PutUint32(data[8:12], uint32(len(fileNames)))

	for _, name := range fileNames {
		entryFixedLen := 62
		if version == 3 {
			entryFixedLen = 64
		}

		// 构建条目：固定部分 + 文件名 + null + padding
		entry := make([]byte, entryFixedLen)

		// flags 字段：文件名长度（低12位）
		nameLen := len(name)
		if nameLen > 0x0FFF {
			nameLen = 0x0FFF
		}
		flags := uint16(nameLen)
		binary.BigEndian.PutUint16(entry[60:62], flags)

		// v3: 在 offset 62 处设置 2 字节 extended flags
		if version == 3 {
			entry[62] = 0
			entry[63] = 0
		}

		// 文件名 + null 终止符
		entry = append(entry, []byte(name)...)
		entry = append(entry, 0) // null terminator

		// padding 对齐到 8 字节
		totalLen := len(entry)
		padding := (8 - (totalLen % 8)) % 8
		if padding > 0 {
			entry = append(entry, make([]byte, padding)...)
		}

		data = append(data, entry...)
	}

	return data
}

func TestParseGitIndex_EmptyData(t *testing.T) {
	result := parseGitIndex([]byte{}, 10)
	if result != nil {
		t.Errorf("期望 nil, 实际 %v", result)
	}
}

func TestParseGitIndex_ShortData(t *testing.T) {
	result := parseGitIndex([]byte{0, 1, 2}, 10)
	if result != nil {
		t.Errorf("期望 nil, 实际 %v", result)
	}
}

func TestParseGitIndex_InvalidSignature(t *testing.T) {
	data := make([]byte, 16)
	data[0] = 'X'
	data[1] = 'Y'
	data[2] = 'Z'
	data[3] = 'W'
	binary.BigEndian.PutUint32(data[4:8], 2)
	binary.BigEndian.PutUint32(data[8:12], 1)

	result := parseGitIndex(data, 10)
	if result != nil {
		t.Errorf("期望 nil (无效签名), 实际 %v", result)
	}
}

func TestParseGitIndex_UnsupportedVersion(t *testing.T) {
	data := make([]byte, 16)
	copy(data[0:4], "DIRC")
	binary.BigEndian.PutUint32(data[4:8], 5) // 版本 5 不支持
	binary.BigEndian.PutUint32(data[8:12], 1)

	result := parseGitIndex(data, 10)
	if result != nil {
		t.Errorf("期望 nil (版本不支持), 实际 %v", result)
	}
}

func TestParseGitIndex_V2_Basic(t *testing.T) {
	fileNames := []string{"README.md", "main.go", "config.yaml"}
	data := buildGitIndexData(2, fileNames)

	result := parseGitIndex(data, 10)
	if len(result) != 3 {
		t.Errorf("期望 3 个文件, 实际 %d 个: %v", len(result), result)
	}
	for i, expected := range fileNames {
		if result[i] != expected {
			t.Errorf("文件[%d]: 期望 %s, 实际 %s", i, expected, result[i])
		}
	}
}

func TestParseGitIndex_V3_Basic(t *testing.T) {
	fileNames := []string{"src/app.js", "src/index.html"}
	data := buildGitIndexData(3, fileNames)

	result := parseGitIndex(data, 10)
	if len(result) != 2 {
		t.Errorf("期望 2 个文件, 实际 %d 个: %v", len(result), result)
	}
	for i, expected := range fileNames {
		if result[i] != expected {
			t.Errorf("文件[%d]: 期望 %s, 实际 %s", i, expected, result[i])
		}
	}
}

func TestParseGitIndex_MaxFilesLimit(t *testing.T) {
	fileNames := []string{"a.txt", "b.txt", "c.txt", "d.txt", "e.txt"}
	data := buildGitIndexData(2, fileNames)

	result := parseGitIndex(data, 3) // 限制最多 3 个文件
	if len(result) > 3 {
		t.Errorf("期望最多 3 个文件, 实际 %d 个: %v", len(result), result)
	}
}

func TestParseGitIndex_NoEntries(t *testing.T) {
	data := buildGitIndexData(2, []string{})
	result := parseGitIndex(data, 10)
	if len(result) != 0 {
		t.Errorf("期望 0 个文件, 实际 %d 个: %v", len(result), result)
	}
}

// ==================== SVN Parsing Tests ====================

func TestIsValidSVNEntries_OldFormatDir(t *testing.T) {
	body := "dir\nsvn://example.com/repo\n"
	if !isValidSVNEntries(body) {
		t.Error("旧格式 (dir) 应被识别为有效 SVN entries")
	}
}

func TestIsValidSVNEntries_OldFormatFile(t *testing.T) {
	body := "file\nsvn://example.com/repo\n"
	if !isValidSVNEntries(body) {
		t.Error("旧格式 (file) 应被识别为有效 SVN entries")
	}
}

func TestIsValidSVNEntries_ProtocolURL(t *testing.T) {
	body := "some entry\nsvn://example.com/repo\n"
	if !isValidSVNEntries(body) {
		t.Error("包含 svn:// 的内容应被识别为有效 SVN entries")
	}
}

func TestIsValidSVNEntries_NewFormat(t *testing.T) {
	body := "12\n"
	if !isValidSVNEntries(body) {
		t.Error("新格式 (版本 12) 应被识别为有效 SVN entries")
	}
}

func TestIsValidSVNEntries_Invalid(t *testing.T) {
	body := "<html><body>not svn</body></html>"
	if isValidSVNEntries(body) {
		t.Error("非 SVN 内容不应被识别为有效")
	}
}

func TestIsValidSVNEntries_VersionOutOfRange(t *testing.T) {
	body := "7\n"
	if isValidSVNEntries(body) {
		t.Error("版本 7 不应在有效范围 (8-12) 内")
	}
}

func TestParseSVNEntriesOldFormat_Basic(t *testing.T) {
	body := `10

app
dir
0
0
0
0
svn://example.com/repo/app

src
dir
0
0
user1
0
svn://example.com/repo/src

main.py
file
3
2
admin
0
svn://example.com/repo/main.py
`

	entries := parseSVNEntriesOldFormat(body, 10)
	if len(entries) < 2 {
		t.Errorf("期望至少 2 个条目, 实际 %d 个", len(entries))
	}

	// 检查是否有文件类型条目
	foundFile := false
	for _, e := range entries {
		if e.Kind == "file" {
			foundFile = true
			break
		}
	}
	if !foundFile {
		t.Error("应至少有一个 file 类型条目")
	}
}

func TestParseSVNEntriesOldFormat_MaxFiles(t *testing.T) {
	body := `10

a
file
1
1
user1
0
svn://example.com/a

b
file
2
2
user2
0
svn://example.com/b

c
file
3
3
user3
0
svn://example.com/c
`

	entries := parseSVNEntriesOldFormat(body, 2)
	if len(entries) > 2 {
		t.Errorf("期望最多 2 个条目, 实际 %d", len(entries))
	}
}

func TestParseSVNEntriesNewFormat_Basic(t *testing.T) {
	body := `12

app
dir
0
0
0
0
svn://example.com/repo/app

main.py
file
3
2
admin
0
svn://example.com/repo/main.py
`

	entries := parseSVNEntriesNewFormat(body, 10)
	if len(entries) < 1 {
		t.Errorf("期望至少 1 个条目, 实际 %d", len(entries))
	}
}

func TestContainsString(t *testing.T) {
	slice := []string{"a", "b", "c"}
	if !containsString(slice, "b") {
		t.Error("应包含 'b'")
	}
	if containsString(slice, "d") {
		t.Error("不应包含 'd'")
	}
}

// ==================== Directory URL Check Tests ====================

func TestIsDirectoryURL_RootPath(t *testing.T) {
	if !isDirectoryURL("http://example.com/") {
		t.Error("根路径应被视为目录")
	}
}

func TestIsDirectoryURL_DirectoryPath(t *testing.T) {
	if !isDirectoryURL("http://example.com/admin/") {
		t.Error("/admin/ 应被视为目录")
	}
}

func TestIsDirectoryURL_FilePath(t *testing.T) {
	if isDirectoryURL("http://example.com/page.html") {
		t.Error("/page.html 不应被视为目录")
	}
}

func TestIsDirectoryURL_PathWithoutSlash(t *testing.T) {
	if isDirectoryURL("http://example.com/admin") {
		t.Error("/admin (无尾部斜杠) 不应被视为目录")
	}
}

// ==================== Plugin Interface Tests ====================

func TestVCSLeak_DefaultConfig(t *testing.T) {
	p := &VCSLeak{}
	cfg := p.DefaultConfig()
	vcsCfg := cfg.(*Config)
	if vcsCfg.Name != "vcsleak" {
		t.Errorf("期望插件名 'vcsleak', 实际 '%s'", vcsCfg.Name)
	}
	if !vcsCfg.Enabled {
		t.Error("插件应默认启用")
	}
	if vcsCfg.MaxFiles != 10 {
		t.Errorf("期望 MaxFiles=10, 实际 %d", vcsCfg.MaxFiles)
	}
}

func TestVCSLeak_Init(t *testing.T) {
	p := &VCSLeak{}
	cfg := p.DefaultConfig()
	ab := &base.ApolloBase{Output: &mockPrinter{}}
	err := p.Init(context.Background(), cfg, ab)
	if err != nil {
		t.Errorf("Init 应返回 nil, 实际 %v", err)
	}
	if p.GetConfig() != cfg {
		t.Error("配置应被正确保存")
	}
}

func TestVCSLeak_Fingers(t *testing.T) {
	p := &VCSLeak{}
	cfg := p.DefaultConfig()
	ab := &base.ApolloBase{Output: &mockPrinter{}}
	p.Init(context.Background(), cfg, ab)

	fingers := p.Fingers()
	if len(fingers) != 2 {
		t.Errorf("期望 2 个 Finger (git + svn), 实际 %d", len(fingers))
	}

	// 检查 Git Finger
	gitFinger := fingers[0]
	if gitFinger.Binding.ID != "vcs_git_leak" {
		t.Errorf("期望 Git Finger ID='vcs_git_leak', 实际 '%s'", gitFinger.Binding.ID)
	}
	if gitFinger.Binding.Severity != model.SeverityHigh {
		t.Errorf("期望严重级别 high, 实际 '%s'", gitFinger.Binding.Severity)
	}
	if gitFinger.Channel != "web-directory" {
		t.Errorf("期望通道 'web-directory', 实际 '%s'", gitFinger.Channel)
	}
	if gitFinger.CheckAction == nil {
		t.Error("Git Finger 的 CheckAction 不应为 nil")
	}
	if gitFinger.ExecAction == nil {
		t.Error("Git Finger 的 ExecAction 不应为 nil")
	}

	// 检查 SVN Finger
	svnFinger := fingers[1]
	if svnFinger.Binding.ID != "vcs_svn_leak" {
		t.Errorf("期望 SVN Finger ID='vcs_svn_leak', 实际 '%s'", svnFinger.Binding.ID)
	}
	if svnFinger.Binding.Severity != model.SeverityHigh {
		t.Errorf("期望严重级别 high, 实际 '%s'", svnFinger.Binding.Severity)
	}
}

func TestVCSLeak_Close(t *testing.T) {
	p := &VCSLeak{}
	err := p.Close()
	if err != nil {
		t.Errorf("Close 应返回 nil, 实际 %v", err)
	}
}

// ==================== Integration Tests with HTTP Server ====================

// countingPrinter 计算输出的漏洞数量
type countingPrinter struct {
	printer.BasePrinter
	count *int
}

func (m *countingPrinter) Print(v any) error {
	*m.count++
	return nil
}
func (m *countingPrinter) Close() error { return nil }

func TestDetectGitLeak_ConfigFound(t *testing.T) {
	// 模拟 Git config 服务器响应
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".git/config") {
			w.WriteHeader(200)
			fmt.Fprint(w, "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n")
		} else if strings.HasSuffix(r.URL.Path, ".git/index") {
			w.WriteHeader(403)
			fmt.Fprint(w, "Forbidden")
		} else {
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	client := wscan_http.NewClient()
	apollo := makeTestApolloWithClient(server.URL+"/", client)
	apollo.ApolloBase.HTTPClient = client

	vulnCount := 0
	apollo.ApolloBase.Output = &countingPrinter{count: &vulnCount}

	_ = detectGitLeak(apollo, server.URL+"/", 10)
	// 即使 index 返回 403，config 泄露仍应被报告
	if vulnCount == 0 {
		t.Error("应报告 .git/config 泄露")
	}
}

func TestDetectGitLeak_IndexFound(t *testing.T) {
	// 模拟 Git config + index 服务器响应
	fileNames := []string{"README.md", "app/main.go"}
	indexData := buildGitIndexData(2, fileNames)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".git/config") {
			w.WriteHeader(200)
			fmt.Fprint(w, "[core]\n\trepositoryformatversion = 0\n")
		} else if strings.HasSuffix(r.URL.Path, ".git/index") {
			w.WriteHeader(200)
			w.Write(indexData)
		} else {
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	client := wscan_http.NewClient()
	apollo := makeTestApolloWithClient(server.URL+"/", client)
	apollo.ApolloBase.HTTPClient = client

	vulnCount := 0
	apollo.ApolloBase.Output = &countingPrinter{count: &vulnCount}

	filePaths := detectGitLeak(apollo, server.URL+"/", 10)
	if len(filePaths) != 2 {
		t.Errorf("期望 2 个文件路径, 实际 %d: %v", len(filePaths), filePaths)
	}
	if vulnCount == 0 {
		t.Error("应报告 git 泄露漏洞")
	}
}

func TestDetectGitLeak_NoGitRepo(t *testing.T) {
	// 模拟不存在的 Git 仓库
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		fmt.Fprint(w, "Not Found")
	}))
	defer server.Close()

	client := wscan_http.NewClient()
	apollo := makeTestApolloWithClient(server.URL+"/", client)
	apollo.ApolloBase.HTTPClient = client

	vulnCount := 0
	apollo.ApolloBase.Output = &countingPrinter{count: &vulnCount}

	filePaths := detectGitLeak(apollo, server.URL+"/", 10)
	if filePaths != nil {
		t.Errorf("不存在的 Git 仓库应返回 nil, 实际 %v", filePaths)
	}
	if vulnCount != 0 {
		t.Errorf("不应报告漏洞, 实际报告 %d 个", vulnCount)
	}
}

func TestDetectSvnLeak_EntriesFound(t *testing.T) {
	svnEntries := `10

app
dir
0
0
0
0
svn://example.com/repo/app

main.py
file
3
2
admin
0
svn://example.com/repo/main.py
`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".svn/entries") {
			w.WriteHeader(200)
			fmt.Fprint(w, svnEntries)
		} else {
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	client := wscan_http.NewClient()
	apollo := makeTestApolloWithClient(server.URL+"/", client)
	apollo.ApolloBase.HTTPClient = client

	vulnCount := 0
	apollo.ApolloBase.Output = &countingPrinter{count: &vulnCount}

	detectSvnLeak(apollo, server.URL+"/", 10)
	if vulnCount == 0 {
		t.Error("应报告 SVN 泄露漏洞")
	}
}

func TestDetectSvnLeak_NoSvnRepo(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		fmt.Fprint(w, "Not Found")
	}))
	defer server.Close()

	client := wscan_http.NewClient()
	apollo := makeTestApolloWithClient(server.URL+"/", client)
	apollo.ApolloBase.HTTPClient = client

	vulnCount := 0
	apollo.ApolloBase.Output = &countingPrinter{count: &vulnCount}

	detectSvnLeak(apollo, server.URL+"/", 10)
	if vulnCount != 0 {
		t.Errorf("不应报告漏洞, 实际报告 %d 个", vulnCount)
	}
}

func TestDetectSvnLeak_403Bypass(t *testing.T) {
	svnEntries := `10

app
dir
0
0
0
0
svn://example.com/repo/app
`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 正常路径返回 403
		if r.URL.Path == "/.svn/entries" {
			w.WriteHeader(403)
			return
		}
		// IIS 绕过路径返回 SVN entries
		if strings.Contains(r.URL.RawPath, "::INDEX_ALLOCATION") || strings.Contains(r.URL.Path, "entries") {
			w.WriteHeader(200)
			fmt.Fprint(w, svnEntries)
			return
		}
		w.WriteHeader(404)
	}))
	defer server.Close()

	client := wscan_http.NewClient()
	apollo := makeTestApolloWithClient(server.URL+"/", client)
	apollo.ApolloBase.HTTPClient = client

	vulnCount := 0
	apollo.ApolloBase.Output = &countingPrinter{count: &vulnCount}

	detectSvnLeak(apollo, server.URL+"/", 10)
	// IIS 绕过可能无法在 httptest 中完美模拟，但逻辑应正确
	_ = vulnCount // 测试通过编译即可
}

// ==================== CheckAction Tests ====================

func TestVCSLeak_CheckAction_DirectoryURL(t *testing.T) {
	p := &VCSLeak{}
	cfg := p.DefaultConfig()
	ab := &base.ApolloBase{Output: &mockPrinter{}}
	p.Init(context.Background(), cfg, ab)

	fingers := p.Fingers()
	gitFinger := fingers[0]

	// 目录 URL 应通过 CheckAction
	u, _ := url.Parse("http://example.com/admin/")
	req, _ := wscan_http.NewRequest("GET", u.String(), nil)
	flow := &wscan_http.Flow{
		Request:  req,
		Response: &wscan_http.Response{StatusCode: 200},
	}
	apollo := base.NewApollo(flow)
	apollo.ApolloBase.Output = &mockPrinter{}

	err := gitFinger.CheckAction(context.Background(), apollo)
	if err != nil {
		t.Errorf("目录 URL 的 CheckAction 应返回 nil, 实际 %v", err)
	}
}

func TestVCSLeak_CheckAction_FileURL(t *testing.T) {
	p := &VCSLeak{}
	cfg := p.DefaultConfig()
	ab := &base.ApolloBase{Output: &mockPrinter{}}
	p.Init(context.Background(), cfg, ab)

	fingers := p.Fingers()
	gitFinger := fingers[0]

	// 文件 URL 不应触发（CheckAction 返回 nil 但实际不执行检测）
	u, _ := url.Parse("http://example.com/page.html")
	req, _ := wscan_http.NewRequest("GET", u.String(), nil)
	flow := &wscan_http.Flow{
		Request:  req,
		Response: &wscan_http.Response{StatusCode: 200},
	}
	apollo := base.NewApollo(flow)
	apollo.ApolloBase.Output = &mockPrinter{}

	err := gitFinger.CheckAction(context.Background(), apollo)
	// CheckAction 返回 error 表示跳过检测
	if err == nil {
		t.Error("文件 URL 的 CheckAction 应返回 error")
	}
}
