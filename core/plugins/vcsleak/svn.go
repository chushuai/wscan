/**
* @Author: shaochuyu
* @Date: 6/16/2026
 */
package vcsleak

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"

	"wscan/core/http"
	"wscan/core/plugins/base"
	logger "wscan/core/utils/log"
)

// svnEntry SVN 条目信息
type svnEntry struct {
	Name     string
	Kind     string // "dir" 或 "file"
	Revision string
	Author   string
	URL      string
}

// detectSvnLeak 检测 SVN 仓库泄露
func detectSvnLeak(apollo *base.Apollo, baseURL string, maxFiles int) {
	// 第一步：请求 .svn/entries
	entriesURL := http.UrlJoinPath(baseURL, ".svn/entries")
	entriesReq, entriesResp, err := doRequest(apollo, "GET", entriesURL)

	// 如果返回 403，尝试 IIS 绕过
	if err != nil || entriesResp.StatusCode == 403 {
		logger.Debug("vcsleak: .svn/entries 返回 403, 尝试 IIS 绕过")
		iisBypassURL := http.UrlJoinPath(baseURL, ".svn/entries::$INDEX_ALLOCATION")
		entriesReq, entriesResp, err = doRequest(apollo, "GET", iisBypassURL)
	}

	if err != nil {
		logger.Debugf("vcsleak: 请求 .svn/entries 失败: %v", err)
		return
	}

	if entriesResp.StatusCode != 200 {
		logger.Debugf("vcsleak: .svn/entries 状态码 %d, 跳过", entriesResp.StatusCode)
		return
	}

	// 验证内容是否是有效的 SVN entries 格式
	body := entriesResp.Text
	if !isValidSVNEntries(body) {
		logger.Debug("vcsleak: .svn/entries 内容不符合 SVN 格式, 可能是误报")
		return
	}

	logger.Info("vcsleak: 发现 .svn/entries 泄露")

	// 第二步：解析 SVN entries 格式
	entries := parseSVNEntries(body, maxFiles)

	// 第三步：报告泄露
	extra := map[string]any{
		"type": "svn_entries_leaks",
	}
	var fileNames []string
	var authors []string
	for _, entry := range entries {
		if entry.Kind == "file" {
			fileNames = append(fileNames, entry.Name)
		}
		if entry.Author != "" && !containsString(authors, entry.Author) {
			authors = append(authors, entry.Author)
		}
	}
	if len(fileNames) > 0 {
		extra["files"] = fileNames
	}
	if len(authors) > 0 {
		extra["authors"] = authors
	}

	makeVuln(apollo, entriesReq, entriesResp, "vcs_svn_leak", "vcs_svn_leak",
		".svn/entries", extra)

	// 第四步：将发现的文件路径添加到爬虫队列
	publishFlows(apollo, baseURL, fileNames)
}

// isValidSVNEntries 验证响应内容是否是有效的 SVN entries 格式
func isValidSVNEntries(body string) bool {
	// 旧格式：包含 "dir" 或 "file" 标记行
	if strings.Contains(body, "dir\n") || strings.Contains(body, "file\n") {
		return true
	}
	// 旧格式变体：包含 svn:// 或 http(s):// 协议行
	if strings.Contains(body, "svn://") || strings.Contains(body, "https://") ||
		strings.Contains(body, "http://") {
		return true
	}
	// 新格式（SVN 1.7+）：以版本号开头，如 "12\n" 或 "10\n"
	lines := strings.SplitN(body, "\n", 2)
	if len(lines) > 0 {
		firstLine := strings.TrimSpace(lines[0])
		version, err := strconv.Atoi(firstLine)
		if err == nil && version >= 8 && version <= 12 {
			return true
		}
	}
	return false
}

// parseSVNEntries 解析 SVN entries 文件内容
// 支持旧格式（SVN 1.6 及以下）和新格式（SVN 1.7+）
func parseSVNEntries(body string, maxFiles int) []svnEntry {
	// 判断是新格式还是旧格式
	firstLine := strings.SplitN(body, "\n", 2)[0]
	version, err := strconv.Atoi(strings.TrimSpace(firstLine))

	if err == nil && version >= 10 {
		// 新格式（XML-based 或 wc-2 格式）
		return parseSVNEntriesNewFormat(body, maxFiles)
	}

	// 旧格式
	return parseSVNEntriesOldFormat(body, maxFiles)
}

// parseSVNEntriesOldFormat 解析旧格式 SVN entries（SVN 1.6 及以下）
// 旧格式是多行文本，每个条目由多行字段组成：
//
//	<name>
//	<kind> (dir/file)
//	...
//	<revision>
//	...
//	<author>
//	...
//	<url>
//	...
//
// 每个条目之间由空行分隔
func parseSVNEntriesOldFormat(body string, maxFiles int) []svnEntry {
	var entries []svnEntry
	scanner := bufio.NewScanner(bytes.NewReader([]byte(body)))

	var currentEntry *svnEntry
	lineIndex := 0 // 当前条目内的行索引

	for scanner.Scan() {
		line := scanner.Text()

		if line == "" {
			// 空行表示条目结束
			if currentEntry != nil && currentEntry.Name != "" {
				entries = append(entries, *currentEntry)
				if len(entries) >= maxFiles {
					break
				}
			}
			currentEntry = nil
			lineIndex = 0
			continue
		}

		// 如果当前没有正在解析的条目，开始新条目
		if currentEntry == nil {
			// 跳过版本号行（第一行是版本号，如 "10"）
			if _, err := strconv.Atoi(line); err == nil && len(entries) == 0 {
				continue
			}
			currentEntry = &svnEntry{Name: line}
			lineIndex = 1
			continue
		}

		// 根据行索引解析字段（lineIndex 从 1 开始，因为名称已在创建条目时设置）
		switch lineIndex {
		case 1:
			currentEntry.Kind = line // "dir" 或 "file"
		case 3:
			currentEntry.Revision = line
		case 5:
			currentEntry.Author = line
		case 7:
			currentEntry.URL = line
		}

		lineIndex++
	}

	// 处理最后一个条目
	if currentEntry != nil && currentEntry.Name != "" && len(entries) < maxFiles {
		entries = append(entries, *currentEntry)
	}

	return entries
}

// parseSVNEntriesNewFormat 解析新格式 SVN entries（SVN 1.7+）
// 新格式使用 XML 或二进制格式，这里主要处理文本格式
func parseSVNEntriesNewFormat(body string, maxFiles int) []svnEntry {
	var entries []svnEntry
	scanner := bufio.NewScanner(bytes.NewReader([]byte(body)))

	var currentEntry *svnEntry
	lineIndex := 0
	firstLine := true

	for scanner.Scan() {
		line := scanner.Text()

		// 跳过第一行（版本号行，如 "12"）
		if firstLine {
			firstLine = false
			continue
		}

		if line == "" {
			if currentEntry != nil && currentEntry.Name != "" {
				entries = append(entries, *currentEntry)
				if len(entries) >= maxFiles {
					break
				}
			}
			currentEntry = nil
			lineIndex = 0
			continue
		}

		if currentEntry == nil {
			currentEntry = &svnEntry{}
			lineIndex = 0
		}

		switch lineIndex {
		case 0:
			currentEntry.Name = line
		case 1:
			currentEntry.Kind = line
		case 3:
			currentEntry.Revision = line
		case 5:
			currentEntry.Author = line
		case 7:
			currentEntry.URL = line
		}

		lineIndex++
	}

	if currentEntry != nil && currentEntry.Name != "" && len(entries) < maxFiles {
		entries = append(entries, *currentEntry)
	}

	return entries
}

// containsString 检查字符串切片是否包含指定字符串
func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}
