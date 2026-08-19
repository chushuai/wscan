package utils

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/fatih/color"
	logger "wscan/core/utils/log"
)

// VersionInfo 当前版本信息
var VersionInfo = "1.0.46"

// GitHubRelease GitHub Release API 响应结构
type GitHubRelease struct {
	TagName     string `json:"tag_name"`
	Name        string `json:"name"`
	PublishedAt string `json:"published_at"`
	HTMLURL     string `json:"html_url"`
	Body        string `json:"body"`
}

// CheckNewVersion 检查是否有新版本可用
func CheckNewVersion() {
	currentVersion := strings.TrimPrefix(VersionInfo, "v")
	
	// 设置超时
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	
	// 请求 GitHub Releases API
	resp, err := client.Get("https://api.github.com/repos/chushuai/wscan/releases/latest")
	if err != nil {
		logger.Debug("Failed to check for new version: " + err.Error())
		return
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		logger.Debug(fmt.Sprintf("GitHub API returned status: %d", resp.StatusCode))
		return
	}
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Debug("Failed to read response body: " + err.Error())
		return
	}
	
	var release GitHubRelease
	if err := json.Unmarshal(body, &release); err != nil {
		logger.Debug("Failed to parse release info: " + err.Error())
		return
	}
	
	latestVersion := strings.TrimPrefix(release.TagName, "v")
	
	// 比较版本号
	if compareVersions(latestVersion, currentVersion) > 0 {
		color.Yellow("\n⚠️  发现新版本可用!")
		color.Green("   当前版本: v%s", currentVersion)
		color.Green("   最新版本: v%s", latestVersion)
		color.Green("   发布时间: %s", release.PublishedAt)
		color.Cyan("   更新地址: %s\n", release.HTMLURL)
		color.Yellow("   建议运行: go install github.com/chushuai/wscan@latest 进行升级\n")
	} else {
		logger.Debug("当前已是最新版本: v" + currentVersion)
	}
}

// compareVersions 比较两个版本号，返回 -1, 0, 或 1
// 如果 v1 > v2 返回 1, v1 < v2 返回 -1, 相等返回 0
func compareVersions(v1, v2 string) int {
	parts1 := splitVersion(v1)
	parts2 := splitVersion(v2)
	
	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}
	
	for i := 0; i < maxLen; i++ {
		num1 := 0
		num2 := 0
		
		if i < len(parts1) {
			fmt.Sscanf(parts1[i], "%d", &num1)
		}
		if i < len(parts2) {
			fmt.Sscanf(parts2[i], "%d", &num2)
		}
		
		if num1 > num2 {
			return 1
		}
		if num1 < num2 {
			return -1
		}
	}
	
	return 0
}

// splitVersion 将版本号字符串分割为部分
func splitVersion(version string) []string {
	return strings.Split(version, ".")
}
