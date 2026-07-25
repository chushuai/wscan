/**
* @Author: shaochuyu
* @Date: 6/16/2026
 */
package vcsleak

import (
	"encoding/binary"
	"strings"

	"wscan/core/http"
	"wscan/core/plugins/base"
	logger "wscan/core/utils/log"
)

// gitIndexHeader Git index 文件头
type gitIndexHeader struct {
	Signature  [4]byte // "DIRC"
	Version    uint32
	EntryCount uint32
}

// detectGitLeak 检测 Git 仓库泄露
// 返回从 .git/index 中提取的文件路径列表
func detectGitLeak(apollo *base.Apollo, baseURL string, maxFiles int) []string {
	// 第一步：请求 .git/config，验证是否包含 repositoryformatversion
	configURL := http.UrlJoinPath(baseURL, ".git/config")
	configReq, configResp, err := doRequest(apollo, "GET", configURL)
	if err != nil {
		logger.Debugf("vcsleak: 请求 .git/config 失败: %v", err)
		return nil
	}

	// 检查状态码和内容特征
	if configResp.StatusCode != 200 {
		logger.Debugf("vcsleak: .git/config 状态码 %d, 跳过", configResp.StatusCode)
		return nil
	}

	if !strings.Contains(configResp.Text, "repositoryformatversion") {
		logger.Debug("vcsleak: .git/config 未包含 repositoryformatversion, 可能是误报")
		return nil
	}

	logger.Info("vcsleak: 发现 .git/config 泄露")

	// 第二步：请求 .git/index 获取索引文件
	indexURL := http.UrlJoinPath(baseURL, ".git/index")
	indexReq, indexResp, err := doRequest(apollo, "GET", indexURL)

	// 如果 .git/index 返回 403，尝试 IIS 绕过
	if err != nil || indexResp.StatusCode == 403 {
		logger.Debug("vcsleak: .git/index 返回 403, 尝试 IIS 绕过")
		iisBypassURL := http.UrlJoinPath(baseURL, ".git::$INDEX_ALLOCATION/index")
		indexReq, indexResp, err = doRequest(apollo, "GET", iisBypassURL)
	}

	if err != nil {
		logger.Debugf("vcsleak: 请求 .git/index 失败: %v", err)
		// 即使无法获取 index，仍然报告 .git/config 泄露
		makeVuln(apollo, configReq, configResp, "vcs_git_leak", "vcs_git_leak",
			".git/config", map[string]any{
				"type": "git_config_leak",
			})
		return nil
	}

	if indexResp.StatusCode != 200 {
		logger.Debugf("vcsleak: .git/index 状态码 %d", indexResp.StatusCode)
		// 报告 .git/config 泄露（即使 index 不可用）
		makeVuln(apollo, configReq, configResp, "vcs_git_leak", "vcs_git_leak",
			".git/config", map[string]any{
				"type": "git_config_leaks",
			})
		return nil
	}

	// 第三步：解析 .git/index 二进制格式，提取文件名
	filePaths := parseGitIndex(indexResp.GetRawBody(), maxFiles)

	// 第四步：报告泄露
	extra := map[string]any{
		"type": "git_index_leaks",
	}
	if len(filePaths) > 0 {
		extra["files"] = filePaths
	}

	makeVuln(apollo, indexReq, indexResp, "vcs_git_leak", "vcs_git_leak",
		".git/index", extra)

	return filePaths
}

// parseGitIndex 解析 Git index 文件的二进制格式
// 提取文件名列表，最多返回 maxFiles 个
func parseGitIndex(data []byte, maxFiles int) []string {
	if len(data) < 12 {
		logger.Debugf("vcsleak: .git/index 数据太短 (%d 字节)", len(data))
		return nil
	}

	// 检查签名 "DIRC"
	if string(data[0:4]) != "DIRC" {
		logger.Debug("vcsleak: .git/index 签名不是 DIRC, 可能不是有效的 index 文件")
		return nil
	}

	// 读取版本号
	version := binary.BigEndian.Uint32(data[4:8])
	if version != 2 && version != 3 {
		logger.Debugf("vcsleak: .git/index 版本 %d 不支持 (仅支持 v2/v3)", version)
		return nil
	}

	// 读取条目数
	entryCount := binary.BigEndian.Uint32(data[8:12])
	logger.Infof("vcsleak: .git/index 版本 %d, 条目数 %d", version, entryCount)

	var filePaths []string
	offset := 12 // 跳过 12 字节的头部

	for i := uint32(0); i < entryCount && offset < len(data); i++ {
		// 每个条目的固定部分长度：
		// v2: 62 字节 (ctime*2 + mtime*2 + dev + ino + mode + uid + gid + size + sha1 + flags = 4*2+4*2+4+4+4+4+4+4+20+2 = 62)
		// v3: 64 字节 (v2 + 2 字节 extended flags)
		entryFixedLen := 62
		if version == 3 {
			entryFixedLen = 64
		}

		if offset+entryFixedLen > len(data) {
			logger.Debugf("vcsleak: 解析条目 %d 时数据不足", i)
			break
		}

		// 读取 flags 字段（在固定部分的最后 2 字节）
		// v2: flags 在 offset+60, v3: flags 在 offset+60（之后还有 2 字节 extended flags）
		flags := binary.BigEndian.Uint16(data[offset+60 : offset+62])

		// 文件名长度：flags 的低 12 位，如果全为 1 则名称长度未知
		nameLen := int(flags & 0x0FFF)
		if nameLen == 0x0FFF {
			// 名称长度未知，需要查找 null 终止符
			nameLen = 0
		}

		nameOffset := offset + entryFixedLen

		if nameLen > 0 {
			// 已知名称长度
			if nameOffset+nameLen > len(data) {
				logger.Debugf("vcsleak: 条目 %d 名称超出数据范围", i)
				break
			}
			name := string(data[nameOffset : nameOffset+nameLen])
			filePaths = append(filePaths, name)
		} else {
			// 名称长度未知，查找 null 终止符
			end := nameOffset
			maxEnd := len(data)
			if maxEnd > nameOffset+4096 {
				maxEnd = nameOffset + 4096 // 文件名最大长度限制
			}
			for end < maxEnd && data[end] != 0 {
				end++
			}
			if end >= maxEnd {
				logger.Debugf("vcsleak: 条目 %d 名称过长或无 null 终止符", i)
				break
			}
			name := string(data[nameOffset:end])
			filePaths = append(filePaths, name)
			nameLen = end - nameOffset
		}

		// 计算下一个条目的偏移量
		// 条目总长度 = fixedLen + nameLen + padding (对齐到 8 字节)
		entryLen := entryFixedLen + nameLen
		// 加上 1 字节的 null 终止符
		entryLen++
		// 对齐到 8 字节边界
		padding := (8 - (entryLen % 8)) % 8
		entryLen += padding

		offset += entryLen

		// 限制报告的文件数量
		if len(filePaths) >= maxFiles {
			break
		}
	}

	return filePaths
}
