/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package upload

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	logger "wscan/core/utils/log"

	"golang.org/x/net/context"
)

type Config struct {
	base.PluginBaseConfig `json:",inline" yaml:",inline"`
}

func (c *Config) BaseConfig() *base.PluginBaseConfig {
	return &c.PluginBaseConfig
}

type Upload struct {
	base.PluginMixinInitConfig
	base.PluginMixinClose
}

func (*Upload) Close() error {
	return nil
}

func (*Upload) DefaultConfig() base.PluginConfigInterface {
	config := &Config{PluginBaseConfig: base.PluginBaseConfig{
		Name:    "upload",
		Enabled: true,
	}}
	return config
}

// commonUploadPaths 扩展的常见上传路径列表
var commonUploadPaths = []string{
	"/upload/",
	"/uploads/",
	//"/upload/images/",
	//"/upload/files/",
	//"/upload/img/",
	//"/static/upload/",
	//"/static/uploads/",
	//"/static/files/",
	//"/public/upload/",
	//"/public/uploads/",
	//"/files/",
	//"/attachments/",
	//"/media/upload/",
	//"/media/uploads/",
	//"/userfiles/",
	//"/uploadfile/",
	//"/uploadfiles/",
	//"/upfiles/",
	//"/assets/upload/",
	//"/img/upload/",
	//"/data/upload/",
	//"/admin/upload/",
}

// extractPathsFromResponse 从上传响应中提取可能的文件路径
func extractPathsFromResponse(res *http.Response, filename string) []string {
	var paths []string
	body := res.Text

	// 尝试从JSON响应中提取路径
	var jsonResp map[string]any
	if err := json.Unmarshal([]byte(body), &jsonResp); err == nil {
		// 常见JSON字段: url, path, file_path, file_url, data.url, data.path, src, link, file
		jsonPathKeys := []string{"url", "path", "file_path", "file_url", "src", "link", "file", "filepath", "fileUrl", "filePath"}
		for _, key := range jsonPathKeys {
			if val, ok := jsonResp[key]; ok {
				if strVal, ok := val.(string); ok && strVal != "" {
					paths = append(paths, strVal)
				}
			}
		}
		// 嵌套在 data 字段中
		if data, ok := jsonResp["data"]; ok {
			if dataMap, ok := data.(map[string]any); ok {
				for _, key := range jsonPathKeys {
					if val, ok := dataMap[key]; ok {
						if strVal, ok := val.(string); ok && strVal != "" {
							paths = append(paths, strVal)
						}
					}
				}
			}
		}
	}

	// 使用正则从HTML/文本响应中提取路径
	pathPatterns := []*regexp.Regexp{
		// 匹配包含文件名的路径
		regexp.MustCompile(`(?:href|src|action|url)\s*[=:]\s*["']([^"']*` + regexp.QuoteMeta(filename) + `[^"']*)["']`),
		// 匹配JSON中的路径值
		regexp.MustCompile(`"(?:url|path|file_path|file_url|src|link)"\s*:\s*"([^"]*` + regexp.QuoteMeta(filename) + `[^"]*)"`),
		// 匹配直接包含文件名的URL
		regexp.MustCompile(`(\/[^\s"'<>]*` + regexp.QuoteMeta(filename) + `[^\s"'<>]*)`),
	}
	for _, pattern := range pathPatterns {
		matches := pattern.FindAllStringSubmatch(body, -1)
		for _, match := range matches {
			if len(match) > 1 && match[1] != "" {
				paths = append(paths, match[1])
			}
		}
	}

	return paths
}

// resolveUploadPaths 根据请求URL和响应生成所有可能的验证路径
func resolveUploadPaths(baseURL *url.URL, res *http.Response, filename string) []string {
	var allPaths []string
	seen := make(map[string]bool)

	addPath := func(path string) {
		// 处理绝对URL
		if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
			if !seen[path] {
				seen[path] = true
				allPaths = append(allPaths, path)
			}
			return
		}
		// 处理以/开头的路径
		if strings.HasPrefix(path, "/") {
			fullURL := fmt.Sprintf("%s://%s%s", baseURL.Scheme, baseURL.Host, path)
			if !seen[fullURL] {
				seen[fullURL] = true
				allPaths = append(allPaths, fullURL)
			}
			return
		}
		// 相对路径：基于请求路径的目录拼接
		reqDir := baseURL.Path
		if idx := strings.LastIndex(reqDir, "/"); idx >= 0 {
			reqDir = reqDir[:idx+1]
		}
		fullURL := fmt.Sprintf("%s://%s%s%s", baseURL.Scheme, baseURL.Host, reqDir, path)
		if !seen[fullURL] {
			seen[fullURL] = true
			allPaths = append(allPaths, fullURL)
		}
	}

	// 优先从响应体中提取路径（最可靠）
	if res != nil {
		responsePaths := extractPathsFromResponse(res, filename)
		for _, p := range responsePaths {
			addPath(p)
		}
	}

	// 从请求URL路径中提取可能的目录
	reqPath := baseURL.Path
	if idx := strings.LastIndex(reqPath, "/"); idx >= 0 {
		reqDir := reqPath[:idx+1]
		// 基于请求路径构造验证URL
		addPath(reqDir + filename)
	}

	// 硬编码的常见路径作为兜底
	for _, path := range commonUploadPaths {
		uploadURL, err := baseURL.Parse(fmt.Sprintf("%s%s", path, filename))
		if err != nil {
			continue
		}
		if !seen[uploadURL.String()] {
			seen[uploadURL.String()] = true
			allPaths = append(allPaths, uploadURL.String())
		}
	}

	return allPaths
}

// isUploadSuccessStatus 判断HTTP状态码是否可能表示上传成功
func isUploadSuccessStatus(statusCode int) bool {
	return statusCode == 200 || statusCode == 201 || statusCode == 202 || statusCode == 204 || statusCode == 301 || statusCode == 302
}

// cleanupWebshell attempts to delete an uploaded webshell file
func cleanupWebshell(ctx context.Context, httpClient *http.Client, checkURL string) {
	// Try DELETE method
	delReq, err := http.NewRequest("DELETE", checkURL, nil)
	if err == nil {
		httpClient.Respond(ctx, delReq)
	}
	logger.Debugf("Cleanup: attempted to remove webshell at %s", checkURL)
}

func (*Upload) Fingers() []*base.Finger {
	fingers := []*base.Finger{}
	fingers = append(fingers, &base.Finger{
		CheckAction: func(ctx context.Context, bi *base.Apollo) error {
			flow := bi.GetTargetFlow()
			if !strings.Contains(flow.Request.ContentType(), "multipart/form-data") {
				return nil
			}
			logger.Debugf("Start detecting Upload vulnerability %s", flow.Request.URL().String())
			for _, param := range flow.Request.ParamsQueryAndBody() {
				if param.Filename == "" {
					continue
				}
				for _, wb := range GenerateWebshells() {
					for _, nameForUpload := range wb.NamesForUpload {
						parameter := &http.Parameter{Position: param.Position,
							Key: param.Key, Prefix: "", Value: string(wb.Content),
							Content: wb.Content,
							Suffix:  "", Filename: nameForUpload}
						req := flow.Request.Mutate(parameter)
						res, err := bi.HTTPClient.Respond(ctx, req)
						if err != nil {
							continue
						}
						if !isUploadSuccessStatus(res.StatusCode) {
							continue
						}
						// 使用智能路径解析，优先从响应体提取路径
						uploadPaths := resolveUploadPaths(flow.Request.URL(), res, nameForUpload)
						for _, checkURL := range uploadPaths {
							logger.Debugf("Check Upload webshell %s", checkURL)
							uploadReq, err := http.NewRequest("GET", checkURL, nil)
							if err != nil {
								logger.Error(err)
								continue
							}
							uploadRes, err := bi.HTTPClient.Respond(ctx, uploadReq)
							if err != nil {
								continue
							}
							if wb.CheckPattern.MatchString(uploadRes.Text) {
								v := bi.NewWebVuln(req, res, &param)
								if v != nil {
									v.SetTargetURL(flow.Request.URL())
									v.Payload = checkURL
									v.Param = parameter
									// Add cleanup path info for manual cleanup
									v.Extra["cleanup_path"] = checkURL
									bi.OutputVuln(v)
								}
								// Attempt to clean up the uploaded webshell
								cleanupWebshell(ctx, bi.HTTPClient, checkURL)
								return nil
							}
						}

					}

				}
			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{ID: "upload/upload/default", Plugin: "upload/upload/default", Category: "upload", Severity: model.SeverityHigh},
	})
	return fingers
}

func (p *Upload) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

func (p *Upload) Init(ctx context.Context, pci base.PluginConfigInterface, ab *base.ApolloBase) error {
	logger.Debug("upload init")
	return p.PluginMixinInitConfig.Init(ctx, pci, ab)
}

func (*Upload) execAction(context.Context, *base.Apollo) error {

	return nil
}
