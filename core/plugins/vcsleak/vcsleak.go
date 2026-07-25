/**
* @Author: shaochuyu
* @Date: 6/16/2026
 */
package vcsleak

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	logger "wscan/core/utils/log"
)

// Config VCS 泄露检测插件配置
type Config struct {
	base.PluginBaseConfig `json:",inline" yaml:",inline"`
	MaxFiles              int `json:"max_files" yaml:"max_files" #:"最大报告文件数"`
}

func (c *Config) BaseConfig() *base.PluginBaseConfig {
	return &c.PluginBaseConfig
}

// VCSLeak VCS（版本控制系统）泄露检测插件
type VCSLeak struct {
	base.PluginMixinInitConfig
	base.PluginMixinClose
}

func (*VCSLeak) Close() error { return nil }

func (*VCSLeak) DefaultConfig() base.PluginConfigInterface {
	return &Config{
		PluginBaseConfig: base.PluginBaseConfig{Name: "vcsleak", Enabled: true},
		MaxFiles:         10,
	}
}

func (p *VCSLeak) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

func (p *VCSLeak) Init(ctx context.Context, pci base.PluginConfigInterface, ab *base.ApolloBase) error {
	logger.Debug("VCSLeak 插件初始化")
	return p.PluginMixinInitConfig.Init(ctx, pci, ab)
}

// isDirectoryURL 检查当前 URL 是否是目录路径（以 / 结尾）
func isDirectoryURL(urlStr string) bool {
	u, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	path := u.Path
	// 根路径或以 / 结尾的路径视为目录
	return path == "/" || strings.HasSuffix(path, "/")
}

// makeVuln 创建并输出漏洞
func makeVuln(apollo *base.Apollo, req *http.Request, resp *http.Response, vulnID, category, payload string, extra map[string]any) {
	v := apollo.NewWebVuln(req, resp, nil)
	if v == nil {
		return
	}
	v.SetTargetURL(req.URL())
	v.Payload = payload
	if extra != nil {
		for k, val := range extra {
			v.Extra[k] = val
		}
	}
	apollo.OutputVuln(v)
}

// doRequest 发送 HTTP 请求的辅助函数
func doRequest(apollo *base.Apollo, method, rawURL string) (*http.Request, *http.Response, error) {
	req, err := http.NewRequest(method, rawURL, nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := apollo.HTTPClient.Respond(context.Background(), req)
	if err != nil {
		return nil, nil, err
	}
	return req, resp, nil
}

// publishFlows 将发现的文件路径添加到爬虫队列
func publishFlows(apollo *base.Apollo, baseURL string, filePaths []string) {
	for _, filePath := range filePaths {
		rawURL := http.UrlJoinPath(baseURL, filePath)
		req, err := http.NewRequest("GET", rawURL, nil)
		if err != nil {
			continue
		}
		capturedReq := req
		err = apollo.SubmitTask(base.AsyncTask{
			Name: "vcsleak:republish:" + filePath,
			Fn: func() {
				resp, err := apollo.HTTPClient.Respond(context.Background(), capturedReq)
				if err != nil {
					return
				}
				if apollo.PublishFlow != nil {
					apollo.PublishFlow(&http.Flow{Request: capturedReq, Response: resp})
				}
			},
		})
		if err != nil {
			logger.Debugf("vcsleak: 提交 republish 任务失败 %s: %v", filePath, err)
		}
	}
}

func (p *VCSLeak) Fingers() []*base.Finger {
	return []*base.Finger{
		// Git 泄露检测
		{
			Channel: "web-directory",
			Binding: &model.VulnBinding{
				ID:       "vcs_git_leak",
				Plugin:   "vcsleak",
				Category: "vcs_git_leak",
				Severity: model.SeverityHigh,
			},
			CheckAction: func(ctx context.Context, apollo *base.Apollo) error {
				flow := apollo.GetTargetFlow()
				if flow == nil || flow.Request == nil {
					return fmt.Errorf("no flow available")
				}
				// 只在目录 URL 上触发
				if !isDirectoryURL(flow.Request.URL().String()) {
					return fmt.Errorf("not a directory URL")
				}
				return nil
			},
			ExecAction: func(ctx context.Context, apollo *base.Apollo) error {
				flow := apollo.GetTargetFlow()
				if flow == nil || flow.Request == nil {
					return nil
				}
				baseURL := flow.Request.URL().String()
				maxFiles := p.GetConfig().(*Config).MaxFiles

				filePaths := detectGitLeak(apollo, baseURL, maxFiles)
				if len(filePaths) > 0 {
					publishFlows(apollo, baseURL, filePaths)
				}
				return nil
			},
		},
		// SVN 泄露检测
		{
			Channel: "web-directory",
			Binding: &model.VulnBinding{
				ID:       "vcs_svn_leak",
				Plugin:   "vcsleak",
				Category: "vcs_svn_leak",
				Severity: model.SeverityHigh,
			},
			CheckAction: func(ctx context.Context, apollo *base.Apollo) error {
				flow := apollo.GetTargetFlow()
				if flow == nil || flow.Request == nil {
					return fmt.Errorf("no flow available")
				}
				// 只在目录 URL 上触发
				if !isDirectoryURL(flow.Request.URL().String()) {
					return fmt.Errorf("not a directory URL")
				}
				return nil
			},
			ExecAction: func(ctx context.Context, apollo *base.Apollo) error {
				flow := apollo.GetTargetFlow()
				if flow == nil || flow.Request == nil {
					return nil
				}
				baseURL := flow.Request.URL().String()
				maxFiles := p.GetConfig().(*Config).MaxFiles

				detectSvnLeak(apollo, baseURL, maxFiles)
				return nil
			},
		},
	}
}
