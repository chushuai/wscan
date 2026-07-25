/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package redirect

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/utils"
	logger "wscan/core/utils/log"
)

type Config struct {
	base.PluginBaseConfig `json:",inline" yaml:",inline"`
}

// BaseConfig 返回基本配置, 固定格式, 无需修改
func (c *Config) BaseConfig() *base.PluginBaseConfig {
	return &c.PluginBaseConfig
}

type WebVulnPlugin struct {
	base.PluginMixinInitConfig
	base.PluginMixinClose
}

type Redirect struct {
	base.PluginMixinInitConfig
	base.PluginMixinClose
}

// Close 关闭函数
func (*Redirect) Close() error {
	return nil
}

// DefaultConfig 返回默认配置, 需要填写插件的默认配置
func (*Redirect) DefaultConfig() base.PluginConfigInterface {
	config := &Config{PluginBaseConfig: base.PluginBaseConfig{
		Name:    "redirect",
		Enabled: true,
	}}
	return config
}

// Fingers 返回漏洞检测配置
func (p *Redirect) Fingers() []*base.Finger {
	fingers := []*base.Finger{}
	fingers = append(fingers, &base.Finger{
		CheckAction: p.execAction,
		Channel:     "web-generic",
		Binding:     &model.VulnBinding{ID: "redirect/redirect/default", Plugin: "redirect/redirect/default", Category: "redirect/redirect/default", Severity: model.SeverityMedium},
	})
	return fingers
}

// GetConfig 获取配置
func (p *Redirect) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

// Init 插件初始化
func (p *Redirect) Init(ctx context.Context, pci base.PluginConfigInterface, ab *base.ApolloBase) error {
	logger.Debug("Redirect init")
	return p.PluginMixinInitConfig.Init(ctx, pci, ab)
}

// D1-18: 扩展 payload 列表 + 修正格式 + 修复 context.TODO()
// 扩展开放重定向 payload，修正非法 URL 格式
// 增加 URL 解析验证 Location 指向的 host
func (p *Redirect) execAction(ctx context.Context, ab *base.Apollo) error {
	flow := ab.GetTargetFlow()
	logger.Debugf("Start detection Redirect漏洞, URL=%s", flow.Request.URL().String())

	// D1-18: 大幅扩展 payload 列表
	randomDomain := fmt.Sprintf("%s.com", utils.RandLetters(6))
	randomInt := utils.RandInt(10000000, 100000000)
	payloads := []struct {
		Value   string
		IsValue bool // true = 替换参数值, false = 追加到参数值
	}{
		// 基本域名 payload（修正原 https:12345678 格式）
		{Value: randomDomain, IsValue: true},
		{Value: fmt.Sprintf("https://evil%s.com", utils.RandLetters(4)), IsValue: true},
		// 协议绕过
		{Value: fmt.Sprintf("//%s", randomDomain), IsValue: true},
		{Value: fmt.Sprintf("https:////%s", randomDomain), IsValue: true},
		// 路径绕过
		{Value: fmt.Sprintf("/\\%s", randomDomain), IsValue: true},
		{Value: fmt.Sprintf("/%s/", randomDomain), IsValue: true},
		// URL 解析差异绕过
		{Value: fmt.Sprintf("https://trusted.com@%s", randomDomain), IsValue: true},
		{Value: fmt.Sprintf("https://%s.trusted.com", utils.RandLetters(4)), IsValue: true},
		// 数字 IP 绕过
		{Value: fmt.Sprintf("https://%d.example.com", randomInt), IsValue: true},
		// 回车换行绕过
		{Value: fmt.Sprintf("https://%s\r\n", randomDomain), IsValue: true},
		{Value: fmt.Sprintf("https://%s\t", randomDomain), IsValue: true},
	}

	// 遍历url和body中的参数
	for _, param := range flow.Request.ParamsAll() {
		// D1-18: 扩展检测范围，不仅限于以 http 开头的参数值
		// 也包括可能包含 URL 的参数（如 redirect, url, next 等）
		if !isPotentialRedirectParam(param) {
			continue
		}
		for _, p := range payloads {
			var req *http.Request
			if p.IsValue {
				req = flow.Request.Mutate(&http.Parameter{Position: param.Position, Key: param.Key, Value: p.Value})
			} else {
				req = flow.Request.Mutate(&http.Parameter{Position: param.Position, Key: param.Key, Value: param.Value, Suffix: p.Value})
			}
			// D1-18: 使用 ctx 替代 context.TODO()
			res, err := ab.HTTPClient.Respond(ctx, req)
			if err == nil {
				if res.StatusCode > 300 && res.StatusCode < 400 {
					location := res.GetHeader(http.LOCATION)
					if location != "" && isRedirectToPayload(location, p.Value) {
						v := ab.NewWebVuln(req, res, &param)
						if v != nil {
							v.SetTargetURL(flow.Request.URL())
							v.Payload = p.Value
							ab.OutputVuln(v)
							break
						}
					}

				}
			}
		}
	}
	return nil
}

// isPotentialRedirectParam 判断参数是否可能是重定向参数
// D1-18: 扩展检测范围，不仅限于以 http 开头的参数值
func isPotentialRedirectParam(param http.Parameter) bool {
	// 参数值以 http 开头（原有逻辑）
	if strings.HasPrefix(param.Value, "http") {
		return true
	}
	// 参数值以 // 开头（协议相对 URL）
	if strings.HasPrefix(param.Value, "//") {
		return true
	}
	// 参数值以 / 开头且看起来像路径（可能被服务端用于重定向）
	if strings.HasPrefix(param.Value, "/") && len(param.Value) > 1 {
		return true
	}
	// 参数名包含重定向相关关键字
	paramNameLower := strings.ToLower(param.Key)
	redirectKeywords := []string{"url", "redirect", "redir", "return", "next", "goto", "link", "target", "destination", "continue", "forward"}
	for _, kw := range redirectKeywords {
		if strings.Contains(paramNameLower, kw) {
			return true
		}
	}
	return false
}

// isRedirectToPayload 验证 Location 头是否真正重定向到 payload 中的目标
// D1-18: 使用 URL 解析验证 Location 指向的 host 是否与 payload 匹配
// 替代简单的 strings.Contains 检查
func isRedirectToPayload(location, payload string) bool {
	// 先尝试 strings.Contains 作为快速检查
	if strings.Contains(location, payload) {
		return true
	}

	// 尝试 URL 解析验证 host
	locURL, err := url.Parse(location)
	if err != nil {
		// URL 解析失败，回退到 contains 检查
		return strings.Contains(location, payload)
	}

	// 检查 payload 是否与 Location 的 host 部分匹配
	payloadURL, err := url.Parse(payload)
	if err != nil {
		return strings.Contains(location, payload)
	}

	if payloadURL.Host != "" {
		return locURL.Host == payloadURL.Host || strings.HasSuffix(locURL.Host, payloadURL.Host)
	}

	// 如果 payload 不是完整 URL，检查是否作为 host 出现
	return strings.Contains(locURL.Host, payload) || strings.Contains(locURL.String(), payload)
}
