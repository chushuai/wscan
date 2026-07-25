/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package cmd_injection

import (
	"context"
	"html"
	"strings"
	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	logger "wscan/core/utils/log"
)

type CmdInjection struct {
	base.PluginMixinInitConfig
	base.PluginMixinClose
}

type Config struct {
	base.PluginBaseConfig `json:",inline" yaml:",inline"`
}

// BaseConfig 返回基本配置, 固定格式, 无需修改
func (c *Config) BaseConfig() *base.PluginBaseConfig {
	return &c.PluginBaseConfig
}

// Close 关闭函数
func (*CmdInjection) Close() error {
	return nil
}

// DefaultConfig 返回默认配置, 需要填写插件的默认配置
func (*CmdInjection) DefaultConfig() base.PluginConfigInterface {
	config := &Config{PluginBaseConfig: base.PluginBaseConfig{
		Name:    "cmd-injection",
		Enabled: true,
	}}
	return config
}

// Fingers 返回漏洞检测配置
func (p *CmdInjection) Fingers() []*base.Finger {
	fingers := []*base.Finger{}
	fingers = append(fingers, &base.Finger{
		CheckAction: p.execAction,
		Channel:     "web-generic",
		Binding:     &model.VulnBinding{ID: "cmd-injection", Plugin: "cmd-injection", Category: "cmd-injection", Severity: model.SeverityCritical},
	})
	return fingers
}

// GetConfig 获取配置
func (p *CmdInjection) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

// Init 插件初始化
func (p *CmdInjection) Init(ctx context.Context, pci base.PluginConfigInterface, ab *base.ApolloBase) error {
	logger.Debug("CmdInjection init")
	return p.PluginMixinInitConfig.Init(ctx, pci, ab)
}

// execAction 执行漏洞检测
// D1-06: 增加 baseline 比对，修复 context.TODO()
func (p *CmdInjection) execAction(ctx context.Context, ab *base.Apollo) error {
	flow := ab.GetTargetFlow()
	logger.Debugf("Start detecting CmdInjection vulnerability URL=%s", flow.Request.URL().String())

	// D1-06: 获取 baseline 响应，发送不含 payload 的原始请求
	baselineReq := flow.Request.DeepClone()
	baselineRes, baselineErr := ab.HTTPClient.Respond(ctx, baselineReq)

	for _, param := range flow.Request.ParamsAll() {
		if strings.ToLower(param.Key) == "submit" {
			continue
		}
		for _, sp := range GenCmdInjectionPayload() {
			parameter := http.Parameter{Position: param.Position, Key: param.Key}
			if sp.ParameterType == http.ParameterTypeValue {
				parameter.Value = sp.Payload
			} else if sp.ParameterType == http.ParameterTypePrefix {
				parameter.Prefix = sp.Payload
				parameter.Value = param.Value
			} else if sp.ParameterType == http.ParameterTypeSuffix {
				parameter.Value = param.Value
				parameter.Suffix = sp.Payload
			}
			req := flow.Request.Mutate(&parameter)
			// D1-06: 使用传入的 ctx 替代 context.TODO()
			res, err := ab.HTTPClient.Respond(ctx, req)
			if err != nil {
				logger.Error(err)
				continue
			}
			if strings.Contains(res.Text, sp.VerifyResult) {
				// Non-2xx/3xx responses (404, 500 etc.) with verifyResult are false positives -
				// the hash appears in server error pages that echo back the request URL
				if res.StatusCode < 200 || res.StatusCode >= 400 {
					continue
				}
				// baseline 比对 - 如果 baseline 响应中也包含验证结果，则判定为误报
				if baselineErr == nil && baselineRes != nil && strings.Contains(baselineRes.Text, sp.VerifyResult) {
					continue
				}
				// 反射误报检测 - 如果 payload 完整出现在响应 body 中，
				// 说明输入被原样回显，VerifyResult 的出现不是因为命令执行
				if isReflectedPayload(res.Text, sp.Payload, sp.VerifyResult) {
					continue
				}
				v := ab.NewWebVuln(req, res, &param)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = sp.Payload
					v.Param = &parameter
					// TODO(PostScan): Record reflection point for stored RCE verification.
					// After detecting command injection, record the reflection so the PostScan
					// phase can check for delayed OOB callbacks indicating stored RCE:
					//   ab.ApolloBase.RecordReflection(&base.ReflectionRecord{
					//       URL:          flow.Request.URL().String(),
					//       Method:       flow.Request.Method,
					//       Parameter:    param.Key,
					//       Payload:      sp.Payload,
					//       PluginName:   "cmd-injection",
					//       VulnType:     "cmdi",
					//       Timestamp:    time.Now(),
					//       ReverseToken: "", // set if using OOB payload
					//   })
					ab.OutputVuln(v)
					break
				}
			}
		}
	}

	return nil
}

// isReflectedPayload checks if VerifyResult appears in the body only because the payload was reflected back
func isReflectedPayload(body string, payload string, verifyResult string) bool {
	// If the full payload string appears in the body, the server is echoing back the input
	if strings.Contains(body, payload) {
		return true
	}
	// HTML entity decoding: "&&" may appear as "&amp;&amp;" in the response
	decodedBody := html.UnescapeString(body)
	if strings.Contains(decodedBody, payload) {
		return true
	}
	// Check if verifyResult appears inside a reflected context in the decoded body
	if strings.Contains(payload, verifyResult) && strings.Contains(decodedBody, payload) {
		return true
	}
	// Check if all occurrences of verifyResult in the body are within reflected payload context
	if strings.Contains(payload, verifyResult) {
		verifyIdx := 0
		reflectedCount := 0
		for {
			idx := strings.Index(decodedBody[verifyIdx:], verifyResult)
			if idx < 0 {
				break
			}
			absIdx := verifyIdx + idx
			start := absIdx - len(payload)
			if start < 0 {
				start = 0
			}
			end := absIdx + len(verifyResult) + len(payload)
			if end > len(decodedBody) {
				end = len(decodedBody)
			}
			surrounding := decodedBody[start:end]
			if strings.Contains(surrounding, payload) {
				reflectedCount++
			}
			verifyIdx = absIdx + 1
		}
		totalCount := strings.Count(decodedBody, verifyResult)
		if totalCount > 0 && reflectedCount == totalCount {
			return true
		}
	}
	return false
}
