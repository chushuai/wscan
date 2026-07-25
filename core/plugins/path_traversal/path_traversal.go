/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package path_traversal

import (
	"context"
	"strings"
	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	logger "wscan/core/utils/log"
)

type Config struct {
	base.PluginBaseConfig `json:",inline" yaml:",inline"`
}

func (c *Config) BaseConfig() *base.PluginBaseConfig {
	return &c.PluginBaseConfig
}

type PathTraversal struct {
	base.PluginMixinInitConfig
	base.PluginMixinClose
}

func (*PathTraversal) Close() error {
	return nil
}

func (*PathTraversal) DefaultConfig() base.PluginConfigInterface {
	return &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "path_traversal",
			Enabled: true,
		},
	}
}

func (p *PathTraversal) Fingers() []*base.Finger {
	fingers := []*base.Finger{}
	fingers = append(fingers, &base.Finger{
		CheckAction: p.execAction,
		Channel:     "web-generic",
		Binding:     &model.VulnBinding{ID: "path-traversal/path-traversal/default", Plugin: "path-traversal/path-traversal", Category: "path-traversal", Severity: model.SeverityMedium},
	})
	return fingers
}

func (p *PathTraversal) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

func (p *PathTraversal) Init(ctx context.Context, pci base.PluginConfigInterface, bb *base.ApolloBase) error {
	logger.Debug("PathTraversal Plugin init")
	return p.PluginMixinInitConfig.Init(ctx, pci, bb)
}

// D1-10: 增加差异化比对 + 修复 context.TODO()
// D1-12: 修正 payload ParameterType
// 优化: 按请求去重，相同的 HTTP 请求只发一次，用多条规则的正则检查同一响应
func (p *PathTraversal) execAction(ctx context.Context, b *base.Apollo) error {
	flow := b.GetTargetFlow()
	logger.Debugf("Start detection path-traversal, URL=%s", flow.Request.URL().String())

	// D1-10: 获取 baseline 响应
	baselineReq := flow.Request.DeepClone()
	baselineRes, _ := b.HTTPClient.Respond(ctx, baselineReq)

	for _, param := range flow.Request.ParamsAll() {
		if param.Position == http.PositionHeader || param.Position == http.PositionCookie {
			continue
		}

		// Group rules by the request they produce: same vector + same parameter type → same request
		type reqGroup struct {
			req   *http.Request
			param http.Parameter
			rules []*Rule
		}
		groups := make(map[string]*reqGroup)

		for i := range pathTraversalRules {
			rule := &pathTraversalRules[i]
			parameter := http.Parameter{Position: param.Position, Key: param.Key}
			if rule.typ == "LFI" && isValueReplacePayload(rule.Vector) {
				parameter.Value = rule.Vector
			} else if rule.Vector == "" {
				parameter.Value = param.Value
			} else {
				parameter.Value = param.Value
				parameter.Suffix = rule.Vector
			}

			req := flow.Request.Mutate(&parameter)
			// Use request URL as dedup key — identical URLs won't be requested twice
			key := req.URL().String()

			if g, exists := groups[key]; exists {
				g.rules = append(g.rules, rule)
			} else {
				groups[key] = &reqGroup{
					req:   req,
					param: parameter,
					rules: []*Rule{rule},
				}
			}
		}

		found := false
		for _, g := range groups {
			if found {
				break
			}
			res, err := b.HTTPClient.Respond(ctx, g.req)
			if err != nil {
				continue
			}
			for _, rule := range g.rules {
				if rule.compiled.Match([]byte(res.Text)) {
					// D1-10: 差异化比对 - 如果 baseline 响应中也匹配相同规则，判定为误报
					if baselineRes != nil && rule.compiled.Match([]byte(baselineRes.Text)) {
						continue
					}
					v := b.NewWebVuln(g.req, res, &g.param)
					if v != nil {
						v.SetTargetURL(flow.Request.URL())
						v.Payload = rule.Vector
						b.OutputVuln(v)
					}
					found = true
					break
				}
			}
		}
	}

	return nil
}

// isValueReplacePayload 判断 payload 是否应使用 Value 替换模式
// D1-12: php://filter, file:/// 等协议 payload 不应追加到参数值后，而应替换整个参数值
func isValueReplacePayload(vector string) bool {
	valueReplacePrefixes := []string{
		"php://",
		"file:///",
		"file://",
	}
	for _, prefix := range valueReplacePrefixes {
		if strings.HasPrefix(vector, prefix) {
			return true
		}
	}
	return false
}
