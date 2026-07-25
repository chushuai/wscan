/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package jsonp

import (
	"context"
	"github.com/thoas/go-funk"
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

type JSONP struct {
	base.PluginMixinInitConfig
	base.PluginMixinClose
}

func (p *JSONP) DefaultConfig() base.PluginConfigInterface {
	config := &Config{PluginBaseConfig: base.PluginBaseConfig{
		Name:    "jsonp",
		Enabled: true,
	}}
	return config
}

func (p *JSONP) Fingers() []*base.Finger {
	fingers := []*base.Finger{}
	fingers = append(fingers, &base.Finger{
		CheckAction: p.execAction,
		Channel:     "web-generic",
		Binding:     &model.VulnBinding{ID: "jsonp/default", Plugin: "jsonp/default", Category: "jsonp", Severity: model.SeverityMedium},
	})
	return fingers
}

// D1-13: 增加回调行为验证
// 不再仅检查参数名，而是发送带有自定义回调函数名的请求验证响应
func (p *JSONP) execAction(ctx context.Context, ab *base.Apollo) error {
	flow := ab.GetTargetFlow()
	logger.Debugf("Start detection JSONP, URL=%s", flow.Request.URL().String())
	// D1-13: 修正拼写并扩展参数名列表
	callbacks := []string{"callback", "cb", "json", "jsonp", "cbfunc", "api", "function", "call"}
	for _, param := range flow.Request.ParamsQueryAndBody() {
		if funk.ContainsString(callbacks, strings.ToLower(param.Key)) {
			// D1-13: 验证回调行为 - 发送自定义回调函数名检查响应
			verifyFuncName := "wscan" + utils.RandLetters(6)
			parameter := http.Parameter{Position: param.Position, Key: param.Key, Value: verifyFuncName}
			req := flow.Request.Mutate(&parameter)
			res, err := ab.HTTPClient.Respond(ctx, req)
			if err != nil {
				continue
			}
			// 检查响应是否以回调函数名开头（真正的 JSONP 回调）
			body := strings.TrimSpace(res.Text)
			if strings.HasPrefix(body, verifyFuncName+"(") || strings.HasPrefix(body, verifyFuncName+" (") {
				v := ab.NewWebVuln(req, res, &param)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = param.Key
					ab.OutputVuln(v)
				}
			}
		}
	}
	return nil
}

func (p *JSONP) Close() error {
	return nil
}

func (p *JSONP) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

func (p *JSONP) Init(ctx context.Context, pci base.PluginConfigInterface, ab *base.ApolloBase) error {
	logger.Debug("JSONP init")
	return p.PluginMixinInitConfig.Init(ctx, pci, ab)
}
