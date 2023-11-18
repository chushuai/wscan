/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package jsonp

import (
	"context"
	"github.com/thoas/go-funk"
	"strings"
	"wscan/core/model"
	"wscan/core/plugins/base"
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
		Binding:     &model.VulnBinding{ID: "jsonp/default", Plugin: "jsonp/default", Category: "jsonp"},
	})
	return fingers
}

func (p *JSONP) execAction(ctx context.Context, ab *base.Apollo) error {
	flow := ab.GetTargetFlow()
	logger.Debugf("开始检测JSONP, URL=%s", flow.Request.URL().String())
	callbaks := []string{"callback", "cb", "json"}
	for _, param := range flow.Request.ParamsQueryAndBody() {
		if funk.ContainsString(callbaks, strings.ToLower(param.Key)) == true {
			v := ab.NewWebVuln(flow.Request, flow.Response, &param)
			if v != nil {
				v.SetTargetURL(flow.Request.URL())
				v.Payload = param.Key
				ab.OutputVuln(v)
			}
		}
	}

	logger.Debugf("开始检测XSS, URL=%s", flow.Request.URL().String())
	return nil
}

func (p *JSONP) Close() error {
	return nil
}

func (p *JSONP) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

func (p *JSONP) Init(ctx context.Context, pci base.PluginConfigInterface, ab *base.ApolloBase) error {
	logger.Info("JSONP init")
	return p.PluginMixinInitConfig.Init(ctx, pci, ab)
}
