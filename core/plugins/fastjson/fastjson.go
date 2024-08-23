/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package fastjson

import (
	"bytes"
	"context"
	"strings"
	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/reverse"
	logger "wscan/core/utils/log"
)

type Config struct {
	base.PluginBaseConfig `json:",inline" yaml:",inline"`
}

// *ssrf.Config
func (c *Config) BaseConfig() *base.PluginBaseConfig {
	return &c.PluginBaseConfig
}

type FastJSON struct {
	base.PluginMixinInitConfig
	base.PluginMixinClose
}

// Close 关闭函数
func (*FastJSON) Close() error {
	return nil
}

// DefaultConfig 返回默认配置, 需要填写插件的默认配置
func (*FastJSON) DefaultConfig() base.PluginConfigInterface {
	config := &Config{PluginBaseConfig: base.PluginBaseConfig{
		Name:    "fastjson",
		Enabled: true,
	},
	}
	return config
}

// Fingers 返回漏洞检测配置
func (p *FastJSON) Fingers() []*base.Finger {
	fingers := []*base.Finger{}
	fingers = append(fingers, &base.Finger{
		CheckAction: p.execAction,
		Channel:     "web-generic",
		NeedReverse: true,
		Binding:     &model.VulnBinding{ID: "fastjson/deserialization/default", Plugin: "fastjson/deserialization/default", Category: "fastjson/deserialization/default"},
	})
	return fingers
}

// GetConfig 获取配置
func (p *FastJSON) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

// Init 插件初始化
func (p *FastJSON) Init(ctx context.Context, pci base.PluginConfigInterface, ab *base.ApolloBase) error {
	logger.Info("fastjson init")
	return p.PluginMixinInitConfig.Init(ctx, pci, ab)
}

// execAction 执行漏洞检测
func (p *FastJSON) execAction(ctx context.Context, ab *base.Apollo) error {
	flow := ab.GetTargetFlow()
	logger.Infof("Start detection fastjson漏洞, URL %s", flow.Request.URL().String())
	for _, payload := range GetRmiPayload() {
		func(oob string) {
			unit := ab.Reverse.Register(nil)
			oob = strings.Replace(oob, "{{reverse-rmi-url}}", unit.GetRmiURL(), -1)
			req, _ := http.NewRequest("POST", flow.Request.URL().String(), nil)
			req.WithJSONBody(bytes.NewReader([]byte(oob)))
			// 发送请求
			res, err := ab.HTTPClient.Respond(context.TODO(), req)
			unit.OnVisit(func(event *reverse.Event) error {
				if err == nil {
					v := ab.NewWebVuln(req, res, nil)
					if v != nil {
						v.SetTargetURL(flow.Request.URL())
						v.Payload = oob
						ab.OutputVuln(v)
					}
				}
				return nil
			})
			unit.Fetch(0)
		}(payload)
	}

	for _, payload := range GetUrlPayload() {
		func(oob string) {
			unit := ab.Reverse.Register(nil)
			oob = strings.Replace(oob, "{{reverse-url}}", unit.GetVisitURL(), -1)
			req, _ := http.NewRequest("POST", flow.Request.URL().String(), nil)
			req.WithJSONBody(bytes.NewReader([]byte(oob)))
			// 发送请求
			res, err := ab.HTTPClient.Respond(context.TODO(), req)
			unit.OnVisit(func(event *reverse.Event) error {
				if err == nil {
					v := ab.NewWebVuln(req, res, nil)
					if v != nil {
						v.SetTargetURL(flow.Request.URL())
						v.Payload = oob
						ab.OutputVuln(v)
					}
				}
				return nil
			})
			unit.Fetch(0)
		}(payload)
	}
	return nil
}
