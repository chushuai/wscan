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
		Binding:     &model.VulnBinding{ID: "fastjson/deserialization/default", Plugin: "fastjson/deserialization/default", Category: "fastjson/deserialization/default", Severity: model.SeverityCritical},
	})
	return fingers
}

// GetConfig 获取配置
func (p *FastJSON) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

// Init 插件初始化
func (p *FastJSON) Init(ctx context.Context, pci base.PluginConfigInterface, ab *base.ApolloBase) error {
	logger.Debug("fastjson init")
	return p.PluginMixinInitConfig.Init(ctx, pci, ab)
}

// execAction 执行漏洞检测
func (p *FastJSON) execAction(ctx context.Context, ab *base.Apollo) error {
	flow := ab.GetTargetFlow()
	logger.Debugf("Start detection fastjson漏洞, URL %s", flow.Request.URL().String())

	// RMI payload detection
	for _, payload := range GetRmiPayload() {
		func(oob string) {
			unit := ab.Reverse.Register(nil)
			oob = strings.Replace(oob, "{{reverse-rmi-url}}", unit.GetRmiURL(), -1)
			req, _ := http.NewRequest("POST", flow.Request.URL().String(), nil)
			req.WithJSONBody(bytes.NewReader([]byte(oob)))
			// 发送请求 — 使用传入的 ctx 替代 context.TODO()
			ab.HTTPClient.Respond(ctx, req)
			// OnVisit 回调中移除对 HTTP 请求 err 的依赖
			// 反连事件到达即说明目标触发了 JNDI/RMI 回连，判定漏洞存在
			unit.OnVisit(func(event *reverse.Event) error {
				v := ab.NewWebVuln(req, nil, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = oob
					ab.OutputVuln(v)
				}
				return nil
			})
			unit.Fetch(0)
		}(payload)
	}

	// HTTP URL payload detection
	for _, payload := range GetUrlPayload() {
		func(oob string) {
			unit := ab.Reverse.Register(nil)
			oob = strings.Replace(oob, "{{reverse-url}}", unit.GetVisitURL(), -1)
			req, _ := http.NewRequest("POST", flow.Request.URL().String(), nil)
			req.WithJSONBody(bytes.NewReader([]byte(oob)))
			// 使用传入的 ctx 替代 context.TODO()
			ab.HTTPClient.Respond(ctx, req)
			// OnVisit 回调中移除对 HTTP 请求 err 的依赖
			unit.OnVisit(func(event *reverse.Event) error {
				v := ab.NewWebVuln(req, nil, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = oob
					ab.OutputVuln(v)
				}
				return nil
			})
			unit.Fetch(0)
		}(payload)
	}

	// LDAP payload detection
	for _, payload := range GetLdapPayload() {
		func(oob string) {
			unit := ab.Reverse.Register(nil)
			oob = strings.Replace(oob, "{{reverse-ldap-url}}", unit.GetLdapURL(), -1)
			req, _ := http.NewRequest("POST", flow.Request.URL().String(), nil)
			req.WithJSONBody(bytes.NewReader([]byte(oob)))
			ab.HTTPClient.Respond(ctx, req)
			unit.OnVisit(func(event *reverse.Event) error {
				v := ab.NewWebVuln(req, nil, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = oob
					ab.OutputVuln(v)
				}
				return nil
			})
			unit.Fetch(0)
		}(payload)
	}

	// DNS payload detection (MySQL JDBC DNS exfiltration)
	for _, payload := range GetDomainPayload() {
		func(oob string) {
			unit := ab.Reverse.Register(nil)
			domainInfo, err := unit.GetQueryDomain()
			if err != nil || domainInfo == nil {
				return
			}
			oob = strings.Replace(oob, "{{reverse-domain}}", domainInfo.Domain, -1)
			req, _ := http.NewRequest("POST", flow.Request.URL().String(), nil)
			req.WithJSONBody(bytes.NewReader([]byte(oob)))
			ab.HTTPClient.Respond(ctx, req)
			unit.OnVisit(func(event *reverse.Event) error {
				v := ab.NewWebVuln(req, nil, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = oob
					ab.OutputVuln(v)
				}
				return nil
			})
			unit.Fetch(0)
		}(payload)
	}

	return nil
}
