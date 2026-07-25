/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package crlf_injection

import (
	"context"
	"net/textproto"
	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	logger "wscan/core/utils/log"
)

type CRLFInjection struct {
	base.PluginMixinInitConfig
	base.PluginMixinClose
}

type Config struct {
	base.PluginBaseConfig `json:",inline" yaml:",inline"`
}

func (c *Config) BaseConfig() *base.PluginBaseConfig {
	return &c.PluginBaseConfig
}

func (*CRLFInjection) Close() error {
	return nil
}

func (*CRLFInjection) DefaultConfig() base.PluginConfigInterface {
	config := &Config{PluginBaseConfig: base.PluginBaseConfig{
		Name:    "crlf-injection",
		Enabled: true,
	}}
	return config
}

func getCRLFPayload() []string {
	payload := []string{
		// Standard CRLF injection
		"%0d%0aDalfoxcrlf: 1234",
		// Double URL encoding CRLF
		"%E5%98%8D%E5%98%8ADalfoxcrlf: 1234",
		// Unicode escape CRLF
		"\\u560d\\u560aDalfoxcrlf: 1234",
		// %0d only (CR without LF)
		"%0dDalfoxcrlf: 1234",
		// %0a only (LF without CR)
		"%0aDalfoxcrlf: 1234",
		// Raw CRLF + Set-Cookie injection
		"%0d%0aSet-Crlf-Cookie: crlfinjected=wscan",
		// Double encoding CRLF
		"%250d%250aDalfoxcrlf: 1234",
		// Tab-based header injection
		"%09Dalfoxcrlf: 1234",
	}
	return payload
}

func (*CRLFInjection) Fingers() []*base.Finger {
	fingers := []*base.Finger{}
	fingers = append(fingers, &base.Finger{
		CheckAction: func(ctx context.Context, bi *base.Apollo) error {
			flow := bi.GetTargetFlow()
			logger.Debugf("Start detection CRLF Injection, URL=%s", flow.Request.URL().String())
			for _, param := range flow.Request.ParamsAll() {
				for _, crlfpayload := range getCRLFPayload() {
					req := flow.Request.Mutate(&http.Parameter{Position: param.Position, Key: param.Key, Value: param.Value, Suffix: crlfpayload})
					res, err := bi.HTTPClient.Respond(ctx, req)
					if err != nil {
						continue
					}
					// Check for standard CRLF header injection
					crlfValue := textproto.MIMEHeader(res.Header).Get("Dalfoxcrlf")
					if crlfValue != "" {
						v := bi.NewWebVuln(req, res, &param)
						if v != nil {
							v.SetTargetURL(flow.Request.URL())
							v.Payload = crlfpayload
							bi.OutputVuln(v)
						}
						return nil
					}
					// Check for Set-Cookie based CRLF injection
					setCrlfCookie := textproto.MIMEHeader(res.Header).Get("Set-Crlf-Cookie")
					if setCrlfCookie != "" {
						v := bi.NewWebVuln(req, res, &param)
						if v != nil {
							v.SetTargetURL(flow.Request.URL())
							v.Payload = crlfpayload
							bi.OutputVuln(v)
						}
						return nil
					}
				}
			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{ID: "crlf-injection/dispatcher/default", Plugin: "crlf-injection", Category: "crlf-injection", Severity: model.SeverityMedium},
	})
	return fingers
}

func (p *CRLFInjection) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

func (p *CRLFInjection) Init(ctx context.Context, pci base.PluginConfigInterface, bb *base.ApolloBase) error {

	logger.Debug("crlf_injection Plugin init")
	return p.PluginMixinInitConfig.Init(ctx, pci, bb)

}
