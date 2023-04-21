/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package path_traversal

import (
	"context"
	"wscan/core/assassin/http"
	"wscan/core/assassin/plugins/base"
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
	return &Config{}
}

func (p *PathTraversal) Fingers() []*base.Finger {
	fingers := []*base.Finger{}
	fingers = append(fingers, &base.Finger{
		CheckAction: p.execAction,
		Channel:     "web-generic",
		Binding:     &base.VulnBinding{ID: "path-traversal/path-traversal/default", Plugin: "path-traversal/path-traversal", Category: "path-traversal"},
	})
	return fingers
}

func (p *PathTraversal) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

func (p *PathTraversal) Init(ctx context.Context, pci base.PluginConfigInterface, bb *base.BifrostBase) error {
	logger.Info("PathTraversal Plugin init")
	return p.PluginMixinInitConfig.Init(ctx, pci)
}

func (p *PathTraversal) execAction(ctx context.Context, b *base.Bifrost) error {
	flow := b.GetTargetFlow()
	logger.Infof("开始检测path-traversal, URL=%s", flow.Request.URL.String())
	for _, param := range flow.Request.ParamsQueryAndBody() {
		for _, rule := range pathTraversalRules {
			logger.Infof("%s, Test path-traversal= %s", flow.Request.URL.String(), rule.Vector)
			req := flow.Request.Mutate(&http.Parameter{Position: param.Position, Key: param.Key, Value: param.Value, Suffix: rule.Vector})
			res, err := b.HTTPClient.Respond(context.TODO(), req)
			if err != nil {
				continue
			}
			if rule.compiled.Match([]byte(res.Text)) {
				v := b.NewWebVuln(req, res, &param)
				if v != nil {
					v.SetTargetURL(&flow.Request.URL)
					v.Payload = rule.Vector
					b.OutputVuln(v)
				}
				logger.Infof("Found %s %s, param.Position=%s; param.Key=%s\n", rule.typ, flow.Request.URL.String(), param.Position, param.Key)
			}
		}
	}

	return nil
}
