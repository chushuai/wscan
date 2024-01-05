/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package struts

import (
	"context"
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

type Struts struct {
	base.PluginMixinInitConfig
	base.PluginMixinClose
}

// Close 关闭函数
func (*Struts) Close() error {
	return nil
}

// DefaultConfig 返回默认配置, 需要填写插件的默认配置
func (*Struts) DefaultConfig() base.PluginConfigInterface {
	config := &Config{PluginBaseConfig: base.PluginBaseConfig{
		Name:    "struts",
		Enabled: true,
	}}
	return config
}

//	label="struts";
//	n816[label="struts/devmode/cve-2012-0392"];
//	n817[label="struts/devmode/cve-2012-0393"];
//	n818[label="struts/devmode/cve-2012-0394"];
//	n815[label="struts/devmode/default"];
//	n31[label="struts/dispatcher/default"];
//	n812[label="struts/ognl-injection/default"];
//	n813[label="struts/s2-005/default"];
//	n814[label="struts/s2-007/default"];
//	n819[label="struts/s2-009/default"];
//	n820[label="struts/s2-012/default"];
//	n821[label="struts/s2-013/default"];
//	n822[label="struts/s2-015/default"];
//	n823[label="struts/s2-016/default"];
//	n824[label="struts/s2-017/default"];
//	n826[label="struts/s2-020/cve-2014-0094"];
//	n825[label="struts/s2-020/default"];
//	n828[label="struts/s2-021/cve-2014-0113"];
//	n827[label="struts/s2-021/default"];
//	n829[label="struts/s2-022/default"];
//	n830[label="struts/s2-032/default"];
//	n831[label="struts/s2-037/default"];
//	n832[label="struts/s2-046/default"];
//	n833[label="struts/s2-048/default"];
//	n834[label="struts/s2-053/default"];
//	n835[label="struts/s2-057/default"];
//	n31->n812[label="web-generic"];
//	n31->n813[label="web-path"];
//	n31->n814[label="web-generic"];
//	n31->n815[label="web-path"];
//	n31->n816[label="web-path"];
//	n31->n817[label="web-path"];
//	n31->n818[label="web-path"];
//	n31->n819[label="web-generic"];
//	n31->n820[label="web-generic"];
//	n31->n821[label="web-generic"];
//	n31->n822[label="web-path"];
//	n31->n823[label="web-path"];
//	n31->n824[label="web-path"];
//	n31->n825[label="web-path"];
//	n31->n826[label="web-path"];
//	n31->n827[label="web-path"];
//	n31->n828[label="web-path"];
//	n31->n829[label="web-path"];
//	n31->n830[label="web-path"];
//	n31->n831[label="web-path"];
//	n31->n832[label="web-path"];
//	n31->n833[label="web-generic"];
//	n31->n834[label="web-generic"];
//	n31->n835[label="web-path"];
//	n835[label="struts/s2-057/default"];
//
// Fingers 返回漏洞检测配置
func (p *Struts) Fingers() []*base.Finger {
	fingers := []*base.Finger{}
	fingers = append(fingers, (&S005{}).Finger())
	fingers = append(fingers, (&S007{}).Finger())
	fingers = append(fingers, (&S009{}).Finger())
	fingers = append(fingers, (&S013{}).Finger())
	fingers = append(fingers, (&S015{}).Finger())
	fingers = append(fingers, (&S016{}).Finger())
	fingers = append(fingers, (&S032{}).Finger())
	fingers = append(fingers, (&S052{}).Finger())
	fingers = append(fingers, (&S057{}).Finger())
	fingers = append(fingers, (&devmode{}).Finger())
	return fingers
}

// GetConfig 获取配置
func (p *Struts) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

// Init 插件初始化
func (p *Struts) Init(ctx context.Context, pci base.PluginConfigInterface, ab *base.ApolloBase) error {
	logger.Info("WebVulnPlugin init")
	return p.PluginMixinInitConfig.Init(ctx, pci, ab)
}

// execAction 执行漏洞检测
func (p *Struts) execAction(ctx context.Context, ab *base.Apollo) error {

	return nil
}
