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
	fingers = append(fingers, (&S037{}).Finger())
	fingers = append(fingers, (&S045{}).Finger())
	fingers = append(fingers, (&S046{}).Finger()...)
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
	logger.Debug("WebVulnPlugin init")
	return p.PluginMixinInitConfig.Init(ctx, pci, ab)
}

// execAction 执行漏洞检测
func (p *Struts) execAction(ctx context.Context, ab *base.Apollo) error {

	return nil
}
