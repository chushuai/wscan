/**
2 * @Author: shaochuyu
3 * @Date: 1/23/24
4 */

package xstream

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

type Xstream struct {
	base.PluginMixinInitConfig
	base.PluginMixinClose
}

// Close 关闭函数
func (*Xstream) Close() error {
	return nil
}

// DefaultConfig 返回默认配置, 需要填写插件的默认配置
func (*Xstream) DefaultConfig() base.PluginConfigInterface {
	config := &Config{PluginBaseConfig: base.PluginBaseConfig{
		Name:    "xstream",
		Enabled: true,
	}}
	return config
}

// Fingers 返回漏洞检测配置
func (p *Xstream) Fingers() []*base.Finger {
	fingers := []*base.Finger{}
	fingers = append(fingers, (&CVE_2021_21345{}).Finger())
	fingers = append(fingers, (&CVE_2020_26259{}).Finger())
	fingers = append(fingers, (&CVE_2020_26217{}).Finger())
	fingers = append(fingers, (&CVE_2013_7285{}).Finger())
	fingers = append(fingers, (&CVE_2021_21351{}).Finger())
	fingers = append(fingers, (&CVE_2020_26258{}).Finger())
	fingers = append(fingers, (&CVE_2021_39152{}).Finger())
	return fingers
}

// GetConfig 获取配置
func (p *Xstream) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

// Init 插件初始化
func (p *Xstream) Init(ctx context.Context, pci base.PluginConfigInterface, ab *base.ApolloBase) error {
	logger.Info("xstream init")
	return p.PluginMixinInitConfig.Init(ctx, pci, ab)
}
