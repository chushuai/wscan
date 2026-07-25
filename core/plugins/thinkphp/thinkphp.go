/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package thinkphp

import (
	"context"
	"wscan/core/plugins/base"
	logger "wscan/core/utils/log"
)

type Config struct {
	base.PluginBaseConfig      `json:",inline" yaml:",inline"`
	DetectThinkPHPSQLInjection bool `json:"detect_thinkphp_sqli" yaml:"detect_thinkphp_sqli" #:"检查 thinkphp 特定语法的 sqli 注入漏洞"`
}

type Thinkphp struct {
	base.PluginMixinInitConfig
	base.PluginMixinClose
}

// BaseConfig 返回基本配置, 固定格式, 无需修改
func (c *Config) BaseConfig() *base.PluginBaseConfig {
	return &c.PluginBaseConfig
}

// Close 关闭函数
func (*Thinkphp) Close() error {
	return nil
}

// DefaultConfig 返回默认配置, 需要填写插件的默认配置
func (*Thinkphp) DefaultConfig() base.PluginConfigInterface {
	config := &Config{PluginBaseConfig: base.PluginBaseConfig{
		Name:    "thinkphp",
		Enabled: true,
	}}
	return config
}

//	subgraph cluster_s6 {
//		label="thinkphp";
//		n7[label="thinkphp/dispatcher/default"];
//		n42[label="thinkphp/rce/invoke"];
//		n43[label="thinkphp/rce/method"];
//		n41[label="thinkphp/rce/preg"];
//		n45[label="thinkphp/sqli/default"];
//		n44[label="thinkphp/v6-file-write/default"];
//		n7->n41[label="website"];
//		n7->n42[label="website"];
//		n7->n43[label="website"];
//		n7->n44[label="C"];
//		n7->n45[label="web-generic"];
//
//	}
//
// Fingers 返回漏洞检测配置
func (p *Thinkphp) Fingers() []*base.Finger {
	fingers := []*base.Finger{}
	fingers = append(fingers, (&InvokeRce{}).Finger())
	fingers = append(fingers, (&MethodRce{}).Finger())
	fingers = append(fingers, (&PregRce{}).Finger())

	// Register sqli detection if configured
	cfg, ok := p.GetConfig().(*Config)
	if ok && cfg != nil && cfg.DetectThinkPHPSQLInjection {
		fingers = append(fingers, (&Sqli{}).Finger())
	}
	// v6-filewrite always registered (triggered via website channel only for directory-type requests)
	fingers = append(fingers, (&V6FileWrite{}).Finger())

	return fingers
}

// GetConfig 获取配置
func (p *Thinkphp) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

// Init 插件初始化
func (p *Thinkphp) Init(ctx context.Context, pci base.PluginConfigInterface, ab *base.ApolloBase) error {
	logger.Debug("Thinkphp init")
	return p.PluginMixinInitConfig.Init(ctx, pci, ab)
}

// execAction 执行漏洞检测
func (p *Thinkphp) execAction(ctx context.Context, ab *base.Apollo) error {
	return nil
}
