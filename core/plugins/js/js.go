/**
2 * @Author: shaochuyu
3 * @Date: 8/4/24
4 */

package js

import (
	"context"
	"wscan/core/plugins/base"
	logger "wscan/core/utils/log"
)

type Config struct {
	base.PluginBaseConfig           `json:",inline" yaml:",inline"`
	CustomSensitiveContentCheckRule string `json:"custom_sensitive_content_check_rule" yaml:"sensitive_content_check" #:"自定义JS敏感内容检测规则"`
}

// BaseConfig 返回基本配置, 固定格式, 无需修改
func (c *Config) BaseConfig() *base.PluginBaseConfig {
	return &c.PluginBaseConfig
}

type JS struct {
	base.PluginMixinInitConfig
	base.PluginMixinClose
	rules []Rule
}

// Close 关闭函数
func (*JS) Close() error {
	return nil
}

// DefaultConfig 返回默认配置, 需要填写插件的默认配置
func (*JS) DefaultConfig() base.PluginConfigInterface {
	config := &Config{PluginBaseConfig: base.PluginBaseConfig{
		Name:    "js",
		Enabled: true,
	}, CustomSensitiveContentCheckRule: ""}
	return config
}

// Fingers 返回漏洞检测配置
func (p *JS) Fingers() []*base.Finger {
	fingers := []*base.Finger{}
	fingers = append(fingers, (&SensitiveContentCheck{rules: p.rules}).Finger())
	return fingers
}

// GetConfig 获取配置
func (p *JS) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

// Init 插件初始化
func (p *JS) Init(ctx context.Context, pci base.PluginConfigInterface, ab *base.ApolloBase) error {
	logger.Info("JS init")
	p.PluginMixinInitConfig.Init(ctx, pci, ab)
	p.LoadRules()
	return p.PluginMixinInitConfig.Init(ctx, pci, ab)
}

func (p *JS) LoadRules() {
	p.rules, _ = LoadRulesWithRaw(ruleYaml)
	cfg := p.GetConfig().(*Config)
	if cfg.CustomSensitiveContentCheckRule != "" {
		if customSensitiveContentCheckRules, err := LoadRulesFromFile(cfg.CustomSensitiveContentCheckRule); err == nil {
			p.rules = append(p.rules, customSensitiveContentCheckRules...)
		} else {
			logger.Errorf("customSensitiveContentCheckRules LoadRules %s", cfg.CustomSensitiveContentCheckRule)
		}
	}

}
