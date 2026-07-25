/**
* @Author: shaochuyu
* @Date: 12/9/23
 */
package waftest

import (
	"context"
	"github.com/pkg/errors"
	"wscan/core/plugins/base"
	logger "wscan/core/utils/log"
)

// PlaceholderSpec 定义占位符规范，支持简单字符串和复杂配置
type PlaceholderSpec struct {
	Name   string // 占位符名称，如 "URLParam", "RawRequest" 等
	Config any    // 占位符配置，简单占位符为 nil，复杂占位符为解析后的配置结构
}

// YamlScript 定义 WAF 测试的攻击脚本
type YamlScript struct {
	Payload      string            // 攻击载荷
	Encoder      []string          // 编码器名称列表
	Placeholders []PlaceholderSpec // 占位符规范列表
	Type         string            // 攻击类型
	Channel      string            // 扫描通道
}

// Template 对应 YAML 模板文件的结构
type Template struct {
	Payloads     []string `yaml:"payload"`     // 攻击载荷列表
	Encoders     []string `yaml:"encoder"`     // 编码器名称列表
	Placeholders []any    `yaml:"placeholder"` // 占位符列表（支持字符串或带配置的映射）
	Type         string   `yaml:"type"`        // 攻击类型
}

// Config waftest 插件配置
type Config struct {
	base.PluginBaseConfig  `json:",inline" yaml:",inline"`
	Depth                  int      `yaml:"depth" json:"depth"`
	POC                    []string `yaml:"-" json:"-"`
	Exclusive              bool     `yaml:"-" json:"-"`
	AutoLoadTmpl           bool     `yaml:"auto_load_tmpl" json:"auto_load_tmpl" #:"自动加载当前目录以tmpl-*为文件名的tmpl文件，等同于在 include_tmpl 中增加 ./tmpl-* "`
	IncludeTmpl            []string `yaml:"include_tmpl" json:"include_tmpl" #:"只使用哪些内置 tmpl 以及 额外加载哪些本地 tmpl, 支持 glob 语法, 如：\"*weblogic*\" 或 \"/home/tmpl/*\""`
	ExcludeTmpl            []string `yaml:"exclude_tmpl" json:"exclude_tmpl" #:"排除哪些 tmpl, 支持 glob 语法, 如: /home/tmpl/*thinkphp* 或 tmpl-yaml-weblogic*"`
	BlockStatusCodes       []int    `yaml:"block_status_codes" json:"block_status_codes" #:"被WAF阻止时HTTP状态码列表,默认值为403"`
	PassStatusCodes        []int    `yaml:"pass_status_codes" json:"pass_status_codes" #:"未被WAF阻止时HTTP状态码列表, 默认值为200或404"`
	BlockRegex             string   `yaml:"block_regex" json:"block_regex"  #:"被WAF阻止网页的正则表达式"`
	PassRegex              string   `yaml:"pass_regex" json:"pass_regex" #:"未被WAF阻止网页的正则表达式"`
	NonBlockedAsPassed     bool     `yaml:"non_blocked_as_passed" json:"non_blocked_as_passed" #:"如果设置为 true，那么即使请求未被阻止，也会将其计入通过的请求数。如果设置为 false，那么只有当请求满足 PassStatusCodes 或 PassRegex 的条件时，才会将其计入通过的请求数"`
	UseBuiltinFingerprints bool     `yaml:"use_builtin_fingerprints" json:"use_builtin_fingerprints" #:"使用内置 WAF 指纹数据库进行检测，默认为 true"`
	ActiveProbe            bool     `yaml:"active_probe" json:"active_probe" #:"启用主动探测模式，发送攻击请求来检测 WAF，默认为 true"`
}

// CustomTmpl WAF 测试插件主体
type CustomTmpl struct {
	base.PluginMixinInitConfig
	base.PluginMixinClose
	enabledPOC []base.FingerFactory
}

func (c *Config) BaseConfig() *base.PluginBaseConfig {
	return &c.PluginBaseConfig
}

func (*CustomTmpl) Close() error {
	return nil
}

func (*CustomTmpl) DefaultConfig() base.PluginConfigInterface {
	return &Config{
		PluginBaseConfig:       base.PluginBaseConfig{Name: "waftest", Enabled: true},
		Depth:                  0,
		PassStatusCodes:        []int{200, 404},
		BlockStatusCodes:       []int{403},
		UseBuiltinFingerprints: true,
		ActiveProbe:            true,
	}
}

func (p *CustomTmpl) DepthCheck(ctx context.Context, ab *base.Apollo) error {
	flow := ab.GetTargetFlow()
	depth := flow.Request.GetURLDepth()
	if depth > p.GetConfig().(*Config).Depth {
		return errors.New("depth check failed")
	}
	return nil
}

func (p *CustomTmpl) Fingers() []*base.Finger {
	fs := []*base.Finger{}
	for _, f := range p.enabledPOC {
		fp := f.Finger()
		fp.CheckAction = p.DepthCheck
		fs = append(fs, fp)
	}
	return fs
}

func (p *CustomTmpl) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

func (p *CustomTmpl) Init(ctx context.Context, pci base.PluginConfigInterface, ab *base.ApolloBase) error {
	logger.Debug("CustomTmpl Plugin init")
	err := p.PluginMixinInitConfig.Init(ctx, pci, ab)
	c := p.GetConfig().(*Config)
	logger.Infof("IncludeTmpl: %v, ExcludeTmpl: %v", c.IncludeTmpl, c.ExcludeTmpl)

	// Load YAML template-based POCs
	p.enabledPOC = LoadYamlTmpl(c)

	// Add built-in WAF fingerprint detection if enabled
	if c.UseBuiltinFingerprints {
		wafFinger := NewWAFFinger(c)
		p.enabledPOC = append(p.enabledPOC, wafFinger)
		logger.Infof("Built-in WAF fingerprint detection enabled (active_probe=%v)", c.ActiveProbe)
	}

	return err
}
