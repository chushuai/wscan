/**
2 * @Author: shaochuyu
3 * @Date: 12/9/23
4 */

package waftest

import (
	"context"
	"github.com/pkg/errors"
	"wscan/core/plugins/base"
	logger "wscan/core/utils/log"
)

type YamlScript struct {
	Payload     string
	Encoder     []string
	Placeholder []string
	Type        string
	Channel     string
}

type Template struct {
	Payloads     []string `yaml:"payload"`
	Encoders     []string `yaml:"encoder"`
	Placeholders []string `yaml:"placeholder"`
	Type         string   `default:"unknown" yaml:"type"`
}

type Case struct {
	Payloads     []string
	Encoders     []string
	Placeholders []*Placeholder
	Type         string

	Set            string
	Name           string
	IsTruePositive bool
}

type Placeholder struct {
	Name   string
	Config any
}

type Config struct {
	base.PluginBaseConfig `json:",inline" yaml:",inline"`
	Depth                 int      `yaml:"depth" json:"depth"`
	POC                   []string `yaml:"-" json:"-"`
	Exclusive             bool     `yaml:"-" json:"-"`
	AutoLoadTmpl          bool     `yaml:"auto_load_tmpl" json:"auto_load_tmpl" #:"自动加载当前目录以tmpl-*为文件名的tmpl文件，等同于在 include_tmpl 中增加 ./tmpl-* "`
	IncludeTmpl           []string `yaml:"include_tmpl" json:"include_tmpl" #:"只使用哪些内置 tmpl 以及 额外加载哪些本地 tmpl, 支持 glob 语法, 如：\"*weblogic*\" 或 \"/home/tmpl/*\""`
	ExcludeTmpl           []string `yaml:"exclude_tmpl" json:"exclude_tmpl" #:"排除哪些 tmpl, 支持 glob 语法, 如: /home/tmpl/*thinkphp* 或 tmpl-yaml-weblogic*"`
	BlockStatusCodes      []int    `yaml:"block_status_codes" json:"block_status_codes" #:"被WAF阻止时HTTP状态码列表,默认值为403"`
	PassStatusCodes       []int    `yaml:"pass_status_codes" json:"pass_status_codes" #:"未被WAF阻止时HTTP状态码列表, 默认值为200或404"`
	BlockRegex            string   `yaml:"block_regex" json:"block_regex"  #:"被WAF阻止网页的正则表达式"`
	PassRegex             string   `yaml:"pass_regex" json:"pass_regex" #:"未被WAF阻止网页的正则表达式"`
	NonBlockedAsPassed    bool     `yaml:"non_blocked_as_passed" json:"non_blocked_as_passed" #:"如果设置为 true，那么即使请求未被阻止，也会将其计入通过的请求数。如果设置为 false，那么只有当请求满足 PassStatusCodes 或 PassRegex 的条件时，才会将其计入通过的请求数"`
}

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
	return &Config{PluginBaseConfig: base.PluginBaseConfig{Name: "waftest", Enabled: true}, Depth: 0, PassStatusCodes: []int{
		200, 404,
	}, BlockStatusCodes: []int{403}}
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
	logger.Info("CustomTmpl Plugin init")
	err := p.PluginMixinInitConfig.Init(ctx, pci, ab)
	c := p.GetConfig().(*Config)
	logger.Infof("IncludeTmpl: %v, ExcludeTmpl: %v", c.IncludeTmpl, c.ExcludeTmpl)
	p.enabledPOC = LoadYamlTmpl(c)
	return err
}
