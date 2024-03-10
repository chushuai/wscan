/**
2 * @Author: shaochuyu
3 * @Date: 12/9/23
4 */

package custom

import (
	"context"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
	"wscan/core/plugins/base"
	logger "wscan/core/utils/log"
)

type SetMapSlice = yaml.MapSlice

type YamlScript struct {
	Temp    *Template
	Payload string
	Channel string
}

type Template struct {
	Name         string      `yaml:"name"`
	Set          SetMapSlice `yaml:"set"`
	Payloads     []string    `yaml:"payload"`
	Encoders     []string    `yaml:"encoder"`
	Placeholders []string    `yaml:"placeholder"`
	Expression   string      `yaml:"expression"`
	Type         string      `default:"unknown" yaml:"type"`
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
}

type Custom struct {
	base.PluginMixinInitConfig
	base.PluginMixinClose
	enabledPOC []base.FingerFactory
}

func (c *Config) BaseConfig() *base.PluginBaseConfig {
	return &c.PluginBaseConfig
}

func (*Custom) Close() error {
	return nil
}

func (*Custom) DefaultConfig() base.PluginConfigInterface {
	return &Config{PluginBaseConfig: base.PluginBaseConfig{Name: "custom", Enabled: true}, Depth: 0}
}

func (p *Custom) DepthCheck(ctx context.Context, ab *base.Apollo) error {
	flow := ab.GetTargetFlow()
	depth := flow.Request.GetURLDepth()
	if depth > p.GetConfig().(*Config).Depth {
		return errors.New("depth check failed")
	}
	return nil
}

func (p *Custom) Fingers() []*base.Finger {
	fs := []*base.Finger{}
	for _, f := range p.enabledPOC {
		fp := f.Finger()
		fp.CheckAction = p.DepthCheck
		fs = append(fs, fp)
	}
	return fs
}

func (p *Custom) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

func (p *Custom) Init(ctx context.Context, pci base.PluginConfigInterface, ab *base.ApolloBase) error {
	logger.Info("Custom Plugin init")
	err := p.PluginMixinInitConfig.Init(ctx, pci, ab)
	c := p.GetConfig().(*Config)
	logger.Infof("IncludeCustomTmpl: %v, ExcludeCustomTmpl: %v", c.IncludeTmpl, c.ExcludeTmpl)
	p.enabledPOC = LoadYamlTmpl(c)
	return err
}
