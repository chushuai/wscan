/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package prometheus

import (
	"errors"
	"golang.org/x/net/context"
	"wscan/core/plugins/base"
	"wscan/core/plugins/prometheus/pocs/gopoc"
	logger "wscan/core/utils/log"
)

type Config struct {
	base.PluginBaseConfig `json:",inline" yaml:",inline"`
	Depth                 int      `yaml:"depth" json:"depth"`
	POC                   []string `yaml:"-" json:"-"`
	Exclusive             bool     `yaml:"-" json:"-"`
	AutoLoadPOC           bool     `yaml:"auto_load_poc" json:"auto_load_poc" #:"自动加载当前目录以poc-*为文件名的POC文件，等同于在 include_poc 中增加 ./poc-* "`
	IncludePOC            []string `yaml:"include_poc" json:"include_poc" #:"只使用哪些内置 poc 以及 额外加载哪些本地 poc, 支持 glob 语法, 如：\"*weblogic*\" 或 \"/home/poc/*\""`
	ExcludePOC            []string `yaml:"exclude_poc" json:"exclude_poc" #:"排除哪些 poc, 支持 glob 语法, 如: /home/poc/*thinkphp* 或 poc-yaml-weblogic*"`
}

type Prometheus struct {
	base.PluginMixinInitConfig
	base.PluginMixinClose
	enabledPOC []base.FingerFactory
}

func (c *Config) BaseConfig() *base.PluginBaseConfig {
	return &c.PluginBaseConfig
}

func (*Prometheus) Close() error {
	return nil
}

func (*Prometheus) DefaultConfig() base.PluginConfigInterface {
	return &Config{PluginBaseConfig: base.PluginBaseConfig{Name: "prometheus", Enabled: true}, Depth: 1}
}

func (p *Prometheus) DepthCheck(ctx context.Context, ab *base.Apollo) error {
	flow := ab.GetTargetFlow()
	depth := flow.Request.GetURLDepth()
	if p.GetConfig().(*Config).Depth != 0 && depth > p.GetConfig().(*Config).Depth {
		return errors.New("depth check failed")
	}
	return nil
}

func (p *Prometheus) Fingers() []*base.Finger {
	fs := []*base.Finger{}
	for _, f := range p.enabledPOC {
		fp := f.Finger()
		if fp.CheckAction == nil {
			fp.CheckAction = p.DepthCheck
		}
		fs = append(fs, fp)
	}
	return fs
}

func (p *Prometheus) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

func (p *Prometheus) Init(ctx context.Context, pci base.PluginConfigInterface, ab *base.ApolloBase) error {
	logger.Debug("Phantasm Plugin init")
	err := p.PluginMixinInitConfig.Init(ctx, pci, ab)
	c := p.GetConfig().(*Config)
	logger.Infof("IncludePOC: %v, ExcludePOC: %v", c.IncludePOC, c.ExcludePOC)
	optionsError := InitExecutorOptions(150, 20)
	if err != nil {
		logger.Error(optionsError)
	}
	p.enabledPOC = LoadEmbeddedYamlPOC()
	p.enabledPOC = append(p.enabledPOC, LoadYamlPOC(c)...)
	p.enabledPOC = append(p.enabledPOC, gopoc.LoadGolangPOC()...)
	return err
}
