/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package shiro

import (
	"bufio"
	"strings"
	"wscan/core/plugins/base"
	logger "wscan/core/utils/log"

	"golang.org/x/net/context"
)

type Config struct {
	base.PluginBaseConfig `json:",inline" yaml:",inline"`
	CookieName            string   `json:"cookie_name" yaml:"cookie_name" #:"默认使用哪个 shiro cookie name"`
	AESKey                []string `json:"aes_key" yaml:"aes_key" #:"自定义 shiro key，配置后将与内置 100 key 做合并"`
}

type Shiro struct {
	base.PluginMixinInitConfig
	base.PluginMixinClose
}

func (c *Config) BaseConfig() *base.PluginBaseConfig {
	return &c.PluginBaseConfig
}

func (*Shiro) Close() error {
	return nil
}

func (*Shiro) DefaultConfig() base.PluginConfigInterface {
	config := &Config{PluginBaseConfig: base.PluginBaseConfig{
		Name:    "shiro",
		Enabled: true,
	}}
	return config
}

func (p *Shiro) Fingers() []*base.Finger {
	fingers := []*base.Finger{}
	cfg, ok := p.GetConfig().(*Config)
	cookieName := ""
	if ok && cfg != nil {
		cookieName = cfg.CookieName
	}
	fingers = append(fingers, (&defaultKey{cookieName: cookieName}).Finger())
	// 注册反序列化检测（依赖 defaultKey 检测结果）
	fingers = append(fingers, (&deserialiazation{cookieName: cookieName}).Finger())
	return fingers
}
func (p *Shiro) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}
func (p *Shiro) Init(ctx context.Context, pci base.PluginConfigInterface, ab *base.ApolloBase) error {
	logger.Debug("Shiro init")
	p.PluginMixinInitConfig.Init(ctx, pci, ab)
	scanner := bufio.NewScanner(strings.NewReader(fileShirokeys))
	seen := make(map[string]struct{})
	for scanner.Scan() {
		text := scanner.Text()
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}
		if _, exist := seen[text]; !exist {
			ShiroKeys = append(ShiroKeys, text)
		}
	}
	c := p.GetConfig().(*Config)
	for _, text := range c.AESKey {
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}
		if _, exist := seen[text]; !exist {
			ShiroKeys = append(ShiroKeys, text)
		}
	}
	logger.Infof("A total of %d Shiro ShiroKeys are loaded", len(ShiroKeys))
	return nil
}
