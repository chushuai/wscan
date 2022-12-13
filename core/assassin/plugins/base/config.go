/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package base

import "context"

type PluginBaseConfig struct {
	Enabled    bool   `json:"enabled" yaml:"enabled"`
	Name       string `json:"-" yaml:"-"`
	IsAdvanced bool   `json:"-" yaml:"-"`
}

type PluginMixinInitConfig struct {
	Config PluginConfigInterface
}

func (p *PluginMixinInitConfig) Init(ctx context.Context, pfi PluginConfigInterface, bb *BifrostBase) error {
	p.Config = pfi
	return nil
}

func (p *PluginMixinInitConfig) BaseConfig() *PluginBaseConfig {
	if p.Config == nil {
		return nil
	}
	return p.Config.BaseConfig()
}

func (p *PluginMixinInitConfig) GetConfig() PluginConfigInterface {
	return p.Config
}

type PluginConfigInterface interface {
	BaseConfig() *PluginBaseConfig
}
