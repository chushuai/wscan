/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package base

type PluginBaseConfig struct {
	Enabled    bool   `json:"enabled" yaml:"enabled"`
	Name       string `json:"-" yaml:"-"`
	IsAdvanced bool   `json:"-" yaml:"-"`
}

type PluginMixinInitConfig struct {
	Config PluginConfigInterface
}

func (*PluginMixinInitConfig) Init() {

}
func (*PluginMixinInitConfig) BaseConfig() *PluginBaseConfig {
	return nil
}

type PluginConfigInterface interface {
	BaseConfig() *PluginBaseConfig
}
