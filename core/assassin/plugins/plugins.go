/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package plugins

import (
	"wscan/core/assassin/plugins/base"
	"wscan/core/assassin/plugins/xss"
)

func GetPluginByName(name string) base.Plugin {
	plugins := All()
	for _, p := range plugins {
		if p.DefaultConfig().BaseConfig().Name == name {
			return p
		}
	}
	return nil
}

func All() []base.Plugin {
	var plugins []base.Plugin
	plugins = append(plugins, &xss.XSS{})
	return plugins
}
