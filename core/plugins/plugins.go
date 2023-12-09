/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package plugins

import (
	"wscan/core/plugins/base"
	"wscan/core/plugins/crlf_injection"
	"wscan/core/plugins/custom_tmpl"
	"wscan/core/plugins/dirscan"
	"wscan/core/plugins/jsonp"
	"wscan/core/plugins/path_traversal"
	"wscan/core/plugins/prometheus"
	"wscan/core/plugins/sql_injection"
	"wscan/core/plugins/xss"
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
	plugins = append(plugins, &path_traversal.PathTraversal{})
	plugins = append(plugins, &sql_injection.SQLInjection{})
	plugins = append(plugins, &crlf_injection.CRLFInjection{})
	plugins = append(plugins, &jsonp.JSONP{})
	plugins = append(plugins, &dirscan.Dirscan{})
	plugins = append(plugins, &prometheus.Prometheus{})
	plugins = append(plugins, &custom_tmpl.CustomTmpl{})
	return plugins
}
