/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package plugins

import (
	"wscan/core/plugins/base"
	"wscan/core/plugins/baseline"
	"wscan/core/plugins/bruteforce"
	"wscan/core/plugins/cmd_injection"
	"wscan/core/plugins/crlf_injection"
	"wscan/core/plugins/custom"
	"wscan/core/plugins/dirscan"
	"wscan/core/plugins/fastjson"
	"wscan/core/plugins/fingerprint"
	"wscan/core/plugins/js"
	"wscan/core/plugins/jsonp"
	"wscan/core/plugins/path_traversal"
	"wscan/core/plugins/prometheus"
	"wscan/core/plugins/redirect"
	"wscan/core/plugins/shiro"
	"wscan/core/plugins/sql_injection"
	"wscan/core/plugins/ssrf"
	"wscan/core/plugins/struts"
	"wscan/core/plugins/thinkphp"
	"wscan/core/plugins/upload"
	"wscan/core/plugins/waftest"
	"wscan/core/plugins/xss"
	"wscan/core/plugins/xstream"
	"wscan/core/plugins/xxe"
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
	plugins = append(plugins, &waftest.CustomTmpl{})
	plugins = append(plugins, &cmd_injection.CmdInjection{})
	plugins = append(plugins, &bruteforce.BruteForce{})
	plugins = append(plugins, &struts.Struts{})
	plugins = append(plugins, &ssrf.SSRF{})
	plugins = append(plugins, &thinkphp.Thinkphp{})
	plugins = append(plugins, &xxe.XXE{})
	plugins = append(plugins, &redirect.Redirect{})
	plugins = append(plugins, &fastjson.FastJSON{})
	plugins = append(plugins, &upload.Upload{})
	plugins = append(plugins, &baseline.Baseline{})
	plugins = append(plugins, &shiro.Shiro{})
	plugins = append(plugins, &custom.Custom{})
	plugins = append(plugins, &xstream.Xstream{})
	plugins = append(plugins, &fingerprint.Fingerprint{})
	plugins = append(plugins, &js.JS{})
	return plugins
}
