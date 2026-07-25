/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package plugins

import (
	"wscan/core/plugins/apikeyleak"
	"wscan/core/plugins/base"
	"wscan/core/plugins/baseline"
	"wscan/core/plugins/bruteforce"
	"wscan/core/plugins/cmd_injection"
	"wscan/core/plugins/crlf_injection"
	"wscan/core/plugins/custom"
	"wscan/core/plugins/dirscan"
	"wscan/core/plugins/djangoaudit"
	"wscan/core/plugins/fastjson"
	"wscan/core/plugins/fingerprint"
	"wscan/core/plugins/jbossaudit"
	"wscan/core/plugins/js"
	"wscan/core/plugins/jsonp"
	"wscan/core/plugins/path_traversal"
	"wscan/core/plugins/pathbrute"
	"wscan/core/plugins/prometheus"
	"wscan/core/plugins/redirect"
	"wscan/core/plugins/sensitivefile"
	"wscan/core/plugins/shiro"
	"wscan/core/plugins/sql_injection"
	"wscan/core/plugins/sslaudit"
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
	// plugins = append(plugins, &prototypepollution.PrototypePollution{})
	plugins = append(plugins, &waftest.CustomTmpl{})
	plugins = append(plugins, &cmd_injection.CmdInjection{})
	plugins = append(plugins, &bruteforce.BruteForce{})
	// plugins = append(plugins, &elinject.ELInject{})
	// plugins = append(plugins, &esiinject.ESIInject{})
	plugins = append(plugins, &struts.Struts{})
	plugins = append(plugins, &ssrf.SSRF{})
	// plugins = append(plugins, &hostheader.HostHeader{})
	// plugins = append(plugins, &hpp.HPP{})
	plugins = append(plugins, &thinkphp.Thinkphp{})
	plugins = append(plugins, &xxe.XXE{})
	plugins = append(plugins, &redirect.Redirect{})
	plugins = append(plugins, &fastjson.FastJSON{})
	plugins = append(plugins, &upload.Upload{})
	plugins = append(plugins, &baseline.Baseline{})
	// plugins = append(plugins, &cookiekey.CookieKey{})
	plugins = append(plugins, &shiro.Shiro{})
	plugins = append(plugins, &custom.Custom{})
	plugins = append(plugins, &xstream.Xstream{})
	plugins = append(plugins, &fingerprint.Fingerprint{})
	plugins = append(plugins, &js.JS{})
	// plugins = append(plugins, &nodejsinject.NodeJSInject{})
	plugins = append(plugins, &pathbrute.PathBrute{})
	// plugins = append(plugins, &swagger.Swaggers{})
	// plugins = append(plugins, &vcsleak.VCSLeak{})
	plugins = append(plugins, &sensitivefile.SensitiveFile{})
	// plugins = append(plugins, &sourcecodedisclosure.SourceCodeDisclosure{})
	plugins = append(plugins, &sslaudit.SSLAudit{})
	plugins = append(plugins, &apikeyleak.APIKeyLeak{})
	//plugins = append(plugins, &esaudit.ESAudit{})
	//plugins = append(plugins, &phpmyadminaudit.PhpMyAdminAudit{})
	//plugins = append(plugins, &solraudit.SolrAudit{})
	//plugins = append(plugins, &weblogicaudit.WebLogicAudit{})
	plugins = append(plugins, &djangoaudit.DjangoAudit{})
	//plugins = append(plugins, &flaskaudit.FlaskAudit{})
	//plugins = append(plugins, &tomcataudit.TomcatAudit{})
	//plugins = append(plugins, &springaudit.SpringAudit{})
	plugins = append(plugins, &jbossaudit.JBossAudit{})

	return plugins
}
