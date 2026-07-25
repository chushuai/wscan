/**
* @Author: shaochuyu
* @Date: 7/25/2026
*
* Embedded vulnerability database. Each .xml file under core/web/vulndb/
* describes one vulnerability type (name/description/impact/recommendation/
* severity/cvss/details_template/tags/references). Files are generated from
* core/scannable_vuln.json by core/web/gen_vulndb.py.
*
* The vuln "type id" (the SPA groups vulns by this) is the xml filename without
* the .xml suffix — e.g. xss.xml -> "xss". Plugin Binding.IDs use action-scoped
* names (xss/reflected/default); vulnIDAliases maps them onto DB ids so a vuln
* record carries the right advisory text without changing plugin ids.
 */
package web

import (
	"embed"
	"encoding/xml"
	"strings"
)

//go:embed vulndb/*.xml
var vulndbFS embed.FS

// vulnDBEntry is the parsed shape of one vulndb/*.xml file.
type vulnDBEntry struct {
	ID               string
	Name             string
	Description      string
	Impact           string
	Recommendation   string
	Severity         int
	Score            float64
	HasScore         bool
	CVSS2            string
	CVSS3            string
	CVSS4            string
	DetailsTemplate  string
	Tags             []string
	References       []vulnDBRef
}

type vulnDBRef struct {
	Title string
	URL   string
}

type vulnDBXML struct {
	XMLName         xml.Name `xml:"vuln"`
	ID              string   `xml:"id,attr"`
	Name            string   `xml:"name"`
	Description     string   `xml:"description"`
	Impact          string   `xml:"impact"`
	Recommendation  string   `xml:"recommendation"`
	Severity        int      `xml:"severity"`
	Score           *float64 `xml:"score"`
	CVSS2           string   `xml:"cvss2"`
	CVSS3           string   `xml:"cvss3"`
	CVSS4           string   `xml:"cvss4"`
	DetailsTemplate string   `xml:"details_template"`
	Tags            []string `xml:"tags>tag"`
	Refs            []struct {
		Title string `xml:"title"`
		URL   string `xml:"url"`
	} `xml:"references>reference"`
}

var vulnDB = func() map[string]*vulnDBEntry {
	db := map[string]*vulnDBEntry{}
	entries, err := vulndbFS.ReadDir("vulndb")
	if err != nil {
		return db
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".xml") {
			continue
		}
		raw, err := vulndbFS.ReadFile("vulndb/" + e.Name())
		if err != nil {
			continue
		}
		var x vulnDBXML
		if err := xml.Unmarshal(raw, &x); err != nil {
			continue
		}
		entry := &vulnDBEntry{
			ID:              x.ID,
			Name:            x.Name,
			Description:     x.Description,
			Impact:          x.Impact,
			Recommendation:  x.Recommendation,
			Severity:        x.Severity,
			CVSS2:           x.CVSS2,
			CVSS3:           x.CVSS3,
			CVSS4:           x.CVSS4,
			DetailsTemplate: x.DetailsTemplate,
			Tags:            x.Tags,
		}
		if x.Score != nil {
			entry.Score = *x.Score
			entry.HasScore = true
		}
		for _, r := range x.Refs {
			entry.References = append(entry.References, vulnDBRef{Title: r.Title, URL: r.URL})
		}
		db[entry.ID] = entry
	}
	return db
}()

// vulnIDAliases maps a plugin Binding.ID to the vulndb xml stem (id) that
// describes the same vulnerability class. The AWVS-derived vuln DB uses its
// own naming (e.g. "xss", "sql_injection", "directory_traversal"); wscan's
// plugins use action-scoped ids (e.g. "xss/reflected/default",
// "sqldet/boolean/default"). Only the canonical id is stored on the vuln
// record (Binding.ID is unchanged for back-compat); the alias is resolved at
// lookup time so a vuln carries the right advisory text without forcing every
// plugin id to match a DB filename exactly.
var vulnIDAliases = map[string]string{
	"xss/reflected/default":               "xss",
	"xss/reflected/cookie":                "xss",
	"xss/reflected/referer":               "xss",
	"xss/reflected/ie-feature":            "xss",
	"blind_xss":                           "xss",
	"sqldet/boolean/default":              "sql_injection",
	"sqldet/blind-based/default":          "sql_injection",
	"sqldet/error-based/default":          "sql_injection",
	"sqldet/cookie/default":               "sql_injection",
	"thinkphp/sqli/default":               "sql_injection",
	"cmd-injection":                       "code_execution",
	"nodejs-injection":                    "code_execution",
	"crlf-injection/dispatcher/default":   "crlf_injection",
	"xxe/dispatcher/default":              "xxe",
	"path-traversal/path-traversal/default": "directory_traversal",
	"pathbrute/default":                   "directory_traversal",
	"redirect/redirect/default":           "open_redirect",
	"baseline/injection/open-redirect":    "open_redirect",
	"ssrf/default":                        "ssrf",
	"ssrf/internal-service":               "ssrf",
	"esi_injection":                       "esi_injection",
	"prototype_pollution":                 "prototype_pollution",
	"el_injection":                        "expression_language_injection",
	"upload/upload/default":               "file_upload",
	"jsonp/default":                       "jsonp_hijacking",
	"fastjson/deserialization/default":    "java_object_deserialization",
	"shiro/shiro/rememberme-deserialization": "java_object_deserialization",
	"shiro/shiro/default-key":             "apache_shiro_auth_bypass_cve-2020-17523",
	"poc-go-log4j-rce":                    "apache_log4j_rce",
	"poc-go-tomcat-put":                   "tomcat_put_cve_2017_12615",
	"struts/devmode/default":              "struts_devmode",
	"struts/s2-046/default":               "apache_struts_s2_046",
	"struts/s2-045/default":               "apache_struts_s2_046",
	"struts/s2-016/default":               "struts2_remote_code_execution_s2016",
	"struts/s2-052/default":               "struts_rce_s2-052_cve-2017-9805",
	"struts/s2-057/default":               "struts2_rce_s2_057",
	"struts/s2-005/default":               "struts2_remote_code_execution_s2014",
	"struts/s2-007/default":               "struts2_remote_code_execution_s2014",
	"struts/s2-009/default":               "struts2_remote_code_execution",
	"struts/s2-013/default":               "struts2_remote_code_execution_s2014",
	"struts/s2-015/default":               "struts2_remote_code_execution",
	"struts/s2-032/default":               "struts2_remote_code_execution",
	"struts/s2-037/default":               "struts2_remote_code_execution",
	"thinkphp/rce/invoke":                 "thinkphp_rce",
	"thinkphp/rce/method":                 "thinkphp_rce",
	"thinkphp/rce/preg":                   "thinkphp_rce",
	"thinkphp/v6-file-write/default":      "thinkphp_v6_file_write",
	"xstream/CVE-2020-26217":              "xstream_cve_2020_26217",
	"xstream/CVE-2020-26258":              "xstream_cve_2020_26258",
	"xstream/CVE-2020-26259":              "xstream_cve_2020_26259",
	"xstream/CVE-2021-21345":              "xstream_cve_2021_21345",
	"xstream/CVE-2021-21351":              "xstream_cve_2021_21351",
	"xstream/CVE-2021-39144":              "xstream_cve_2021_39144",
	"xstream/CVE-2021-39152":              "xstream_cve_2021_39152",
	"xstream/RCE/CVE-2013-7285":           "xstream_cve_2013_7285",
	"jboss-audit/deserialization":         "java_object_deserialization",
	"baseline/sensitive/application_error": "application_error",
	"baseline/config/django-debug-mode":   "django_debug_mode",
	"django-audit/debug-mode":             "django_debug_mode",
	"flask-audit/debug-mode":              "flask_debug_mode",
	"baseline/config/flask-debug-mode":    "flask_debug_mode",
	"baseline/config/python-traceback-debug": "application_error_traceback",
	"baseline/config/rails-debug-mode":    "rails_debug_mode",
	"django-audit/fingerprint":            "fingerprint",
	"flask-audit/fingerprint":             "fingerprint",
	"spring-audit/fingerprint":            "fingerprint",
	"jboss-audit/fingerprint":             "fingerprint",
	"weblogic-audit/fingerprint":          "fingerprint",
	"tomcat-audit/fingerprint":            "fingerprint",
	"fingerprint/default":                 "fingerprint",
	"waf/detection":                       "waf_detected",
	"baseline/sensitive/email-leak":       "email_address_found",
	"baseline/sensitive/china-id-card":    "sensitive_info_china_id_card",
	"baseline/sensitive/china-bank-card":  "sensitive_info_china_bank_card",
	"baseline/sensitive/china-phone":      "sensitive_info_china_phone",
	"baseline/sensitive/china-address":    "sensitive_info_china_address",
	"baseline/sensitive/cookie-password-leak": "possible_sensitive_files",
	"baseline/sensitive/system-path":      "possible_sensitive_files",
	"baseline/sensitive/html-comment":     "possible_sensitive_files",
	"baseline/sensitive/private-ip":       "possible_sensitive_files",
	"baseline/sensitive/serialization-data": "possible_sensitive_files",
	"sensitive_file_exposure":             "possible_sensitive_files",
	"js/sensitive-content-check":          "possible_sensitive_files",
	"apikey-leak/secret-key-exposure":     "api_key_exposure",
	"source-code-disclosure/default":      "server_source_code_disclosure",
	"vcs_git_leak":                        "git_repository_found",
	"vcs_svn_leak":                        "vcs_svn_leak",
	"baseline/ssl/outdated-version":       "crawler_https_insecure_maxtls",
	"ssl_insecure_protocol":               "crawler_https_insecure_maxtls",
	"ssl_weak_cipher":                     "crawler_https_weak_key_length",
	"ssl_certificate_expired":             "ssl_certificate_expired",
	"ssl_freak_vulnerable":                "crawler_https_weak_key_length",
	"ssl_drown_vulnerable":                "crawler_https_insecure_maxtls",
	"hsts_not_implemented":                "hsts_not_implemented",
	"baseline/config/unsafe-scheme":       "no_https",
	"baseline/cookie/http-only":           "crawler_cookie_without_httponly",
	"baseline/cookie/secure":              "crawler_cookie_without_secure",
	"baseline/cookie/loosely_scoped":      "crawler_session_cookie_scoped_to_parent_domain",
	"baseline/cookie/no_sameSite":         "cookie_misconfiguration",
	"baseline/cookie/none_sameSite":       "cookie_misconfiguration",
	"baseline/cookie/badval_sameSite":     "cookie_misconfiguration",
	"baseline/csp/notices":                "csp_not_implemented",
	"baseline/csp/both":                   "csp_misconfiguration",
	"baseline/csp/malformed":              "csp_misconfiguration",
	"baseline/csp/meta_bad_directive":     "csp_misconfiguration",
	"baseline/csp/scriptsrc_unsafe":       "csp_unsafe_inline_script",
	"baseline/csp/scriptsrc_unsafe_eval":  "csp_unsafe_eval",
	"baseline/csp/scriptsrc_unsafe_hashes": "csp_unsafe_hashes",
	"baseline/csp/stylesrc_unsafe_hashes": "csp_unsafe_hashes",
	"baseline/csp/stylesrc_unsafe_inline": "csp_unsafe_inline_style",
	"baseline/csp/wildcard":               "csp_wildcard",
	"baseline/csp/xcsp":                   "csp_legacy_header",
	"baseline/csp/xwkcsp":                 "csp_legacy_header",
	"baseline/header/content_security_policy_missing": "csp_not_implemented",
	"baseline/header/content_type_missing": "content_type_missing",
	"baseline/injection/host-injection":   "host_header_attack",
	"host-header/default":                 "host_header_attack",
	"http_parameter_pollution":            "http_parameter_pollution",
	"es_exposed":                          "elasticsearch_exposed",
	"phpmyadmin_exposed":                  "phpmyadmin_exposed",
	"solr_exposed":                        "solr_exposed",
	"spring-audit/actuator-endpoints":     "spring_actuator_endpoints_exposed",
	"spring-audit/env-secrets":            "spring_actuator_env_secrets",
	"spring-audit/jolokia":                "spring_jolokia_exposed",
	"spring-audit/known-cves":             "spring_known_cves",
	"spring-audit/spel-injection":         "expression_language_injection",
	"jboss-audit/default-credentials":     "web_applications_default_credentials",
	"jboss-audit/jmx-console":             "jboss_jmx_console_exposed",
	"jboss-audit/mbeans":                  "jboss_mbeans_exposed",
	"jboss-audit/status-servlet":          "jboss_status_servlet",
	"weblogic-audit/console-exposure":     "weblogic_console_exposed",
	"weblogic-audit/default-creds":        "web_applications_default_credentials",
	"weblogic-audit/uddi-ssrf":            "ssrf",
	"weblogic-audit/wls-wsat-rce":         "weblogic_wls_wsat_rce",
	"tomcat-audit/default-credentials":    "web_applications_default_credentials",
	"tomcat-audit/example-apps":           "tomcat_example_apps",
	"tomcat-audit/manager-exposure":       "tomcat_manager_exposure",
	"tomcat-audit/ghostcat-cve-2020-1938": "tomcat_ghostcat_cve_2020_1938",
	"tomcat-audit/put-rce-cve-2017-12615": "tomcat_put_cve_2017_12615",
	"django-audit/admin-weak-password":    "weak_password",
	"brute-force/basic-auth/default":      "basic_auth_over_http",
	"brute-force/form-brute/default":      "weak_password",
	"baseline/cache/control":              "crawler_sensitive_page_could_be_cached",
	"baseline/config/autocomplete-missing": "autocomplete_enabled",
	"baseline/config/crossdomain":         "crossdomain_policy",
	// cookie weak-key checks all share one advisory entry.
	"cookiekey/beaker/weak-key":             "cookiekey_weak_key",
	"cookiekey/bottlepy/weak-key":           "cookiekey_weak_key",
	"cookiekey/django/weak-key":             "cookiekey_weak_key",
	"cookiekey/express-cookie-session/weak-key": "cookiekey_weak_key",
	"cookiekey/express-session/weak-key":    "cookiekey_weak_key",
	"cookiekey/flask/weak-key":              "cookiekey_weak_key",
	"cookiekey/jwt/weak-key":                "cookiekey_weak_key",
	"cookiekey/laravel/weak-key":            "cookiekey_weak_key",
	"cookiekey/pyramid/weak-key":            "cookiekey_weak_key",
	"cookiekey/rack/weak-key":               "cookiekey_weak_key",
	"cookiekey/tornado/weak-key":            "cookiekey_weak_key",
	"cookiekey/web2py/weak-key":             "cookiekey_weak_key",
	"cookiekey/yii2/weak-key":               "cookiekey_weak_key",
}

// lookupVulnDB returns the DB entry for a vuln type id (Binding.ID / xml stem),
// or nil if no matching entry exists. Aliases (vulnIDAliases) are tried first
// so a plugin id like "xss/reflected/default" resolves to the "xss" entry.
func lookupVulnDB(id string) *vulnDBEntry {
	if id == "" {
		return nil
	}
	if alias, ok := vulnIDAliases[id]; ok {
		if e, ok := vulnDB[alias]; ok {
			return e
		}
	}
	if e, ok := vulnDB[id]; ok {
		return e
	}
	return nil
}
