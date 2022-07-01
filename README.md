# xmap
# TODO:
使用Golang，重新实现xray，并且开源


# 参考代码：
被动扫描 https://github.com/zema1/martian  
被动扫描 https://github.com/lqqyt2423/go-mitmproxy  
POC扫描  https://github.com/jweny/pocassist   
POC扫描  https://github.com/WAY29/pocV   
动态爬虫 https://github.com/Qianlitp/crawlergo  
基础爬虫 https://github.com/geziyor/geziyor  
SQL注入 https://github.com/sqlmapproject/sqlmap  
OWASP TOP10检测 https://github.com/andresriancho/w3af  
XSS 检测 https://github.com/hahwul/dalfox  
网站技术  https://github.com/chushuai/wappalyzer   
用Golang运行JavaScript https://github.com/dop251/goja  
返连平台 https://github.com/chennqqi/godnslog


# 目录结构
```
├── core
│   ├── assassin
│   │   ├── collector
│   │   │   ├── basiccrawler
│   │   │   │   └── basic_crawler.go
│   │   │   ├── burp.go
│   │   │   ├── config.go
│   │   │   ├── dummy.go
│   │   │   ├── mitm.go
│   │   │   ├── mitmhelper
│   │   │   │   ├── basic_auth.go
│   │   │   │   ├── encoding.go
│   │   │   │   ├── httpmirror.go
│   │   │   │   ├── ip_source.go
│   │   │   │   ├── webctrl_data.go
│   │   │   │   ├── webctrl.go
│   │   │   │   └── websocket.go
│   │   │   ├── request.go
│   │   │   ├── service-list.go
│   │   │   └── url-list.go
│   │   ├── ctrl
│   │   │   ├── bus.go
│   │   │   ├── config.go
│   │   │   ├── dispatcher.go
│   │   │   └── runner.go
│   │   ├── dev
│   │   │   └── license
│   │   │       └── license.go
│   │   ├── entry
│   │   │   ├── config.go
│   │   │   ├── convert.go
│   │   │   ├── entry.go
│   │   │   ├── genca.go
│   │   │   ├── reverse.go
│   │   │   ├── service_scan.go
│   │   │   ├── subdomain.go
│   │   │   ├── upgrade.go
│   │   │   ├── utils.go
│   │   │   └── webscan.go
│   │   ├── http
│   │   │   ├── client.go
│   │   │   ├── config.go
│   │   │   ├── cookie.go
│   │   │   ├── flow.go
│   │   │   ├── param.go
│   │   │   ├── request.go
│   │   │   ├── resource.go
│   │   │   ├── response.go
│   │   │   ├── statistics.go
│   │   │   └── utils.go
│   │   ├── main.go
│   │   ├── model
│   │   │   └── vuln.go
│   │   ├── output
│   │   │   ├── html_data.go
│   │   │   ├── htmlfile.go
│   │   │   ├── stdout.go
│   │   │   └── webhook.go
│   │   ├── plugins
│   │   │   ├── base
│   │   │   │   ├── bifrost.go
│   │   │   │   ├── config.go
│   │   │   │   └── plugin.go
│   │   │   ├── baseline
│   │   │   │   ├── baseline.go
│   │   │   │   ├── cookie.go
│   │   │   │   ├── cors.go
│   │   │   │   ├── header.go
│   │   │   │   ├── host_injection.go
│   │   │   │   ├── redirect.go
│   │   │   │   ├── sensitive_info.go
│   │   │   │   ├── serialization.go
│   │   │   │   ├── server_error.go
│   │   │   │   ├── ssl.go
│   │   │   │   └── unsafe_scheme.go
│   │   │   ├── bruteforce
│   │   │   │   ├── basicauth.go
│   │   │   │   ├── bruteforce_finger_community.go
│   │   │   │   ├── bruteforce.go
│   │   │   │   ├── data.go
│   │   │   │   ├── dvwa.go
│   │   │   │   └── formbrute_community.go
│   │   │   ├── cmd_injection
│   │   │   │   ├── cmd_injection.go
│   │   │   │   ├── expression.go
│   │   │   │   ├── generic.go
│   │   │   │   ├── payload.go
│   │   │   │   ├── phpcode.go
│   │   │   │   └── template.go
│   │   │   ├── crlf_injection
│   │   │   │   └── crlf_injection.go
│   │   │   ├── dirscan
│   │   │   │   ├── backup.go
│   │   │   │   ├── compare.go
│   │   │   │   ├── dirscan_data.go
│   │   │   │   ├── dirscan.go
│   │   │   │   ├── sourcemap.go
│   │   │   │   └── yaml.go
│   │   │   ├── fastjson
│   │   │   │   ├── deserialization.go
│   │   │   │   └── fastjson.go
│   │   │   ├── helper
│   │   │   │   ├── expr
│   │   │   │   │   ├── CustomInt.go
│   │   │   │   │   ├── element.go
│   │   │   │   │   ├── expr.go
│   │   │   │   │   ├── Origin.go
│   │   │   │   │   ├── OriginNumberToExpr.go
│   │   │   │   │   ├── OriginNumberToHex.go
│   │   │   │   │   ├── RandInt.go
│   │   │   │   │   ├── RandStr.go
│   │   │   │   │   ├── SleepTime.go
│   │   │   │   │   └── Space.go
│   │   │   │   ├── expression
│   │   │   │   │   ├── expression.go
│   │   │   │   │   └── types.go
│   │   │   │   ├── knowledge
│   │   │   │   │   └── know.go
│   │   │   │   └── seeyon
│   │   │   │       └── encode.go
│   │   │   ├── jsonp
│   │   │   │   ├── jsonp.go
│   │   │   │   └── parser.go
│   │   │   ├── path_traversal
│   │   │   │   ├── path_traversal.go
│   │   │   │   └── payloads.go
│   │   │   ├── phantasm
│   │   │   │   ├── loader.go
│   │   │   │   ├── phantasm.go
│   │   │   │   ├── pocs
│   │   │   │   │   └── gopoc
│   │   │   │   │       ├── ecology-dbconfig-info-leak.go
│   │   │   │   │       ├── poc_community.go
│   │   │   │   │       ├── seeyon-htmlofficeservlet-rce.go
│   │   │   │   │       ├── tomcat-cve-2020-1938.go
│   │   │   │   │       ├── tomcat-put.go
│   │   │   │   │       ├── tongda-arbitrarily-auth.go
│   │   │   │   │       └── tongda-lfi-upload-rce.go
│   │   │   │   ├── yaml_finger.go
│   │   │   │   └── yaml_poc_data.go
│   │   │   ├── plugins.go
│   │   │   ├── redirect
│   │   │   │   ├── redirect.go
│   │   │   │   └── script.go
│   │   │   ├── shiro
│   │   │   │   ├── default.go
│   │   │   │   ├── deserialization.go
│   │   │   │   └── shiro.go
│   │   │   ├── sql_injection
│   │   │   │   ├── sqli_detector
│   │   │   │   │   ├── db_error.go
│   │   │   │   │   ├── detector.go
│   │   │   │   │   └── sqli_payload
│   │   │   │   │       ├── base.go
│   │   │   │   │       ├── booleaned_based.go
│   │   │   │   │       ├── error_based.go
│   │   │   │   │       └── time_based.go
│   │   │   │   └── sql_injection.go
│   │   │   ├── ssrf
│   │   │   │   ├── payload.go
│   │   │   │   └── ssrf.go
│   │   │   ├── struts
│   │   │   │   ├── devmode.go
│   │   │   │   ├── ognl.go
│   │   │   │   ├── s2-005.go
│   │   │   │   ├── s2-007.go
│   │   │   │   ├── s2-009.go
│   │   │   │   ├── s2-013.go
│   │   │   │   ├── s2-015.go
│   │   │   │   ├── s2-016.go
│   │   │   │   ├── s2-032.go
│   │   │   │   ├── s2-037.go
│   │   │   │   ├── s2-045.go
│   │   │   │   ├── s2-046.go
│   │   │   │   ├── s2-052.go
│   │   │   │   ├── s2-057.go
│   │   │   │   └── struts.go
│   │   │   ├── thinkphp
│   │   │   │   ├── invoke_rce.go
│   │   │   │   ├── method_rce.go
│   │   │   │   ├── preg_rce.go
│   │   │   │   ├── sqli.go
│   │   │   │   ├── thinkphp.go
│   │   │   │   └── v6_filewrite.go
│   │   │   ├── upload
│   │   │   │   ├── payloads.go
│   │   │   │   └── upload.go
│   │   │   ├── xss
│   │   │   │   ├── element.go
│   │   │   │   ├── helper.go
│   │   │   │   ├── js
│   │   │   │   │   ├── esprima.go
│   │   │   │   │   └── parser.go
│   │   │   │   ├── pos_script.go
│   │   │   │   ├── pos_style.go
│   │   │   │   ├── pos_tag.go
│   │   │   │   ├── pos_text.go
│   │   │   │   ├── query_response.go
│   │   │   │   ├── request_builder.go
│   │   │   │   └── xss.go
│   │   │   └── xxe
│   │   │       ├── blind.go
│   │   │       ├── echo.go
│   │   │       ├── payloads.go
│   │   │       └── xxe.go
│   │   ├── resource
│   │   │   └── service.go
│   │   ├── reverse
│   │   │   ├── api_base.go
│   │   │   ├── cland
│   │   │   │   └── cland_data.go
│   │   │   ├── config.go
│   │   │   ├── conn.go
│   │   │   ├── db.go
│   │   │   ├── dns_server.go
│   │   │   ├── fetch.go
│   │   │   ├── group.go
│   │   │   ├── http_server.go
│   │   │   ├── payload_template.go
│   │   │   ├── reverse.go
│   │   │   ├── rmi_server.go
│   │   │   └── server.go
│   │   └── utils
│   │       ├── buildinfo
│   │       │   ├── info.go
│   │       │   ├── oui_data.go
│   │       │   └── update.go
│   │       ├── case_insensitive.go
│   │       ├── cert.go
│   │       ├── comparer
│   │       │   ├── header.go
│   │       │   ├── htmlcompare
│   │       │   │   └── compare.go
│   │       │   ├── response.go
│   │       │   └── strcompare
│   │       │       ├── compare.go
│   │       │       └── utils.go
│   │       ├── cusctx
│   │       │   └── ctx.go
│   │       ├── file.go
│   │       ├── guess
│   │       │   ├── guess.go
│   │       │   ├── response.go
│   │       │   └── value.go
│   │       ├── math.go
│   │       ├── network.go
│   │       ├── print.go
│   │       ├── rand.go
│   │       ├── rlimit
│   │       │   └── file.go
│   │       ├── string.go
│   │       ├── sync.go
│   │       ├── tamper.go
│   │       ├── test.go
│   │       ├── time.go
│   │       ├── url.go
│   │       └── ysoserial
│   │           ├── Gadgets
│   │           │   ├── CommonsBeanutils1.go
│   │           │   ├── CommonsBeanutils2.go
│   │           │   ├── CommonsCollectionsK1.go
│   │           │   ├── CommonsCollectionsK2.go
│   │           │   ├── gadget.go
│   │           │   ├── Jdk7u21.go
│   │           │   └── Jdk8u20.go
│   │           └── ysoserial.go
│   ├── rpc
│   │   └── pb
│   │       └── gunkit.pb.go
│   └── utils
│       ├── checker
│       │   ├── error.go
│       │   ├── filter
│       │   │   ├── badger_filter.go
│       │   │   └── sync_map_filter.go
│       │   ├── matcher
│       │   │   ├── glob_matcher.go
│       │   │   ├── hostname_matcher.go
│       │   │   ├── interface.go
│       │   │   ├── key_matcher.go
│       │   │   ├── port_matcher.go
│       │   │   └── regexp_matcher.go
│       │   ├── request_checker.go
│       │   ├── service_checker.go
│       │   ├── url_checker.go
│       │   └── util.go
│       ├── collections
│       │   └── queue.go
│       ├── config.go
│       ├── connection.go
│       ├── domainutil.go
│       ├── host_n_port_utils.go
│       ├── http_utils.go
│       ├── log
│       │   ├── config.go
│       │   └── log.go
│       ├── network
│       │   └── network.go
│       ├── os_utils.go
│       ├── printer
│       │   ├── base.go
│       │   ├── console.go
│       │   ├── json.go
│       │   ├── multi.go
│       │   ├── nice
│       │   │   └── color.go
│       │   └── text.go
│       ├── rand_utils.go
│       └── str_utils.go
├── doc
│   ├── xray_dep.txt
│   ├── xray_file.md
│   └── xray.md
├── ext
│   ├── crawler
│   │   ├── analysis_page.go
│   │   ├── basic_task_hander.go
│   │   ├── body.go
│   │   ├── browser_task_hander.go
│   │   ├── check_url.go
│   │   ├── chrome_util.go
│   │   ├── client.go
│   │   ├── config.go
│   │   ├── crawer.go
│   │   ├── filter.go
│   │   ├── js
│   │   │   └── js.go
│   │   └── util.go
│   ├── fastdomain
│   │   ├── datasource
│   │   │   ├── alienvault.go
│   │   │   ├── ask.go
│   │   │   ├── baidu.go
│   │   │   ├── base.go
│   │   │   ├── bing.go
│   │   │   ├── brute.go
│   │   │   ├── certspotter.go
│   │   │   ├── crtsh.go
│   │   │   ├── dnsfinder.go
│   │   │   ├── fofa.go
│   │   │   ├── google.go
│   │   │   ├── hacktarget.go
│   │   │   ├── httpfinder.go
│   │   │   ├── ip138.go
│   │   │   ├── myssl.go
│   │   │   ├── qianxun.go
│   │   │   ├── quake.go
│   │   │   ├── rapiddns.go
│   │   │   ├── riskiq.go
│   │   │   ├── sogou.go
│   │   │   ├── sublist3r.go
│   │   │   ├── threatminer.go
│   │   │   ├── virustotal.go
│   │   │   └── yahoo.go
│   │   ├── dns
│   │   │   ├── client.go
│   │   │   └── round_robin.go
│   │   ├── fastdomain.go
│   │   ├── geodb
│   │   │   ├── client.go
│   │   │   └── geodb.go
│   │   ├── model
│   │   │   ├── dict_data.go
│   │   │   ├── dicts.go
│   │   │   └── model.go
│   │   └── utils
│   │       └── utils.go
│   └── yamlcel
│       ├── client
│       │   ├── http
│       │   │   ├── request.go
│       │   │   └── response.go
│       │   ├── http.go
│       │   ├── reverse.go
│       │   ├── tcp.go
│       │   └── udp.go
│       └── load.go
├── go.mod
├── go.sum
└── README.md
```
