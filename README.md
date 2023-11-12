# wscan
Wscan是一款专注于WEB安全的扫描器，它向Nmap致敬，而Nmap已经开源25年了。我们也计划在未来25年内持续更新Wscan，并将其持续开源。我们欢迎所有对web安全感兴趣的人一起加入我们的开发团队。

我们的目标是开发一款使用机器学习进行渗透测试的工具。与其他工具不同的是，我们的工具可以自动学习攻击和防御的模式，并根据具体的目标进行个性化的攻击。这样一来，我们的攻击效率和准确性将大大提高，同时也能降低误判的概率。

我们的工具采用了机器学习技术，实现了全自动化的Web渗透测试。这意味着无需手动添加和更新规则和签名，它能够自动学习和适应新的攻击模式和漏洞。

机器学习技术还能够快速处理大量的数据和流量，从而大幅提高测试效率和准确性。此外，它能够识别和发现一些人工难以察觉的漏洞和弱点，从而改善测试质量和可靠性。

我们相信，使用机器学习技术进行渗透测试，将是未来网络安全的一个重要方向。我们希望我们的工具能够帮助更多的人保障网络安全，为网络安全事业做出贡献。


# 运行示例 

⬇️[下载地址](https://github.com/chushuai/wscan/releases)
```
（1）主动扫描
/wscan/core/wscan  --log-level=debug ws --basic-crawler http://testphp.vulnweb.com/
（2）被动扫描
/wscan/core/wscan  --log-level=debug ws --listen=127.0.0.1:1000
```
# 项目进展
很高兴地宣布，基于事件订阅WEB通用插件调度和HTTP参数形变模块已经完成了开发工作，同时，动态漏扫爬虫也已经完成了。一旦项目在GitHub上获得超过500个星星，将其全部开源。 
在此之前，开始接收第三方提交的WEB通用插件代码，希望能够与更多的开发者们一起合作，共同完善Wscan，为用户提供更好的服务。欢迎您的参与和贡献！
具体请参考《WEB通用漏扫插件编写指南.md》,直接提交PR即可，保证一天内回复。

2023.04.22 完成了基于消息订阅的插件调度模块，可以完成简单的扫描功能 (Stars > 300 解锁)  
2023.07.07 完成了YAML POC扫描模块 (Stars > 500 解锁)  
2023.11.05 发布v1.0.0 二进制版,支持简单的Web通用漏洞检测  
2023.11.12 发布v1.0.2 二进制版,支持被动扫描  


# TODO:
传统的扫描部分采用了Golang语言重新实现了xray，并将其开源。未来的扫描部分将采用机器学习技术，旨在构建更为先进的扫描器。   

2023.08.30 完成WEB通用漏洞扫描插件  
2023.10.30 完成通过机器学习降低误报  
2023.11.30 重构扫描器(代号apollo)  
202X.XX.XX 使用机器学习构建Payload进行自动化扫描  
# 架构简析
![](doc/img/Wscan.png)

# 参考代码：
机器学习库 :https://github.com/cdipaolo/goml  
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
用Golang运行JavaScript https://github.com/dop251/goja  
反连平台 https://github.com/chennqqi/godnslog  
WEB漏洞扫描器 https://www.zaproxy.org/    
WEB漏洞扫描器 https://github.com/Arachni/arachni   
WEB漏洞扫描器 https://github.com/andresriancho/w3af  
WEB漏洞扫描器 https://github.com/w-digital-scanner/w13scan  
WEB漏洞扫描器 https://github.com/wrenchonline/glint  
JSONP劫持漏洞检测 https://github.com/jweny/check_jsonp_based_on_ast  
子域名爆破 https://github.com/projectdiscovery/subfinder/  
OWASP Cornucopia: 这是一个由OWASP（开放Web应用程序安全项目）开发的开源项目，它使用机器学习算法自动化检测Web应用程序中的漏洞。

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


