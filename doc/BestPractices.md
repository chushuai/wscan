# Preamble
Recently, I conducted an in-depth analysis of several Webscan scanners, originally assuming that their developers were experienced, near-retirement veterans with many years of experience. However, the reality is quite different, as they are actually young people with flexible minds who have just graduated a few years ago.
This has caught me off guard as someone who has been developing scanners for nearly a decade, and I feel deeply anxious. As long as people need Wscan, I will work with young people for another 25 years in the next 25 years, continuing to update Wscan and bring young people into the old.
I will try my best to make it the best and strive for perfection, leaving no regrets.
# Function Introduction
Wscan is an open source security assessment tool that is mainly used to scan common web security issues, supports custom POCs, and is a very powerful web vulnerability scanner. Additionally, the tool has machine learning-based vulnerability detection and automated testing capabilities.

When using Wscan for scanning, it is essential to obtain authorization from the other party. Otherwise, it is unethical to scan someone else's server.

A vulnerability scanner is not omnipotent, and it may not detect some very deep vulnerabilities. Therefore, we must learn the principles of vulnerabilities well and use knowledge to solve vulnerability problems.

# Detection Module

|       Detection Module       | Wscan | Xray | illustrate                                                              |
|--------------|-------|------|-----------------------------------------------------------------|
| `xss`        |   √    |   √   | Detect XSS vulnerabilities using semantic analysis                                               |
| `sqldet`     |   √    |   √   | Support for error injection, boolean injection, and time blind injection                                             |
| `cmd-injection` |      √ |   √   | Support shell command injection, PHP code execution, template injection, etc.                                   |
| `dirscan`    |    √   |   √   | Detect more than 10 sensitive paths and files such as backup files, temporary files, debug pages, configuration files, and so on                          |
| `path-traversal` |     √  |   √   | Supports common platforms and encodings                                                       |
| `xxe`        |    √   |    √  | Support for echo and anti-connection platform detection                                                    |
| `upload`     |     √  |    √  | Support common backend languages                                                       |
| `brute-force` |     √  |    √  | The community edition supports detecting HTTP basic authentication and simple form weak passwords, with built-in common username and password dictionaries                          |
| `jsonp`      |    √   |  √    | Detecting the jsonp interface that contains sensitive information that can be read across domains                                      |
| `ssrf`       |    √   |   √   | SSRF detection module, supporting common bypass techniques and anti-connection platform detection                                      |
| `baseline`   |    √   |  √    | Detect low SSL versions, missing or incorrectly added HTTP headers, and more                                   |
| `redirect`   |   √    |  √    | Support HTML meta redirect, 30x redirect, etc.                                        |
| `crlf-injection` |     √  | √     | Detect HTTP header injection, support query, body and other parameters                               |
| `xstream`    |     developing  |√      | Detect XStream series vulnerabilities                                                 |
| `struts`     |    √   | √     | Detect whether the target website has Struts2 series vulnerabilities, including common vulnerabilities such as s2-016, s2-032, s2-045, s2-059, and s2-061.|
| `thinkphp`   |  √     | √     | Detecting vulnerabilities in websites developed using ThinkPHP                                            |
| `shiro`      |    developing   |   √   | Detecting Shiro deserialization vulnerabilities                                                |
| `fastjson`   |  √     |  √    | Detect fastjson vulnerability                                                 |
| `Nuclei YAML POC` |    √    |  ×     | Nuclei standard POC detection plugin                                               |
| `Xray YAML POC` |     √     | √        | POC detection plugin for Xray standard                                                 |
| `Goby JSON POC` |     √       |     ×      | Gody standard POC detection plugin                                                 |
| `WAF bypass detection`    |     √         |  ×           |       Customize various special payloads to test whether Waf can intercept them                                                          |

# Active Scanning
## Ⅰ.Deep scanning
When Wscan is run for the first time, it will generate a file named config.yaml. Set the enabled setting to True for all plugins under plugins.
**If you want to perform a POC scan, please first refer to the POC scan configuration, download the plugin package, and configure the plugin package path.**
```
./wscan  --log-level=debug ws --basic-crawler http://testphp.vulnweb.com/ --json-output=wscan_scan_result.json --html-output=wscan_scan_result.html
./wscan  --log-level=debug ws --browser  http://testphp.vulnweb.com/ --html-output=wscan_scan_result.html
./wscan  --log-level=debug ws --url http://testphp.vulnweb.com/listproducts.php?cat=1  --json-output=wscan_scan_result.json
./wscan  --log-level=debug ws --url-file=/wscan/url_file.txt --html-output=wscan_scan_result.html
```
## Ⅱ.Special scanning
Use the plug parameter in the command line to enable the plug-in to be scanned
```
./wscan  --log-level=debug ws  --plug=sqldet --basic-crawler http://testphp.vulnweb.com/ --html-output=wscan_scan_result.html
```
# Passive scanning
## Ⅰ.Generate and install CA
After running the genca command, two files, ca.crt and ca.key, will be generated in the current folder.
```
./wscan genca
```
The installation method of CA is the same as XRAY, and you can refer to the XRAY document

## Ⅱ.Special scanning
Use the plug parameter in the command line to enable the plug-in to be scanned
```
./wscan  --log-level=debug ws  --plug=sqldet,xss  --listen=127.0.0.1:1000 --json-output=wscan_scan_result.json  
```

## Ⅲ.Deep scanning passive
When Wscan is run for the first time, it will generate a file named config.yaml. Set the enabled property of all the plugins under plugins to True.
**If you want to perform a POC scan, please first refer to the POC scan configuration, download the plugin package, and configure the plugin package path.**
```
./wscan  --log-level=debug ws --listen=127.0.0.1:1000 --json-output=wscan_scan_result.json  
```

# POC scanning
## Download plugin package
Wscan does not have any built-in POC plugins, but its Prometheus plugin engine already supports Nuclei, XRAY, and Goby standard POC plugins.  
Unlike other scanners, Wscan can customize the depth of POC detection, allowing it to discover more web security issues.
### Step1 
Xray/Goby POC plugin package download address
```
https://github.com/chushuai/wscan-poc/releases
```

### Step2
Nuclei POC plugin package download address
``` 
https://github.com/projectdiscovery/nuclei-templates/tree/main/http
```

## Special scanning
Ⅰ. Simultaneously scan Nuclei, XRAY, and Goby POC plugins. In this mode, only the POC detection plugin is enabled, and other types of plugins are not enabled.
```
./wscan --log-level=debug ws  --poc=/your_wscan_poc/wscan-poc/pocs/* --url http://testphp.vulnweb.com/ --html-output=wscan_scan_result.html
./wscan --log-level=debug ws  --poc=/your_wscan_poc/wscan-poc/pocs/*  --url-file=/url_file.txt  --html-output=wscan_scan_result.html
```
## Deep scanning
Ⅰ.The operation mode is consistent with the active and passive scanning, but the plug-in package path needs to be configured
```
prometheus:
    enabled: true
    depth: 1                 # Is the detection depth, default is 1, that is, only run the plugin when the URL depth is 0 and 1
    auto_load_poc: false
    include_poc: 
       - C:\wscan_windows_amd64.exe\wscan-poc-1.0.1\pocs\*
    exclude_poc: []

```


# Reverse module
When performing vulnerability detection, we will find that there are many vulnerabilities that appear to have no response after executing some commands, such as command execution vulnerabilities, log4j rce, fastjson, ssrf, etc. However, due to the lack of corresponding display on the front end, we cannot know whether the file was successfully read. Therefore, when facing such vulnerabilities, we need an anti-connection platform. By letting the target execute ping, curl, and other commands, we can initiate requests to the anti-connection platform. After receiving the request, the anti-connection platform can tell us that the command was triggered, which means that there is a vulnerability.

Notice： **Wscan does not support third-party referral platforms, so we will continue to optimize and improve its built-in referral platform to ensure its stability and reliability.**

## Independent deployment mode
### Ⅰ.Server deployment
```
reverse:
    db_file_path: ""
    token: ""
    http:
        enabled: false
        listen_ip: 0.0.0.0
        listen_port: ""
        ip_header: ""
    dns:
        enabled: false
        listen_ip: 0.0.0.0
        domain: ""
        is_domain_name_server: false
        resolve:
            - type: A
              record: localhost
              value: 127.0.0.1
              ttl: 60
    rmi:
        enabled: false
        listen_ip: 0.0.0.0
        listen_port: ""
```
### Ⅱ.client configuration
```
reverse:
    token: ""
    client:
        remote_server: true
        http_base_url: ""
        dns_server_ip: ""
```

