[**English**](README.md)

# wscan

一款覆盖主动、被动与 AI 驱动渗透测试的 Web 安全扫描器。

wscan 覆盖完整 OWASP Web 漏洞面——XSS、SQL 注入、命令执行、路径穿越、SSRF、XXE、文件上传等——并具备组件指纹识别、敏感信息检测,以及一个能同时跑 Nuclei / Xray / Goby POC 的插件引擎。它自带浏览器版 WebUI 管理扫描任务、内置反连平台用于验证盲打漏洞,还有 AI 智能体模式:通过本机 Claude CLI 自主驱动扫描器完成你设定的目标。

> ⚠️ **法律免责声明**:未经事先双方同意,使用 wscan 扫描目标是非法的。wscan 仅用于授权的安全测试。使用前请务必阅读并同意 [License](LICENSE.md),否则请勿安装使用本工具。

---

## 核心特性一览

- **WebUI** —— 浏览器里管理目标、扫描与结果;结果落盘,重启不丢;支持 IM 推送通知(飞书/Lark、企业微信、钉钉)。
- **主动 + 被动扫描** —— 先爬后扫(静态或无头浏览器爬虫)、单 URL / URL 文件 / 原始请求模式,以及基于 MITM 的被动监听。
- **28+ 内置检测插件** —— 语义分析 XSS、SQL 注入(报错/布尔/时间盲注)、命令注入、路径穿越、XXE、SSRF、文件上传、弱口令爆破、JSONP、跳转、CRLF、基线,以及 Struts2 / Shiro / Fastjson / ThinkPHP / XStream 组件检测。
- **POC 引擎** —— 一个目录同时跑 Nuclei、Xray、Goby POC,检测深度可配。
- **自定义 FUZZ 与 WAF 测试** —— YAML 定义 payload,配 encoder、placeholder 与 CEL/正则验证;测试 WAF 是否能拦截你的 payload。
- **AI 自动渗透** —— 智能体循环:Claude(本机 CLI)在事实黑板上推理,调用 wscan 工具(爬取 / 扫描 / 单插件 / HTTP)逐步达成你设定的目标。
- **反连平台** —— HTTP / DNS / RMI / LDAP 回连,验证盲打 RCE、SSRF、Log4j、Fastjson 等。
- **MCP 服务器** —— Streamable HTTP 协议,供其他工具远程管理任务与扫描。

---

## 检测模块

| 模块 | wscan | Xray | 说明 |
|---|:--:|:--:|---|
| 动态爬虫(浏览器) | √ | × | 爬取 JavaScript 渲染页面 |
| 静态爬虫 | √ | √ | 爬取静态 HTML |
| MITM 被动扫描 | √ | √ | 中间人方式被动分析流量 |
| `xss` | √ | √ | 语义分析检测 XSS |
| `sqldet` | √ | 部分 | 报错/布尔/时间盲注/头注入/路径注入 |
| `cmd-injection` | √ | √ | Shell 注入、PHP 代码执行、模板注入 |
| `dirscan` | √ | √ | 备份文件、debug 页面、配置文件等 10+ 敏感路径 |
| `path-traversal` | √ | √ | 常见平台与编码 |
| `xxe` | √ | √ | 有回显与反连检测 |
| `upload` | √ | √ | 常见后端语言 |
| `brute-force` | √ | √ | HTTP 基础认证与简易表单弱口令 |
| `jsonp` | √ | √ | 跨域读取敏感信息的 JSONP 接口 |
| `ssrf` | √ | √ | 常见绕过 + 反连检测 |
| `baseline` | √ | √ | 低 SSL 版本、缺失/误加的 HTTP 头 |
| `redirect` | √ | √ | HTML meta、30x 跳转 |
| `crlf-injection` | √ | √ | HTTP 头注入(query/body) |
| `xstream` | √ | √ | XStream 系列漏洞 |
| `struts` | √ | √ | Struts2 s2-016/032/045/059/061 |
| `thinkphp` | √ | √ | ThinkPHP 相关漏洞 |
| `shiro` | √ | √ | Shiro 反序列化 |
| `fastjson` | √ | √ | Fastjson 系列漏洞 |
| Nuclei YAML POC | √ | × | Nuclei 标准 POC |
| Xray YAML POC | √ | √ | Xray 标准 POC |
| Goby JSON POC | √ | × | Goby 标准 POC |
| 自定义 FUZZ 插件 | √ | × | 对 body/query/header/cookie 参数模糊测试 |
| WAF 绕过 / WAF 测试 | √ | × | 自定义 payload 测试 WAF 拦截能力 |
| Web 组件识别 | √ | × | 识别网站组件与技术 |
| JS 敏感内容检测 | √ | × | JS 中的 AK/SK、API key、电话、邮箱 |
| Swagger / OpenAPI | √ | × | Swagger/OpenAPI 渗透测试 |

---

## 快速开始

⬇️ [下载地址](https://github.com/chushuai/wscan/releases) · 🏠 [最佳实践](doc/最佳实践.md) · 🔌 [插件编写指南](#插件编写)

### WebUI(浏览器管理)

最简单的用法:启动 WebUI,然后在浏览器里完成一切——添加目标、发起扫描、查看结果、跑 AI 渗透。

```bash
./wscan webui --webui-host=0.0.0.0 --webui-port=7002
```

浏览器打开 `http://<host>:7002` 即可管理目标、发起扫描、查看结果。扫描与漏洞结果落盘,重启后历史保留。可在全局配置页配置 IM 推送通知(飞书/Lark、企业微信、钉钉)。

在 WebUI 中也可以新建 **AI 渗透** 项目:设定目标 origin 和目标成果(例如"找出所有 RCE 漏洞"),选择 worker,即可看着智能体驱动 wscan 完成任务。

### AI 自动渗透

在 WebUI 中新建一个 **AI 渗透** 项目:设定目标 origin 和目标成果(例如"找出所有 RCE 漏洞"),选择 worker:

- **Claude Code** —— 通过本机 `claude` CLI 驱动智能体循环。每轮 Claude 在事实黑板(已发现 URL、事实、已知漏洞)上推理,调用 wscan 工具(`wscan_crawl`、`wscan_run_plugin`、`wscan_scan`、`wscan_list_plugins`、`http`)推进,工具调用与结果实时推送到界面。需要 PATH 中有 `claude`,并设置 `ANTHROPIC_API_KEY` / `ANTHROPIC_AUTH_TOKEN`。
- **LLM** —— OpenAI/Anthropic 兼容的 chat-completions 接口。
- **Mock** —— 规则 worker,无需 LLM。

当 Claude 不可用时,项目会优雅回退到基于规则的 OODA 循环。

### 主动扫描

```bash
# 爬取 + 扫描单个 URL
./wscan --log-level=debug ws --basic-crawler --url http://testphp.vulnweb.com/ \
  --json-output=result.json --html-output=result.html

# 无头浏览器爬取(JS 渲染站点)
./wscan --log-level=debug ws --browser --url http://testphp.vulnweb.com/ --html-output=result.html

# 扫描 URL 文件(每行一个 URL)
./wscan --log-level=debug ws --basic-crawler --url-file=urls.txt --html-output=result.html

# 带 body 扫描单个端点
./wscan --log-level=debug ws -d "uname=111&pass=111" --url http://testphp.vulnweb.com/userinfo.php

# 只跑指定插件
./wscan --log-level=debug ws --plug=sqldet --basic-crawler --url http://testphp.vulnweb.com/

# 仅爬取,不扫描
./wscan --log-level=debug ws --browser --url http://testphp.vulnweb.com/ --no-scan --json-crawler-output=crawl.json
```

### 被动扫描(MITM)

```bash
# 生成并安装 CA(方法与 Xray 一致)
./wscan genca

# 监听并对代理流量被动扫描
./wscan --log-level=debug ws --listen=127.0.0.1:1000 --json-output=result.json

# 指定插件被动扫描
./wscan --log-level=debug ws --plug=sqldet,xss --listen=127.0.0.1:1000 --json-output=result.json
```

### POC 扫描

wscan 不内置 POC,但 `prometheus` 引擎可一个目录同时跑 Nuclei / Xray / Goby POC。下载 POC 包:

- Xray / Goby:https://github.com/chaitin/xray/tree/master/pocs
- Nuclei:https://github.com/projectdiscovery/nuclei-templates/tree/main/http(只保留 `http/` 模板)

用 `--poc` 指向它们,或在 `config.yaml` 配 `include_poc` 做深度扫描:

```bash
./wscan --log-level=debug ws --poc=/path/to/wscan-poc/pocs/* \
  --url http://testphp.vulnweb.com/ --html-output=result.html
```

```yaml
prometheus:
    enabled: true
    depth: 1                 # 探测深度,1 = URL 深度 0 和 1
    auto_load_poc: false
    include_poc:
       - /path/to/wscan-poc/pocs/*
    exclude_poc: []
```

### 反连平台

面对盲打漏洞(RCE、SSRF、Log4j、Fastjson,目标无可见响应),运行反连平台,通过回连证明漏洞存在:

```bash
./wscan reverse
```

wscan 支持 HTTP、DNS、RMI、LDAP 四种反连(HTTP/RMI/LDAP 复用同一端口)。客户端/服务端配置见[最佳实践](doc/最佳实践.md)。

### MCP 服务器

通过 Streamable HTTP 协议把扫描管理暴露给其他工具:

```bash
./wscan mcp --mcp-host=0.0.0.0 --mcp-port=7001
```

---

## 代理扫描

在 `config.yaml` 为爬虫与扫描器配置代理:

```yaml
http:
    proxy: "socks5://153.34.245.41:7777"
```

---

## 插件编写

- 🎯 [Web 指纹插件编写指南](doc/WEB指纹插件编写指南.md)
- 🎯 [Web 通用漏扫插件编写指南](doc/WEB通用漏扫插件编写指南.md)
- 🧩 [自定义 FUZZ 插件指南](doc/自定义FUZZ插件.md)

自定义 FUZZ 插件用 YAML 定义 payload,配 encoder、placeholder 与 CEL/正则验证,对指定位置参数模糊测试:

```yaml
name: "custom-sqli"
set:
  r1: randomInt(800000000, 1000000000)
payload:
  - extractvalue(1,concat(char(126),md5({{r1}})))
placeholder:
  - query
  - body
  - header
  - cookie
expression: response.body.bcontains(bytes(substr(md5(string(r1)), 0, 31)))
```

---

## Star History

[![Star History Chart](https://star-history.dera.page/svg?repos=chushuai/wscan,chaitin/xray,projectdiscovery/nuclei&type=Date)](https://star-history.dera.page/#chushuai/wscan&chaitin/xray&projectdiscovery/nuclei&Date)
