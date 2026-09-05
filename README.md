[**中文**](README_CN.md)

# wscan

A web security scanner for active, passive, and AI-driven penetration testing.

wscan covers the full OWASP web vulnerability landscape — XSS, SQLi, RCE, path traversal, SSRF, XXE, file upload, and more — plus component fingerprinting, sensitive-info detection, and a plugin engine that runs Nuclei / Xray / Goby POCs. It ships with a browser-based WebUI for managing scans, a built-in reverse-connect platform for blind vulnerabilities, and an AI agent mode that drives the scanner autonomously via the local Claude CLI.

> ⚠️ **Legal**: Scanning a target without prior authorization is illegal. wscan is intended for authorized security testing only. Read and agree to the [License](LICENSE.md) before use.

---

## Features at a glance

- **WebUI** — manage targets, scans, and results in a browser; results persist across restarts; IM push notifications (Feishu/Lark, WeCom, DingTalk).
- **Active & passive scanning** — crawl-then-scan (static or headless-browser crawler), single-URL / URL-file / raw-request modes, and MITM-based passive listening.
- **28+ built-in detection plugins** — semantic XSS, SQLi (error/boolean/time-blind), command injection, path traversal, XXE, SSRF, file upload, brute-force, JSONP, redirect, CRLF, baseline, plus Struts2 / Shiro / Fastjson / ThinkPHP / XStream component checks.
- **POC engine** — runs Nuclei, Xray, and Goby POCs from one directory, with configurable detection depth.
- **Custom FUZZ & WAF testing** — YAML-defined payloads with encoders, placeholders, and CEL/regex verification; test whether a WAF blocks your payloads.
- **AI automated pentest** — an agentic loop where Claude (local CLI) reasons over a blackboard of facts and drives wscan tools (crawl / scan / run-plugin / http) to reach a goal you define.
- **Reverse-connect platform** — HTTP / DNS / RMI / LDAP callbacks for blind RCE, SSRF, Log4j, Fastjson, etc.
- **MCP server** — Streamable HTTP protocol for remote task management and scanning from other tools.

---

## Detection modules

| Module | wscan | Xray | Notes |
|---|:--:|:--:|---|
| Dynamic (browser) crawler | √ | × | Crawls JavaScript-rendered pages |
| Static crawler | √ | √ | Crawls static HTML |
| MITM passive scan | √ | √ | Passive traffic analysis via man-in-the-middle |
| `xss` | √ | √ | Semantic-analysis XSS detection |
| `sqldet` | √ | partial | Error / boolean / time-blind / header / path injection |
| `cmd-injection` | √ | √ | Shell injection, PHP code exec, template injection |
| `dirscan` | √ | √ | 10+ sensitive paths: backups, debug pages, config files |
| `path-traversal` | √ | √ | Common platforms and encodings |
| `xxe` | √ | √ | Echo and reverse-connect detection |
| `upload` | √ | √ | Common backend languages |
| `brute-force` | √ | √ | HTTP basic-auth and simple form weak passwords |
| `jsonp` | √ | √ | Cross-domain sensitive-info JSONP endpoints |
| `ssrf` | √ | √ | Common bypasses + reverse-connect detection |
| `baseline` | √ | √ | Low SSL versions, missing/misadded HTTP headers |
| `redirect` | √ | √ | HTML meta and 30x redirects |
| `crlf-injection` | √ | √ | HTTP header injection (query/body) |
| `xstream` | √ | √ | XStream vulnerability series |
| `struts` | √ | √ | Struts2 s2-016/032/045/059/061 |
| `thinkphp` | √ | √ | ThinkPHP vulnerabilities |
| `shiro` | √ | √ | Shiro deserialization |
| `fastjson` | √ | √ | Fastjson vulnerabilities |
| Nuclei YAML POC | √ | × | Nuclei-standard POCs |
| Xray YAML POC | √ | √ | Xray-standard POCs |
| Goby JSON POC | √ | × | Goby-standard POCs |
| Custom FUZZ plugin | √ | × | Fuzz params in body/query/header/cookie |
| WAF bypass / testing | √ | × | Custom payloads to test WAF interception |
| Web component fingerprint | √ | × | Identify components and technologies |
| JS sensitive-content detection | √ | × | AK/SK, API keys, phones, emails in JS |
| Swagger / OpenAPI | √ | × | Swagger/OpenAPI pentest support |

---

## Quick start

⬇️ [Download](https://github.com/chushuai/wscan/releases) · 🏠 [Best Practices](doc/BestPractices.md) · 🔌 [Plugin authoring guides](#plugin-authoring)

### WebUI (browser-based management)

The easiest way to use wscan: start the WebUI, then do everything — add targets, launch scans, review results, run AI pentests — from the browser.

```bash
./wscan webui --webui-host=0.0.0.0 --webui-port=7002
```

Open `http://<host>:7002` to manage targets, launch scans, and review results. Scans and vulnerabilities persist to disk, so history survives restarts. Configure IM push notifications (Feishu/Lark, WeCom, DingTalk) from the global settings page.

From the WebUI you can also create an **AI Pentest** project: give it a target origin and a goal (e.g. "find all RCE vulnerabilities"), pick a worker, and watch the agent drive wscan to completion.

### AI automated pentest

Create an **AI Pentest** project from the WebUI: set a target origin and a goal (e.g. "find all RCE vulnerabilities"), then pick a worker:

- **Claude Code** — drives an agentic loop via your local `claude` CLI. Each round Claude reasons over a blackboard (discovered URLs, facts, known vulns) and calls wscan tools (`wscan_crawl`, `wscan_run_plugin`, `wscan_scan`, `wscan_list_plugins`, `http`) to make progress; tool calls and results stream to the UI in real time. Requires `claude` on PATH and `ANTHROPIC_API_KEY` / `ANTHROPIC_AUTH_TOKEN`.
- **LLM** — OpenAI/Anthropic-compatible chat-completions endpoint.
- **Mock** — rule-based worker, no LLM needed.

If Claude is unavailable, the project gracefully falls back to the rule-based OODA loop.

### Active scan

```bash
# Crawl + scan a single URL
./wscan --log-level=debug ws --basic-crawler --url http://testphp.vulnweb.com/ \
  --json-output=result.json --html-output=result.html

# Headless-browser crawl (for JS-rendered sites)
./wscan --log-level=debug ws --browser --url http://testphp.vulnweb.com/ --html-output=result.html

# Scan a URL file (one URL per line)
./wscan --log-level=debug ws --basic-crawler --url-file=urls.txt --html-output=result.html

# Scan a single endpoint with body data
./wscan --log-level=debug ws -d "uname=111&pass=111" --url http://testphp.vulnweb.com/userinfo.php

# Run a specific plugin only
./wscan --log-level=debug ws --plug=sqldet --basic-crawler --url http://testphp.vulnweb.com/

# Crawl only (no scanning)
./wscan --log-level=debug ws --browser --url http://testphp.vulnweb.com/ --no-scan --json-crawler-output=crawl.json
```

### WebUI passive scan

After starting the WebUI, choose **Passive listener** in **New Scan**, enter a listen address such as `127.0.0.1:7100`, and start it. Configure your browser or client to use that proxy, install `ca.crt`, and browse only authorized targets. Stop the listener from the task detail when finished.

### Passive scan (MITM)
```bash
# Generate and install the CA (same approach as Xray)
./wscan genca

# Listen and passively scan proxied traffic
./wscan --log-level=debug ws --listen=127.0.0.1:1000 --json-output=result.json

# Passive scan with specific plugins
./wscan --log-level=debug ws --plug=sqldet,xss --listen=127.0.0.1:1000 --json-output=result.json
```

### POC scan

wscan ships no POCs, but its `prometheus` engine runs Nuclei / Xray / Goby POCs from one directory. Download POC packs:

- Xray / Goby: https://github.com/chaitin/xray/tree/master/pocs
- Nuclei: https://github.com/projectdiscovery/nuclei-templates/tree/main/http (keep only the `http/` templates)

Point `--poc` at them, or configure `include_poc` in `config.yaml` for deep scans:

```bash
./wscan --log-level=debug ws --poc=/path/to/wscan-poc/pocs/* \
  --url http://testphp.vulnweb.com/ --html-output=result.html
```

```yaml
prometheus:
  enabled: true
  depth: 1                 # detection depth; 1 = URL depth 0 and 1
  auto_load_poc: false
  include_poc:
    - /path/to/wscan-poc/pocs/*
  exclude_poc: []
```

### Reverse-connect platform

For blind vulnerabilities (RCE, SSRF, Log4j, Fastjson) where the target makes no visible response, run the reverse platform so callbacks prove exploitation:

```bash
./wscan reverse
```

wscan supports HTTP, DNS, RMI, and LDAP callbacks (HTTP/RMI/LDAP share one port). See [Best Practices](doc/BestPractices.md) for client/server configuration.

### MCP server

Expose scan management to other tools over the Streamable HTTP protocol:

```bash
./wscan mcp --mcp-host=0.0.0.0 --mcp-port=7001
```

---

## Proxy

Set a proxy for the crawler and scanner in `config.yaml`:

```yaml
http:
  proxy: "socks5://153.34.245.41:7777"
```

---

## Plugin authoring

- 🎯 [Web fingerprint plugin guide (中文)](doc/WEB指纹插件编写指南.md)
- 🎯 [Web vuln-scan plugin guide (中文)](doc/WEB通用漏扫插件编写指南.md)
- 🧩 [Custom FUZZ plugin guide (中文)](doc/自定义FUZZ插件.md)

Custom FUZZ plugins fuzz parameters at specified locations with YAML-defined payloads, encoders, placeholders, and CEL/regex verification:

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
