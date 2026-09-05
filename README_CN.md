[**English**](README.md)

# wscan

一款面向授权安全测试的 Web 安全扫描器。最快的使用方式是启动 WebUI；需要脚本化、批量化或 CI 执行时使用 CLI。

> ⚠️ **必须获得授权**：只能扫描你拥有或明确获准测试的系统。被动扫描会捕获经过配置代理的流量，启动前必须明确扫描范围，不能把与测试无关的浏览器流量导入被动任务。使用前请阅读 [License](LICENSE.md)。

## 你可以用 wscan 做什么

- 在 WebUI 中管理目标、扫描任务、漏洞、页面和技术识别结果。
- 使用静态爬虫、无头浏览器爬虫、单 URL、URL 文件或原始请求进行主动扫描。
- 创建有范围限制的 MITM 被动扫描，分析授权浏览器或客户端产生的流量。
- 查看、筛选和导出结果；WebUI 重启后扫描历史仍然保留。
- 按需选择插件或加载 POC 模板。
- 使用内置反连平台验证盲打漏洞回连。
- 在 WebUI 中创建 AI 自动渗透项目，执行有目标的多步骤测试。

## 可以扫描哪些漏洞

wscan 主要覆盖常见 Web 应用漏洞和安全配置问题。实际覆盖范围取决于选择的插件、请求数据、鉴权状态、目标行为和扫描模式，主要包括：

- **注入类**：SQL 注入、命令注入、表达式/模板注入、CRLF/HTTP 头注入以及其他参数注入检查。
- **跨站与跨域问题**：反射型/存储型 XSS、JSONP 和跨域敏感数据暴露。
- **文件与路径问题**：路径穿越、敏感文件/目录探测、备份文件和配置文件暴露、文件上传检查。
- **服务端请求与解析问题**：SSRF、XXE、不安全反序列化，以及 Fastjson、Shiro、XStream、ThinkPHP、Struts 等组件相关检查。
- **认证与会话问题**：HTTP Basic/Digest 弱点、简单表单弱口令、Cookie 安全属性，以及认证相关信息暴露。
- **配置与信息泄露**：HTTP 安全响应头缺失或配置不安全、TLS/SSL 配置问题、调试/错误信息泄露、HTML 注释敏感信息，以及响应或 JavaScript 中的凭据、API Key、邮箱、手机号等敏感内容。
- **组件和 API 发现**：Web 组件指纹识别、JavaScript 接口发现、Swagger/OpenAPI 发现、重定向和其他暴露的 Web 资源。
- **自定义和外部检查**：基于 YAML 的自定义 FUZZ 规则，以及可选的 Nuclei/Xray/Goby 兼容 POC 模板。

扫描结果是需要复核的线索，不等于已经确认的实际影响。对于主动探测、鉴权、文件上传、SSRF 和反连验证等检查，务必在授权范围内人工确认重要结果。

## 快速开始：WebUI

### 1. 启动 WebUI

从 [Releases](https://github.com/chushuai/wscan/releases) 下载程序，或从当前仓库构建后运行：

```bash
./wscan webui --webui-host=127.0.0.1 --webui-port=7002
```

浏览器打开 <http://127.0.0.1:7002>。只有在确实需要其他机器访问时才使用 `0.0.0.0`，并通过网络访问控制保护 WebUI。

### 2. 创建主动扫描

1. 打开「新建扫描」。
2. 保持「主动扫描」模式。
3. 输入已获授权的目标 URL，例如 `https://example.com/`。
4. 选择已保存目标，或配置爬虫和扫描范围。
5. 选择「爬取+扫描」「仅爬取」或「仅扫描」。
6. 打开任务查看进度、页面、技术识别和漏洞结果。

JavaScript 较多的应用选择「动态」；普通 HTML 站点可以选择「静态」，速度更快。

### 3. 创建被动扫描

被动模式只启动本地 MITM 代理，不会主动爬取目标。

1. 打开「新建扫描」，选择「被动监听」。
2. 填写「扫描目标」。该目标用于限制允许的主机和路径范围。
3. 保持默认监听地址 `127.0.0.1:7100`，或改为其他未占用地址。
4. 选择需要启用的插件和范围。
5. 点击「启动监听」。
6. 将已获授权的浏览器或客户端代理设置为页面显示的监听地址。
7. 在该浏览器或客户端中安装项目 CA 证书 `ca.crt`。
8. 通过代理访问授权目标。
9. 在任务中查看流量和漏洞，完成后点击「停止」。

被动任务必须填写扫描目标，这样访问其他主机的流量会被拒绝。不要把被动代理当成普通浏览器代理使用。

需要时先生成 CA：

```bash
./wscan genca
```

`ca.key` 是 CA 私钥，属于敏感文件，不要上传或分享。

## 查看和导出结果

- 「扫描」页面显示任务状态、进度、目标、流量/页面数量和漏洞数量。
- 打开任务可以查看收集到的页面/请求、技术识别、漏洞和本次任务配置。
- 使用漏洞筛选器按严重性或类型缩小结果范围。
- 任务导出功能可以将收集到的 URL 导出为 TXT、JSON 或 XML。
- 扫描和漏洞历史保存在数据目录中，重启后会自动恢复。

## CLI 快速参考

CLI 适合脚本、CI 和可重复扫描。命令名为 `ws` 或 `webscan`。

### 主动扫描

```bash
# 静态爬取 + 扫描
./wscan ws --basic-crawler \
  --url https://example.com/ \
  --json-output=result.json --html-output=result.html

# 针对 JavaScript 应用使用无头浏览器爬取
./wscan ws --browser-crawler \
  --url https://example.com/ \
  --html-output=result.html

# 扫描 URL 文件，每行一个 URL
./wscan ws --basic-crawler --url-file=urls.txt --json-output=result.json

# 带请求体扫描一个端点
./wscan ws --url https://example.com/login \
  --data 'username=test&password=test' \
  --json-output=result.json

# 仅爬取，不执行漏洞检测
./wscan ws --browser-crawler --url https://example.com/ \
  --no-scan --json-crawler-output=crawl.json

# 只运行指定插件
./wscan ws --basic-crawler --url https://example.com/ \
  --plug=sqldet,xss --json-output=result.json
```

### CLI 被动扫描

```bash
# 如果尚未生成 CA，先执行
./wscan genca

# 在本机监听
./wscan ws --listen=127.0.0.1:7100 --json-output=result.json

# 限制插件集合
./wscan ws --listen=127.0.0.1:7100 \
  --plug=sqldet,xss --json-output=result.json
```

浏览器/客户端代理和 CA 的配置方式与上面的 WebUI 被动扫描相同。CLI 被动扫描可以在 `config.yaml` 的 `mitm.restriction` 中配置主机、路径、端口和参数限制。

## 目标、范围、鉴权和代理

为了方便重复使用，可以先在 WebUI 中保存目标，再填写包含/排除规则和鉴权配置，然后创建任务。

- **目标**：你获准测试的基础 URL。
- **包含/排除**：限制路径和请求模式；除非测试明确要求，否则建议排除退出登录、删除、支付等有状态变化的接口。
- **鉴权**：在任务表单或已保存目标中选择支持的鉴权方式。账号、Cookie、Token 都应作为敏感信息保管。
- **代理**：在「全局配置 → 代理」中设置全局代理，也可以为主动扫描单独覆盖。它是 wscan 访问上游的代理，与被动模式给浏览器使用的本地 MITM 监听地址不同。

上游代理配置示例：

```yaml
http:
  proxy: "socks5://127.0.0.1:1080"
```

## POC 模板和自定义插件

项目不内置 POC。如果授权测试需要，可以将本地 Nuclei/Xray/Goby 兼容模板目录传给 POC 参数：

```bash
./wscan ws --url https://example.com/ \
  --poc=/path/to/pocs/* --html-output=poc-result.html
```

高级编写参考：

- [Web 指纹插件编写指南](doc/WEB指纹插件编写指南.md)
- [Web 通用漏扫插件编写指南](doc/WEB通用漏扫插件编写指南.md)
- [自定义 FUZZ 插件指南](doc/自定义FUZZ插件.md)

## AI 自动渗透

在 WebUI 中创建「AI 自动渗透」项目，填写已授权的目标 origin 和明确目标，选择 worker 后启动。页面会实时展示智能体进度、工具调用、发现的事实和结果。

请使用明确且较小的目标范围，检查每一项自动生成的动作和发现，再将结果视为确认结论。本机 Claude Code worker 需要系统中可执行 `claude` 命令并完成认证；规则 worker 不需要 LLM。

## 盲打漏洞反连平台

授权测试需要外部回连来确认盲打漏洞时，启动反连平台：

```bash
./wscan reverse
```

部署和回连配置参见[最佳实践](doc/最佳实践.md)。

## MCP 服务器

将任务和扫描操作通过 Streamable HTTP 暴露给授权的 MCP 客户端：

```bash
./wscan mcp --mcp-host=127.0.0.1 --mcp-port=7001
```

不要在没有认证和网络访问控制的情况下，将 MCP 或 WebUI 端口暴露到公网。

## 配置和排查

- `config.yaml` 包含爬虫、HTTP、MITM、插件和反连平台配置。
- 使用 `./wscan ws --help` 和 `./wscan webui --help` 查看当前版本支持的参数。
- 被动任务无法启动时，检查监听端口是否已被占用，以及 `ca.crt` / `ca.key` 是否可读。
- HTTPS 流量无法通过 MITM 时，在客户端安装生成的 CA，并确认客户端信任该证书。
- 扫描没有结果时，检查目标范围、鉴权状态、插件选择，以及客户端是否确实通过配置的代理发送流量。

## 使用建议

- 从小范围、低影响插件开始，确认结果后再扩大范围。
- 除非项目明确覆盖，否则排除退出登录、删除、支付、重置密码等有状态变化的接口。
- 被动扫描使用独立的浏览器配置文件，避免捕获与测试无关的流量。
- 安全保存结果文件、Cookie、Token、CA 私钥和配置备份。
- 不使用时停止 WebUI、MCP、反连平台和被动监听器。

## License

参见 [LICENSE.md](LICENSE.md)。
