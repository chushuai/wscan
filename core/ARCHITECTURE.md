# Wscan 代码架构文档

## 项目概览

**Wscan** 是一个 Go 语言编写的 Web 安全扫描引擎，支持主动爬取 + 被动代理两种流量采集方式，内置 20+ 漏洞检测插件，并提供 MCP 服务接口供 AI 调用。

- **语言**: Go
- **模块路径**: `wscan/core`
- **版本**: 1.0.41
- **作者**: shaochuyu

---

## 整体数据流

```
目标输入 → Collector(采集器) → chan Resource → Dispatcher(调度器) → EventBus → Plugin(插件) → Output(输出)
```

详细流程：

1. 用户通过 CLI 或 MCP 接口提交扫描目标
2. `Collector` 采集流量，输出 `chan resource.Resource` 通道
3. `Dispatcher` 从通道消费，根据请求特征发布到不同 EventBus Channel
4. 已订阅对应 Channel 的插件 `BasicRunner` 被触发，执行 `CheckAction` → `ExecAction`
5. 发现漏洞时通过 `Output Printer` 输出（stdout / JSON / HTML / Webhook）

---

## 目录结构

```
core/
├── main.go            # 程序入口，CLI 命令定义
├── config.yaml        # 默认配置文件
├── entry/             # CLI 入口，配置加载，组件组装
├── collector/         # 流量采集器（Fitter 接口）
│   ├── basiccrawler/  # 基础/浏览器爬虫采集器
│   └── mitmhelper/    # MITM 代理辅助
├── crawler/           # 爬虫核心引擎
│   └── js/            # JavaScript 解析
├── ctrl/              # 调度中心（Dispatcher + EventBus）
├── plugins/           # 漏洞检测插件（20+）
│   ├── base/          # 插件基础接口与抽象
│   ├── helper/        # 插件辅助工具（知识库等）
│   ├── xss/           # XSS 检测
│   ├── sql_injection/ # SQL 注入
│   ├── cmd_injection/ # 命令注入
│   ├── ssrf/          # SSRF
│   ├── xxe/           # XXE
│   └── ...            # 其他插件
├── http/              # HTTP 客户端与数据模型
├── reverse/           # 反连平台（HTTP/DNS/RMI/LDAP）
├── model/             # 数据模型（Vuln, WebVuln 等）
├── output/            # 输出层（stdout/JSON/HTML/Webhook）
├── mcp/               # MCP Server 接口
├── resource/          # Resource 接口（扫描目标抽象）
├── rpc/               # gRPC Proto 定义
├── utils/             # 工具集
│   ├── checker/       # 请求检查器与过滤
│   ├── log/           # 日志
│   ├── printer/       # 打印器抽象
│   ├── jsonpath/      # JSONPath 解析
│   ├── comparer/      # HTTP 响应比对
│   ├── network/       # 网络工具
│   └── ...            # 其他工具
└── web/               # Web 相关
```

---

## 核心模块详解

### 1. entry — 入口与配置

**关键文件**: `entry/entry.go`, `entry/config.go`

职责：
- 解析 CLI 参数（`urfave/cli/v2`）
- 加载或生成 `config.yaml`
- 根据输入模式选择 Collector
- 组装 Dispatcher 并启动扫描

核心函数 `NewApp()`：
1. 加载配置 → `LoadOrGenConfig()`
2. 根据参数选择采集器：
   - `--url` / `--url-file` → URLListReader 或 BasicCrawler 或 BrowserCrawler
   - `--listen` → MitmProxy
3. 调用 `col.FitOut()` 获取流量通道
4. 创建 Dispatcher → `Init()` → `Run()`

### 2. collector — 流量采集

**关键接口**: `collector.Fitter`

```go
type Fitter interface {
    FitOut(ctx context.Context, targets []string) (chan resource.Resource, error)
}
```

三种实现：

| 实现 | 文件 | 说明 |
|------|------|------|
| `URLListReader` | `collector/url-list.go` | 直接从 URL 列表构建 HTTP 请求 |
| `basicCrawlerCollector` | `collector/basiccrawler/basic_crawler.go` | 基础爬虫 + 浏览器爬虫包装 |
| `MitmProxy` | `collector/mitm.go` | MITM 代理（基于 google/martian），被动采集浏览器流量 |

辅助采集器：
- `BurpImporter` — 导入 Burp Suite 导出文件
- `DummyCollector` — 测试用空采集器

### 3. crawler — 爬虫引擎

**关键文件**: `crawler/crawer.go`, `crawler/basic_task_hander.go`, `crawler/browser_task_hander.go`

核心结构 `Crawler`：
- 支持两种模式：**基础 HTTP 爬取** 和 **浏览器爬取**（chromedp）
- 协程池（`ants`）控制并发
- 智能过滤（`SmartFilter`）去重
- 事件回调：`OnFlow` / `OnRequest` / `OnResponse` / `OnDocument`

爬取流程：
1. 初始化 Crawler，设置 URLChecker、SmartFilter
2. 通过 `NewTask()` 添加初始 URL
3. `Feed()` 从队列取任务送入 `taskChan`
4. Worker 从 `taskChan` 消费，根据模式调用 `handleBasicTask` 或 `handleBrowserTask`
5. 每个爬取到的 Flow 通过 `OnFlow` 回调输出

关键特性：
- 深度控制（`MaxDepth`）
- URL 数量限制（`MaxCountOfURLs`）
- 自动爬取 `/robots.txt`、`/sitemap.xml`
- 浏览器模式支持表单自动填充、DOM 事件触发

### 4. ctrl — 调度中心

**关键文件**: `ctrl/dispatcher.go`, `ctrl/runner.go`, `ctrl/bus.go`

#### Dispatcher（调度器）

核心结构，管理插件生命周期与任务分发：

```go
type Dispatcher struct {
    plugins       []base.Plugin
    pluginConfig  map[string]base.PluginConfigInterface
    reactor       *ants.Pool          // 协程池
    root          *Node               // 插件树根节点
    evBus         *EventBus           // 事件总线
    requestFilter *checker.RequestChecker
    apolloBase    *base.ApolloBase    // 插件运行环境
}
```

工作流程：

1. **`Init()`**：
   - 创建 EventBus
   - 初始化启用的插件
   - 构建插件树 `buildTree()`
   - 遍历树叶子节点，将 Finger 包装为 `BasicRunner`，订阅到 EventBus

2. **`Run(taskChan, noScan)`**：
   - 从 taskChan 消费 Flow
   - 调用 `publishToNode()` 分发到 EventBus Channel
   - 等待所有异步回调完成

3. **`publishToNode()`** — 事件分发逻辑：
   - JavaScript 请求 → `javascript` Channel
   - 目录路径（以 `/` 结尾）→ `web-directory` + `website` Channel
   - 新路径 → `web-path` Channel
   - 所有请求 → `web-generic` Channel

#### EventBus（事件总线）

基于发布-订阅模式，支持：
- 同步/异步订阅
- 一次性订阅
- 事务性订阅（串行执行）
- 协程池提交异步任务

#### Node（插件树）

```
root
├── xss
│   ├── xss/default
│   └── xss/cookie
├── sql_injection
│   ├── sqldet/boolean_based
│   ├── sqldet/error_based
│   └── sqldet/time_based
├── ...
```

- 一级节点 = 插件
- 二级节点 = Finger（具体检测规则）
- 按子节点数量排序，优化执行效率

#### BasicRunner（运行器）

```go
type BasicRunner struct {
    check   func(context.Context, *base.Apollo) error
    exec    func(context.Context, *base.Apollo) error
    biBase  *base.ApolloBase
    binding *model.VulnBinding
}
```

执行逻辑：先执行 `check`，通过后执行 `exec`。

### 5. plugins — 插件体系

#### Plugin 接口

```go
// plugins/base/plugin.go
type Plugin interface {
    Close() error
    DefaultConfig() PluginConfigInterface
    Fingers() []*Finger
    GetConfig() PluginConfigInterface
    Init(ctx context.Context, pfi PluginConfigInterface, bb *ApolloBase) error
}
```

#### Finger 结构（核心检测规则）

```go
// plugins/base/plugin.go
type Finger struct {
    Binding         *model.VulnBinding          // 漏洞绑定（插件名+分类+ID）
    Channel         string                      // 订阅的事件通道
    NeedReverse     bool                        // 是否需要反连平台
    NeedStandalone  bool
    NeedTransaction bool
    CheckAction     func(context.Context, *Apollo) error  // 检测函数
    ExecAction      func(context.Context, *Apollo) error  // 利用/确认函数
    ReTestAction    func(context.Context, *Apollo) error  // 复测函数
    CloseAction     func() error
}
```

#### Apollo 运行环境

```go
// plugins/base/apollo.go
type ApolloBase struct {
    HTTPClient *http.Client
    KDB        *knowledge.KnowledgeDB
    Reverse    *reverse.Reverse
    Output     printer.Printer
    FilterContainer filter.Filter
    FilterConfig    *checker.RequestCheckerConfig
}

type Apollo struct {
    *ApolloBase
    tempDB  *sync.Map
    binding *model.VulnBinding
    target  resource.Resource     // 当前扫描目标（http.Flow）
}
```

Apollo 为插件提供：
- HTTP 客户端
- 知识库查询
- 反连平台
- 漏洞输出
- 请求过滤
- 目标 Flow 获取

#### 插件列表

| 插件 | 目录 | 检测能力 |
|------|------|---------|
| XSS | `plugins/xss/` | XSS 注入（Query/Cookie/Referer） |
| SQL Injection | `plugins/sql_injection/` | SQL 注入（布尔/报错/时间盲注） |
| CMD Injection | `plugins/cmd_injection/` | 命令注入 |
| Path Traversal | `plugins/path_traversal/` | 目录遍历 |
| SSRF | `plugins/ssrf/` | 服务端请求伪造（需反连平台） |
| XXE | `plugins/xxe/` | XML 外部实体注入（含 Blind XXE） |
| CRLF Injection | `plugins/crlf_injection/` | CRLF 注入 |
| FastJSON | `plugins/fastjson/` | FastJSON 反序列化 |
| Shiro | `plugins/shiro/` | Shiro 反序列化 |
| Struts | `plugins/struts/` | Struts2 RCE |
| ThinkPHP | `plugins/thinkphp/` | ThinkPHP 漏洞（RCE/SQLi/文件写入） |
| XStream | `plugins/xstream/` | XStream 反序列化 |
| BruteForce | `plugins/bruteforce/` | 暴力破解 |
| DirScan | `plugins/dirscan/` | 目录扫描 |
| Baseline | `plugins/baseline/` | 基线检测（Cookie/Headers/CORS/SSL/敏感信息） |
| Fingerprint | `plugins/fingerprint/` | Web 指纹识别 |
| JSONP | `plugins/jsonp/` | JSONP 劫持 |
| Redirect | `plugins/redirect/` | 开放重定向 |
| Upload | `plugins/upload/` | 任意文件上传 |
| Prometheus | `plugins/prometheus/` | Nuclei POC 引擎 |
| Custom | `plugins/custom/` | 自定义 POC 模板 |
| WAF Test | `plugins/waftest/` | WAF 检测 |
| JS | `plugins/js/` | JS 敏感信息泄露 |

### 6. http — HTTP 层

**关键文件**: `http/client.go`, `http/flow.go`, `http/request.go`, `http/response.go`

核心数据模型：

- **`Flow`** — 请求-响应对，是系统流转的核心数据单元
  ```go
  type Flow struct {
      Request   *Request
      Response  *Response
      History   []*Response
      TimeStamp int64
  }
  ```
- **`Request`** — HTTP 请求封装，支持参数提取、克隆、原始报文序列化
- **`Response`** — HTTP 响应封装
- **`Client`** — HTTP 客户端，支持代理、QPS 限制、HTTP/2、TLS、重定向控制
- **`Statistics`** — 统计信息（请求数/扫描数/平均延迟等）
- **`Parameter`** — 参数抽象（key/value/position）

### 7. reverse — 反连平台

**关键文件**: `reverse/reverse.go`, `reverse/http_server.go`, `reverse/dns_server.go`

内置完整反连平台，用于盲注类漏洞检测：

| 协议 | 服务 | 用途 |
|------|------|------|
| HTTP | `HTTPServer` | 监听 HTTP 回连 |
| DNS | `DNSServer` | 监听 DNS 查询 |
| RMI | `RMIServer` | 监听 Java RMI 回连 |
| LDAP | `LdapServer` | 监听 LDAP 回连 |

两种部署模式：
- **本地模式**：所有服务在同一进程启动，端口复用（HTTP/RMI/LDAP 共享一个 Listener）
- **远程模式**：连接远程反连服务器，通过 API 获取回连事件

核心机制：
- `Group` — 每次检测生成唯一 Group ID，用于关联回连事件
- `DB` — BoltDB 持久化回连记录
- `FetchEvent` — 定期从远程服务器拉取回连事件
- GC — 自动清理过期 Group

### 8. model — 数据模型

**关键文件**: `model/vuln.go`

核心结构：

- **`Vuln`** — 漏洞模型
  ```go
  type Vuln struct {
      Binding    *VulnBinding          // 漏洞绑定信息
      Extra      map[string]interface{}
      Flow       []*vhttp.Flow         // 漏洞相关的请求-响应对
      Payload    string                // 攻击载荷
      Param      *vhttp.Parameter      // 注入参数
      CreateTime int64
  }
  ```
- **`VulnBinding`** — 漏洞绑定（插件名 + 分类 + ID）
- **`WebVuln`** — JSON 输出格式
- **`CrawlerResult`** — 爬虫结果
- **`StatisticRecord`** — 统计记录

### 9. output — 输出层

**关键文件**: `output/stdout.go`, `output/htmlfile.go`, `output/webhook.go`

支持多种输出格式：
- **stdout** — 彩色终端输出（`pio`）
- **JSON** — JSON 文件输出
- **HTML** — HTML 报告输出（基于模板 `output/html_template.html`）
- **Webhook** — HTTP POST 推送

统一通过 `printer.Printer` 接口抽象。

### 10. mcp — MCP Server

**关键文件**: `mcp/mcp.go`, `mcp/muti_task.go`, `mcp/task.go`

基于 MCP SDK 提供 AI Agent 调用接口：

| 工具 | 说明 |
|------|------|
| `create_task` | 创建扫描任务（name, scan_url, crawler_type） |
| `control_task` | 控制任务（start/pause/stop/delete） |
| `get_task_status` | 查询任务状态 |
| `get_task_result` | 分页获取扫描结果（start, size） |

爬取模式：
- `url` — 直接请求
- `basic` — 基础爬虫（默认）
- `browser` — 浏览器爬虫

传输方式：Streamable HTTP（`mcp.NewStreamableHTTPHandler`）

### 11. resource — 资源抽象

**关键文件**: `resource/service.go`

```go
type Resource interface {
    DeepClone() Resource
    Name() string
    String() string
    Timestamp() int64
    Type() int
}
```

两种实现：
- `http.Flow` — Web 扫描目标（请求-响应对）
- `resource.Service` — 服务扫描目标（Host/Port/Protocol/Banner/Fingerprint）

### 12. utils — 工具集

| 子包 | 职责 |
|------|------|
| `checker/` | 请求/URL/服务检查器，白名单/黑名单过滤 |
| `checker/filter/` | BadgerDB 去重过滤器 + SyncMap 内存过滤器 |
| `log/` | 分级日志 |
| `printer/` | 打印器抽象（console/json/text/multi） |
| `jsonpath/` | JSONPath 查询与替换 |
| `comparer/` | HTTP 响应比对（404 识别、Header 比对） |
| `network/` | 网络工具（端口扫描等） |
| `collections/` | 队列数据结构 |
| `guess/` | 参数值猜测 |
| `ysoserial/` | Java 反序列化 Payload 生成 |
| `rlimit/` | 文件描述符限制 |
| `buildinfo/` | 版本信息与 OUI 数据 |

---

## 配置系统

`config.yaml` 统一管理所有配置，主要分块：

### http — HTTP 客户端
- `proxy` — 代理地址
- `dial_timeout` / `read_timeout` — 超时
- `max_conns_per_host` — 单 Host 最大连接数
- `max_qps` — QPS 限制
- `max_redirect` — 最大重定向次数
- `headers` — 默认请求头

### reverse — 反连平台
- `http.enabled` / `dns.enabled` — 启用协议
- `client.remote_server` — 远程模式开关
- `db_file_path` — 数据库持久化路径

### mitm — MITM 代理
- `ca_cert` / `ca_key` — CA 证书
- `restriction` — 域名/端口/路径/参数黑白名单
- `upstream_proxy` — 上游代理

### basic-crawler / browser-crawler — 爬虫
- `max_depth` / `max_count_of_links` — 爬取深度与数量
- `restriction` — 爬取范围限制
- 浏览器特有：`exec_path`, `disable_headless`, `max_interactive` 等

### plugins — 各插件配置
每个插件独立开关（`enabled`）+ 特有参数，例如：
- `sqldet`: `boolean_based_detection`, `error_based_detection`, `time_based_detection`
- `xss`: `detect_xss_in_cookie`, `detect_xss_in_referer`, `ie_feature`
- `shiro`: `cookie_name`, `aes_key`
- `dirscan`: `depth`, `dictionary`

---

## CLI 命令

```
wscan [全局选项] <命令> [命令选项]

全局选项:
  --config        配置文件路径（默认 ./config.yaml）
  --log-level     日志级别（debug/info/warn/error/fatal）

命令:
  webscan (ws)    Web 漏洞扫描
    --url (-u)          单 URL 扫描
    --url-file (-uf)    从文件读取 URL
    --burp-file (-bf)   导入 Burp 文件
    --listen            启动 MITM 代理采集
    --basic-crawler     启用基础爬虫
    --browser-crawler   启用浏览器爬虫
    --plugins           指定启用的插件
    --poc               指定 POC
    --no-scan           仅爬取不扫描
    --json-output       JSON 输出
    --html-output       HTML 输出
    --webhook-output    Webhook 输出

  reverse         启动独立反连服务器
  genca           生成 CA 证书
  version         显示版本
  mcp             启动 MCP Server
    --mcp-host    监听地址（默认 0.0.0.0）
    --mcp-port    监听端口（默认 7001）
```

---

## 关键依赖

| 依赖 | 用途 |
|------|------|
| `urfave/cli/v2` | CLI 框架 |
| `panjf2000/ants/v2` | 协程池 |
| `chromedp` | 浏览器自动化 |
| `google/martian/v3` | MITM 代理 |
| `PuerkitoBio/goquery` | HTML 解析 |
| `modelcontextprotocol/go-sdk/mcp` | MCP SDK |
| `dgraph-io/badger` | 嵌入式 KV 数据库（去重） |
| `fatih/color` + `kataras/pio` | 终端彩色输出 |
| `gopkg.in/yaml.v3` | YAML 配置解析 |
| `emicklei/dot` | DOT 图生成 |

---

## 架构特点总结

1. **事件驱动**：基于 EventBus 的发布-订阅模式，解耦采集与检测
2. **插件化**：统一 Plugin 接口，Finger 抽象实现检测规则热插拔
3. **树形调度**：插件组织为树结构，支持指纹联动（父节点匹配后触发子节点）
4. **多采集源**：主动爬虫 + 被动代理 + 文件导入，统一输出 `chan Resource`
5. **协程池控制**：ants 池化并发，避免 goroutine 爆炸
6. **反连平台内置**：HTTP/DNS/RMI/LDAP 四协议，支持本地/远程部署
7. **MCP 集成**：暴露为 AI Agent 工具，支持任务创建、控制、结果查询
8. **BadgerDB 去重**：基于嵌入式 KV 的请求去重，避免重复扫描
