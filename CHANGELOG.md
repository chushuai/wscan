# 1.0.58  2026-07-28
## SUPPORT
* 【1】插件可复用 Web 技术识别门禁(TechGate):新增 `core/plugins/base/techgate.go`,封装 `core/fingerprint` wappalyzer 引擎(与 WebUI「技术识别」同源),对当前 `*http.Flow` 实时检测指定技术是否命中。导出 `base.HasTech(bi, flow, "PHP")`、`base.TechVersion`(返回版本)、`base.DetectTechs`(返回全栈)三个助手,任意插件在 `CheckAction` 内一行即可门禁。引擎单例 `fingerprint.DefaultEngine()` 全进程共享、惰性加载,加载失败或 flow 无响应时优雅降级为「不命中」而非 panic,不依赖 `fingerprint` CEL 插件是否启用、不受 KDB 累积顺序影响(规避 CEL 规则名 "PHP Detect" 与 wappalyzer 技术名 "PHP" 不一致及异步竞态)。
* 【2】示例插件 `phpaudit`(`core/plugins/phpaudit`):演示 TechGate 用法 —— 仅当 `base.HasTech(bi, flow, "PHP")` 命中才执行,探测 PHP 专属信息泄露端点(`phpinfo.php`/`info.php`/`test.php`/`?phpinfo=1`/`phpcgi`/`.user.ini`/`.htaccess`),响应体经正则二次校验(phpinfo 页/INI 指令/CGI 状态签名)防误报,按 host+路径去重。非 PHP 目标零探测、零误报。已在 `plugins.All()` 注册,默认启用,`config.yaml` 可调 `check_paths`。补 `techgate`/`phpaudit` 单测(PHP/非 PHP/空响应三态门禁 + 真实 httptest 服务端门禁集成)。

# 1.0.57  2026-07-28
## BUGFIX
* 【1】修复 WebUI 重启后扫描任务列表不按开始时间倒序展示(最旧在前)的问题:`rehydrateScans` 误把持久化记录按 `StartedAt.After` 排序后正序 append 进 `m.order`,而 `taskManager.list()` 倒序遍历 `m.order` 产出最新在前 —— 二者叠加使重启恢复的任务变成「最旧在前」。改为按 `StartedAt.Before` 升序 append,与 `startScan` 的 `add()` 语义一致,`list()` 倒序遍历后恢复最新在前。

# 1.0.56  2026-07-27
## SUPPORT
* 【1】WebUI 新增「技术识别」(wappalyzer 指纹)功能:新增 `core/fingerprint` 包移植 wappalyzer 静态信号引擎(加载嵌入的 `technologies.json` 签名库,对 url/headers/html/cookies/scripts/meta 做正则匹配,经 implies/excludes 解析、按 confidence 聚合),实现前端早已调用但后端缺失的 `/api/technologies?taskId=` 接口,返回 `{technologies:[{name,version,confidence,categories,hits,sampleUrls}],count}`;`runScan` 用 tee goroutine 在 collector 输出与 dispatcher 之间旁路捕获每个 `*http.Flow` 的完整响应(头/体/cookie/script src/meta)跑指纹,结果存入 `scanTask.techPages`;`scanRecord` 新增 `TechPages` 持久化,重启后历史任务的技术识别结果仍可展示。前端「技术识别」页面与扫描详情 tech pane 现可直接渲染技术栈与版本。
* 【2】AI 自动渗透 `claudecode` worker 实现真正的 claude CLI 编排循环:每轮 headless 调本机 `claude -p --output-format json`(禁用 claude 自带工具、只产出工具调用意图 JSON),把黑板快照(origin/goal/facts/urls/已知漏洞)注入 prompt,我们在本进程执行真实 wscan 工具,emit `tool_call`/`tool_done`/`llm_turn`(补 `model`/`round` 字段)事件,结果回写黑板循环至目标达成(最多 8 轮)。修复此前 `claudecode` 从未真正调用 claude CLI、三种 worker 共用同一套写死 OODA 流程、对话 tab 的 "crawl + tech fingerprint" 为硬编码假事件、`tool_call`/`tool_done` 事件前端已实现却后端零 emit 的问题;claude CLI 不可用或失败时优雅回退到原 OODA。
* 【3】AI 自动渗透 crawl→scan 解耦,flow 复用不重爬:`aiProject` 黑板新增运行时 `flows` 缓存(`*http.Flow`,不落盘),`wscan_crawl` 爬取时 tee 捕获 flow 入板,后续 `wscan_scan`/`wscan_run_plugin` 优先吃缓存 flow 走新增的 `runDispatcherForFlows`(从 flow 列表直接喂 dispatcher,绕开 collector 爬取阶段),缓存空才回退自爬。并修复静态爬虫 `MaxDepth` 零值导致只抓首页、`aiScanSync` 忽略 `intent` 参数永远全插件全扫的问题(新增 `pluginsFromIntent` 从意图文本解析插件名传 `Plugins` 白名单)。
* 【4】AI 自动渗透新增 5 个可被 claude 调用的 wscan 工具执行器(`wscan_crawl`/`wscan_scan`/`wscan_run_plugin`/`wscan_list_plugins`/`http`),统一签名,产出的漏洞标 `provenance:"ai-tool"` 经 vulndb 富化;补 flow 缓存去重、工具注册表、claude 意图 JSON 解析(裸 JSON/markdown 代码块/带解释/空/无 JSON)、intent→插件解析、工具范围校验等单测。

# 1.0.55  2026-07-27
## SUPPORT
* 【1】WebUI 扫描详情页新增「任务详情」tab:展示本次扫描的请求配置(目标/类型/状态/开始时间/耗时/爬虫模式/最大页数/最大深度/并发/自动扫描/插件/自定义请求头/包含·排除路径/代理/靶场/种子方法·请求体/鉴权)。`scanTask` 新增 `req scanRequest` 字段并在 `startScan` 赋值,`toFrontTaskDetail` 把 `req` 一并返回;`scanRecord` 新增 `Req` 字段持久化,`rehydrateScans` 用 helper(`strVal/intVal/boolVal/strSlice/mapVal`)还原 `scanRequest`,重启后历史任务也能看配置。密码字段以星号脱敏,token/cookie/长值截断显示。
## BUGFIX
* 【1】修复 WebUI「仅爬取」任务实际仍执行漏洞扫描、且列表类型显示为「爬取+扫描」的问题:`handleCrawl` 无条件 `req.AutoScan=true` 把前端传来的 `autoScan:false`(仅爬取)改成了 true;`startScan` 又用 `CrawlerMode=="static" && Method!="" && Data!=nil` 判定 taskType,与是否扫描脱节。现 `handleCrawl` 不再强制置 true,语义完全由 `autoScan` 字段决定;`startScan` 改用 `autoScan` 判定 taskType:`true`→`crawl`(爬取+扫描)、`false`→`crawlonly`(仅爬取,只爬不扫,`disp.Run` 传 `noScan=true`)、扫描入口→`scan`。新增 `misc.crawlOnlyType` 文案,列表与详情按三态正确显示。

# 1.0.54  2026-07-26
## SUPPORT
* 【1】WebUI「AI 自动渗透」详情页新增「URL 结果」tab:黑板结构加 `URLs` 段(按 url 去重),dispatcher bootstrap 侦察爬取到的页面/端点经 `addURL` 写入黑板并广播 SSE `url` 事件;`GET /api/ai-pentest/:id/urls` 返回 URL 列表,前端 tab 复用扫描详情的 resultsTable 行结构(状态/方法/URL/标题/来源 + 点开查看完整请求-响应),支持 TXT/JSON/XML 导出。
* 【2】AI 自动渗透「工具范围 (Tool scope)」支持用户自定义工具:新增 `/api/ai-pentest/tools`(GET 列出内置+自定义 / POST 新建或更新)与 `DELETE /api/ai-pentest/tools/:tid`,自定义工具持久化到 `data/ai_custom_tools.json`;「新建 AI 渗透」模态框的工具范围区把内置工具与自定义工具合并勾选,并支持就地新增(名称/描述/图标/分类)与删除,详情页右侧工具箱同步展示。
* 【3】移除顶层菜单状态栏的「New Scan」按钮(新建扫描入口仍在各列表页的「+ 新建扫描」按钮)。
## BUGFIX
* 【1】修复 WebUI 扫描目标指定了 Basic 认证但爬取和扫描都没生效的问题:`startScan` 只处理了自定义请求头,未处理前端 `auth` 鉴权字段。新增 `applyScanAuth` 把鉴权(basic/digest/token/jwt/cookie/header)注入到单次扫描任务的配置克隆(basic 写入 `cfg.Crawler.BasicAuth` + `Authorization` 头,其余作为默认头注入),爬虫与扫描器共用同一份 `cfg.HTTP` 故一并生效,与 CLI 入口 `entry.go` 的 basic-auth 注入同构。
* 【2】修复动态(浏览器)爬虫在目标配了 Basic 认证时爬不到受保护页面(如 `?id=1`)的问题:`startScan` 构造动态爬虫的 `crawler.Config` 时未传 `AuthConfig`,且 `HandleAuthRequired` 收到 401/407 挑战时只回固定占位凭证 `Scan/Scan`。现把 `cfg.Crawler.BasicAuth` 传入动态/静态两路 `crawler.Config.AuthConfig`,并将 `HandleAuthRequired` 改为优先用配置的 BasicAuth 凭证应答挑战,无配置时才回退占位凭证。

# 1.0.53  2026-07-26
## SUPPORT
* 【1】补齐 WebUI「AI 自动渗透」页全部后端接口与 Cairn 风格黑板模型:新增 `core/web/ai_pentest.go` + `core/web/ai_pentest_handlers.go`,实现 `/api/ai-pentest` 项目列表/新建、`/:id` 详情、`/:id/{start,stop,hint,vulns,events}`、`/llm-config`、`/llm-test` 全部路由,数据持久化到 `data/ai_pentestest.json`;黑板结构含 Fact(已确认发现)/Intent(探索方向,unclaimed→claimed→done)/Event(事件流,经 SSE 实时推前端)/aiVuln(漏洞,provenance 标 scanner/ai-tool/ai-manual,经 vulndb 富化复用扫描详情卡片)。
* 【2】实现 AI 渗透 dispatcher 的 OODA 循环(bootstrap 侦察→reason 生成探索意图→explore 执行意图产出 Fact)与三种 worker:`claudecode`(本机 claude CLI)、`llm`(OpenAI/Anthropic 兼容 chat-completions,新增 `llmChat` HTTP 客户端)、`mock`(规则 worker,无 LLM 也可用);bootstrap/explore 复用 `startScan` 同步跑爬取/扫描并把结果回喂黑板。
* 【3】LLM 配置与 claude CLI 探测:GET/POST `/api/ai-pentest/llm-config` 持久化到 `data/ai_llm_config.json` 并返回 `claude` 可用性(`exec.LookPath("claude")` + ANTHROPIC_API_KEY/AUTH_TOKEN/BASE_URL 环境变量探测);POST `/api/ai-pentest/llm-test` 发一条 ping 验证连通。前端「新建 AI 渗透」「LLM 配置」模态框现可真实保存与测试。
## BUGFIX
* 【1】修复 wscan 启动时 `flag redefined: v` panic:`github.com/google/martian/v3` 与 `github.com/golang/glog` 都在包 init 时用 `flag.Int/Var("v")` 向 `flag.CommandLine` 注册 `-v`,二者同时入链即冲突 panic,导致 `wscan version`/`webui` 等所有子命令都启动失败。给 `vendor/.../martian/v3/init.go` 的 `level` 改为先 `flag.Lookup("v")` 复用占位再注册(避免 redefined),并在 `cmd/wscan/main.go` 加兜底 `init()` 重建 `flag.CommandLine`。

# 1.0.52  2026-07-26
## SUPPORT
* 【1】WebUI 推送通知改为 wscan 原生直连 IM,不再依赖 cc-connect 桥接:新增 `core/web/notify.go`,原生支持飞书/Lark、企业微信、钉钉三个平台,均走标准 HTTPS POST,无第三方 SDK 依赖;飞书/钉钉 webhook 支持加签 secret 完整性校验,企业微信/钉钉支持 @全体。
* 【2】飞书支持扫码建机器人→1v1 应用消息模式(复刻 cc-connect `feishu setup` 的 device_code 流程):新增 `/api/ai-notify/feishu/qrcode/start` 与 `/api/ai-notify/feishu/qrcode/poll`,后端用 `github.com/skip2/go-qrcode` 把 verification_uri_complete 编码成 PNG 返给前端;扫码成功后用 app_id/app_secret 换 tenant_access_token,调 `/open-apis/im/v1/messages` 给创建者发 1v1 文本,无需群、无需公网回调。
* 【3】补齐前端已调用但后端缺失的 `/api/ai-notify`(GET 读取 / POST 保存推送配置)与 `/api/ai-notify/test`(POST 发测试消息)handler,配置持久化到 `data/webui_notify.json`;前端「全局配置 → 推送」页支持平台选择、飞书 webhook/扫码两种模式切换、二维码渲染与自动轮询,移除原 cc-connect 的 bin/project/sessionKey 配置。

# 1.0.51  2026-07-25
## SUPPORT
* 【1】WebUI 漏洞详情补全漏洞描述库：按扫描插件可映射到的漏洞类型生成单文件 XML（`core/web/vulndb/*.xml`，93 条，`go:embed` 嵌入二进制；后端按漏洞 ID（含插件 ID 别名映射）查库，向前端填充 name/description/impact/recommendation/CVSS/tags/references，扫描详情漏洞卡片与分组标题展示完整顾问文案。映射严格按语义一一对应，匹配不上的插件（CSP 各类问题、cookiekey 弱密钥、thinkphp、xstream 各 CVE、tomcat/jboss/weblogic/spring 暴露检查等）单独补充对应 XML 描述。

# 1.0.50  2026-07-25
## SUPPORT
* 【1】扫描详情页漏洞卡片补全 HTTP 请求/响应快照展示：后端将 `WebVuln.Detail.SnapShot` 的原始报文解析为结构化 request/response，前端 `httpSec` 渲染完整的请求头、请求体、响应头与响应体。
## BUGFIX
* 【1】修复扫描详情页漏洞列表不显示的问题（`renderVulns` 用 `const t=taskCache[curTask]` 覆盖了全局翻译函数 `t`，导致 `t('vul.empty')` 抛出 `t is not a function`，漏洞面板空白）。

# 1.0.49  2026-07-25
## SUPPORT
* 【1】WebUI 扫描任务结果持久化（落盘 data/webui_scans.json），服务重启后历史扫描任务与漏洞结果保留并可继续查看。
## BUGFIX
* 【1】修复 WebUI 漏洞扫描结果未持久化、重启后全部丢失的问题。
* 【2】修复扫描详情页漏洞列表为空的问题（`/api/task/:id/vulns` 平铺分页响应缺少 `vulnTotal` 字段，前端据此判断无漏洞）。

# 1.0.48  2026-07-25
## SUPPORT
* 【1】WebUI 目标分组支持持久化存储（落盘 JSON），新增分组的创建、编辑、删除及成员管理 CRUD 接口。
* 【2】批量新增目标时支持勾选加入分组，自动将新目标追加为对应分组成员。
## BUGFIX
* 【1】修复 WebUI「目标分组 → 新建分组」无响应的问题（原后端为空 stub，未实现 POST/PUT/DELETE）。
* 【2】修复目标分组成员保存后未持久化、刷新后丢失的问题（成员字段在 JSON 重载后类型变为 []any，统一归一化为 []string）。
* 【3】修复删除目标后其 id 仍残留在分组成员列表中的问题，新增级联清理。

# 1.0.47  2026-07-25
## SUPPORT
* 【1】WebUI 支持中英文双语切换，顶栏新增语言切换按钮（globe 图标）。首次按浏览器语言自动判定，手动切换后用 localStorage 记住偏好。
* 【2】补全 WebUI 全部页面的国际化文案（顶栏/导航/仪表盘/目标/目标分组/靶场/漏洞/扫描/扫描详情/AI 自动渗透/报告/发现/技术识别/扫描配置/全局配置/新建扫描/鉴权等），原硬编码中文统一收口到 I18N 词典（key→[zh,en]）。
## BUGFIX
* 【1】修复 I18N 词典中 `ai.intClaimed` 键重复定义（探索中/已认领）导致后者覆盖前者的问题，拆分为 `ai.intExploring` 与 `ai.intClaimed` 两个键。

# 1.0.46  2026-06-16
## SUPPORT
* 【1】新增高级敏感文件检测插件 (sensitivefile)，支持 40 种敏感文件类型
* 【2】新增盲打 XSS (Blind XSS) 检测能力（增强 XSS 插件）
* 【3】新增 SSL/TLS 安全审计插件 (sslaudit)，支持 6 类检测规则
* 【4】新增 EL/SpEL 表达式注入检测插件 (elinject)
* 【5】新增原型链污染检测插件 (prototypepollution)
* 【6】新增 Cookie 弱密钥暴力破解插件 (cookiekey)，支持 6 种框架

# 1.0.45 2026-06-11
## BUGFIX
* 【1】 优化文件上传、命令执行、目录爆破、SQL 注入等插件。
* 【2】 优化爬虫，支持 Basic Auth 认证。

# 1.0.44 2026-06-08
## SUPPORT
* 【1】 爬虫新增父目录发现功能
## BUGFIX
* 【1】 修复Swagger / OpenAPI重复执行的问题
* 【2】 修复目录穿越、SQL注入、s2-009误报问题

# 1.0.43 2026-06-07
## SUPPORT
* 【1】 重新设计扫描报告
* 【2】 重新设计返连平台界面
* 【3】 支持按严重等级过滤扫描结果，以及排除/指定漏洞ID

# 1.0.42 2026-06-06
## SUPPORT
* 【1】支持 Swagger / OpenAPI 接口的渗透测试。
## BUGFIX
* 【1】修复 Baseline（基线）相关配置项未生效的问题。

# 1.0.41 2026-05-24
## SUPPORT
* 【1】爬虫新增解析 robots.txt、sitemap.xml 及 sourcemap 文件
* 【2】升级 Nuclei 引擎，新增 Flow支持
## BUGFIX
* 【1】修复批量爬取网站时部分页面遗漏的问题

# 1.0.40 2026-01-03
## SUPPORT
* 【1】优化时间盲注检测逻辑，引入三阶梯验证与标准差过滤
详情：
准确度优化： 将原有的固定验证改为 2s/4s/8s 三阶梯时延验证，确保耗时随 Payload 线性增长，有效排除固定慢查询干扰。
噪声过滤： 引入统计学标准差（Standard Deviation），增加 avg + 3*stdDev (3-Sigma) 判定阈值，自动适应不同质量的网络环境，压制网络抖动导致的误报。
结构重构： 更新 TimeBasedDetectionStatInfo 结构，将固定验证字段改为动态 Steps 切片，支持记录多轮验证数据。
回归测试： 在输出漏洞前增加原始请求恢复性验证，排除服务器整体瞬时负载波动干扰。

# 1.0.39 2026-01-03
## SUPPORT
* 【1】优化命令行扫描参数，使动态和静态爬虫均支持批量扫描

# 1.0.38 2026-01-02
## BUGFIX
* 【1】修复因过滤规则导致的漏爬问题
* 【2】修复 url-file 中包含畸形 URL 引发程序崩溃的问题
* 【3】修复 MCP 服务获取结果时崩溃的问题

# 1.0.37 2025-12-31
## SUPPORT
* 【1】支持以 MCP 服务器模式启动 WScan，实现远程任务管理与网站安全扫描
* 【2】修复默认UA配置错误的问题

# 1.0.36 2025-07-20
## BUGFIX
* 【1】对反连平台进行了性能优化，提升系统响应速度与稳定性
* 
# 1.0.35 2025-07-07
## BUGFIX
* 【1】修复Nuclei插件加载报错的问题

# 1.0.34 2025-07-01
## SUPPORT
* 【1】新增两个 SQL 注入检测规则（Payload）
## BUGFIX
* 【1】修复 Cookie 注入失败问题（因未正确编码导致）
* 【2】修复一处路径注入时可能出现的数组越界异常

# 1.0.33 2025-06-30
## BUGFIX
* 【1】修复因多余一次 URL 编码导致的路径参数模糊测试失败问题

# 1.0.32 2025-06-29
## SUPPORT
* 【1】支持路径参数模糊测试
* 【2】HTTP Header 模糊测试能力升级
## BUGFIX
* 【1】修复指纹插件关闭配置未生效的问题

# 1.0.31 2024-10-30
* 【1】 支持Fuzz复杂的JSON、XML请求，如列表、字段等等
* 【2】 默认关闭基线检查
* 【3】 默认启用无头浏览器，隐藏浏览器窗口

# 1.0.30 2024-10-03
* 【1】 支持通过 webhook 输出扫描结果

# 1.0.29 2024-07-31
* 【1】支持JavaScript敏感内容检测，识别JavaScript包含的AK/SK、ApiKey、电话、邮箱等敏感内容

# 1.0.28 2024-07-30
## BUGFIX
* 【1】修复动静态爬虫HTTP代理不生效的问题
* 【2】修复临时文件残留的问题

# 1.0.27 2024-07-28
## SUPPORT
* 【1】cmd-injection插件，新增ssti系列漏洞检测payload
* 【2】优化扫描状态日志

# 1.0.26 2024-07-28
## SUPPORT
* 【1】支持自定用户名密码字典，增强表单爆破能力

# 1.0.25 2024-07-21
## SUPPORT
* 【1】自动判断Nuclei插件是否支持多级目录扫描，将nuclei插件的扫描能力发挥到极致
* 【2】支持cookie注入

# 1.0.24 2024-07-20
## SUPPORT
* 【1】支持对 JSON 格式的参数进行模糊测试
* 【2】使用--json-crawler-output输出动静态爬虫的扫描结果
## BUGFIX
* 【1】修复不支持不安全证书的问题
* 【2】修复指定config文件了，还是会自动生成config.yaml 文件
* 【3】修复由于处理 EventRequestPaused 事件时 HTTP 头部构建错误而导致的爬取结果缺失的问题

# 1.0.23 2024-07-07
## SUPPORT
* 【1】支持通用log4j-rce漏洞检测
* 【2】Yaml POC支持ldap_url, rmi_url
* 【3】新增--no-scan参数，绕过漏洞扫描，只进行主动或被动爬取
* 【4】优化动态爬虫，避免对Data URLs（URL中编码的文件）发起请求

# 1.0.22 2024-07-06
## SUPPORT
* 【1】实现利用语义分析的方式检测XSS漏洞，XSS检测准确率大幅提升
## BUGFIX
* 【1】修复由于客户端反连平台配置导致的退出

# 1.0.21 2024-04-06
## SUPPORT
* 【1】主被动扫描支持WEB组件识别，内置3700+WEB组件识别插件
* 【2】修复反连平台异常退出的问题

# 1.0.20 2024-03-27
## SUPPORT
* 【1】主被动扫描支持hostname、path作为过滤条件

# 1.0.19 2024-03-25
## SUPPORT
* 【1】新增xstream系列漏洞检测插件
* 【2】重构反连模块


# 1.0.18 2024-03-10
## SUPPORT
* 【1】支持自定义FUZZ插件，对body、query中的参数进行模糊测试
* 【2】将custom_tmpl插件重命名为waftest
* 【3】config.yml添加版本号，自动更新覆盖旧的配置 
* 【4】支持http、socks5代理扫描

# 1.0.17 2024-03-08
## BUGFIX
* 【1】优化了页面相似度分析算法，解决了Boolean SQL注入误报问题
* 【2】修复动态爬虫没有使用深拷贝导致POST数据缺失问题


# 1.0.16 2024-01-21
## SUPPORT
* 【1】支持 baseline/sensitive/application_error
* 【2】支持 Nuclei Yaml POC插件
* 【3】支持 Shiro 框架识别与默认key破解插件


# 1.0.15 2024-01-18
## BUGFIX
* 【1】修复主被动爬虫无法访问不安全TLS连接的问题 
* 【2】修复 DVWA命令执行漏洞漏报的问题
* 【3】优化 提高被动扫描响应速度
## SUPPORT
* 【1】支持PHP、JSP、ASP、ASPX任意文件上传检测
* 【2】被动扫描支持智能请求过滤


# 1.0.14 2024-01-15
## BUGFIX
* 【1】修复s2-046漏洞漏报
## SUPPORT
* 【1】支持thinkphp系列漏洞批量检测

# 1.0.13 2024-01-07
## SUPPORT
* 【1】支持XXE、SSRF、Fastjson漏洞检测，但需开启内置的反连模块
* 【2】支持struts2系列漏洞批量检测
* 【3】基于真假的SQL注入，保存True、False的快照到结果中

# 1.0.12 2023-12-30
## BUGFIX
* 【1】修复XRAY YAML POC不支持多层目录扫描的问题
* 【2】修复XRAY YAML POC CEL由于缺少Header导致执行失败的问题
## SUPPORT 
* 【1】支持Goby JSON POC插件，多层URL目录POC扫描  

# 1.0.11 2023-12-24
## SUPPORT 
* 【1】支持独立部署反连模块，同时Yaml POC支持反连功能。  
* 【2】支持使用--poc参数指定待扫描POC  

# 1.0.10 2023-12-12
## SUPPORT
* 【1】目录扫描内置400条常见规则、支持自定义扫描路径爆破。
* 【2】支持ASP、PHP通用命令执行检测


# 1.0.9 2023-12-09
## SUPPORT
* 【1】支持自定义WEB通用漏洞扫描模板(Waf绕过/Waf测试)

# 1.0.8 2023-12-04
## SUPPORT
* 【1】支持通过命令行指定要启用的plugins

# 1.0.7 2023-12-03
## SUPPORT
* 【1】支持从url-file加载扫描目标
* 【2】支持Yaml POC扫描插件

# 1.0.6 2023-12-02
## SUPPORT
* 【1】支持输出JSON、HTML格式的扫描结果
## BUGFIX
* 【1】修复浏览器爬虫去重不到位等问题
* 【2】修复POST请求相关的问题

# 1.0.5 2023-11-30
## SUPPORT
* 【1】支持浏览器爬虫
* 【2】支持URL、表单智能过滤

# 1.0.4 2023-11-25
## BUGFIX
* 【1】修复部分情况下无法退出的问题
* 【2】修复部分情况任务没有执行完就退出的问题
* 【3】修复部分情况下XSS、SQL注入漏报的问题
## SUPPORT
* 【1】支持对单个URL进行漏洞检测

# 1.0.3 2023-11-18
## BUGFIX
* 【1】修复基于错误的SQL注入误报

## SUPPORT
* 【1】支持form表单爬取
* 【2】实现一个简单的JSOP插件

# 1.0.2 2023.11.12
## BUGFIX
* 【1】修复了与HTTP复制相关的异常，并支持在被动扫描中加载证书。
# 1.0.1 2023.11.12
## SUPPORT
* 【1】支持静态爬虫

# 1.0.0 2023.11.05
## SUPPORT
* 【1】支持简单的Web通用漏洞检测
