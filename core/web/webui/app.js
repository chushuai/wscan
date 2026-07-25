/*
 * app.js — browser-side SPA for the WEB UI (crawler + scanner).
 *
 * Author: shaochuyu
 */

// server-injected default exclude patterns (logout). Visible + editable in the
// scan form Exclude field + target modal. Kept in sync with crawler_util.
window.DEFAULT_EXCLUDE_PATTERNS = ["(?:^|\\/)(?:log[\\s-]?out|sign[\\s-]?out|signout|deconnexion|cerrar[\\s-]?sesion|sair|abmelden|uitloggen|ausloggen|disconnect|end[\\s-]?session|desconectar|afmelden|wyloguj|sign[\\s-]?off)(?:\\.[a-z0-9]+)?(?:[\\/?#]|$)"];

// ===== i18n (中英文切换) =====
// curLang: 'zh'|'en'. 首次按 navigator.language 判定;用户手动切换后用 localStorage 记住。
// 词典格式: key -> [zh, en]。t(key) 返回当前语言文案,缺失时回退返回 key 本身。
let curLang = localStorage.getItem('webscan-lang') || (/^en/i.test(navigator.language||'') ? 'en' : 'zh');
const I18N = {
  // --- topbar / chrome ---
  'app.title': ['WScan · Web 漏洞扫描', 'WScan · Web Vulnerability Scanner'],
  'app.subtitle': ['Web 漏洞扫描', 'Web Vulnerability Scanner'],
  'status.ready': ['就绪', 'Ready'],
  'top.newScan': ['新建扫描', 'New Scan'],
  'top.theme': ['切换明暗主题', 'Toggle theme'],
  'top.langTo': ['切换到英文', 'Switch to Chinese'],
  'top.langToEn': ['切换到英文', 'Switch to English'],
  'top.langToZh': ['切换到中文', 'Switch to Chinese'],
  'top.localRun': ['本地运行', 'Local'],
  // --- nav ---
  'nav.dashboard': ['仪表盘', 'Dashboard'],
  'nav.targets': ['目标', 'Targets'],
  'nav.targetGroups': ['目标分组', 'Target Groups'],
  'nav.labs': ['靶场', 'Labs'],
  'nav.vulnerabilities': ['漏洞', 'Vulnerabilities'],
  'nav.scans': ['扫描', 'Scans'],
  'nav.aiPentest': ['AI 自动渗透', 'AI Auto-Pentest'],
  'nav.reports': ['报告', 'Reports'],
  'nav.discovery': ['发现', 'Discovery'],
  'nav.technologies': ['技术识别', 'Technologies'],
  'nav.users': ['用户', 'Users'],
  'nav.profiles': ['扫描配置', 'Profiles'],
  'nav.config': ['全局配置', 'Config'],
  // --- common ---
  'c.refresh': ['刷新', 'Refresh'],
  'c.cancel': ['取消', 'Cancel'],
  'c.save': ['保存', 'Save'],
  'c.delete': ['删除', 'Delete'],
  'c.edit': ['编辑', 'Edit'],
  'c.add': ['添加', 'Add'],
  'c.start': ['启动', 'Start'],
  'c.stop': ['停止', 'Stop'],
  'c.scan': ['扫描', 'Scan'],
  'c.crawl': ['爬取', 'Crawl'],
  'c.export': ['导出', 'Export'],
  'c.filter': ['过滤', 'Filter'],
  'c.all': ['全选', 'All'],
  'c.none': ['清空', 'None'],
  'c.close': ['关闭', 'Close'],
  'c.confirm': ['确认', 'Confirm'],
  'c.detail': ['详情', 'Details'],
  'c.collapse': ['收起', 'Collapse'],
  'c.expand': ['展开', 'Expand'],
  'c.loading': ['加载中…', 'Loading…'],
  'c.loadMore': ['加载更多', 'Load more'],
  'c.allShown': ['已显示全部 ', 'Showing all '],
  'c.unit': ['条', 'items'],
  'c.page': ['页', 'page'],
  'c.total': ['共 ', 'Total '],
  'c.perPage': ['每页', 'Per page'],
  'c.view': ['查看', 'View'],
  'c.back': ['返回', 'Back'],
  'c.create': ['创建', 'Create'],
  'c.test': ['测试', 'Test'],
  'c.enabled': ['启用', 'Enabled'],
  'c.yes': ['是', 'Yes'],
  'c.no': ['否', 'No'],
  'c.none2': ['无', 'None'],
  // --- status pills ---
  'st.running': ['运行', 'Running'],
  'st.done': ['完成', 'Done'],
  'st.error': ['错误', 'Error'],
  'st.paused': ['已暂停', 'Paused'],
  'st.stopped': ['已停止', 'Stopped'],
  'st.notScanned': ['未扫描', 'Not scanned'],
  // --- dashboard ---
  'dash.title': ['仪表盘', 'Dashboard'],
  'dash.desc': ['扫描概览 · 实时统计', 'Scan overview · live stats'],
  'dash.viewScans': ['查看扫描', 'View scans'],
  'dash.targets': ['目标', 'Targets'],
  'dash.scans': ['扫描', 'Scans'],
  'dash.vulns': ['漏洞', 'Vulns'],
  'dash.profiles': ['扫描配置', 'Profiles'],
  'dash.sevDist': ['漏洞严重度分布', 'Vulnerability severity distribution'],
  'dash.recent': ['最近扫描', 'Recent scans'],
  'dash.sevHigh': ['高危', 'High'],
  'dash.sevMed': ['中危', 'Medium'],
  'dash.sevLow': ['低危', 'Low'],
  'dash.sevInfo': ['信息', 'Info'],
  'dash.noScans': ['暂无扫描', 'No scans'],
  'dash.vulnCount': ['漏洞', 'vulns'],
  // --- targets ---
  'tgt.title': ['目标', 'Targets'],
  'tgt.desc': ['管理扫描目标 — 每个目标对应一个 URL；多个目标可组合成分组', 'Manage scan targets — one URL per target; group multiple targets together'],
  'tgt.groups': ['目标分组', 'Target Groups'],
  'tgt.add': ['+ 添加目标', '+ Add Target'],
  'tgt.thAddr': ['地址', 'Address'],
  'tgt.thDesc': ['描述', 'Description'],
  'tgt.thType': ['类型', 'Type'],
  'tgt.thVulns': ['漏洞', 'Vulns'],
  'tgt.thLast': ['最近扫描', 'Last scan'],
  'tgt.thOp': ['操作', 'Actions'],
  'tgt.empty': ['暂无目标，点击「+ 添加目标」', 'No targets — click "+ Add Target"'],
  'tgt.delConfirm': ['删除该目标? 将从所有分组移除。', 'Delete this target? It will be removed from all groups.'],
  // --- add targets ---
  'at.title': ['添加目标', 'Add Targets'],
  'at.desc': ['每行一个 URL = 一个目标；可在底部勾选要加入的分组。支持从 CSV 导入 (格式: Address, Description)，上限 500。', 'One URL per row = one target; optionally assign to groups below. CSV import supported (format: Address, Description), limit 500.'],
  'at.import': ['导入 CSV', 'Import CSV'],
  'at.hint': ['提示: http://example.com/ 扫描该主机全部路径；http://example.com/dir/ 仅扫描该目录下路径。CSV 格式: 每行 <code>Address,Description</code> (首行可为表头，描述可省略/含逗号)。', 'Tip: http://example.com/ scans all paths on the host; http://example.com/dir/ scans only that directory. CSV format: <code>Address,Description</code> per line (first row may be a header; description optional/may contain commas).'],
  'at.more': ['+ 再添加一个目标', '+ Add another target'],
  'at.joinGroup': ['加入分组 (可选)', 'Add to groups (optional)'],
  'at.joinHint': ['勾选的分组会把本次新增的每个目标都加为成员。分组也可之后在「目标分组 → 成员」里调整。', 'Checked groups will have every new target added as a member. Groups can also be adjusted later under "Target Groups → Members".'],
  'at.thGroup': ['分组名', 'Group'],
  'at.noGroup': ['暂无分组。可先到「目标分组」新建。', 'No groups yet. Create one under "Target Groups".'],
  'at.cap500': ['已达上限 500', 'Limit of 500 reached'],
  'at.noAddr': ['请至少填写一个目标地址', 'Please fill in at least one target address'],
  'at.over500': ['超过上限 500，请减少目标数量', 'Exceeds limit of 500, please reduce'],
  'at.added': ['已添加 ', 'Added '],
  'at.targets': [' 个目标', ' targets'],
  'at.csvDropped': [' (CSV 超限丢弃 ', ' (CSV over limit dropped '],
  'at.csvLoad': ['已从 CSV 载入 ', 'Loaded '],
  'at.csvFromCsv': [' 个目标', ' targets from CSV'],
  'at.csvCap': [' (达上限 500，多余已截断)', ' (limit 500 reached, extras truncated)'],
  'at.csvCheck': ['，请检查后点「保存」', ', review then click "Save"'],
  'at.csvNoParse': ['CSV 未解析到有效目标 (格式: Address,Description)', 'CSV parsed no valid targets (format: Address,Description)'],
  'at.csvReadErr': ['读取文件失败', 'Failed to read file'],
  'at.lblAddr': ['地址', 'Address'],
  'at.lblDesc': ['描述', 'Description'],
  // --- target modal ---
  'tm.edit': ['编辑目标', 'Edit Target'],
  'tm.add': ['添加目标', 'Add Target'],
  'tm.fldTarget': ['目标', 'Target'],
  'tm.addrSingle': ['地址 (单个 URL)', 'Address (single URL)'],
  'tm.crit': ['危险等级', 'Criticality'],
  'tm.inGroup': ['所属分组', 'In groups'],
  'tm.noGroup': ['无', 'None'],
  'tm.scope': ['范围 (Discovery)', 'Scope (Discovery)'],
  'tm.include': ['Include (正则,逗号)', 'Include (regex, comma)'],
  'tm.exclude': ['Exclude (正则,逗号)', 'Exclude (regex, comma)'],
  'tm.auth': ['鉴权 (可选)', 'Authentication (optional)'],
  'tm.noAddr': ['请填写地址', 'Please fill in the address'],
  // --- target groups ---
  'tg.title': ['目标分组', 'Target Groups'],
  'tg.desc': ['由多个目标组成的集合 — 可整组扫描、统一查看漏洞', 'A set of targets — scan the whole group, view vulns together'],
  'tg.back': ['返回目标', 'Back to targets'],
  'tg.new': ['+ 新建分组', '+ New Group'],
  'tg.thName': ['分组名', 'Group'],
  'tg.thDesc': ['描述', 'Description'],
  'tg.thCount': ['目标数', 'Targets'],
  'tg.thVulns': ['漏洞', 'Vulns'],
  'tg.thOp': ['操作', 'Actions'],
  'tg.members': ['成员', 'Members'],
  'tg.empty': ['暂无分组，点击「+ 新建分组」', 'No groups — click "+ New Group"'],
  'tg.delConfirm': ['删除该分组? (不会删除其中的目标)', 'Delete this group? (Targets inside are not deleted)'],
  'tg.editM': ['编辑分组', 'Edit Group'],
  'tg.newM': ['新建分组', 'New Group'],
  'tg.fldGroup': ['分组', 'Group'],
  'tg.nameReq': ['分组名 *', 'Group name *'],
  'tg.nameEmpty': ['请填写分组名', 'Please fill in the group name'],
  // --- group membership ---
  'gm.title': ['分组成员 — ', 'Group Members — '],
  'gm.desc': ['勾选后用中间按钮在「成员」与「可选目标」之间移动', 'Check items then use the middle buttons to move between "Members" and "Available"'],
  'gm.back': ['← 返回分组', '← Back to groups'],
  'gm.members': ['成员', 'Members'],
  'gm.avail': ['可选目标', 'Available'],
  'gm.addBtn': [' 加入分组', ' Add to group'],
  'gm.rmBtn': ['移出分组 ', 'Remove from group '],
  'gm.emptyMem': ['暂无成员', 'No members'],
  'gm.emptyAvail': ['全部目标已是成员', 'All targets are members'],
  'gm.updated': ['分组「', 'Group "'],
  'gm.updated2': ['」成员已更新 (', '" members updated ('],
  'gm.updated3': [')', ')'],
  'gm.noMembers': ['该分组没有目标，请先添加成员', 'This group has no targets, add members first'],
  'gm.scanConfirm': ['将对分组「', 'Will scan all '],
  'gm.scanConfirm2': ['」的 ', '" targets of group "'],
  'gm.scanConfirm3': [' 个目标逐一发起爬取+扫描，确认?', '" one by one (crawl+scan). Confirm?'],
  'gm.starting': ['正在启动分组扫描 (', 'Starting group scan ('],
  'gm.starting2': [' 个目标)...', ' targets)...'],
  'gm.started': ['分组扫描已启动: ', 'Group scan started: '],
  'gm.started2': ['/', '/'],
  // --- vulnerabilities (agg) ---
  'vul.title': ['漏洞', 'Vulnerabilities'],
  'vul.desc': ['跨所有扫描聚合 · 按严重度降序', 'Aggregated across all scans · sorted by severity'],
  'vul.sevAll': ['全部严重度', 'All severities'],
  'vul.sevHigh': ['高危', 'High'],
  'vul.sevMed': ['中危', 'Medium'],
  'vul.sevLow': ['低危', 'Low'],
  'vul.sevInfo': ['信息', 'Info'],
  'vul.groupOn': ['聚合中 ✓', 'Grouping ✓'],
  'vul.groupOff': ['按漏洞名聚合', 'Group by vuln name'],
  'vul.empty': ['暂无漏洞', 'No vulnerabilities'],
  'vul.urls': [' 个 URL', ' URLs'],
  'vul.expand': ['▾ 展开', '▾ Expand'],
  'vul.collapse': ['▴ 收起', '▴ Collapse'],
  'vul.detail': ['▾ 详情', '▾ Details'],
  'vul.unitType': ['个类型', 'types'],
  'vul.extraVulns': [' 条漏洞', ' vulns'],
  'vul.allShown': ['已显示全部 ', 'Showing all '],
  'vul.loadMore': ['加载更多 (', 'Load more ('],
  // --- scans list ---
  'sc.title': ['扫描', 'Scans'],
  'sc.desc': ['所有扫描任务 (并发运行)', 'All scan tasks (concurrent)'],
  'sc.delSel': ['删除选中', 'Delete selected'],
  'sc.new': ['+ 新建扫描', '+ New Scan'],
  'sc.thSel': ['', ''],
  'sc.thId': ['#', '#'],
  'sc.thType': ['类型', 'Type'],
  'sc.thTarget': ['目标', 'Target'],
  'sc.thStatus': ['状态', 'Status'],
  'sc.thProg': ['进度', 'Progress'],
  'sc.thVulns': ['漏洞', 'Vulns'],
  'sc.thCrawled': ['已爬', 'Crawled'],
  'sc.thStart': ['开始时间', 'Started'],
  'sc.thOp': ['操作', 'Actions'],
  'sc.typeCrawlScan': ['爬取+扫描', 'Crawl+Scan'],
  'sc.typeScanOnly': ['仅扫描', 'Scan only'],
  'sc.pageUnit': ['页', 'pages'],
  'sc.empty': ['暂无扫描，点击「新建扫描」', 'No scans — click "New Scan"'],
  'sc.delSelConfirm': ['确认删除选中的 ', 'Delete the selected '],
  'sc.delSelConfirm2': [' 个扫描任务及其扫描结果?仅已完成/错误的任务会被删除。', ' scan tasks and their results? Only done/error tasks will be deleted.'],
  'sc.deleted': ['已删除 ', 'Deleted '],
  'sc.deleted2': [' 个任务', ' tasks'],
  'sc.skipped': [' (跳过: ', ' (skipped: '],
  'sc.delRowConfirm': ['确认删除扫描任务 #', 'Delete scan task #'],
  'sc.delRowConfirm2': [' 及其扫描结果?', ' and its results?'],
  'sc.deletedTask': ['已删除任务 #', 'Deleted task #'],
  'sc.stopping': ['正在停止任务 #', 'Stopping task #'],
  'sc.stopping2': ['…', '…'],
  // --- scan detail ---
  'sd.back': ['← 返回扫描列表', '← Back to scans'],
  'sd.report': ['报告', 'Report'],
  'sd.crawled': ['已爬', 'Crawled'],
  'sd.scan': ['扫描', 'Scan'],
  'sd.elapsed': ['耗时', 'Elapsed'],
  'sd.vulns': ['漏洞', 'Vulns'],
  'sd.status': ['状态', 'Status'],
  'sd.pause': ['暂停', 'Pause'],
  'sd.resume': ['恢复', 'Resume'],
  'sd.stop': ['停止', 'Stop'],
  'sd.tabSitemap': ['站点地图', 'Sitemap'],
  'sd.tabResults': ['URL结果', 'URL Results'],
  'sd.tabVulns': ['漏洞', 'Vulns'],
  'sd.tabTech': ['技术识别', 'Tech'],
  'sd.delInvalid': ['删除无效', 'Delete invalid'],
  'sd.rescan': ['重扫选中', 'Rescan selected'],
  'sd.rescanFromUrl': ['以此请求新建扫描', 'New scan from this request'],
  'sd.noUrlRec': ['未找到该 URL 的记录', 'No record found for this URL'],
  'sd.noInvalid': ['无可删除的无效URL', 'No invalid URLs to delete'],
  'sd.deleted': ['删除 ', 'Deleted '],
  'sd.selUrlFirst': ['请先选择URL', 'Please select URLs first'],
  'sd.rescanning': ['重扫 ', 'Rescanning '],
  'sd.rescanning2': [' 个URL...', ' URLs...'],
  'sd.pauseReq': ['已请求暂停…', 'Pause requested…'],
  'sd.resumed': ['已恢复', 'Resumed'],
  'sd.stopConfirm': ['确定停止该扫描任务?', 'Stop this scan task?'],
  'sd.stopping': ['正在停止…', 'Stopping…'],
  'sd.noResults': ['无结果', 'No results'],
  'sd.thStatus': ['状态', 'Status'],
  'sd.thMethod': ['方法', 'Method'],
  'sd.thUrl': ['URL', 'URL'],
  'sd.thTitle': ['标题', 'Title'],
  'sd.thSource': ['来源', 'Source'],
  'sd.rdMethod': ['方法', 'Method'],
  'sd.rdUrl': ['URL', 'URL'],
  'sd.rdStatus': ['状态', 'Status'],
  'sd.rdType': ['类型', 'Type'],
  'sd.rdTitle': ['标题', 'Title'],
  'sd.rdDepth': ['深度', 'Depth'],
  'sd.rdSource': ['来源', 'Source'],
  'sd.rdParams': ['参数', 'Params'],
  'sd.rdParamName': ['名称', 'Name'],
  'sd.rdParamVal': ['值', 'Value'],
  'sd.req': ['请求', 'Request'],
  'sd.res': ['响应', 'Response'],
  'sd.noSitemap': ['无站点地图', 'No sitemap'],
  'sd.scanDone': ['扫描 #', 'Scan #'],
  'sd.scanDone2': [' 完成', ' done'],
  'sd.scanStopped': ['扫描 #', 'Scan #'],
  'sd.scanStopped2': [' 已停止', ' stopped'],
  'sd.errPrefix': ['错误: ', 'Error: '],
  'sd.soft404': [' (soft-404)', ' (soft-404)'],
  // --- vuln detail ---
  'vd.type': ['类型', 'Type'],
  'vd.name': ['名称', 'Name'],
  'vd.severity': ['严重度', 'Severity'],
  'vd.ssl': ['SSL', 'SSL'],
  'vd.plugin': ['插件', 'Plugin'],
  'vd.url': ['URL', 'URL'],
  'vd.affects': ['影响', 'Affects'],
  'vd.param': ['参数', 'Parameter'],
  'vd.payload': ['攻击载荷', 'Attack vector'],
  'vd.desc': ['漏洞描述', 'Description'],
  'vd.impact': ['影响', 'Impact'],
  'vd.fix': ['修复建议', 'Remediation'],
  'vd.details': ['详情', 'Details'],
  'vd.detailsTpl': ['漏洞详情', 'Vuln Details'],
  'vd.refs': ['参考链接', 'References'],
  'vd.foundAt': ['发现时间: ', 'Found at: '],
  'vd.srcScan': ['来源: ', 'Source: '],
  'vd.scan': ['扫描', 'Scan'],
  'vd.provScanner': ['扫描器', 'scanner'],
  'vd.provAiTool': ['AI 调工具', 'AI tool-call'],
  'vd.provAiManual': ['AI 自主验证', 'AI self-verify'],
  // --- reports ---
  'rp.title': ['报告', 'Reports'],
  'rp.desc': ['导出扫描报告 (HTML / JSON) 与 URL 列表 (TXT / JSON / XML)', 'Export scan reports (HTML / JSON) and URL lists (TXT / JSON / XML)'],
  'rp.byScan': ['按扫描导出', 'Export by scan'],
  'rp.thId': ['#', '#'],
  'rp.thTarget': ['目标', 'Target'],
  'rp.thVulns': ['漏洞', 'Vulns'],
  'rp.thReport': ['报告 (HTML/JSON)', 'Report (HTML/JSON)'],
  'rp.thUrlList': ['URL列表 (TXT/JSON/XML)', 'URL list (TXT/JSON/XML)'],
  'rp.agg': ['聚合报告', 'Aggregate report'],
  'rp.aggDesc': ['汇总所有扫描的漏洞。', 'Aggregates vulns from all scans.'],
  'rp.dlHtml': ['下载 HTML', 'Download HTML'],
  'rp.dlJson': ['下载 JSON', 'Download JSON'],
  'rp.empty': ['暂无扫描', 'No scans'],
  // --- discovery ---
  'dc.title': ['发现', 'Discovery'],
  'dc.desc': ['包含/排除的地址与组织 (按目标管理扫描范围)', 'Included/excluded addresses (scope managed per target)'],
  'dc.editTarget': ['在目标页编辑', 'Edit on Targets page'],
  'dc.thTarget': ['目标', 'Target'],
  'dc.thInc': ['Include', 'Include'],
  'dc.thExc': ['Exclude', 'Exclude'],
  'dc.empty': ['暂无目标。范围在「目标」页随目标一起配置。', 'No targets. Scope is configured with each target on the Targets page.'],
  // --- technologies ---
  'tech.title': ['技术识别', 'Technologies'],
  'tech.desc': ['wappalyzer 指纹:识别目标站点技术栈与版本 (Server/X-Powered-By/JS库/DOM 等) · 跨所有扫描任务聚合', 'wappalyzer fingerprints: detect target tech stack & versions (Server/X-Powered-By/JS libs/DOM etc.) · aggregated across all scans'],
  'tech.allTasks': ['全部任务', 'All tasks'],
  'tech.thTech': ['技术', 'Technology'],
  'tech.thVer': ['版本', 'Version'],
  'tech.thConf': ['置信度', 'Confidence'],
  'tech.thCat': ['类别', 'Category'],
  'tech.thHits': ['命中页数', 'Hits'],
  'tech.thSample': ['示例 URL', 'Sample URLs'],
  'tech.stat': ['共 ', 'Total '],
  'tech.stat2': [' 项技术 · 覆盖 ', ' technologies · covering '],
  'tech.stat3': [' 个页面', ' pages'],
  'tech.empty': ['暂无识别结果。先运行一次爬取/扫描任务 (动态模式)。', 'No results yet. Run a crawl/scan task first (dynamic mode).'],
  'tech.emptyDetail': ['暂无识别结果。爬取完成后此处会展示 wappalyzer 检出的技术栈与版本。', 'No results. After crawling, wappalyzer-detected tech stack & versions appear here.'],
  'tech.loadFail': ['技术识别加载失败', 'Failed to load technologies'],
  'tech.descSource': [' · 数据来自 wappalyzer 指纹( Server/X-Powered-By 头 + &lt;script src&gt; 文件名 + 浏览器 window 属性链/DOM )', ' · data from wappalyzer fingerprints (Server/X-Powered-By headers + &lt;script src&gt; filenames + browser window prop chain/DOM)'],
  // --- labs ---
  'lab.title': ['靶场', 'Labs'],
  'lab.desc': ['按功能划分的漏洞靶场 · 启动/停止持久化实例 · 从靶场发起扫描 · 自由组合端点新建靶场', 'Vulnerable labs by category · start/stop persistent instances · scan from a lab · mix endpoints to build a custom lab'],
  'lab.new': ['+ 新建靶场', '+ New Lab'],
  'lab.running': ['运行中', 'Running'],
  'lab.stopped': ['已停止', 'Stopped'],
  'lab.starting': ['启动中…', 'Starting…'],
  'lab.startFail': ['启动失败', 'Start failed'],
  'lab.started': ['靶场已启动: ', 'Lab started: '],
  'lab.jump': ['跳转到靶场', 'Open lab'],
  'lab.scanFrom': ['从此扫描', 'Scan from here'],
  'lab.crawlFrom': ['从此爬取', 'Crawl from here'],
  'lab.custom': ['(自定义)', '(custom)'],
  'lab.thEp': ['端点', 'Endpoint'],
  'lab.thVuln': ['触发漏洞', 'Vuln triggered'],
  'lab.cat': ['类别: ', 'Categories: '],
  'lab.eps': [' 个端点', ' endpoints'],
  'lab.empty': ['暂无靶场', 'No labs'],
  'lab.delConfirm': ['删除该自定义靶场?', 'Delete this custom lab?'],
  'lab.newM': ['新建靶场', 'New Lab'],
  'lab.fldBasic': ['基本', 'Basic'],
  'lab.nameLbl': ['名称', 'Name'],
  'lab.namePh': ['例如：注入综合靶场', 'e.g. Injection practice lab'],
  'lab.fldEndpoints': ['选择端点（按类别勾选）', 'Select endpoints (by category)'],
  'lab.needCat': ['至少选一个类别', 'Select at least one category'],
  'lab.defaultName': ['自定义靶场', 'Custom lab'],
  // --- profiles ---
  'pf.title': ['扫描配置', 'Profiles'],
  'pf.desc': ['命名的插件选择预设 · 启动扫描时选用', 'Named plugin-selection presets · choose when starting a scan'],
  'pf.new': ['+ 新建配置', '+ New Profile'],
  'pf.thName': ['名称', 'Name'],
  'pf.thDesc': ['描述', 'Description'],
  'pf.thPlugins': ['插件', 'Plugins'],
  'pf.thOp': ['操作', 'Actions'],
  'pf.autoAll': ['自动 (全部适用)', 'Auto (all applicable)'],
  'pf.nSel': [' 个已选', ' selected'],
  'pf.empty': ['暂无配置', 'No profiles'],
  'pf.delConfirm': ['删除该配置?', 'Delete this profile?'],
  'pf.editM': ['编辑扫描配置', 'Edit Profile'],
  'pf.newM': ['新建扫描配置', 'New Profile'],
  'pf.fldBasic': ['基本', 'Basic'],
  'pf.fldPlugins': ['插件', 'Plugins'],
  'pf.nameLbl': ['名称', 'Name'],
  'pf.descLbl': ['描述', 'Description'],
  'pf.autoSel': [' 自动选择 (不勾选即跑全部适用插件)', ' Auto-select (unchecked = run all applicable plugins)'],
  'pf.filterPh': ['过滤(标题/rel)...', 'Filter (title/rel)...'],
  'pf.allBtn': ['全选', 'All'],
  'pf.noneBtn': ['清空', 'None'],
  'pf.loading': ['加载中...', 'Loading...'],
  'pf.noMatch': ['无匹配插件', 'No matching plugins'],
  'pf.selected': ['已选 ', 'Selected '],
  'pf.selUnit': [' 个', ''],
  // --- users stub ---
  'usr.title': ['用户', 'Users'],
  'usr.blurb': ['用户与角色管理。', 'User & role management.'],
  'usr.hint': ['本单机运行时无用户模型；通过 node runtime/run.js --webui 启动即获得全部权限，无需登录。', 'No user model in this single-host runtime; start via node runtime/run.js --webui for full access, no login needed.'],
  'stub.unavail': ['本运行时不可用', 'Unavailable in this runtime'],
  // --- config ---
  'cfg.title': ['全局配置', 'Configuration'],
  'cfg.desc': ['集中管理 LLM、推送、邮件、MCP/技能与代理', 'Manage LLM, notifications, email, MCP/skills and proxy'],
  'cfg.tabLlm': ['LLM', 'LLM'],
  'cfg.tabNotify': ['推送', 'Notify'],
  'cfg.tabEmail': ['邮件', 'Email'],
  'cfg.tabExt': ['MCP/技能', 'MCP/Skills'],
  'cfg.tabProxy': ['代理', 'Proxy'],
  // --- config: LLM ---
  'llm.ccTitle': ['Claude Code(本机 CLI)', 'Claude Code (local CLI)'],
  'llm.ccDesc': ['Claude Code 模式走本机 <code>claude</code> CLI,无需在此配 API Key(认证用环境变量)。LLM 模式配 OpenAI/Anthropic 兼容 chat-completions;留空 api_key/base_url 则降级为规则 worker。', 'Claude Code mode uses the local <code>claude</code> CLI; no API key here (auth via env vars). LLM mode configures OpenAI/Anthropic-compatible chat-completions; empty api_key/base_url falls back to the rule worker.'],
  'llm.ccReady': ['已检测到 <code>', 'Detected <code>'],
  'llm.ccReady2': ['</code> + ANTHROPIC 认证环境变量 → 可用 claudecode worker', '</code> + ANTHROPIC auth env vars → claudecode worker available'],
  'llm.ccNotReady': ['未就绪:', 'Not ready:'],
  'llm.noKey': ['无 ANTHROPIC_API_KEY/AUTH_TOKEN ', 'no ANTHROPIC_API_KEY/AUTH_TOKEN '],
  'llm.noBase': ['无 ANTHROPIC_BASE_URL ', 'no ANTHROPIC_BASE_URL '],
  'llm.ccModel': ['Claude Code 模型别名(可选,留空用默认)', 'Claude Code model alias (optional, default if empty)'],
  'llm.ccModelPh': ['sonnet / opus / claude-sonnet-5', 'sonnet / opus / claude-sonnet-5'],
  'llm.llmTitle': ['LLM 模式(chat-completions)', 'LLM mode (chat-completions)'],
  'llm.configured': ['已配置', 'Configured'],
  'llm.notConfigured': ['未配置', 'Not configured'],
  'llm.provider': ['Provider', 'Provider'],
  'llm.providerOpenai': ['OpenAI 兼容', 'OpenAI compatible'],
  'llm.providerAnthropic': ['Anthropic 兼容', 'Anthropic compatible'],
  'llm.model': ['Model', 'Model'],
  'llm.modelPh': ['gpt-4o-mini / claude-3-5-sonnet-latest', 'gpt-4o-mini / claude-3-5-sonnet-latest'],
  'llm.baseUrl': ['Base URL', 'Base URL'],
  'llm.baseUrlPh': ['https://api.openai.com 或 https://api.anthropic.com', 'https://api.openai.com or https://api.anthropic.com'],
  'llm.apiKey': ['API Key', 'API Key'],
  'llm.testConn': ['测试连通', 'Test connection'],
  'llm.saved': ['LLM 配置已保存', 'LLM config saved'],
  'llm.saveFail': ['保存失败', 'Save failed'],
  'llm.ccModelSaved': ['Claude Code 模型已保存', 'Claude Code model saved'],
  'llm.savedRule': ['LLM 配置已保存(将用规则 worker)', 'LLM config saved (will use rule worker)'],
  'llm.testing': ['测试中…', 'Testing…'],
  'llm.testOk': ['连通 (', 'OK ('],
  'llm.testOk2': ['): ', '): '],
  'llm.testFail': ['失败: ', 'Failed: '],
  'llm.testFail2': ['未配置 LLM', 'LLM not configured'],
  // --- config: notify ---
  'notify.principle': ['原理', 'How it works'],
  'notify.principleDesc': [' wscan 原生调用飞书 / 企业微信 / 钉钉的<b>群机器人 incoming webhook</b>,把扫描事件直接推到对应 IM,无需自建应用或外部桥接。在 IM 群里添加「自定义机器人」拿到 webhook URL 填入即可;飞书/钉钉可选填加签 secret。', ' wscan natively calls the <b>group-bot incoming webhook</b> of Feishu / WeCom / DingTalk to push scan events directly — no app or external bridge required. Add a "custom bot" in your IM group, paste the webhook URL; Feishu/DingTalk optionally accept a signing secret.'],
  'notify.enableLbl': ['启用推送', 'Enable notifications'],
  'notify.enable': ['启用', 'Enable'],
  'notify.platform': ['推送平台', 'Platform'],
  'notify.webhook': ['Webhook URL', 'Webhook URL'],
  'notify.webhookPh': ['群机器人 incoming webhook 地址', 'group-bot incoming webhook URL'],
  'notify.secret': ['加签 Secret', 'Signing secret'],
  'notify.secretPh': ['飞书/钉钉可选,企业微信无需', 'Feishu/DingTalk optional; WeCom none'],
  'notify.atAll': [' @全体 (企业微信/钉钉支持)', ' @all (WeCom/DingTalk)'],
  'notify.events': ['触发事件', 'Trigger events'],
  'notify.evtFact': ['发现新 Fact', 'New Fact found'],
  'notify.evtGoal': ['目标达成', 'Goal reached'],
  'notify.evtStopped': ['项目停止/完成', 'Project stopped/done'],
  'notify.testBtn': ['测试推送', 'Test push'],
  'notify.saved': ['推送配置已保存', 'Notify config saved'],
  'notify.testing': ['测试中…', 'Testing…'],
  'notify.testOk': ['测试消息已发送(请到 IM 确认)', 'Test message sent (check your IM)'],
  'notify.testFail': ['推送失败: ', 'Push failed: '],
  'notify.testFail2': ['webhook 地址不对或网络不通', 'webhook URL wrong or network unreachable'],
  'notify.mode': ['接入模式', 'Mode'],
  'notify.modeWebhook': ['群机器人 Webhook', 'Group-bot webhook'],
  'notify.modeApp': ['扫码建机器人 (1v1 应用消息)', 'Scan to create bot (1v1 app msg)'],
  'notify.appBound': ['已绑定应用(扫码获取),消息将发送给创建者', 'App bound (via scan); messages go to the creator'],
  'notify.appUnbound': ['尚未扫码绑定,点下方生成二维码', 'Not bound yet — click the button to generate a QR code'],
  'notify.qrGen': ['生成二维码', 'Generate QR code'],
  'notify.qrRegen': ['重新生成二维码', 'Regenerate QR code'],
  'notify.qrWait': ['请用飞书/Lark App 扫码完成机器人创建与授权…', 'Scan with Feishu/Lark app to create & authorize the bot…'],
  'notify.qrDone': ['✓ 扫码成功,凭证已保存', '✓ Scan done, credentials saved'],
  'notify.qrExpire': ['二维码已过期,请重新生成', 'QR expired, regenerate'],
  'notify.qrFail': ['生成二维码失败: ', 'QR generation failed: '],
  // --- config: email ---
  'email.zeroDep': ['零依赖', 'Zero-dependency'],
  'email.desc': [' 直接讲 SMTP 协议(net/tls),支持隐式 TLS(465)/STARTTLS(587)、AUTH LOGIN。扫描完成与发现高危漏洞时触发。', ' Speaks SMTP directly (net/tls), supports implicit TLS (465)/STARTTLS (587), AUTH LOGIN. Triggered on scan completion and high-severity vuln discovery.'],
  'email.enable': ['启用邮件通知', 'Enable email notifications'],
  'email.host': ['SMTP 主机', 'SMTP host'],
  'email.hostPh': ['smtp.example.com', 'smtp.example.com'],
  'email.port': ['端口', 'Port'],
  'email.portPh': ['25 / 465 / 587', '25 / 465 / 587'],
  'email.secure': ['加密方式', 'Encryption'],
  'email.secureNone': ['无 / STARTTLS(587)', 'None / STARTTLS (587)'],
  'email.secureTls': ['隐式 TLS(465)', 'Implicit TLS (465)'],
  'email.from': ['发件人', 'From'],
  'email.fromPh': ['awvs@example.com 或 名称 <a@b.c>', 'awvs@example.com or Name <a@b.c>'],
  'email.user': ['用户名 (可选)', 'Username (optional)'],
  'email.userPh': ['SMTP 登录账号', 'SMTP login account'],
  'email.pass': ['密码 (可选)', 'Password (optional)'],
  'email.passPh': ['留空为匿名', 'Empty for anonymous'],
  'email.to': ['收件人 (多个用逗号分隔)', 'Recipients (comma-separated)'],
  'email.toPh': ['sec@example.com, ops@example.com', 'sec@example.com, ops@example.com'],
  'email.events': ['触发事件', 'Trigger events'],
  'email.evtDone': ['扫描完成', 'Scan done'],
  'email.evtHigh': ['发现高危/严重漏洞', 'High/critical vuln found'],
  'email.testBtn': ['测试发送', 'Test send'],
  'email.saved': ['邮件配置已保存', 'Email config saved'],
  'email.saveFail': ['保存失败: ', 'Save failed: '],
  'email.sending': ['发送中…', 'Sending…'],
  'email.testOk': ['测试邮件已发送,请查收', 'Test email sent, please check'],
  'email.testFail': ['失败: ', 'Failed: '],
  'email.testFail2': ['未知错误', 'unknown error'],
  // --- config: extensions (MCP/skills) ---
  'ext.mcpTitle': ['MCP 服务器', 'MCP Servers'],
  'ext.mcpSub': ['为 AI worker 挂载外部能力(Model Context Protocol)', 'Mount external capabilities for the AI worker (Model Context Protocol)'],
  'ext.mcpDesc': ['stdio 型:Claude Code worker 直接经 --mcp-config 拉起子进程;LLM worker 由内置极简 JSON-RPC 客户端连。http/sse 型:向指定 URL 发 JSON-RPC。工具名形如 <code>mcp__&lt;id&gt;__&lt;tool&gt;</code>,自动并入 worker 工具表。', 'stdio: the Claude Code worker spawns a subprocess via --mcp-config; the LLM worker uses a built-in minimal JSON-RPC client. http/sse: sends JSON-RPC to the given URL. Tool names look like <code>mcp__&lt;id&gt;__&lt;tool&gt;</code> and are merged into the worker tool table.'],
  'ext.noMcp': ['尚未配置 MCP 服务器', 'No MCP servers configured'],
  'ext.mcpAdd': ['+ 添加 MCP 服务器', '+ Add MCP server'],
  'ext.skillTitle': ['技能 (Skills)', 'Skills'],
  'ext.skillSub': ['可复用指令,注入 worker 系统提示', 'Reusable instructions injected into the worker system prompt'],
  'ext.skillDesc': ['每条技能是一段指令文本,遇到匹配场景模型按此操作(如「发现 SQL 注入先用 sqlmap 验证」)。对 claudecode/llm worker 生效。', 'Each skill is an instruction text; the model follows it when a matching scenario arises (e.g. "verify SQLi with sqlmap first"). Applies to claudecode/llm workers.'],
  'ext.noSkill': ['尚未配置技能', 'No skills configured'],
  'ext.skillAdd': ['+ 添加技能', '+ Add skill'],
  'ext.saveAll': ['保存全部', 'Save all'],
  'ext.saved': ['已保存 (', 'Saved ('],
  'ext.saved2': [' MCP, ', ' MCP, '],
  'ext.saved3': [' 技能)', ' skills)'],
  'ext.saveFail': ['保存失败', 'Save failed'],
  'ext.nameId': ['名称 / ID', 'Name / ID'],
  'ext.namePh': ['my-tool', 'my-tool'],
  'ext.type': ['类型', 'Type'],
  'ext.url': ['URL', 'URL'],
  'ext.urlPh': ['http://host/mcp', 'http://host/mcp'],
  'ext.command': ['命令', 'Command'],
  'ext.commandPh': ['npx / node / uvx ...', 'npx / node / uvx ...'],
  'ext.args': ['参数 (空格分隔)', 'Args (space-separated)'],
  'ext.argsPh': ['-y @modelcontextprotocol/server-filesystem /tmp', '-y @modelcontextprotocol/server-filesystem /tmp'],
  'ext.env': ['环境变量 (KEY=val,每行一个)', 'Env vars (KEY=val, one per line)'],
  'ext.envPh': ['API_KEY=xxx', 'API_KEY=xxx'],
  'ext.testList': ['测试(列出工具)', 'Test (list tools)'],
  'ext.del': ['删除', 'Delete'],
  'ext.testConn': ['连接中…', 'Connecting…'],
  'ext.invalid': ['无效条目', 'Invalid entry'],
  'ext.testOk': ['连通,暴露 <b>', 'Connected, exposes <b>'],
  'ext.testOk2': ['</b> 个工具:', '</b> tools:'],
  'ext.testFail': ['连接失败', 'Connection failed'],
  'ext.skillName': ['名称', 'Name'],
  'ext.skillNamePh': ['sql-injection-verify', 'sql-injection-verify'],
  'ext.skillBody': ['指令内容', 'Instruction'],
  'ext.skillBodyPh': ['发现疑似 SQL 注入时,先用 sqlmap 验证可利用性,再写回 Fact', 'When SQLi is suspected, verify exploitability with sqlmap first, then write back a Fact'],
  // --- config: proxy ---
  'px.cur': ['当前代理', 'Current proxy'],
  'px.loading': ['加载中…', 'Loading…'],
  'px.cfg': ['配置代理', 'Configure proxy'],
  'px.scheme': ['协议', 'Scheme'],
  'px.schemeSocks5h': ['socks5 (远端DNS)', 'socks5 (remote DNS)'],
  'px.host': ['主机', 'Host'],
  'px.hostPh': ['127.0.0.1', '127.0.0.1'],
  'px.port': ['端口', 'Port'],
  'px.portPh': ['1080', '1080'],
  'px.user': ['用户名 (可选)', 'Username (optional)'],
  'px.userPh': ['留空则匿名', 'Empty for anonymous'],
  'px.pass': ['密码 (可选)', 'Password (optional)'],
  'px.test': ['测试连通性', 'Test connectivity'],
  'px.clear': ['清除', 'Clear'],
  'px.hint': ['示例: http://user:pass@127.0.0.1:8080 · socks5://127.0.0.1:1080。全局代理对爬虫与扫描生效,单次扫描可在新建扫描时覆盖。', 'Examples: http://user:pass@127.0.0.1:8080 · socks5://127.0.0.1:1080. The global proxy applies to crawler & scanner; a single scan can override it.'],
  'px.enabled': ['已启用: ', 'Enabled: '],
  'px.disabled': ['未启用 (直连)', 'Disabled (direct)'],
  'px.hostReq': ['请填写代理主机', 'Please fill in the proxy host'],
  'px.urlReq': ['请填写代理 URL', 'Please fill in the proxy URL'],
  'px.saved': ['代理已保存', 'Proxy saved'],
  'px.cleared': ['代理已清除', 'Proxy cleared'],
  'px.testing': ['测试中…', 'Testing…'],
  'px.ok': ['连通 (HTTP ', 'OK (HTTP '],
  'px.ok2': [', ', ', '],
  'px.ok3': ['ms)', 'ms)'],
  'px.fail': ['失败: ', 'Failed: '],
  'px.curGlobal': ['当前全局代理: ', 'Current global proxy: '],
  'px.noGlobal': ['当前未设全局代理 (默认直连)', 'No global proxy (direct by default)'],
  'px.global': [' 使用全局代理 (默认)', ' Use global proxy (default)'],
  'px.custom': [' 本次指定代理', ' Custom proxy this time'],
  'px.proxyUrl': ['代理 URL', 'Proxy URL'],
  'px.proxyUrlPh': ['http://user:pass@host:port 或 socks5://host:port', 'http://user:pass@host:port or socks5://host:port'],
  'px.none': [' 本次禁用代理 (直连)', ' Disable proxy this time (direct)'],
  // --- config: runtime ---
  'rt.title': ['运行时信息 (只读)', 'Runtime info (read-only)'],
  'rt.version': ['版本', 'Version'],
  'rt.root': ['项目根', 'Project root'],
  'rt.port': ['端口', 'Port'],
  'rt.testServer': ['内置靶场', 'Built-in lab'],
  'rt.enabled': ['启用', 'Enabled'],
  'rt.disabled': ['禁用', 'Disabled'],
  'rt.targetCount': ['目标数', 'Targets'],
  'rt.profileCount': ['扫描配置数', 'Profiles'],
  'rt.cmdTitle': ['启动命令', 'Start command'],
  // --- new scan modal ---
  'ns.title': ['新建扫描', 'New Scan'],
  'ns.fldTarget': ['目标', 'Target'],
  'ns.selTarget': ['选择已保存目标', 'Select a saved target'],
  'ns.manual': ['— 手动输入地址 —', '— Enter address manually —'],
  'ns.orAddr': ['或输入地址', 'Or enter address'],
  'ns.addrPh': ['http://host/', 'http://host/'],
  'ns.useTest': [' 使用内置测试靶场 (忽略上面地址)', ' Use built-in test lab (ignore above)'],
  'ns.fldScan': ['扫描配置', 'Scan config'],
  'ns.autoSel': [' 自动选择 (不勾选即按配置/全部适用插件)', ' Auto-select (unchecked = profile/all applicable plugins)'],
  'ns.fldCrawler': ['爬虫', 'Crawler'],
  'ns.mode': ['模式', 'Mode'],
  'ns.modeDynamic': ['动态(DeepScan)', 'Dynamic (DeepScan)'],
  'ns.modeStatic': ['静态', 'Static'],
  'ns.apiEnum': ['API枚举', 'API enum'],
  'ns.apiYes': ['是', 'Yes'],
  'ns.apiNo': ['否', 'No'],
  'ns.discoverParent': [' 自动发现父目录 (PerFolder 按目录自身响应检测 401/目录列表等;关闭更快但漏目录级漏洞)', ' Auto-discover parent dirs (PerFolder detects 401/dir-listing by the dir response; faster but misses dir-level vulns)'],
  'ns.postScan': [' 闭环回填插件发现的端点 (扫描后把插件通过 addLink/addHttp 发现的 URL 抓取并再扫描一轮;如 JS 里 $.ajax 的 API 端点)', ' Closed-loop backfill of plugin-discovered endpoints (after scanning, fetch & re-scan URLs found by plugins via addLink/addHttp; e.g. $.ajax API endpoints in JS)'],
  'ns.backfillLimit': ['回填上限', 'Backfill limit'],
  'ns.backfillLimitTitle': ['单轮回填抓取的端点数硬上限,防止一次回填几百个。', 'Hard cap on endpoints fetched per round, prevents backfilling hundreds at once.'],
  'ns.backfillRounds': ['回填轮数', 'Backfill rounds'],
  'ns.backfillRoundsTitle': ['回填+再扫描的迭代轮数。1=单次;>1 时连回填页面上新发现的端点也继续回填。', 'Iterations of backfill+rescan. 1=once; >1 keeps backfilling endpoints newly found on backfilled pages.'],
  'ns.pages': ['页数', 'Pages'],
  'ns.depth': ['深度', 'Depth'],
  'ns.concurrency': ['并发', 'Concurrency'],
  'ns.timeout': ['请求超时(ms)', 'Request timeout (ms)'],
  'ns.timeoutTitle': ['单次HTTP请求的硬超时(毫秒)。超时后强制断开socket,避免被卡住的服务器拖死整个爬虫/扫描。默认30秒。', 'Hard timeout per HTTP request (ms). Forces socket close on timeout so a stuck server cannot stall the crawler/scanner. Default 30s.'],
  'ns.timeoutHint': ['单个请求超过该时间将被强制中断,防止爬虫卡死。', 'A request exceeding this is forcibly aborted to prevent crawler hang.'],
  'ns.fldScope': ['范围', 'Scope'],
  'ns.incPh': ['/api/,/admin', '/api/,/admin'],
  'ns.excPh': ['/shop/', '/shop/'],
  'ns.fldReq': ['请求 (仅扫描的种子请求; 自定义请求头会叠加到鉴权头之后)', 'Request (seed request for scan-only; custom headers append after auth headers)'],
  'ns.method': ['方法', 'Method'],
  'ns.reqSeedHint': ['仅扫描模式下用作种子请求; 爬取模式由爬虫自行抓取。', 'Used as the seed request in scan-only mode; the crawler fetches its own in crawl mode.'],
  'ns.customHeaders': ['自定义请求头 (每行一个, 格式 Name: value)', 'Custom headers (one per line, Name: value)'],
  'ns.headersPh': ['X-Custom: 1&#10;X-Api-Key: abc', 'X-Custom: 1&#10;X-Api-Key: abc'],
  'ns.reqBody': ['请求体 (POST/PUT/PATCH 的 body, 纯文本)', 'Request body (POST/PUT/PATCH body, plain text)'],
  'ns.bodyPh': ['param=value&#10;或 JSON / 原始内容', 'param=value&#10;or JSON / raw content'],
  'ns.fldAuth': ['鉴权', 'Authentication'],
  'ns.fldProxy': ['代理', 'Proxy'],
  'ns.scanOnly': [' 仅扫描', ' Scan only'],
  'ns.crawlOnly': [' 仅爬取', ' Crawl only'],
  'ns.crawlScan': [' 爬取+扫描', ' Crawl+Scan'],
  'ns.noAddr': ['请输入目标地址或勾选内置靶场', 'Enter a target address or check the built-in lab'],
  'ns.selAllPlugins': ['已选 ', 'Selected '],
  'ns.selPlugins2': [' 个插件', ' plugins'],
  'ns.autoAll2': ['自动选择全部适用插件', 'Auto-select all applicable plugins'],
  'ns.starting': ['正在启动扫描...', 'Starting scan...'],
  'ns.started': ['扫描 #', 'Scan #'],
  'ns.started2': [' 已启动', ' started'],
  'ns.startFail': ['启动失败', 'Start failed'],
  'ns.startFail2': ['启动失败: ', 'Start failed: '],
  'ns.unknownErr': ['未知错误', 'unknown error'],
  'ns.prefilled': ['已预填请求信息 → 请点【仅扫描】以该请求为种子(自定义方法/头/体仅扫描模式生效)', 'Request prefilled → click "Scan only" to use it as the seed (custom method/headers/body apply only in scan mode)'],
  // --- auth ---
  'auth.none': ['无', 'None'],
  'auth.form': ['表单登录', 'Form login'],
  'auth.basic': ['Basic', 'Basic'],
  'auth.digest': ['Digest', 'Digest'],
  'auth.jwt': ['JWT', 'JWT'],
  'auth.token': ['Token', 'Token'],
  'auth.cookie': ['Cookie', 'Cookie'],
  'auth.header': ['Header', 'Header'],
  'auth.user': ['用户', 'Username'],
  'auth.pass': ['密码', 'Password'],
  'auth.tokenLbl': ['Token', 'Token'],
  'auth.headerLbl': ['Header', 'Header'],
  'auth.value': ['值', 'Value'],
  'auth.cookieLbl': ['Cookie', 'Cookie'],
  'auth.loginUrl': ['登录URL', 'Login URL'],
  'auth.method': ['方法', 'Method'],
  'auth.validUrl': ['校验URL', 'Validation URL'],
  'auth.fields': ['字段(name=val,...)', 'Fields (name=val,...)'],
  'auth.headerLines': ['Header(每行)', 'Headers (per line)'],
  // --- AI pentest ---
  'ai.title': ['AI 自动渗透', 'AI Auto-Pentest'],
  'ai.desc': ['Cairn 黑板模型 · 给定 Origin(目标)与 Goal(目标成果),AI worker 自主 OODA 循环搜索攻击路径,实时把 Fact/Intent 写回黑板', 'Cairn blackboard model · given an Origin (target) and Goal (outcome), the AI worker autonomously runs an OODA loop to search attack paths, writing Fact/Intent back to the blackboard in real time'],
  'ai.llmCfg': [' LLM 配置', ' LLM config'],
  'ai.new': [' 新建 AI 渗透', ' New AI pentest'],
  'ai.projects': ['渗透项目', 'Projects'],
  'ai.active': ['进行中', 'Active'],
  'ai.facts': ['已确认 Fact', 'Confirmed Facts'],
  'ai.completed': ['已完成', 'Completed'],
  'ai.empty': ['暂无 AI 渗透项目,点击「新建 AI 渗透」启动', 'No AI pentest projects — click "New AI pentest"'],
  'ai.reopen': [' 重新打开', ' Reopen'],
  'ai.hint': [' 注入 Hint', ' Inject Hint'],
  'ai.worker': ['Worker: ', 'Worker: '],
  'ai.intentsConv': [' 意图已收敛', ' intents converged'],
  'ai.tabTimeline': ['事件流', 'Timeline'],
  'ai.tabTalk': ['对话', 'Talk'],
  'ai.tabVulns': ['漏洞', 'Vulns'],
  'ai.tabFacts': ['Facts', 'Facts'],
  'ai.tabIntents': ['Intents', 'Intents'],
  'ai.tabHints': ['Hints', 'Hints'],
  'ai.tabGraph': ['攻击链', 'Attack chain'],
  'ai.blackboard': ['黑板概览', 'Blackboard'],
  'ai.fact': ['Fact', 'Fact'],
  'ai.conv': ['已收敛', 'Converged'],
  'ai.exploring': ['探索中', 'Exploring'],
  'ai.progTxt': ['探索进度 ', 'Exploration progress '],
  'ai.toolbox': ['AI 工具箱', 'AI Toolbox'],
  'ai.toolboxDesc': ['dispatcher 中 worker 可调用的能力(结果结构化回喂 AI)', 'Capabilities the worker can call in the dispatcher (results fed back structured)'],
  'ai.notify': ['推送通知', 'Notifications'],
  'ai.notifyCfg': ['前往配置', 'Go to config'],
  'ai.notifyOn': [' 已启用 · ', ' Enabled · '],
  'ai.notifyDefault': ['(未配 webhook)', '(no webhook)'],
  'ai.notifyPush': [' → 经 webhook 推送', ' → via webhook'],
  'ai.notifyOff': [' 未启用 (新建时勾选,或在「全局配置 → 推送」页开启)', ' Disabled (check when creating, or enable under "Config → Notify")'],
  'ai.timelineDesc': ['<span class="live"></span>黑板实时事件流 · Fact 已确认发现 / Intent 探索方向 / tool_call 工具调用', '<span class="live"></span>Live blackboard events · Fact confirmed / Intent direction / tool_call invocations'],
  'ai.timelineEmpty': ['黑板为空 — 等待 dispatcher 启动 worker 跑 OODA 循环', 'Blackboard empty — waiting for the dispatcher to start the OODA loop'],
  'ai.talkDesc': ['<span class="live"></span>LLM 对话回合 · 仅 LLM / Claude Code worker 产生(规则 worker 无)。点开查看 prompt 与完整响应', '<span class="live"></span>LLM turns · only LLM / Claude Code workers produce these (rule worker has none). Click to see prompt & full response'],
  'ai.talkEmpty': ['暂无对话 — 仅 LLM / Claude Code worker 产生', 'No turns — only LLM / Claude Code workers produce these'],
  'ai.vulnsDesc': ['<span class="live"></span>已确认漏洞 · 标记来源:扫描器(规则 worker 自动扫)/ AI 调工具(AI 决策调 awvs_scan 等)/ AI 自主验证(AI 自主 curl 验证),按严重度排序', '<span class="live"></span>Confirmed vulns · source badges: scanner (rule worker auto-scan) / AI tool-call (AI calls awvs_scan etc.) / AI self-verify (AI curls to verify), sorted by severity'],
  'ai.vulnsEmpty': ['暂无已确认漏洞 — worker 调 awvs_scan / run_plugin 发现的漏洞(标「扫描器/AI 调工具」)与 AI 自主 curl 验证的漏洞(标「AI 自主验证」)均在此汇总', 'No confirmed vulns — vulns found via awvs_scan / run_plugin (badged "scanner/AI tool-call") and AI self-verified via curl (badged "AI self-verify") are aggregated here'],
  'ai.vulnsLoadFail': ['加载失败', 'Load failed'],
  'ai.factsEmpty': ['暂无 Fact', 'No Facts'],
  'ai.intentsEmpty': ['暂无 Intent', 'No Intents'],
  'ai.hintsEmpty': ['暂无 Hint — 新建时填写,或运行中点「', 'No Hints — fill in when creating, or click "'],
  'ai.hintsEmpty2': [' 注入 Hint」', ' Inject Hint" while running'],
  'ai.graphDesc': ['攻击路径图谱 · 节点 Origin/Goal/Fact,虚线框为待探索 Intent', 'Attack-path graph · nodes Origin/Goal/Fact, dashed boxes are unexplored Intents'],
  'ai.openIntent': ['待探索 Intent (', 'Open Intents ('],
  'ai.openIntent2': [')', ')'],
  'ai.goalReached': ['Goal 达成', 'Goal reached'],
  'ai.goalReachedDesc': ['目标已达成,项目完成。', 'Goal reached, project complete.'],
  'ai.stoppedEv': ['已停止', 'Stopped'],
  'ai.turn': ['对话', 'Turn'],
  'ai.phaseBoot': ['Bootstrap', 'Bootstrap'],
  'ai.phaseReason': ['Reason', 'Reason'],
  'ai.phaseExplore': ['Explore', 'Explore'],
  'ai.turnFail': ['失败', 'Failed'],
  'ai.intDone': ['已收敛', 'Converged'],
  'ai.intClaimed': ['已认领', 'Claimed'],
  'ai.intExploring': ['探索中', 'Exploring'],
  'ai.intUnclaimed': ['待认领', 'Unclaimed'],
  'ai.noClaim': ['无人认领', 'unclaimed'],
  'ai.by': ['by', 'by'],
  'ai.by2': ['by ', 'by '],
  'ai.action': [' 行动: ', ' actions: '],
  'ai.actionUnit': [' 个工具调用', ' tool calls'],
  'ai.hypothesis': ['假设: ', 'Hypothesis: '],
  'ai.finding': ['发现: ', 'Findings: '],
  'ai.toolCallSum': [' ' + '' + '', ' '],
  'ai.backToList': ['← 返回列表', '← Back to list'],
  'ai.notExist': ['项目不存在', 'Project not found'],
  'ai.factLbl': ['Fact', 'Fact'],
  'ai.intentLbl': ['Intent', 'Intent'],
  'ai.hintLbl': ['Hint', 'Hint'],
  'ai.toolCallLbl': ['tool_call', 'tool_call'],
  'ai.toolDoneLbl': ['tool_done', 'tool_done'],
  'ai.goalReachedLbl': ['Goal 达成', 'Goal reached'],
  'ai.stopLbl': ['停止', 'Stop'],
  'ai.reopenLbl': [' 重新打开', ' Reopen'],
  'ai.injectHint': [' 注入 Hint', ' Inject Hint'],
  'ai.back': ['返回', 'Back'],
  'ai.promptLbl': ['Prompt', 'Prompt'],
  'ai.responseLbl': ['Response', 'Response'],
  // --- new AI modal ---
  'aiM.title': ['新建 AI 渗透', 'New AI Pentest'],
  'aiM.fldOrigin': ['目标 (Origin)', 'Origin'],
  'aiM.selTarget': ['选择已保存目标', 'Select a saved target'],
  'aiM.manual': ['— 手动输入地址 —', '— Enter address manually —'],
  'aiM.orUrl': ['或输入目标 URL', 'Or enter target URL'],
  'aiM.originPh': ['http://target.example.com/', 'http://target.example.com/'],
  'aiM.fldGoal': ['目标成果 (Goal)', 'Goal'],
  'aiM.goalFlag': ['拿 Flag', 'Get Flag'],
  'aiM.goalShell': ['拿 Shell', 'Get Shell'],
  'aiM.goalVuln': ['挖漏洞', 'Find vulns'],
  'aiM.goalPh': ['例: 获取后台管理员权限并拿到 shell', 'e.g. Gain admin privileges and get a shell'],
  'aiM.fldHints': ['人工提示 (Hints, 每行一条)', 'Hints (one per line)'],
  'aiM.hintsPh': ['优先验证已知历史漏洞&#10;目标可能存在反序列化', 'Verify known historical vulns first&#10;Target may have deserialization'],
  'aiM.fldEngine': ['AI 引擎 (Worker)', 'AI Engine (Worker)'],
  'aiM.engineDesc': ['Claude Code 模式调用本机 <code>claude</code> CLI(自带 Bash/curl 等工具,认证经环境变量);LLM 模式调用 OpenAI/Anthropic 兼容 chat-completions;未配置 LLM 时降级为「规则 worker」(按模板跑 awvs 全扫)。', 'Claude Code mode calls the local <code>claude</code> CLI (bundles Bash/curl etc., auth via env vars); LLM mode calls OpenAI/Anthropic-compatible chat-completions; with no LLM configured it falls back to the "rule worker" (runs a template awvs full scan).'],
  'aiM.workerType': ['Worker 类型', 'Worker type'],
  'aiM.ccOpt': ['Claude Code (本机 CLI', 'Claude Code (local CLI'],
  'aiM.ccNotDet': [' — 未检测到 claude/认证', ' — claude/auth not detected'],
  'aiM.ccDet': [')', ')'],
  'aiM.llmState': ['LLM 状态', 'LLM status'],
  'aiM.llmOk': ['已配置 ', 'Configured '],
  'aiM.llmOk2': [' / ', ' / '],
  'aiM.llmDefault': ['(默认模型)', '(default model)'],
  'aiM.llmNone': ['未配置 LLM(将用规则 worker)', 'No LLM configured (will use rule worker)'],
  'aiM.cfg': ['配置', 'Configure'],
  'aiM.fldTools': ['工具范围', 'Tool scope'],
  'aiM.toolsDesc': ['勾选 worker 可调用的工具(默认全开)。scope 严格限制在 Origin 主机。', 'Check tools the worker may call (all on by default). Scope is strictly limited to the Origin host.'],
  'aiM.fldNotify': ['通知推送 (飞书/企业微信/钉钉)', 'Notifications (Feishu/WeCom/DingTalk)'],
  'aiM.notifyDesc': ['wscan 原生调用群机器人 webhook,把事件(发现 Fact / 目标达成 / 停止)推到所选 IM 平台,无需外部桥接。', 'wscan natively calls the group-bot webhook to push events (Fact found / Goal reached / stopped) to the selected IM platform; no external bridge.'],
  'aiM.enablePush': ['启用推送', 'Enable push'],
  'aiM.webhook': ['Webhook URL', 'Webhook URL'],
  'aiM.webhookPh': ['群机器人 incoming webhook 地址', 'group-bot incoming webhook URL'],
  'aiM.secret': ['加签 Secret', 'Signing secret'],
  'aiM.secretPh': ['飞书/钉钉可选', 'Feishu/DingTalk optional'],
  'aiM.platform': ['推送平台', 'Platform'],
  'aiM.atAll': [' @全体 (企业微信/钉钉支持)', ' @all (WeCom/DingTalk)'],
  'aiM.testPush': [' 测试推送', ' Test push'],
  'aiM.start': [' 启动 AI 渗透', ' Start AI pentest'],
  'aiM.testSent': ['测试消息已发送(请到 IM 确认)', 'Test message sent (check your IM)'],
  'aiM.testFail': ['推送失败: ', 'Push failed: '],
  'aiM.testFail2': ['webhook 地址不对或网络不通', 'webhook URL wrong or network unreachable'],
  'aiM.noOrigin': ['请输入目标 URL', 'Please enter a target URL'],
  'aiM.noGoal': ['请输入目标成果', 'Please enter a goal'],
  'aiM.createFail': ['创建失败: ', 'Create failed: '],
  'aiM.unknownErr': ['未知错误', 'unknown error'],
  'aiM.started': ['AI 渗透 #', 'AI pentest #'],
  'aiM.started2': [' 已启动', ' started'],
  // --- hint modal ---
  'hint.title': [' 注入 Hint', ' Inject Hint'],
  'hint.desc': ['人工提示会被 worker 下次读取时吸收,任何时候可注入(运行中/停止/完成均可)。', 'Hints are absorbed by the worker on its next read; injectable anytime (running/stopped/done).'],
  'hint.ph': ['例:优先验证 CVE-2024-xxxx', 'e.g. verify CVE-2024-xxxx first'],
  'hint.creator': ['创建者 (默认 analyst)', 'Creator (default analyst)'],
  'hint.submit': ['注入', 'Inject'],
  'hint.empty': ['请输入提示内容', 'Please enter the hint'],
  'hint.fail': ['注入失败', 'Injection failed'],
  // --- LLM modal ---
  'llmM.title': [' LLM 配置', ' LLM config'],
  'llmM.desc': ['Claude Code 模式走本机 <code>claude</code> CLI,无需在此配 API Key(认证用环境变量)。LLM 模式配 OpenAI/Anthropic 兼容 chat-completions;留空 api_key/base_url 则降级为规则 worker。', 'Claude Code mode uses the local <code>claude</code> CLI; no API key here (auth via env vars). LLM mode configures OpenAI/Anthropic-compatible chat-completions; empty api_key/base_url falls back to the rule worker.'],
  'llmM.ccTitle': ['Claude Code(本机 CLI)', 'Claude Code (local CLI)'],
  'llmM.ccReady': ['已检测到 <code>', 'Detected <code>'],
  'llmM.ccReady2': ['</code> + ANTHROPIC 认证环境变量 → 可用 claudecode worker', '</code> + ANTHROPIC auth env vars → claudecode worker available'],
  'llmM.ccNotReady': ['未就绪:', 'Not ready:'],
  'llmM.ccModel': ['Claude Code 模型别名(可选,留空用默认)', 'Claude Code model alias (optional, default if empty)'],
  'llmM.llmTitle': ['LLM 模式(chat-completions)', 'LLM mode (chat-completions)'],
  'llmM.provider': ['Provider', 'Provider'],
  'llmM.model': ['Model', 'Model'],
  'llmM.baseUrl': ['Base URL', 'Base URL'],
  'llmM.apiKey': ['API Key', 'API Key'],
  'llmM.save': ['保存', 'Save'],
  // --- severity labels (badge text is data, but these are UI-side) ---
  'sev.critical': ['critical', 'critical'],
  'sev.high': ['high', 'high'],
  'sev.medium': ['medium', 'medium'],
  'sev.low': ['low', 'low'],
  'sev.info': ['info', 'info'],
  // --- AI worker / tool / platform labels (descriptions) ---
  'aiw.claudecode': ['Claude Code (本机 CLI,自带工具)', 'Claude Code (local CLI, bundled tools)'],
  'aiw.llm': ['LLM (OpenAI/Anthropic 兼容)', 'LLM (OpenAI/Anthropic compatible)'],
  'aiw.mock': ['规则 worker (无 LLM,跑 awvs 全扫)', 'Rule worker (no LLM, runs awvs full scan)'],
  'aiw.mockShort': ['规则 worker', 'Rule worker'],
  'ait.awvs_crawl': ['爬站点 URL/表单/参数/技术指纹', 'Crawl site URLs/forms/params/tech fingerprints'],
  'ait.awvs_scan': ['对 URL 自动选插件扫漏洞', 'Auto-select plugins to scan a URL for vulns'],
  'ait.awvs_list_plugins': ['列插件目录供选', 'List the plugin catalog for selection'],
  'ait.awvs_run_plugin': ['跑指定 rel 插件', 'Run a specific plugin by rel'],
  'ait.awvs_glob': ['按 glob 批量跑插件', 'Batch-run plugins by glob'],
  'ait.awvs_write_plugin': ['写自定义插件并跑', 'Write & run a custom plugin'],
  'ait.awvs_js_leak': ['语义分析 JS 文件,提取泄露的 API/凭据并推理漏洞', 'Semantically analyze JS files, extract leaked API/credentials and infer vulns'],
  'ait.http': ['curl 等价 HTTP 请求', 'curl-equivalent HTTP request'],
  // --- misc status strings used inline ---
  'misc.scanOnlyType': ['仅扫描', 'Scan only'],
  'misc.crawlScanType': ['爬取+扫描', 'Crawl+Scan'],
  'misc.paramPrefix': ['param=', 'param='],
};
function t(key){ const e = I18N[key]; if(!e) return key; return e[curLang==='en'?1:0]; }
function setLang(lang){
  curLang = lang;
  localStorage.setItem('webscan-lang', lang);
  document.documentElement.lang = (lang==='en') ? 'en' : 'zh-CN';
  // 刷新顶栏/title 等静态文本
  applyStaticI18n();
  // 重渲染当前视图
  if(typeof router==='function') router();
  syncLangIcon();
}
function applyStaticI18n(){
  document.title = t('app.title');
  const sub=document.querySelector('#topbar .logo .sub'); if(sub) sub.textContent = t('app.subtitle');
  const ss=$('srvStatus'); if(ss && ss.getAttribute('data-default')!=='0') ss.textContent = t('status.ready');
  const tt=$('themeToggle'); if(tt){ tt.title=t('top.theme'); tt.setAttribute('aria-label', t('top.theme')); }
  const av=document.querySelector('#topbar .avatar'); if(av) av.title = t('top.localRun');
  const ns=$('btnNewScan'); if(ns && window.ic) ns.innerHTML = ic('plus','btn-ic')+' '+t('top.newScan');
}
function syncLangIcon(){
  const btn=$('langToggle'); if(!btn||!window.ic) return;
  btn.innerHTML = ic('globe');
  btn.title = t(curLang==='en'?'top.langToZh':'top.langToEn');
  btn.setAttribute('aria-label', t(curLang==='en'?'top.langToZh':'top.langToEn'));
}
// ===== state =====
let curTask=null, evtSrc=null, taskCache={};
let _targets=[], _groups=[], _profiles=[], _status={};
// pagination state for scan-detail results / vulns (not sitemap)
// vulGroup: 开启「按漏洞名聚合」——按 typeId 折叠分组,组可展开看具体实例。
// scan-detail vulns are SERVER-SIDE paginated (/api/task/:id/vulns): the browser
// holds only vulTotal (count) + the current page, never the whole vuln set.
// vulFetchGen guards against stale fetches overwriting a newer render; vulLastTask
// avoids a flash of the previous task's vulns when switching tasks (we only blank
// to a loading state when the task actually changes, not on every page nav).
let resPage=0, resPageSize=50, vulPage=0, vulPageSize=15, vulGroup=false, vulTotal=0, vulGroupTotal=0, vulFetchGen=0, vulLastTask=null;
// pagination state for the scan-list table + the per-scan report table
// (client-side slice over the full /api/tasks array, same pager pattern as
// results/vulns above). Reset to page 0 whenever the page size changes.
// _scTasks / _rpTasks cache the last fetched list so pager nav (scGo/rpGo)
// can re-slice without re-fetching (client-side slice; the agg-vulns pager
// by contrast fetches each page from the server — see renderAggVulns).
let scPage=0, scPageSize=15, rpPage=0, rpPageSize=15, _scTasks=[], _rpTasks=[];
// live-refresh bookkeeping: while a detail (vuln card / URL-result row) is
// expanded, list re-renders are suppressed so they never collapse what the
// user is reading. listDirty marks that a refresh was skipped and should run
// once nothing is expanded anymore.
let listRenderTimer=null, listDirty=false;
const $=(id)=>document.getElementById(id);
async function api(path,opts){const r=await fetch(path,opts);const t=await r.text();try{return JSON.parse(t)}catch(e){return t}}
function esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
function escapeHtml(s){return String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}

// ===== nav (grouped MAIN / SETTINGS) =====
// ic 字段现在存 Lucide icon id(window.ic 注入内联 SVG),不再是 emoji/字符。
const NAV=[
  {id:'dashboard',ic:'layout-dashboard',lbl:'nav.dashboard'},
  {id:'targets',ic:'target',lbl:'nav.targets'},
  {id:'target-groups',ic:'boxes',lbl:'nav.targetGroups'},
  {id:'labs',ic:'flask-conical',lbl:'nav.labs'},
  {id:'vulnerabilities',ic:'bug',lbl:'nav.vulnerabilities'},
  {id:'scans',ic:'refresh-cw',lbl:'nav.scans'},
  {id:'ai-pentest',ic:'bot',lbl:'nav.aiPentest'},
  {id:'reports',ic:'file-text',lbl:'nav.reports'},
  {id:'discovery',ic:'globe',lbl:'nav.discovery'},
  {id:'technologies',ic:'network',lbl:'nav.technologies'},
  {id:'users',ic:'user',lbl:'nav.users'},
  {id:'profiles',ic:'crosshair',lbl:'nav.profiles'},
  {id:'config',ic:'settings',lbl:'nav.config'},
];
function renderNav(){
  const h=[];
  for(const it of NAV){
    h.push('<div class="nav-item'+(curSection===it.id?' active':'')+'" data-nav="'+it.id+'"><span class="ic">'+ic(it.ic)+'</span><span>'+t(it.lbl)+'</span></div>');
  }
  $('sidebar').innerHTML=h.join('');
  $('sidebar').querySelectorAll('.nav-item').forEach(n=>n.onclick=()=>{location.hash='#/'+n.dataset.nav;});
}

// ===== router =====
let curSection='dashboard', curScanId=null;
function router(){
  // close SSE when leaving a scan detail view
  const h=location.hash.replace(/^#\/?/,'');
  const parts=h.split('/');
  const sec=parts[0]||'dashboard';
  if(sec!=='scans'||!parts[1]){ if(evtSrc){evtSrc.close();evtSrc=null;} curScanId=null; }
  curSection=sec; curScanId=parts[1]||null;
  renderNav();
  const r={
    dashboard:renderDashboard, targets:renderTargets, 'add-targets':renderAddTargets,
    'target-groups':renderTargetGroups, 'group-membership':parts[1]?()=>renderGroupMembership(parts[1]):renderTargetGroups,
    'edit-group':parts[1]?()=>renderEditGroup(parts[1]):renderTargetGroups,
    labs:renderLabs, vulnerabilities:renderVulnsAgg,
    scans:parts[1]?()=>renderScanDetail(parts[1]):renderScans,
    'ai-pentest':parts[1]?()=>renderAIDetail(parts[1]):renderAIPentest,
    reports:renderReports, discovery:renderDiscovery, profiles:renderProfiles, technologies:renderTechnologies,
    users:()=>renderStub(t('usr.title'),t('usr.blurb'),t('usr.hint')),
    config:renderConfig,
  };
  (r[sec]||renderDashboard)();
}
window.onhashchange=router;

// ===== page chrome =====
function pageHead(title,desc,extra){return '<div class="page-head"><div><h1>'+esc(title)+'</h1>'+(desc?'<div class="desc">'+desc+'</div>':'')+'</div>'+(extra||'')+'</div>'}
function empty(msg){return '<div class="empty">'+esc(msg)+'</div>'}
function statusPill(s){return '<span class="pill st-'+s+'">'+({running:t('st.running'),done:t('st.done'),error:t('st.error'),paused:t('st.paused'),stopped:t('st.stopped')}[s]||s)+'</span>'}
// progress bar percentage from task status + progress object.
// - done  -> 100 (a finished task is complete regardless of pages vs maxPages)
// - error -> 0
// - scanning phase -> done/total
// - crawl phase -> crawled/maxPages (crawler onProgress always carries maxPages)
function progressPct(status,p){
  if(status==='done')return 100;
  if(status==='error')return 0;
  if(!p)return 0;
  if(p.phase==='scanning')return p.total?Math.min(100,(p.done||0)/(p.total||1)*100):0;
  return p.maxPages?Math.min(100,(p.crawled||0)/(p.maxPages||1)*100):0;
}
function sevBadge(s){const k=String(s||'info').toLowerCase();return '<span class="badge sev-'+(k==='moderate'?'medium':k)+'">'+esc(s||'info')+'</span>'}
function sevClass(s){const k=String(s||'info').toLowerCase();return 's-'+(k==='moderate'?'medium':k==='informational'?'info':k)}
// render a row of severity count badges (c/h/m/l/i) from a vulnBreakdown object.
// zero counts are omitted (matches the Acunetix Target Groups row style).
function vulnCountBadges(br){
  br=br||{};
  const cells=[['critical',br.critical||0,'vc'], ['high',br.high||0,'vh'], ['medium',br.medium||0,'vm'], ['low',br.low||0,'vl'], ['info',br.info||0,'vi']];
  return cells.map(c=>c[1]>0?('<span class="vcount '+c[2]+'">'+c[1]+'</span>'):'').join(' ');
}
// human-readable "last scanned" line for a target: status pill + relative/absolute date.
function lastScanLine(status,at){
  if(!status&&!at)return '<span class="muted tiny">'+t('st.notScanned')+'</span>';
  const lbl={running:t('st.running'),done:t('st.done'),error:t('st.error')}[status]||status||'—';
  const cls=status==='done'?'st-done':(status==='error'?'st-error':(status==='running'?'st-running':''));
  let when='';
  if(at){const d=new Date(at);if(!isNaN(d))when=' · '+d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0')+'-'+String(d.getDate()).padStart(2,'0');}
  return '<span class="pill '+cls+'">'+esc(lbl)+'</span><span class="muted tiny">'+esc(when)+'</span>';
}

// ===== Dashboard =====
async function renderDashboard(){
  $('view').innerHTML=pageHead(t('dash.title'),t('dash.desc'),'<button class="sec" onclick="renderDashboard()">'+t('c.refresh')+'</button> <button class="sec" onclick="location.hash=\'#/scans\'">'+t('dash.viewScans')+'</button> <button id="dbNew">+ '+t('top.newScan')+'</button>')+
    '<div class="grid g4" id="dbStats"></div><div class="grid g2"><div class="card"><h3>'+t('dash.sevDist')+'</h3><div id="dbSev"></div></div><div class="card"><h3>'+t('dash.recent')+'</h3><div id="dbRecent"></div></div></div>';
  $('dbNew').onclick=()=>openNewScanModal();
  const [st,ts,vs]=await Promise.all([api('/api/status'),api('/api/tasks'),api('/api/vulnerabilities?summary=1')]);
  _status=st;
  const sev={high:vs.high||0,medium:vs.medium||0,low:vs.low||0,info:vs.info||0};
  $('dbStats').innerHTML=
    statCard(st.targetCount,t('dash.targets'),'t')+statCard(st.taskCount,t('dash.scans'),'')+statCard(vs.total||0,t('dash.vulns'),'v')+statCard(st.profileCount,t('dash.profiles'),'');
  const tot=vs.total||1;
  $('dbSev').innerHTML='<div class="sevbar"><div style="width:'+(sev.high/tot*100)+'%;background:var(--high)"></div><div style="width:'+(sev.medium/tot*100)+'%;background:var(--med)"></div><div style="width:'+(sev.low/tot*100)+'%;background:var(--low)"></div><div style="width:'+(sev.info/tot*100)+'%;background:var(--info)"></div></div>'+
    '<div class="sevlegend"><span><b style="background:var(--high)"></b>'+t('dash.sevHigh')+' '+sev.high+'</span><span><b style="background:var(--med)"></b>'+t('dash.sevMed')+' '+sev.medium+'</span><span><b style="background:var(--low)"></b>'+t('dash.sevLow')+' '+sev.low+'</span><span><b style="background:var(--info)"></b>'+t('dash.sevInfo')+' '+sev.info+'</span></div>';
  $('dbRecent').innerHTML=ts.length?ts.slice(0,6).map(t=>'<div style="display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid var(--bd)"><span class="pill st-'+t.status+'">'+({running:t('st.running'),done:t('st.done'),error:t('st.error'),paused:t('st.paused'),stopped:t('st.stopped')}[t.status])+'</span><a href="#/scans/'+t.id+'" style="font-family:ui-monospace,monospace;font-size:11px">'+esc(t.target)+'</a><span style="margin-left:auto" class="muted tiny">#'+t.id+' · '+t.vulns+' '+t('dash.vulnCount')+'</span></div>').join(''):empty(t('dash.noScans'));
}
function statCard(n,l,cls){return '<div class="statcard '+(cls||'')+'"><div class="n">'+n+'</div><div class="l">'+l+'</div></div>'}

// ===== Targets =====
// A Target holds exactly ONE url (one address -> one target). Grouping is done
// via the Target Groups entity (members reference target ids), not a string label.
let _addRows=[{address:'',description:''}], _addGroupSel=[];
async function renderTargets(){
  $('view').innerHTML=pageHead(t('tgt.title'),t('tgt.desc'),'<button class="sec" onclick="location.hash=\'#/target-groups\'">'+t('tgt.groups')+'</button> <button id="tgAdd">+ '+t('tgt.add')+'</button>')+
    '<div class="card"><table><thead><tr><th>'+t('tgt.thAddr')+'</th><th>'+t('tgt.thDesc')+'</th><th>'+t('tgt.thType')+'</th><th>'+t('tgt.thVulns')+'</th><th>'+t('tgt.thLast')+'</th><th>'+t('tgt.thOp')+'</th></tr></thead><tbody id="tgBody"></tbody></table></div>';
  $('tgAdd').onclick=()=>{ _addRows=[{address:'',description:''}]; _addGroupSel=[]; location.hash='#/add-targets'; };
  _targets=await api('/api/targets');
  $('tgBody').innerHTML=_targets.length?_targets.map(tg=>'<tr><td class="url">'+esc(tg.address)+'</td><td>'+esc(tg.description||'')+'</td><td class="tiny muted">Web</td><td>'+vulnCountBadges(tg.vulnBreakdown)+'</td><td>'+lastScanLine(tg.lastScanStatus,tg.lastScanAt)+'</td><td><button class="sec tiny" data-scan="'+tg.id+'">'+t('c.scan')+'</button> <button class="sec tiny" data-edit="'+tg.id+'">'+t('c.edit')+'</button> <button class="danger tiny" data-del="'+tg.id+'">'+t('c.delete')+'</button></td></tr>').join(''):empty(t('tgt.empty'));
  $('tgBody').querySelectorAll('[data-scan]').forEach(b=>b.onclick=()=>{const t=_targets.find(x=>x.id===b.dataset.scan);openNewScanModal({targetId:t.id});});
  $('tgBody').querySelectorAll('[data-edit]').forEach(b=>b.onclick=()=>{const t=_targets.find(x=>x.id===b.dataset.edit);openTargetModal(t);});
  $('tgBody').querySelectorAll('[data-del]').forEach(b=>b.onclick=async()=>{if(!confirm(t('tgt.delConfirm')))return;await api('/api/targets/'+b.dataset.del,{method:'DELETE'});renderTargets();});
}
// Add Targets view (Acunetix-style): one url per row, add as many rows as needed,
// optionally assign all new rows to one or more existing groups on save.
async function renderAddTargets(){
  $('view').innerHTML=pageHead(t('at.title'),t('at.desc'),'<button class="sec" onclick="location.hash=\'#/targets\'">'+t('c.cancel')+'</button> <button class="sec" id="atImport">'+t('at.import')+'</button> <button id="atSave">'+t('c.save')+'</button>')+
    '<input type="file" id="atFile" accept=".csv,text/csv" style="display:none">'+
    '<div class="card" style="max-width:920px"><div class="row" style="margin-bottom:6px"><label style="grid-column:1/-1" class="tiny muted">'+t('at.hint')+'</label></div>'+
    '<div id="atRows"></div>'+
    '<button class="sec" id="atMore">'+t('at.more')+'</button>'+
    '<fieldset style="margin-top:16px"><legend>'+t('at.joinGroup')+'</legend><p class="tiny muted" style="margin:0 0 8px">'+t('at.joinHint')+'</p>'+
    '<table id="atGroupTbl" style="border:1px solid var(--bd)"><thead class="muted tiny"><tr><th style="width:30px"></th><th>'+t('at.thGroup')+'</th><th>'+t('tgt.thDesc')+'</th></tr></thead><tbody></tbody></table></fieldset></div>';
  renderAddRows();
  $('atMore').onclick=()=>{ if(_addRows.length>=500){alert(t('at.cap500'));return;} _addRows.push({address:'',description:''}); renderAddRows(); };
  $('atImport').onclick=()=>$('atFile').click();
  $('atFile').onchange=(e)=>{ const f=e.target.files[0]; if(f)importCsvFile(f); e.target.value=''; };
  _groups=await api('/api/target-groups');
  $('atGroupTbl').querySelector('tbody').innerHTML=_groups.length?_groups.map(g=>'<tr><td style="text-align:center"><input type="checkbox" data-gid="'+g.id+'"'+(_addGroupSel.includes(g.id)?' checked':'')+'></td><td class="tiny" style="font-family:ui-monospace,monospace">'+esc(g.name)+'</td><td class="tiny muted">'+esc(g.description||'-')+'</td></tr>').join(''):'<tr><td colspan="3" class="muted tiny" style="padding:8px">'+t('at.noGroup')+'</td></tr>';
  $('atGroupTbl').querySelectorAll('[data-gid]').forEach(cb=>cb.onchange=()=>{ if(cb.checked)_addGroupSel.push(cb.dataset.gid); else _addGroupSel=_addGroupSel.filter(x=>x!==cb.dataset.gid); });
  $('atSave').onclick=async()=>{
    const rows=_addRows.filter(r=>r.address.trim()).map(r=>({address:r.address.trim(),description:r.description||''}));
    if(!rows.length){alert(t('at.noAddr'));return;}
    if(rows.length>500){alert(t('at.over500'));return;}
    const groups=_addGroupSel.slice();
    const r=await api('/api/targets/bulk',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({targets:rows,groups})});
    $('srvStatus')&&($('srvStatus').textContent=t('at.added')+(r.created||0)+t('at.targets')+(r.dropped?(t('at.csvDropped')+r.dropped+')'):''));
    _addRows=[{address:'',description:''}]; _addGroupSel=[];
    location.hash='#/targets';
  };
}
// parse CSV text -> [{address,description}]. First row is skipped if it looks like
// a header (first cell is "address", case-insensitive). Split on the FIRST comma so
// a description containing commas stays intact. Empty address rows are dropped.
// Hard cap 500 rows (matches server TARGET_IMPORT_LIMIT).
function parseCsvTargets(text){
  const LIMIT=500;
  const lines=text.split(/\r?\n/);
  const out=[];
  let headerSeen=false;
  for(let raw of lines){
    const line=raw.trim();
    if(!line) continue;
    const ci=line.indexOf(',');
    let addr, desc;
    if(ci<0){ addr=line; desc=''; }
    else { addr=line.slice(0,ci).trim(); desc=line.slice(ci+1).trim(); }
    // strip optional surrounding quotes
    addr=addr.replace(/^"(.*)"$/,'$1'); desc=desc.replace(/^"(.*)"$/,'$1');
    if(!headerSeen && /^address$/i.test(addr)){ headerSeen=true; continue; }
    if(!addr) continue;
    out.push({address:addr, description:desc});
    if(out.length>=LIMIT) break;
  }
  return out;
}
function importCsvFile(file){
  const rd=new FileReader();
  rd.onload=()=>{
    const parsed=parseCsvTargets(rd.result);
    if(!parsed.length){alert(t('at.csvNoParse'));return;}
    _addRows=parsed;
    renderAddRows();
    const dropped=(rd.result.split(/\r?\n/).filter(l=>l.trim()).length - (parsed.length));
    $('srvStatus')&&($('srvStatus').textContent=t('at.csvLoad')+parsed.length+t('at.csvFromCsv')+(parsed.length>=500?t('at.csvCap'):'')+t('at.csvCheck'));
  };
  rd.onerror=()=>alert(t('at.csvReadErr'));
  rd.readAsText(file);
}
function renderAddRows(){
  const c=$('atRows'); if(!c)return;
  c.innerHTML=_addRows.map((r,i)=>'<div class="row" data-r="'+i+'"><div><label>'+t('at.lblAddr')+'</label><input class="atAddr" value="'+esc(r.address)+'" placeholder="http://example.com/"></div><div><label>'+t('at.lblDesc')+'</label><input class="atDesc" value="'+esc(r.description||'')+'"></div></div>').join('');
  c.querySelectorAll('[data-r]').forEach(div=>{
    const i=+div.dataset.r;
    div.querySelector('.atAddr').oninput=e=>_addRows[i].address=e.target.value;
    div.querySelector('.atDesc').oninput=e=>_addRows[i].description=e.target.value;
  });
}
function openTargetModal(tg){
  tg=tg||{address:'',description:'',criticality:'normal',includePatterns:[],excludePatterns:(window.DEFAULT_EXCLUDE_PATTERNS||[]).slice(),auth:null};
  modalBox('<h2>'+(tg.id?t('tm.edit'):t('tm.add'))+'</h2>',
    '<fieldset><legend>'+t('tm.fldTarget')+'</legend><label>'+t('tm.addrSingle')+'</label><input id="tgAddr" value="'+esc(tg.address)+'" placeholder="http://example.com/">'+
    '<div class="row"><div><label>'+t('tg.thDesc')+'</label><input id="tgDesc" value="'+esc(tg.description||'')+'"></div><div><label>'+t('tm.crit')+'</label><select id="tgCrit"><option value="normal"'+(tg.criticality==='normal'?' selected':'')+'>Normal</option><option value="high"'+(tg.criticality==='high'?' selected':'')+'>High</option><option value="critical"'+(tg.criticality==='critical'?' selected':'')+'>Critical</option></select></div></div>'+
    (tg.id?('<label class="tiny muted">'+t('tm.inGroup')+'</label><div id="tgGroups" class="tiny">'+esc((tg.groups||[]).length?(tg.groups.map(gid=>{const g=_groups.find(x=>x.id===gid);return g?g.name:gid;}).join(', ')):t('tm.noGroup'))+'</div>'):'')+'</fieldset>'+
    '<fieldset><legend>'+t('tm.scope')+'</legend><label>'+t('tm.include')+'</label><input id="tgInc" value="'+esc((tg.includePatterns||[]).join(','))+'"><label>'+t('tm.exclude')+'</label><input id="tgExc" value="'+esc((tg.excludePatterns||[]).join(','))+'"></fieldset>'+
    '<fieldset><legend>'+t('tm.auth')+'</legend>'+authFieldsHtml(tg.auth)+'</fieldset>',
    '<button class="sec" onclick="closeModal()">'+t('c.cancel')+'</button><button id="tgSave">'+t('c.save')+'</button>');
  renderAuthFromObj(tg.auth);
  $('tgSave').onclick=async()=>{
    const body={address:$('tgAddr').value.trim(),description:$('tgDesc').value,criticality:$('tgCrit').value,
      includePatterns:splitCsv($('tgInc').value),excludePatterns:splitCsv($('tgExc').value),auth:collectAuthFromModal()};
    if(!body.address){alert(t('tm.noAddr'));return;}
    if(tg.id){ await api('/api/targets/'+tg.id,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}); }
    else { await api('/api/targets',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}); }
    closeModal();renderTargets();
  };
}
function splitCsv(s){return (s||'').split(',').map(x=>x.trim()).filter(Boolean)}

// ===== Target Groups =====
// A group is a named set of target ids. The list view shows member count + summed
// vuln badges; members are managed in a transfer (穿梭) view. Scanning a group
// starts one scan per member, each carrying its own saved auth/scope.
async function renderTargetGroups(){
  $('view').innerHTML=pageHead(t('tg.title'),t('tg.desc'),'<button class="sec" onclick="location.hash=\'#/targets\'">'+t('tg.back')+'</button> <button id="tgNew">+ '+t('tg.new')+'</button>')+
    '<div class="card"><table><thead><tr><th>'+t('tg.thName')+'</th><th>'+t('tg.thDesc')+'</th><th>'+t('tg.thCount')+'</th><th>'+t('tg.thVulns')+'</th><th>'+t('tg.thOp')+'</th></tr></thead><tbody id="tgGrpBody"></tbody></table></div>';
  $('tgNew').onclick=()=>openGroupModal();
  _groups=await api('/api/target-groups');
  $('tgGrpBody').innerHTML=_groups.length?_groups.map(g=>'<tr><td class="tiny" style="font-family:ui-monospace,monospace">'+esc(g.name)+'</td><td class="tiny muted">'+esc(g.description||'-')+'</td><td>'+g.memberCount+'</td><td>'+vulnCountBadges(g.vulnBreakdown)+'</td><td><button class="sec tiny" data-edit="'+g.id+'">'+t('c.edit')+'</button> <button class="sec tiny" data-mem="'+g.id+'">'+t('tg.members')+'</button> <button class="tiny" data-scan="'+g.id+'">'+t('c.scan')+'</button> <button class="danger tiny" data-del="'+g.id+'">'+t('c.delete')+'</button></td></tr>').join(''):empty(t('tg.empty'));
  $('tgGrpBody').querySelectorAll('[data-edit]').forEach(b=>b.onclick=()=>{const g=_groups.find(x=>x.id===b.dataset.edit);openGroupModal(g);});
  $('tgGrpBody').querySelectorAll('[data-mem]').forEach(b=>b.onclick=()=>{location.hash='#/group-membership/'+b.dataset.mem;});
  $('tgGrpBody').querySelectorAll('[data-scan]').forEach(b=>b.onclick=()=>startGroupScan(b.dataset.scan));
  $('tgGrpBody').querySelectorAll('[data-del]').forEach(b=>b.onclick=async()=>{if(!confirm(t('tg.delConfirm')))return;await api('/api/target-groups/'+b.dataset.del,{method:'DELETE'});renderTargetGroups();});
}
function openGroupModal(g){
  g=g||{name:'',description:''};
  modalBox('<h2>'+(g.id?t('tg.editM'):t('tg.newM'))+'</h2>',
    '<fieldset><legend>'+t('tg.fldGroup')+'</legend><label>'+t('tg.nameReq')+'</label><input id="grpName" value="'+esc(g.name||'')+'"><label>'+t('tg.thDesc')+'</label><input id="grpDesc" value="'+esc(g.description||'')+'"></fieldset>',
    '<button class="sec" onclick="closeModal()">'+t('c.cancel')+'</button><button id="grpSave">'+t('c.save')+'</button>');
  $('grpSave').onclick=async()=>{
    const body={name:$('grpName').value.trim(),description:$('grpDesc').value};
    if(!body.name){alert(t('tg.nameEmpty'));return;}
    if(g.id){ await api('/api/target-groups/'+g.id,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}); }
    else { const r=await api('/api/target-groups',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}); if(r&&r.id){ _addGroupSel=[]; location.hash='#/group-membership/'+r.id; closeModal(); return; } }
    closeModal();renderTargetGroups();
  };
}
// Group Membership transfer view: left = current members, right = available
// targets, middle buttons move the checked selection across. PUT updates members.
let _gmGroup=null, _gmMembers=[], _gmAvail=[], _gmSelMem=new Set(), _gmSelAvail=new Set();
async function renderGroupMembership(gid){
  _groups=await api('/api/target-groups'); _targets=await api('/api/targets');
  _gmGroup=_groups.find(g=>g.id===gid);
  $('view').innerHTML=pageHead(t('gm.title')+esc(_gmGroup?_gmGroup.name:gid),t('gm.desc'),'<button class="sec" onclick="location.hash=\'#/target-groups\'">'+t('gm.back')+'</button>')+
    '<div class="transfer"><div class="tf-pane"><div class="tf-head">'+t('gm.members')+' <span class="muted tiny" id="gmMemCnt"></span></div><div class="tf-filter"><input id="gmMemF" placeholder="'+t('c.filter')+'..."></div><div class="tf-list" id="gmMem"></div></div>'+
    '<div class="tf-mid"><button class="sec" id="gmAdd">'+ic('arrow-left','btn-ic')+t('gm.addBtn')+'</button><button class="sec" id="gmRm">'+t('gm.rmBtn')+ic('arrow-right','btn-ic')+'</button></div>'+
    '<div class="tf-pane"><div class="tf-head">'+t('gm.avail')+'</div><div class="tf-filter"><input id="gmAvF" placeholder="'+t('c.filter')+'..."></div><div class="tf-list" id="gmAv"></div></div></div>';
  _gmMembers=((_gmGroup&&_gmGroup.members)||[]).map(String);
  _gmAvail=_targets.map(t=>String(t.id)).filter(id=>!_gmMembers.includes(id));
  _gmSelMem=new Set(); _gmSelAvail=new Set();
  renderGmLists();
  $('gmMemF').oninput=renderGmLists; $('gmAvF').oninput=renderGmLists;
  $('gmAdd').onclick=async()=>{ if(!_gmSelAvail.size)return; const add=[..._gmSelAvail]; _gmMembers=[..._gmMembers,...add]; _gmAvail=_gmAvail.filter(id=>!_gmSelAvail.has(id)); _gmSelAvail.clear(); renderGmLists(); await saveGmMembers(); };
  $('gmRm').onclick=async()=>{ if(!_gmSelMem.size)return; const rm=[..._gmSelMem]; _gmMembers=_gmMembers.filter(id=>!_gmSelMem.has(id)); _gmAvail=[..._gmAvail,...rm]; _gmSelMem.clear(); renderGmLists(); await saveGmMembers(); };
}
function renderGmLists(){
  const mf=($('gmMemF')?$('gmMemF').value:'').toLowerCase();
  const af=($('gmAvF')?$('gmAvF').value:'').toLowerCase();
  const row=(id,sel,set)=>{
    const t=_targets.find(x=>String(x.id)===String(id)); if(!t)return'';
    const f=(t.address+' '+(t.description||'')).toLowerCase();
    return '<label class="tf-item'+(sel?' sel':'')+'"><input type="checkbox" data-id="'+id+'" '+(sel?'checked':'')+'><span class="url" title="'+esc(t.address)+'">'+esc(t.address)+'</span><span class="tfdesc tiny muted" title="'+esc(t.description||'')+'">'+esc(t.description||'')+'</span></label>';
  };
  $('gmMem').innerHTML=_gmMembers.filter(id=>{const t=_targets.find(x=>String(x.id)===String(id));return t&&(t.address+' '+(t.description||'')).toLowerCase().includes(mf);}).map(id=>row(id,_gmSelMem.has(id))).join('')||'<div class="muted tiny tf-empty">'+t('gm.emptyMem')+'</div>';
  $('gmAv').innerHTML=_gmAvail.filter(id=>{const t=_targets.find(x=>String(x.id)===String(id));return t&&(t.address+' '+(t.description||'')).toLowerCase().includes(af);}).map(id=>row(id,_gmSelAvail.has(id))).join('')||'<div class="muted tiny tf-empty">'+t('gm.emptyAvail')+'</div>';
  $('gmMemCnt').textContent='('+_gmMembers.length+')';
  $('gmMem').querySelectorAll('[data-id]').forEach(cb=>cb.onchange=()=>{const id=cb.dataset.id; if(cb.checked)_gmSelMem.add(id); else _gmSelMem.delete(id); cb.closest('.tf-item').classList.toggle('sel',cb.checked);});
  $('gmAv').querySelectorAll('[data-id]').forEach(cb=>cb.onchange=()=>{const id=cb.dataset.id; if(cb.checked)_gmSelAvail.add(id); else _gmSelAvail.delete(id); cb.closest('.tf-item').classList.toggle('sel',cb.checked);});
}
async function saveGmMembers(){
  if(!_gmGroup)return;
  await api('/api/target-groups/'+_gmGroup.id,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({members:_gmMembers})});
  $('srvStatus')&&($('srvStatus').textContent=t('gm.updated')+_gmGroup.name+t('gm.updated2')+_gmMembers.length+t('gm.updated3'));
}
// scan every member of a group — one crawl+scan per target, each carrying its own
// saved auth/include/exclude. Fire-and-forget (server runs them concurrently).
async function startGroupScan(gid){
  _groups=await api('/api/target-groups'); _targets=await api('/api/targets');
  const g=_groups.find(x=>x.id===gid); if(!g)return;
  const members=(g.members||[]).map(id=>_targets.find(t=>String(t.id)===String(id))).filter(Boolean);
  if(!members.length){alert(t('gm.noMembers'));return;}
  if(!confirm(t('gm.scanConfirm')+g.name+t('gm.scanConfirm2')+members.length+t('gm.scanConfirm3')))return;
  $('srvStatus')&&($('srvStatus').textContent=t('gm.starting')+members.length+t('gm.starting2'));
  let started=0;
  for(const t of members){
    const body={target:t.address,useTestServer:false,autoScan:true,
      includePatterns:t.includePatterns||[],excludePatterns:t.excludePatterns||(window.DEFAULT_EXCLUDE_PATTERNS||[]),
      auth:t.auth||null,plugins:null};
    try{ const r=await fetch('/api/crawl',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}); const res=await r.json(); if(res.id)started++; }catch(e){}
  }
  $('srvStatus')&&($('srvStatus').textContent=t('gm.started')+started+t('gm.started2')+members.length);
  if(started)location.hash='#/scans';
}
// edit-group deep link: render the groups list as the backdrop, then open the
// edit modal on top of it (editing is normally triggered from the list row).
function renderEditGroup(gid){ renderTargetGroups(); openGroupModalById(gid); }
async function openGroupModalById(gid){ _groups=await api('/api/target-groups'); const g=_groups.find(x=>x.id===gid); if(g)openGroupModal(g); }

// ===== Vulnerabilities (aggregated, severity-sorted) =====
// SERVER-SIDE pagination: the browser holds only the CURRENT page (aggVulItems)
// + the total count (aggVulTotal) for the pager. Every page nav / filter change
// re-queries /api/vulnerabilities?page=&pageSize=&group= — we never pull the
// whole result set into the browser (that was what choked large scans).
// aggVulGroup: 开启「按漏洞名聚合」——服务端按 typeId 分组,分页单位=组,组可展开看具体实例。
let aggVulItems=[],aggVulTotal=0,aggVulVulnTotal=0,aggVulPage=0,aggVulPageSize=15,aggVulSev='',aggVulGroup=false;
// 单条漏洞卡片 markup(全局页:带「来源: 扫描 #taskId」行)。平铺与聚合组内共用。
function aggVulnCard(v){
  return '<div class="vuln '+sevClass(v.severity)+'"><div class="t">'+sevBadge(v.severity)+' '+vulnTitle(v)+'<span class="tw">'+t('vul.detail')+'</span></div>'+
    vulnUrlRow(v)+
    '<div class="p">'+esc(v.plugin||'')+(v.affects?' · '+esc(v.affects):'')+(v.parameter?' · '+t('misc.paramPrefix')+esc(v.parameter):'')+(v.attackVector?' · '+esc(String(v.attackVector).slice(0,40)):'')+'<br><span class="muted tiny">'+t('vd.srcScan')+'<a href="#/scans/'+v.taskId+'">'+t('vd.scan')+' #'+v.taskId+'</a>'+(v.target&&v.target!==vulnUrl(v)?' · '+esc(v.target):'')+'</span></div><div class="exp">'+vulnDetail(v)+'</div></div>';
}
function aggVulToolbar(){
  const opts=[['',t('vul.sevAll')],['high',t('vul.sevHigh')],['medium',t('vul.sevMed')],['low',t('vul.sevLow')],['info',t('vul.sevInfo')]];
  const gbtn='<button class="sec" id="vlGrp" onclick="aggVulGroup=!aggVulGroup;aggVulPage=0;renderAggVulns()"'+(aggVulGroup?' style="background:var(--acc);color:#fff"':'')+'>'+(aggVulGroup?t('vul.groupOn'):t('vul.groupOff'))+'</button>';
  return '<div class="toolbar"><select id="vlSev" onchange="aggVulSev=this.value;aggVulPage=0;renderAggVulns()">'+opts.map(o=>'<option value="'+o[0]+'"'+(o[0]===aggVulSev?' selected':'')+'>'+o[1]+'</option>').join('')+'</select> '+gbtn+' <button class="sec" onclick="renderVulnsAgg()">'+t('c.refresh')+'</button></div>';
}
async function renderVulnsAgg(){
  $('view').innerHTML=pageHead(t('vul.title'),t('vul.desc'),aggVulToolbar())+'<div id="vlList"></div>';
  aggVulPage=0;
  await renderAggVulns();
}
// Fetch ONE page from the server (flat or grouped) and render it + the pager.
// Every call hits /api/vulnerabilities?page=&pageSize=&group= — the browser
// never holds the full result set, only the current page + total count.
async function renderAggVulns(){
  const vlList=$('vlList');
  if(!vlList)return;
  const qs=[];
  if(aggVulSev)qs.push('severity='+encodeURIComponent(aggVulSev));
  qs.push('page='+aggVulPage);
  qs.push('pageSize='+aggVulPageSize);
  if(aggVulGroup)qs.push('group=1');
  const data=await api('/api/vulnerabilities?'+qs.join('&'));
  // the view may have switched away during the await (user navigated off the
  // vulns page); vlList is gone from the DOM → bail instead of crashing on
  // setting innerHTML of null.
  const host=$('vlList');
  if(!host)return;
  aggVulItems=Array.isArray(data.items)?data.items:[];
  aggVulTotal=data.total||0;
  aggVulVulnTotal=data.vulnTotal||0;
  // server clamps page too, but sync our state in case it shrank mid-session
  aggVulPage=clampPage(data.page||0,aggVulTotal,aggVulPageSize);
  if(aggVulGroup){renderAggVulnsGrouped();return;}
  host.innerHTML=aggVulItems.length?aggVulItems.map(v=>aggVulnCard(v)).join('')+pagerHtml('aggVul',aggVulTotal,aggVulPageSize,aggVulPage):empty(t('vul.empty'));
  wireVulnCards(host);
}
// 按漏洞名聚合渲染:服务端按「类型(组)」分页,aggVulItems 即本页的 N 个不同类型。
// 每个组卡只渲染表头(×N 计数),组体留空;首次展开时懒加载该 typeId 的实例(平铺分页 +
// 「加载更多」追加),避免首页把 no_https×455 这类大组的几百张卡片全塞进 DOM。
function renderAggVulnsGrouped(){
  const groups=aggVulItems,total=aggVulTotal;
  const extra=aggVulVulnTotal?(' · '+aggVulVulnTotal+t('vul.extraVulns')):'';
  const host=$('vlList');
  if(!host)return;
  host.innerHTML=groups.length?groups.map((g,gi)=>{
    return '<div class="vgrp '+sevClass(g.sev)+'" data-gi="'+gi+'" data-tid="'+esc(g.typeId)+'"><div class="vgrp-h">'+
      sevBadge(g.sev)+' '+vulnTitle({typeId:g.typeId,name:g.name})+'<span class="vgrp-cnt">×'+(g.total||0)+'</span>'+
      '<span class="muted tiny"> · '+(g.urlCount||0)+t('vul.urls')+'</span><span class="tw">'+t('vul.expand')+'</span></div>'+
      '<div class="vgrp-b" data-loaded="0"></div></div>';
  }).join('')+pagerHtml('aggVul',total,aggVulPageSize,aggVulPage,t('vul.unitType'),extra):empty(t('vul.empty'));
  // 组头点击:展开/收起(带 getSelection 守卫,防拖选误收起);首次展开触发懒加载实例。
  host.querySelectorAll('.vgrp').forEach(grp=>{
    grp.querySelector('.vgrp-h').onclick=(e)=>{
      if(e.target.matches('a,input,button'))return;
      if(window.getSelection().toString())return;
      const on=grp.classList.toggle('open');
      grp.querySelector('.tw').textContent=on?t('vul.collapse'):t('vul.expand');
      if(on) aggGroupExpand(grp);
    };
  });
}
// 组内实例懒加载分页大小(独立于 aggVulPageSize —— 后者是「每页多少组」)。
const AGG_GROUP_PS=20;
// 首次展开:拉取该 typeId 的第一页实例并渲染;后续展开不重复拉取。
async function aggGroupExpand(grp){
  const body=grp.querySelector('.vgrp-b');
  if(!body || (body.dataset.loaded && body.dataset.loaded!=='0')) return;
  const typeId=grp.dataset.tid;
  body.innerHTML='<div class="muted tiny" style="padding:6px 2px">'+t('c.loading')+'</div>';
  const data=await api('/api/vulnerabilities?'+aggGroupQs(typeId,0));
  const items=Array.isArray(data.items)?data.items:[];
  const total=data.total||items.length;
  body.dataset.loaded=String(items.length);
  body.dataset.page='0';
  body.dataset.total=String(total);
  body.innerHTML=items.map(v=>aggVulnCard(v)).join('')+aggGroupMoreHtml(total,items.length);
  wireVulnCards(body);
}
// 「加载更多」:拉取下一页实例并追加。
async function aggGroupMore(btn){
  const grp=btn.closest('.vgrp');
  const body=grp.querySelector('.vgrp-b');
  const typeId=grp.dataset.tid;
  const page=(+body.dataset.page||0)+1;
  const total=+body.dataset.total||0;
  const loaded=+body.dataset.loaded||0;
  btn.disabled=true; btn.textContent=t('c.loading');
  const data=await api('/api/vulnerabilities?'+aggGroupQs(typeId,page));
  const items=Array.isArray(data.items)?data.items:[];
  const more=body.querySelector('.vgrp-more'); if(more) more.remove();
  body.insertAdjacentHTML('beforeend', items.map(v=>aggVulnCard(v)).join('')+aggGroupMoreHtml(total,loaded+items.length));
  body.dataset.page=String(page);
  body.dataset.loaded=String(loaded+items.length);
  wireVulnCards(body);
}
// 组内实例请求 query:平铺模式按 typeId 过滤,带当前严重度筛选,分页大小=AGG_GROUP_PS。
function aggGroupQs(typeId,page){
  const qs=['typeId='+encodeURIComponent(typeId),'page='+page,'pageSize='+AGG_GROUP_PS];
  if(aggVulSev) qs.push('severity='+encodeURIComponent(aggVulSev));
  return qs.join('&');
}
// 「加载更多」按钮 / 全部已显示提示。
function aggGroupMoreHtml(total,loaded){
  if(loaded>=total) return '<div class="muted tiny vgrp-more" style="padding:6px 2px">'+t('vul.allShown')+total+t('c.unit')+'</div>';
  return '<button class="sec vgrp-more" style="margin:6px 0" onclick="aggGroupMore(this)">'+t('vul.loadMore')+loaded+'/'+total+')</button>';
}
// 给容器内的 .vuln 卡片绑展开详情点击;click 不冒泡,避免在聚合组内点卡片时收起整个组。
function wireVulnCards(scope){
  scope.querySelectorAll('.vuln').forEach(c=>{
    c.onclick=(e)=>{
      e.stopPropagation();
      if(e.target.matches('a,input,button'))return;
      if(window.getSelection().toString())return;
      const on=c.classList.toggle('open');
      c.querySelector('.tw').textContent=on?t('vul.collapse'):t('vul.detail');
    };
  });
}
function aggVulGo(act){const total=aggVulTotal;const pages=Math.max(1,Math.ceil(total/aggVulPageSize));
  if(act==='first')aggVulPage=0;else if(act==='last')aggVulPage=pages-1;else if(act==='next')aggVulPage=Math.min(aggVulPage+1,pages-1);else if(act==='prev')aggVulPage=Math.max(aggVulPage-1,0);
  renderAggVulns();}
function aggVulSize(v){aggVulPageSize=+v||15;aggVulPage=0;renderAggVulns();}

// ===== Scans (list) =====
async function renderScans(){
  $('view').innerHTML=pageHead(t('sc.title'),t('sc.desc'),'<button class="sec" onclick="renderScans()">'+t('c.refresh')+'</button> <button id="scDelSel" class="sec" disabled>'+t('sc.delSel')+'</button> <button id="scNew">+ '+t('sc.new')+'</button>')+'<div class="card"><table><thead><tr><th style="width:28px"><input type="checkbox" id="scSelAll" style="width:auto"></th><th>'+t('sc.thId')+'</th><th>'+t('sc.thType')+'</th><th>'+t('sc.thTarget')+'</th><th>'+t('sc.thStatus')+'</th><th>'+t('sc.thProg')+'</th><th>'+t('sc.thVulns')+'</th><th>'+t('sc.thCrawled')+'</th><th>'+t('sc.thStart')+'</th><th>'+t('sc.thOp')+'</th></tr></thead><tbody id="scBody"></tbody></table><div id="scPager"></div></div>';
  $('scNew').onclick=()=>openNewScanModal();
  const ts=await api('/api/tasks'); _scTasks=ts;
  // client-side pagination over the task list (same pattern as results/vulns).
  // Bindings below (select-all / 删除选中 / per-row delete+stop) naturally scope
  // to the visible slice because they query the rendered DOM.
  renderScansSlice();
}
// render the current scPage slice of _scTasks into the scan table + pager.
// Called by renderScans (after fetch) and scGo/scSize (pager nav, no re-fetch).
function renderScansSlice(){
  const ts=_scTasks, total=ts.length;
  scPage=clampPage(scPage,total,scPageSize);
  const start=scPage*scPageSize;
  const slice=ts.slice(start,start+scPageSize);
  $('scBody').innerHTML=slice.length?slice.map(sc=>{const p=sc.progress||((taskCache[sc.id]||{}).progress)||{};const pct=progressPct(sc.status,p);const crawled=p.crawled!=null?p.crawled:sc.crawled;const progTxt=p.phase==='scanning'?(p.done+'/'+p.total):(crawled!=null?crawled+t('sc.pageUnit'):'-');
    const canDel=sc.status==='done'||sc.status==='error'||sc.status==='stopped';
    const canStop=sc.status==='running'||sc.status==='paused';
    return '<tr><td onclick="event.stopPropagation()">'+(canDel?'<input type="checkbox" class="scsel" data-id="'+sc.id+'" style="width:auto">':'')+'</td><td>#'+sc.id+'</td><td>'+(sc.type==='crawl'?t('misc.crawlScanType'):t('misc.scanOnlyType'))+'</td><td class="url">'+esc(sc.target||'')+'</td><td>'+statusPill(sc.status)+'</td><td><div class="pbar"><div style="width:'+pct+'%"></div></div><span class="tiny">'+progTxt+'</span></td><td style="color:var(--err);font-weight:700">'+sc.vulns+'</td><td>'+sc.crawled+'</td><td class="tiny">'+(sc.startedAt||'').slice(0,19).replace('T',' ')+'</td><td><a class="btn sec tiny" href="#/scans/'+sc.id+'">'+t('c.view')+'</a> '+(canStop?'<button class="btn danger tiny" data-stop="'+sc.id+'">'+t('c.stop')+'</button> ':'')+(canDel?'<button class="btn danger tiny" data-del="'+sc.id+'">'+t('c.delete')+'</button>':'')+'</td></tr>';}).join(''):empty(t('sc.empty'));
  const scPager=$('scPager'); if(scPager) scPager.innerHTML= total?pagerHtml('sc',total,scPageSize,scPage):'';
  // select-all toggles all deletable rows (done/error only)
  $('scSelAll').onchange=(e)=>document.querySelectorAll('.scsel').forEach(c=>c.checked=e.target.checked);
  // enable 删除选中 only when at least one row is checked
  const updDelSel=()=>{const n=document.querySelectorAll('.scsel:checked').length;const b=$('scDelSel');b.disabled=n===0;b.textContent=n?(t('sc.delSel')+' ('+n+')'):t('sc.delSel');};
  document.querySelectorAll('.scsel').forEach(c=>c.onchange=updDelSel);
  $('scDelSel').onclick=async()=>{
    const ids=[...document.querySelectorAll('.scsel:checked')].map(c=>c.dataset.id);
    if(!ids.length)return;
    if(!confirm(t('sc.delSelConfirm')+ids.length+t('sc.delSelConfirm2')))return;
    const r=await api('/api/tasks/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ids})});
    const skipped=(r.skipped||[]).map(s=>s.id).join(', ');
    $('srvStatus').textContent=t('sc.deleted')+r.deleted.length+t('sc.deleted2')+(r.skipped&&r.skipped.length?(t('sc.skipped')+skipped+')'):'');
    renderScans();
  };
  // per-row delete buttons
  document.querySelectorAll('[data-del]').forEach(b=>b.onclick=async()=>{
    const id=b.dataset.del;
    if(!confirm(t('sc.delRowConfirm')+id+t('sc.delRowConfirm2')))return;
    const r=await api('/api/task/'+id,{method:'DELETE'});
    if(r.error){alert(r.error);return;}
    $('srvStatus').textContent=t('sc.deletedTask')+id;
    renderScans();
  });
  // stop button on a running/paused scan row (scoped to the scan table so it
  // never collides with the lab-card data-stop buttons, which use a different API)
  $('scBody').querySelectorAll('[data-stop]').forEach(b=>b.onclick=async()=>{
    const id=b.dataset.stop;
    await api('/api/task/'+id+'/stop',{method:'POST'});
    $('srvStatus').textContent=t('sc.stopping')+id+t('sc.stopping2');
    setTimeout(renderScans,800);
  });
}
// scan-list pager navigation (mirrors aggVulGo; re-slices cached _scTasks, no re-fetch)
function scGo(act){const total=_scTasks.length,pages=Math.max(1,Math.ceil(total/scPageSize));
  if(act==='first')scPage=0;else if(act==='last')scPage=pages-1;else if(act==='next')scPage=Math.min(scPage+1,pages-1);else if(act==='prev')scPage=Math.max(scPage-1,0);
  renderScansSlice();}
function scSize(v){scPageSize=+v||15;scPage=0;renderScansSlice();}

// ===== Scan detail (reuses the live stat-bar / sitemap / results / vulns panes) =====
function renderScanDetail(id){
  curTask=id;
  // reset pagination state when entering a (different) scan detail. vulTotal=0
  // + vulLastTask=null guard the vulns pane until refreshTask() loads the real
  // count, so a stray live re-render can't flash the previous task's vulns.
  resPage=0;vulPage=0;_resPagerKey='';vulTotal=0;vulLastTask=null;vulFetchGen++;
  $('view').innerHTML=pageHead(t('sc.title')+' #'+id,'<a href="#/scans" class="tiny">'+t('sd.back')+'</a>','<a class="btn sec" href="#/reports">'+t('sd.report')+'</a>')+
    '<div class="det-topbar"><div class="det-stat"><div class="n" id="stCrawled">0</div><div class="l">'+t('sd.crawled')+'</div></div>'+
    '<div class="det-stat"><div class="n" id="stScan">0/0</div><div class="l">'+t('sd.scan')+'</div></div>'+
    '<div class="det-stat"><div class="n" id="stElapsed">0s</div><div class="l">'+t('sd.elapsed')+'</div></div>'+
    '<div class="det-stat v"><div class="n" id="stVulns">0</div><div class="l">'+t('sd.vulns')+'</div></div>'+
    '<div class="det-stat"><div class="n" id="stStatus">-</div><div class="l">'+t('sd.status')+'</div></div>'+
    '<div class="det-ctrl"><button class="btn sec" id="btnPauseScan" style="display:none">'+ic('pause','btn-ic')+' '+t('sd.pause')+'</button><button class="btn sec" id="btnResumeScan" style="display:none">'+ic('play','btn-ic')+' '+t('sd.resume')+'</button><button class="btn danger" id="btnStopScan" style="display:none">'+ic('circle-stop','btn-ic')+' '+t('sd.stop')+'</button></div></div>'+
    '<div class="gbar"><div id="gbar"></div></div>'+
    '<div class="tabs"><div class="tab active" data-pane="sitemap">'+t('sd.tabSitemap')+'<span class="cnt" id="cSite">0</span></div><div class="tab" data-pane="results">'+t('sd.tabResults')+'<span class="cnt" id="cUrl">0</span></div><div class="tab" data-pane="vulns">'+t('sd.tabVulns')+'<span class="cnt" id="cVuln">0</span></div><div class="tab" data-pane="tech">'+t('sd.tabTech')+'<span class="cnt" id="cTech">0</span></div></div>'+
    '<div class="pane" id="paneSitemap"></div>'+
    '<div class="pane" id="paneResults" style="display:none"><div class="toolbar"><button class="sec" id="btnDelInvalid">'+t('sd.delInvalid')+'</button><button class="sec" id="btnRescan">'+t('sd.rescan')+'</button><span style="flex:1"></span><button class="sec" data-export="txt">TXT</button><button class="sec" data-export="json">JSON</button><button class="sec" data-export="xml">XML</button></div><table id="resultsTable"><thead><tr><th><input type="checkbox" id="selAll" style="width:auto"></th><th>'+t('sd.thStatus')+'</th><th>'+t('sd.thMethod')+'</th><th>'+t('sd.thUrl')+'</th><th>'+t('sd.thTitle')+'</th><th>'+t('sd.thSource')+'</th></tr></thead><tbody class="rtbody"></tbody></table><div id="resPager"></div></div>'+
    '<div class="pane" id="paneVulns" style="display:none"></div>'+
    '<div class="pane" id="paneTech" style="display:none"></div>';
  wireScanDetail();
  openSSE(id);refreshTask();
}
function wireScanDetail(){
  $('resultsTable').querySelector('tbody').addEventListener('click',(e)=>{
    if(e.target.matches('input,.badge'))return;
    // 「以此请求新建扫描」按钮：用该 URL 的请求信息预填新建扫描弹窗
    const rbtn=e.target.closest('[data-rescan-url]');
    if(rbtn){
      e.stopPropagation();
      const url=rbtn.dataset.rescanUrl;
      const pages=(taskCache[curTask]&&taskCache[curTask].pages)||[];
      const p=pages.find(x=>x.url===url);
      if(!p){alert(t('sd.noUrlRec'));return;}
      const req=(p.http&&p.http.request)||{};
      openNewScanModal({url:p.url,method:req.method||'GET',headers:req.headers,body:req.body||''});
      return;
    }
    const tr=e.target.closest('tr.rrow');if(!tr)return;
    const det=document.querySelector('tr.rdet[data-url="'+CSS.escape(tr.dataset.url)+'"]');
    if(det){const on=det.style.display==='none';det.style.display=on?'':'none';tr.querySelector('.tw').textContent=on?'▴':'▾';}
    onDetailToggled();
  });
  $('paneVulns').addEventListener('click',(e)=>{
    if(e.target.matches('a,input,button'))return;
    // 选中文字时不折叠卡片 — 拖选详情文本复制时 mouseup 冒泡成 click 会误触收起
    if(window.getSelection().toString())return;
    // 聚合态:点组头(.vgrp-h)展开/收起整个组;组内 .vuln 卡片仍独立展开详情。
    // 首次展开触发 detGroupExpand 懒加载该 typeId 的实例(组体默认空)。
    const gh=e.target.closest('.vgrp-h');
    if(gh){const grp=gh.closest('.vgrp');if(grp){const on=grp.classList.toggle('open');const tw=grp.querySelector('.tw');if(tw)tw.textContent=on?t('vul.collapse'):t('vul.expand');if(on&&grp.dataset.tid)detGroupExpand(grp);}onDetailToggled();return;}
    const card=e.target.closest('.vuln');if(!card)return;
    const on=card.classList.toggle('open');const tw=card.querySelector('.tw');if(tw)tw.textContent=on?t('vul.collapse'):t('vul.detail');
    onDetailToggled();
  });
  document.querySelectorAll('.tab[data-pane]').forEach(t=>t.onclick=()=>{document.querySelectorAll('.tab[data-pane]').forEach(x=>x.classList.remove('active'));t.classList.add('active');['sitemap','results','vulns','tech'].forEach(p=>$('pane'+p.charAt(0).toUpperCase()+p.slice(1)).style.display='none');$('pane'+t.dataset.pane.charAt(0).toUpperCase()+t.dataset.pane.slice(1)).style.display='block';flushPane(t.dataset.pane);onDetailToggled();});
  $('btnDelInvalid').onclick=async()=>{const sel=Array.from(document.querySelectorAll('tr[data-url]')).filter(tr=>{const s=tr.querySelector('.badge');return s&&(+s.textContent>=400||tr.querySelector('.url.soft'));}).map(tr=>tr.dataset.url);if(!sel.length){alert(t('sd.noInvalid'));return;}const r=await api('/api/task/'+curTask+'/url',{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({urls:sel})});$('srvStatus').textContent=t('sd.deleted')+r.removed+' '+t('c.unit');refreshTask();};
  $('btnRescan').onclick=async()=>{const urls=[...document.querySelectorAll('.urlsel:checked')].map(c=>c.dataset.url);if(!urls.length){alert(t('sd.selUrlFirst'));return;}await api('/api/task/'+curTask+'/rescan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({urls})});$('srvStatus').textContent=t('sd.rescanning')+urls.length+t('sd.rescanning2');};
  document.querySelectorAll('[data-export]').forEach(b=>b.onclick=async()=>{const fmt=b.dataset.export;const r=await fetch('/api/task/'+curTask+'/export',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({format:fmt})});const blob=await r.blob();const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='urls.'+fmt;a.click();});
  $('selAll').onchange=(e)=>document.querySelectorAll('.urlsel').forEach(c=>c.checked=e.target.checked);
  // pause / resume / stop the running task. Each just flips the server-side
  // control slot; the SSE 'paused'/'resumed'/'stopped' events (or refreshTask)
  // then update the buttons + status pill via updateScanCtrl().
  $('btnPauseScan').onclick=async()=>{await api('/api/task/'+curTask+'/pause',{method:'POST'});$('srvStatus').textContent=t('sd.pauseReq');};
  $('btnResumeScan').onclick=async()=>{await api('/api/task/'+curTask+'/resume',{method:'POST'});$('srvStatus').textContent=t('sd.resumed');};
  $('btnStopScan').onclick=async()=>{if(!confirm(t('sd.stopConfirm')))return;await api('/api/task/'+curTask+'/stop',{method:'POST'});$('srvStatus').textContent=t('sd.stopping');};
}
// show/hide the pause/resume/stop buttons in the scan-detail topbar based on the
// task status. running → pause+stop; paused → resume+stop; else → none.
function updateScanCtrl(t){
  const s=t&&t.status, p=$('btnPauseScan'), r=$('btnResumeScan'), s2=$('btnStopScan');
  if(!p||!r||!s2)return;
  p.style.display=(s==='running')?'':'none';
  r.style.display=(s==='paused')?'':'none';
  s2.style.display=(s==='running'||s==='paused')?'':'none';
}
// ---- live-refresh helpers (scan-detail) ----
// Update only the top stat bar + count badges from a task object. Pure local
// DOM patches (textContent / width) — never rebuilds a list, so it is always
// safe to call mid-scan without collapsing an expanded detail.
function updateStatBar(task){
  const p=task.progress||{}; const pages=task.pages||[];
  $('stStatus').innerHTML=task.status==='running'?'<span class="live"></span>'+t('st.running'):(task.status==='done'?t('st.done'):(task.status==='error'?t('st.error'):(task.status==='paused'?t('st.paused'):(task.status==='stopped'?t('st.stopped'):task.status))));
  $('stVulns').textContent=task.vulnCount;$('cVuln').textContent=task.vulnCount;vulTotal=task.vulnCount||0;
  $('cUrl').textContent=pages.length;$('cSite').textContent=pages.length;
  $('stCrawled').textContent=p.phase==='scanning'?(p.totalPages!=null?p.totalPages:pages.length):(p.crawled!=null?p.crawled:pages.length);
  $('stScan').textContent=p.phase==='scanning'?((p.done||0)+'/'+(p.total||0)):'0/0';
  $('stElapsed').textContent=((p.elapsedMs||0)/1000|0)+'s';
  $('gbar').style.width=progressPct(task.status,p)+'%';
  updateScanCtrl(task);
}
// true if the *visible* pane has an expanded detail (an open vuln card or a
// visible result detail row). Only visible panes count, so expanding a row on
// the Results tab does not freeze the Vulns tab.
function hasExpandedDetail(){
  const vp=$('paneVulns'); if(vp&&vp.style.display!=='none'&&(vp.querySelector('.vuln.open')||vp.querySelector('.vgrp.open'))) return true;
  const rp=$('paneResults'); if(rp&&rp.style.display!=='none'){
    for(const tr of rp.querySelectorAll('tr.rdet')){ if(tr.style.display!=='none') return true; }
  }
  return false;
}
// Throttled, expansion-aware, visible-pane-only list refresh. Live events
// (vuln / page-scanned / page) call this: coalesces to one render per 500ms,
// skips entirely while a detail is expanded (listDirty), and only patches the
// currently-visible pane — hidden panes get a dirty flag and are rendered when
// the user switches to them. Each renderer is itself an incremental patch, so
// even the visible pane is never fully rebuilt (异步局部刷新).
let paneDirty={sitemap:false,results:false,vulns:false,tech:false};
function visiblePane(){
  for(const k of ['sitemap','results','vulns','tech']){
    const el=$('pane'+k.charAt(0).toUpperCase()+k.slice(1));
    if(el&&el.style.display!=='none')return k;
  }
  return 'sitemap';
}
function renderPane(k){
  const t=taskCache[curTask]; if(!t)return;
  if(k==='sitemap')renderTree();
  else if(k==='results')renderResults(t.pages);
  else if(k==='vulns')renderVulns();
  else if(k==='tech')renderTech(true);
}
function safeRenderLists(){
  if(listRenderTimer) return;
  listRenderTimer=setTimeout(()=>{
    listRenderTimer=null;
    if(curSection!=='scans'||!curTask||!taskCache[curTask]) return;
    if(hasExpandedDetail()){ listDirty=true; return; }
    const v=visiblePane();
    // mark every pane dirty; then flush only the visible one now
    paneDirty.sitemap=paneDirty.results=paneDirty.vulns=paneDirty.tech=true;
    renderPane(v); paneDirty[v]=false;
    listDirty=false;
  },500);
}
// flush a pane if it's dirty (used by the tab-switch + onDetailToggled paths so
// a pane the user just navigated to catches up to live state).
function flushPane(k){ if(paneDirty[k]){ renderPane(k); paneDirty[k]=false; } }
// Called after a detail is toggled: if the user just collapsed the last open
// detail and lists were held back (listDirty), render them now.
function onDetailToggled(){
  if(listDirty&&!hasExpandedDetail()&&curTask&&taskCache[curTask]){
    listDirty=false;
    const v=visiblePane(); renderPane(v);
  }
}
// ---- SSE: live progress / vuln / page-scanned events (scan-detail only) ----
function openSSE(id){
  if(evtSrc)evtSrc.close();
  evtSrc=new EventSource('/api/task/'+id+'/events');
  evtSrc.onmessage=(e)=>{const ev=JSON.parse(e.data);handleEvent(ev);};
}
async function handleEvent(ev){
  if(curSection!=='scans')return; // ignore SSE if user navigated away
  if(ev.type==='progress'){
    const p=ev.progress;
    // skip the stat-bar update for a task already done: SSE replays the final
    // crawl progress (crawled/maxPages < 100) on reconnect, which would briefly
    // drop the bar below 100%. The 'done' event + refreshTask own the final state.
    const done=taskCache[curTask]&&taskCache[curTask].status==='done';
    if(!done){
      if(p.phase==='scanning'){$('stCrawled').textContent=p.totalPages||'-';$('stScan').textContent=(p.done||0)+'/'+(p.total||0);}
      else{$('stCrawled').textContent=p.crawled!=null?p.crawled:'-';$('stScan').textContent='0/0';}
      $('gbar').style.width=progressPct('running',p)+'%';
      $('stElapsed').textContent=((p.elapsedMs||0)/1000|0)+'s';
    }
    if(taskCache[curTask])taskCache[curTask].progress=p;
  } else if(ev.type==='vuln'){
    // local stat update only; list re-render is throttled + expansion-aware
    // (safeRenderLists) so an open vuln card is never collapsed by a new hit.
    $('stVulns').textContent=(+$('stVulns').textContent||0)+1;$('cVuln').textContent=(+$('cVuln').textContent||0)+1;
    vulTotal=(vulTotal||0)+1; // vulns are server-paginated now; just bump the count
    safeRenderLists();
  } else if(ev.type==='page'){
    // a newly discovered/known page (dir discovery etc.) arrives with its FULL
    // mapped object (same shape as GET /api/task). Upsert into the cached pages
    // (patch if the URL is known, append if new) so the URL/sitemap panes grow
    // live during the scan instead of staying frozen until 'done'.
    if(taskCache[curTask]&&ev.page){
      const t=taskCache[curTask];t.pages=t.pages||[];
      const i=t.pages.findIndex(p=>p.url===ev.page.url);
      if(i>=0)t.pages[i]=Object.assign(t.pages[i],ev.page);
      else t.pages.push(ev.page);
      $('cUrl').textContent=t.pages.length;$('cSite').textContent=t.pages.length;
    }
    safeRenderLists();
  } else if(ev.type==='page-scanned'){safeRenderLists();}
  else if(ev.type==='done'){$('stStatus').textContent=t('st.done');$('gbar').style.width='100%';refreshTask();$('srvStatus').textContent=t('sd.scanDone')+curTask+t('sd.scanDone2');}
  else if(ev.type==='stopped'){$('stStatus').textContent=t('st.stopped');$('srvStatus').textContent=t('sd.scanStopped')+curTask+t('sd.scanStopped2');if(taskCache[curTask])taskCache[curTask].status='stopped';updateScanCtrl(taskCache[curTask]);refreshTask();}
  else if(ev.type==='paused'){$('stStatus').textContent=t('st.paused');$('srvStatus').textContent=t('st.paused');if(taskCache[curTask])taskCache[curTask].status='paused';updateScanCtrl(taskCache[curTask]);}
  else if(ev.type==='resumed'){$('stStatus').innerHTML='<span class="live"></span>'+t('st.running');$('srvStatus').textContent=t('sd.resumed');if(taskCache[curTask])taskCache[curTask].status='running';updateScanCtrl(taskCache[curTask]);}
  else if(ev.type==='start'){$('stStatus').innerHTML='<span class="live"></span>'+t('st.running');}
  else if(ev.type==='log'){if(ev.level>=2)$('srvStatus').textContent=ev.msg;}
  else if(ev.type==='error'){$('stStatus').textContent=t('st.error');$('srvStatus').textContent=t('sd.errPrefix')+ev.message;}
}
async function refreshTask(){
  if(!curTask||curSection!=='scans')return;
  const t=await api('/api/task/'+curTask);taskCache[curTask]=t;
  updateStatBar(t);
  // only rebuild the lists when nothing is expanded; otherwise hold off
  // (listDirty) so opening a finished task or finishing a scan does not
  // collapse a detail the user is reading — it refreshes on collapse.
  if(hasExpandedDetail()){ listDirty=true; paneDirty.sitemap=paneDirty.results=paneDirty.vulns=paneDirty.tech=true; }
  else { renderResults(t.pages);renderTree();renderVulns();renderTech(); listDirty=false; paneDirty.sitemap=paneDirty.results=paneDirty.vulns=paneDirty.tech=false; }
}
function statusBadge(s){return '<span class="badge s'+(s>=500?5:s>=400?4:s>=300?3:s>=200?2:0)+'">'+(s||0)+'</span>'}
// method badge for the URL results table: colored by verb family (read/write/other)
function methodBadge(m){m=String(m||'').toUpperCase();if(!m)return '<span class="mbadge m-none">-</span>';const fam=(m==='GET'||m==='HEAD'||m==='OPTIONS')?'read':(m==='POST'||m==='PUT'||m==='PATCH'||m==='DELETE')?'write':'other';return '<span class="mbadge m-'+fam+'">'+esc(m)+'</span>';}
function hdrsBlock(h){if(!h)return '';if(Array.isArray(h))return h.map(p=>esc(p[0])+': '+esc(p[1])).join('\n');if(typeof h==='string')return esc(h);return Object.keys(h).map(k=>esc(k)+': '+esc(Array.isArray(h[k])?h[k].join(', '):h[k])).join('\n');}
// headers -> plain "Name: value" lines (no HTML escaping) for the new-scan modal textarea.
// Mirrors hdrsBlock's three shapes: null / array [[k,v]] / object {k: v | k:[v]}.
function headersToLines(h){if(!h)return '';if(Array.isArray(h))return h.map(p=>p[0]+': '+p[1]).join('\n');if(typeof h==='string')return h;return Object.keys(h).map(k=>k+': '+(Array.isArray(h[k])?h[k].join(', '):h[k])).join('\n');}
// pagination: build the pager control. kind='res'|'vul'; total=items; size=per-page;
// page=0-based current. Renders prev/next/first/last + page info + per-page selector.
// Buttons call resGo()/vulGo(); the per-page select calls resSize()/vulSize().
function pagerHtml(kind,total,size,page,unit,extra){
  unit=unit||t('c.unit'); extra=extra||'';
  const pages=Math.max(1,Math.ceil(total/size));
  const info=pages<=1?(t('c.total')+total+' '+unit+extra):(t('c.page')+' '+(page+1)+' / '+pages+' · '+t('c.total')+total+' '+unit+extra);
  if(pages<=1)return '<div class="pager"><span class="pg-info">'+info+'</span><span style="flex:1"></span>'+pgSizeSel(kind,size)+'</div>';
  const dis=(c)=>c?' disabled':'';
  // NOTE: the onclick arg is quoted with single quotes inside a double-quoted HTML
  // attribute. Because this JS lives inside the APP_HTML template literal, the
  // single quotes must come from double-quoted JS string fragments ("Go('first')")
  // — a literal ' would be unescaped to ' by the template literal and break the
  // outer single-quoted JS string at parse time.
  return '<div class="pager">'+
    '<button class="sec pg-btn" onclick="'+kind+"Go('first')"+'"'+dis(page<=0)+'>«</button>'+
    '<button class="sec pg-btn" onclick="'+kind+"Go('prev')"+'"'+dis(page<=0)+'>&#8249;</button>'+
    '<span class="pg-info">'+info+'</span>'+
    '<button class="sec pg-btn" onclick="'+kind+"Go('next')"+'"'+dis(page>=pages-1)+'>&#8250;</button>'+
    '<button class="sec pg-btn" onclick="'+kind+"Go('last')"+'"'+dis(page>=pages-1)+'>»</button>'+
    '<span style="flex:1"></span>'+pgSizeSel(kind,size)+'</div>';
}
function pgSizeSel(kind,size){return '<label class="pg-size-lbl">'+t('c.perPage')+' <select class="pg-size" onchange="'+kind+'Size(this.value)">'+[15,30,50,100,200].map(n=>'<option value="'+n+'"'+(n==size?' selected':'')+'>'+n+'</option>').join('')+'</select></label>';}
// clamp a page index to the valid range for the given total/size
function clampPage(page,total,size){return Math.max(0,Math.min(page,Math.max(0,Math.ceil(total/size)-1)));}
// results pager navigation
function resGo(act){const t=taskCache[curTask];const total=t&&t.pages?t.pages.length:0;const pages=Math.max(1,Math.ceil(total/resPageSize));
  if(act==='first')resPage=0;else if(act==='last')resPage=pages-1;else if(act==='next')resPage=Math.min(resPage+1,pages-1);else if(act==='prev')resPage=Math.max(resPage-1,0);
  renderResults(taskCache[curTask].pages);}
function resSize(v){resPageSize=+v||50;resPage=0;renderResults(taskCache[curTask].pages);}
// vulns pager navigation
function vulGo(act){const total=vulGroup?vulGroupTotal:vulTotal;const pages=Math.max(1,Math.ceil(total/vulPageSize));
  if(act==='first')vulPage=0;else if(act==='last')vulPage=pages-1;else if(act==='next')vulPage=Math.min(vulPage+1,pages-1);else if(act==='prev')vulPage=Math.max(vulPage-1,0);
  renderVulns();}
function vulSize(v){vulPageSize=+v||15;vulPage=0;renderVulns();}
function renderResults(pages){
  const tb=$('resultsTable').querySelector('tbody');
  const total=pages?pages.length:0;
  if(!total){tb.innerHTML='<tr><td colspan=6 class="empty">'+t('sd.noResults')+'</td></tr>';const pg=$('resPager');if(pg)pg.innerHTML='';return;}
  resPage=clampPage(resPage,total,resPageSize);
  const start=resPage*resPageSize;
  const slice=pages.slice(start,start+resPageSize);
  const wantUrls=slice.map(p=>p.url);
  // ---- incremental fast path ----
  // If the tbody already shows exactly the first K rows of the desired slice (same
  // urls, same order) we only PATCH the changed cells of those existing rows and
  // APPEND the new ones. This preserves scroll position, checkbox selection and
  // any expanded tr.rdet detail — the whole point of "局部刷新". Pagination nav /
  // deletions / first render fall through to the full-rebuild fallback below.
  const curRows=[...tb.querySelectorAll('tr.rrow')];
  const patchable=curRows.length && curRows.every((r,i)=>r.dataset.url===wantUrls[i]);
  if(patchable){
    const have=curRows.length;
    for(let i=0;i<have;i++) patchResultRow(curRows[i],slice[i]);
    for(let i=have;i<slice.length;i++) tb.insertAdjacentHTML('beforeend',resultRowHtml(slice[i]));
    updateResPager(total);
    return;
  }
  // ---- full-rebuild fallback (first render / page change / removals) ----
  tb.innerHTML=slice.map(resultRowHtml).join('');
  updateResPager(total);
}
// one URL-result row (rrow + paired hidden rdet), keyed by url so the
// incremental patch + click-to-expand stay stable as the list grows.
function resultRowHtml(p){
  const method=(p.http&&p.http.request&&p.http.request.method)||p.method||'';
  const rows='<tr class="rrow" data-url="'+esc(p.url)+'"><td onclick="event.stopPropagation()"><input type="checkbox" class="urlsel" data-url="'+esc(p.url)+'" style="width:auto"></td><td>'+statusBadge(p.status)+'</td><td class="mtd">'+methodBadge(method)+'</td><td class="url '+(p.isSoft404?'soft':'')+'">'+esc(p.url)+'<span class="tw">▾</span></td><td>'+esc((p.title||'').slice(0,30))+'</td><td>'+esc((p.source||'').slice(0,12))+'</td></tr>';
  const det='<tr class="rdet" data-url="'+esc(p.url)+'" style="display:none"><td colspan=6><div class="rd">'+
    '<div class="rd-actions"><button class="sec" data-rescan-url="'+esc(p.url)+'">'+t('sd.rescanFromUrl')+'</button></div>'+
    '<div class="rd-grid">'
    +rdCell(t('sd.rdMethod'),method||'-')
    +rdCell(t('sd.rdUrl'),p.url,true)
    +rdCell(t('sd.rdStatus'),(p.status||0)+(p.isSoft404?t('sd.soft404'):''))
    +rdCell(t('sd.rdType'),p.contentType||'')
    +rdCell(t('sd.rdTitle'),p.title||'')
    +rdCell(t('sd.rdDepth'),p.depth!=null?p.depth:'')
    +rdCell(t('sd.rdSource'),p.source||'')
    +'</div>'
    +((p.params&&p.params.length)?'<div class="rd-sec"><div class="rd-sec-h">'+t('sd.rdParams')+' ('+p.params.length+')</div><table class="rd-params"><thead><tr><th>'+t('sd.rdParamName')+'</th><th>'+t('sd.rdParamVal')+'</th></tr></thead><tbody>'+p.params.map(pp=>'<tr><td class="mono">'+esc(pp.name||pp)+'</td><td class="mono">'+esc(pp.value!=null?pp.value:'')+'</td></tr>').join('')+'</tbody></table></div>':'')
    +(p.http&&p.http.request?httpSec(p.http.request,true):'')
    +(p.http&&p.http.response?httpSec(p.http.response,false):'')
    +'</div></td></tr>';
  return rows+det;
}
// patch only the cells that can change on an already-rendered row (status/title/
// method/source/soft-404). Leaves the checkbox + any open detail untouched, so a
// live event never disturbs a row the user is reading or has checked.
function patchResultRow(row,p){
  const cells=row.children;
  // [0]=checkbox td, [1]=status, [2]=method, [3]=url, [4]=title, [5]=source
  const method=(p.http&&p.http.request&&p.http.request.method)||p.method||'';
  const newStatus=statusBadge(p.status);
  if(cells[1].innerHTML!==newStatus)cells[1].innerHTML=newStatus;
  const newMethod=methodBadge(method);
  if(cells[2].innerHTML!==newMethod)cells[2].innerHTML=newMethod;
  const urlCell=cells[3];
  const soft=p.isSoft404?'soft':'';
  if(urlCell.className!=='url '+(p.isSoft404?'soft':''))urlCell.className='url '+(p.isSoft404?'soft':'');
  const newTitle=esc((p.title||'').slice(0,30));
  if(cells[4].innerHTML!==newTitle)cells[4].innerHTML=newTitle;
  const newSrc=esc((p.source||'').slice(0,12));
  if(cells[5].innerHTML!==newSrc)cells[5].innerHTML=newSrc;
}
// rebuild the pager only when total/page-count changes — avoids clobbering the
// per-page <select> (and its focus) on every throttled tick while scanning.
let _resPagerKey='';
function updateResPager(total){
  const key=total+':'+resPageSize+':'+resPage;
  const pg=$('resPager');
  if(!pg)return;
  if(key===_resPagerKey)return;
  _resPagerKey=key;
  pg.innerHTML=pagerHtml('res',total,resPageSize,resPage);
}
function rdCell(k,val,mono){return '<div class="rd-cell"><span class="rd-k">'+esc(k)+'</span><span class="rd-v'+(mono?' mono':'')+'">'+esc(val==null?'':val)+'</span></div>';}
// shared HTTP request/response section (used by URL-result detail + vuln detail)
function httpSec(msg,isReq){
  if(!msg)return '';
  const line=isReq?esc((msg.method||'GET')+' '+(msg.uri||'/')+' '+(msg.version||'HTTP/1.1')):esc((msg.status||0)+' '+(msg.reason||''));
  const badge=isReq?esc(msg.method||'GET'):esc(msg.status||0);
  const bCls=isReq?'vd-req-badge':'vd-res-badge';
  const blockCls=isReq?'vd-req':'vd-res';
  const label=isReq?t('sd.req'):t('sd.res');
  const body=hdrsBlock(msg.headers)+(msg.body?'\n\n'+esc(msg.body):'');
  return '<div class="vd-sec"><div class="vd-sec-h"><span class="vd-badge '+bCls+'">'+badge+'</span>'+label+'</div><pre class="vd-http '+blockCls+'">'+line+'\n'+body+'</pre></div>';
}
function renderTree(){
  const el=$('paneSitemap');
  if(!taskCache[curTask]||!taskCache[curTask].pages||!taskCache[curTask].pages.length){el.innerHTML=empty(t('sd.noSitemap'));return;}
  const tree=buildSiteTree(taskCache[curTask].pages,taskCache[curTask].target);
  // incremental patch: if a tree is already shown, reconcile it in place so a
  // user's open/close toggles (and any expanded detail) survive live refreshes.
  // First render (or after an empty-state) falls back to a full build.
  const root=el.querySelector(':scope > .tree > details');
  if(root && root.getAttribute('data-path')===tree.path){
    patchTreeDir(root,tree);
  } else {
    el.innerHTML='<div class="tree">'+treeDirHtml(tree)+'</div>';
  }
}
function ti(t){return {dir:ic('folder'),page:ic('file'),api:ic('plug'),resource:ic('image'),xml:ic('file-code'),error:ic('triangle-alert')}[t]||ic('file')}
// ---- client-side site-map tree (mirrors runtime/sitemap.js buildSiteMap) ----
// Built from the cached pages so the tree refreshes WITHOUT a /sitemap fetch on
// every tick. classify() is the same heuristic as the server.
function classifyTree(page){
  const ct=(page.contentType||'').toLowerCase(),url=page.url||'';
  let path='';try{path=new URL(url).pathname;}catch(e){}
  if(/\/api\/|\/v\d+\//.test(path))return 'api';
  if(page.status===0)return 'error';
  if(/\/$/.test(path)||path==='')return 'dir';
  if(/json/i.test(ct))return 'api';
  if(/xml/i.test(ct))return 'xml';
  if(/html/i.test(ct))return 'page';
  if(/\.(js|css)$/i.test(path))return 'resource';
  if(/\.(png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot|mp4)$/i.test(path))return 'resource';
  return 'page';
}
function buildSiteTree(pages,target){
  const rootName=(target&&typeof target==='string'&&target.length)?target:'/';
  const root={name:rootName,path:'/',type:'dir',count:0,children:[],pages:[]};
  const dirIndex=new Map();dirIndex.set('/',root);
  function dirNode(dirPath){
    if(dirIndex.has(dirPath))return dirIndex.get(dirPath);
    const segs=dirPath.replace(/^\/|\/$/g,'').split('/').filter(Boolean);
    let cur=root,acc='';
    for(const s of segs){acc+='/'+s;const cp=acc+'/';let ch=dirIndex.get(cp);
      if(!ch){ch={name:s,path:cp,type:'dir',count:0,children:[],pages:[]};cur.children.push(ch);dirIndex.set(cp,ch);}cur=ch;}
    return cur;
  }
  for(const page of pages){
    if(!page||!page.url)continue;
    let dirPath,name;try{const u=new URL(page.url);const pth=u.pathname;const i=pth.lastIndexOf('/');
      dirPath=i<=0?'/':pth.slice(0,i+1);name=pth.slice(i+1)||'/';}catch(e){continue;}
    const node=dirNode(dirPath);
    const q=page.url.indexOf('?')>-1?page.url.slice(page.url.indexOf('?')):'';
    node.pages.push({name:name+q,url:page.url,type:classifyTree(page),status:page.status||0,
      title:page.title||'',contentType:page.contentType||'',isSoft404:!!page.isSoft404,depth:page.depth||0});
  }
  (function sort(n){n.children.sort((a,b)=>a.name.localeCompare(b.name));n.pages.sort((a,b)=>a.name.localeCompare(b.name));n.children.forEach(sort);})(root);
  (function rec(n){let t=n.pages.length;for(const c of n.children)t+=rec(c);n.count=t;return t;})(root);
  return root;
}
// full-build HTML for a dir node (used on first render). <details> carries
// data-path so the patcher can locate it; leaves carry data-url.
function treeDirHtml(n){
  const s=(n.children||[]).map(treeDirHtml).join('');
  const l=(n.pages||[]).map(treeLeafHtml).join('');
  return '<details open data-path="'+esc(n.path)+'"><summary>'+ti('dir')+' '+esc(n.name)+' <span class="st">'+n.count+'</span></summary><div style="margin-left:7px">'+s+l+'</div></details>';
}
function treeLeafHtml(p){
  return '<div class="leaf" data-url="'+esc(p.url)+'"><span>'+ti(p.type)+'</span><span class="'+(p.isSoft404?'soft':'')+'">'+esc(p.name)+'</span><span class="st s'+Math.floor(p.status/100)+'">'+p.status+'</span></div>';
}
// reconcile an existing <details> (data-path) against a new dir node IN PLACE.
// Preserves the user's open/close state (we never touch the open attribute),
// only inserts new subdirs/leaves, removes gone ones, patches counts + leaf
// status. This is the "局部刷新" of the sitemap.
function patchTreeDir(det,node){
  const content=det.querySelector(':scope > div'); if(!content)return;
  // ---- subdirs: key existing <details> by data-path ----
  const dirNodes=[...content.querySelectorAll(':scope > details')];
  const dirByPath=new Map(dirNodes.map(d=>[d.getAttribute('data-path'),d]));
  const wantPaths=new Set(node.children.map(c=>c.path));
  for(const d of dirNodes){ if(!wantPaths.has(d.getAttribute('data-path'))) d.remove(); }
  // Recurse into existing dirs (patch counts/leaves); create new ones. Then
  // re-append in the new sorted order so newly inserted nodes land correctly —
  // re-appending an existing node does NOT reset its open state, so toggles
  // the user made survive.
  for(const child of node.children){
    let d=dirByPath.get(child.path);
    if(!d){ d=htmlToEl(treeDirHtml(child)); dirByPath.set(child.path,d); }
    else { patchTreeDir(d,child); setDirCount(d,child.count); }
    content.appendChild(d);
  }
  // ---- leaves: key existing .leaf by data-url ----
  const leafNodes=[...content.querySelectorAll(':scope > .leaf')];
  const leafByUrl=new Map(leafNodes.map(l=>[l.getAttribute('data-url'),l]));
  const wantUrls=new Set(node.pages.map(p=>p.url));
  for(const l of leafNodes){ if(!wantUrls.has(l.getAttribute('data-url'))) l.remove(); }
  for(const p of node.pages){
    let l=leafByUrl.get(p.url);
    if(!l){ l=htmlToEl(treeLeafHtml(p)); leafByUrl.set(p.url,l); }
    else { patchTreeLeaf(l,p); }
    content.appendChild(l);
  }
  setDirCount(det,node.count);
}
// helpers for the tree patcher
function setDirCount(det,count){const st=det.querySelector(':scope > summary > .st');if(st)st.textContent=count;}
function patchTreeLeaf(l,p){
  const cls=p.isSoft404?'soft':'';
  if(l.firstElementChild&&l.firstElementChild.tagName==='SPAN'){} // icon span — keep
  const spans=l.querySelectorAll(':scope > span');
  if(spans[1]){ if(spans[1].className!==cls)spans[1].className=cls; if(spans[1].textContent!==p.name)spans[1].textContent=p.name; }
  if(spans[2]){ const c='st s'+Math.floor(p.status/100); if(spans[2].className!==c)spans[2].className=c; if(spans[2].textContent!=p.status)spans[2].textContent=p.status; }
}
// parse an HTML string into a single element node (for inserting built subtrees)
function htmlToEl(html){const t=document.createElement('div');t.innerHTML=html.trim();return t.firstElementChild;}
// the full URL of the vulnerable page. v.target is the page URL the plugin ran
// against (always set by the worker); v.affects may be a path or full URL. Prefer
// target (the clickable, complete URL); fall back to affects.
function vulnUrl(v){ return v.target || v.affects || ''; }
// card title: prefer the human vuln name from the DB (v.name); show the raw
// typeId as a muted suffix so the technical identifier stays visible.
function vulnTitle(v){
  const tid=v.typeId||'?';
  if(v.name && v.name!==tid) return esc(v.name)+' <span class="muted tiny" style="font-family:ui-monospace,Menlo,Consolas,monospace">'+esc(tid)+'</span>';
  return esc(tid);
}
// summary row shown on every vuln card: a labelled, clickable link to the vuln URL.
function vulnUrlRow(v){
  const u=vulnUrl(v); if(!u)return '';
  return '<div class="vurl"><span class="vurl-k">URL</span><a class="vurl-v" href="'+esc(u)+'" target="_blank" rel="noopener" onclick="event.stopPropagation()">'+esc(u)+'</a></div>';
}
function vulnDetail(v){
  const req=v.request, res=v.response;
  let cells='';
  cells+=vdCell(t('vd.type'),v.typeId||'?',true);
  if(v.name&&v.name!==v.typeId)cells+=vdCell(t('vd.name'),v.name);
  if(v.severity)cells+=vdCell(t('vd.severity'),v.severity);
  const cvss=v.cvss3||v.cvss2||v.cvss4||'';
  if(cvss)cells+=vdCell('CVSS',cvss,true);
  if(v.ssl)cells+=vdCell(t('vd.ssl'),t('c.yes'));
  cells+=vdCell(t('vd.plugin'),v.plugin||'',true);
  if(vulnUrl(v))cells+=vdCell(t('vd.url'),vulnUrl(v),true);
  cells+=vdCell(t('vd.affects'),v.affects||'');
  if(v.parameter)cells+=vdCell(t('vd.param'),v.parameter,true);
  if(v.attackVector)cells+=vdCell(t('vd.payload'),v.attackVector,true);
  let s='<div class="vd"><div class="vd-grid">'+cells+'</div>';
  if(v.tags&&v.tags.length)s+='<div class="vd-tags">'+v.tags.map(t=>'<span class="vd-tag">'+esc(t)+'</span>').join('')+'</div>';
  if(v.description)s+='<div class="vd-sec"><div class="vd-sec-h">'+t('vd.desc')+'</div><div class="vd-desc">'+escBr(v.description)+'</div></div>';
  if(v.impact)s+='<div class="vd-sec"><div class="vd-sec-h">'+t('vd.impact')+'</div><div class="vd-desc">'+escBr(v.impact)+'</div></div>';
  if(v.recommendation)s+='<div class="vd-sec"><div class="vd-sec-h">'+t('vd.fix')+'</div><div class="vd-desc">'+escBr(v.recommendation)+'</div></div>';
  if(v.details)s+='<div class="vd-sec"><div class="vd-sec-h">'+t('vd.details')+'</div><pre class="vd-pre">'+esc(typeof v.details==='string'?v.details:JSON.stringify(v.details,null,2))+'</pre></div>';
  const dt=renderDetailsTemplate(v);
  if(dt)s+='<div class="vd-sec"><div class="vd-sec-h">'+t('vd.detailsTpl')+'</div><div class="vd-tpl">'+dt+'</div></div>';
  if(v.references&&v.references.length){
    s+='<div class="vd-sec"><div class="vd-sec-h">'+t('vd.refs')+'</div><ul class="vd-refs">'+
      v.references.map(r=>{const url=(r&&r.url)||(typeof r==='string'?r:'');const title=(r&&r.title)||'';return url?'<li><a href="'+esc(url)+'" target="_blank" rel="noopener" onclick="event.stopPropagation()">'+esc(title||url)+'</a></li>':'';}).join('')+
      '</ul></div>';
  }
  s+=httpSec(req,true);
  s+=httpSec(res,false);
  if(v.foundAt)s+='<div class="vd-foot">'+t('vd.foundAt')+esc(v.foundAt)+'</div>';
  s+='</div>';return s;
}
// ---- Mustache renderer (zero-dep) for vuln details_template ----------------
// AWVS details_template is a Mustache template that produces HTML from
// scan-result fields, e.g. the XSS template:
//   {{#repro}}<div class="bb-coolbox"><span class="bb-dark">{{.}}</span></div><br/>{{/repro}}
//   {{#uri}}URI was set to <strong>{{uri}}</strong>{{/uri}}
//   {{#input_type}}{{input_type}} input <strong>{{input_name}}</strong> ... {{/input_type}}
// Supported: {{var}} (HTML-escaped), {{{var}}} (raw), {{.}} (current item),
// {{#name}}...{{/name}} (truthy scalar -> render once with value as scope;
// array -> iterate; falsy/empty -> skip), {{^name}}...{{/name}} (inverted),
// {{!comment}}. Variable output is HTML-escaped via esc() so a payload value
// like <script>alert(1)</script> can NEVER inject markup — only the template's
// own literal HTML (the <div>/<strong> it ships with) is passed through.
function mustacheParse(tpl){
  const nodes=[]; const stack=[{children:nodes}];
  const re=/\{\{([\s\S]*?)\}\}/g; let last=0,m;
  while((m=re.exec(tpl))!==null){
    if(m.index>last) stack[stack.length-1].children.push({t:'text',v:tpl.slice(last,m.index)});
    const tag=m[1].trim(); const c=tag[0];
    if(c==='#'||c==='^'){ const n={t:'section',name:tag.slice(1).trim(),invert:c==='^',children:[]}; stack[stack.length-1].children.push(n); stack.push(n); }
    else if(c==='/'){ const n=stack.pop(); n.name=tag.slice(1).trim(); /* sanity */ }
    else if(c==='!'){ /* comment, drop */ }
    else if(tag==='.'){ stack[stack.length-1].children.push({t:'dot'}); }
    else { const raw=tag[0]==='{'&&tag[tag.length-1]==='}'; stack[stack.length-1].children.push({t:'var',name:raw?tag.slice(1,-1).trim():tag,raw}); }
    last=re.lastIndex;
  }
  if(last<tpl.length) stack[stack.length-1].children.push({t:'text',v:tpl.slice(last)});
  return nodes;
}
function _muLookup(scopes,name){
  for(let i=scopes.length-1;i>=0;i--){
    const s=scopes[i];
    if(s==null) continue;
    if(name==='.') return s;
    if(typeof s==='object'&&!(s instanceof Array)&&Object.prototype.hasOwnProperty.call(s,name)) return s[name];
  }
  return undefined;
}
function _muTruthy(v){ return v!==null&&v!==undefined&&v!==false&&v!==''&&!(Array.isArray(v)&&v.length===0); }
function mustacheRender(nodes,scopes){
  let out='';
  for(const n of nodes){
    if(n.t==='text') out+=n.v;
    else if(n.t==='var'){ const v=_muLookup(scopes,n.name); if(v!=null) out+= n.raw?String(v):esc(String(v)); }
    else if(n.t==='dot'){ const v=_muLookup(scopes,'.'); if(v!=null) out+=esc(String(v)); }
    else if(n.t==='section'){
      const v=_muLookup(scopes,n.name);
      if(n.invert){ if(!_muTruthy(v)) out+=mustacheRender(n.children,scopes); }
      else if(Array.isArray(v)){ for(const it of v){ if(_muTruthy(it)) out+=mustacheRender(n.children,scopes.concat([it])); } }
      else if(_muTruthy(v)){ out+=mustacheRender(n.children,scopes.concat([v])); }
    }
  }
  return out;
}
// Build the details_template render context from a vuln record. Maps AWVS
// template variables onto the fields our scan records actually carry. Fields
// we don't have (reflection_point/extra_details/test_result/test_calculation)
// are simply omitted — their {{#section}} blocks then render empty (Mustache
// falsy-skip), which is the correct degraded behaviour.
function detailsTemplateCtx(v){
  const req=v.request||{};
  const method=(req.method||'GET').toUpperCase();
  // input_type: best-effort. POST with a body -> "Body parameter", else "Query parameter".
  let inputType='';
  if(v.parameter){ inputType = (method==='POST'&&req.body) ? 'Body parameter' : 'Query parameter'; }
  const ctx={};
  if(v.target||v.affects) ctx.uri=v.target||v.affects;
  // {{url}} — the vulnerable/affected URL. Many DB templates iterate the `details`
  // array for this (handled by the structured path in renderDetailsTemplate), but
  // plugins like Spring_Boot_Actuator_v2 use {{#.}}<li>{{url}}</li>{{/.}} WITHOUT
  // setting a details array (they only set `affects`). When details is absent the
  // root scope becomes this ctx object, so {{url}} must resolve to the affected
  // URL or the list item renders empty. Prefer `affects` (the exact vuln location)
  // over `target` (the site root).
  if(v.affects) ctx.url=v.affects; else if(v.target) ctx.url=v.target;
  if(v.parameter) ctx.input_name=v.parameter;
  if(v.attackVector) ctx.test_value=v.attackVector;
  if(inputType) ctx.input_type=inputType;
  if(v.target||v.affects) ctx.test_url=v.target||v.affects;
  if(v.details!=null && v.details!=='') ctx.repro=v.details;
  // {{match}} — the matched text. Many DB templates pair {{url}} with
  // {{match}} (e.g. email_address_found.xml: <li>{{url}} <strong>{{match}}</strong></li>),
  // but plugins store the matched text under `matched_text` (NOT `match`) inside
  // `details`. Reconstruct `match` from `details.matched_text` so those templates
  // render the match alongside the URL instead of an empty <strong></strong>.
  // Only set when the record doesn't already carry a real `match` (array-`details`
  // plugins put `match` on each item; those reach the template via the structured
  // path, not this ctx, so this never clobbers a plugin-supplied value).
  const d=v.details;
  if(d&&typeof d==='object'&&!Array.isArray(d)&&d.match==null&&d.matched_text!=null&&d.matched_text!==false){
    ctx.match=d.matched_text;
  }
  return ctx;
}
function renderDetailsTemplate(v){
  if(!v||!v.details_template) return '';
  try {
    const nodes=mustacheParse(v.details_template);
    // AWVS renders details_template with the vuln's `details` field AS the root
    // context. Three shapes occur in practice:
    //  (a) a structured array the template iterates directly — e.g.
    //      cookie_misconfiguration.xml stores
    //      [{url,headerSetCookie,nicelyFormattedOutput}] and uses {{#.}} to
    //      iterate; directory_listing/csp_not_implemented/hsts_not_implemented
    //      and ~70 other DB templates use the same {{#.}} root-iteration form.
    //      For these, `details` must be the root scope so {{#.}} iterates and
    //      the per-item fields ({{url}} etc.) resolve.
    //  (b) a plain string or absent details (e.g. XSS stores raw repro text) —
    //      the template uses named vars ({{#repro}}, {{#uri}}, {{#input_type}})
    //      reconstructed by detailsTemplateCtx from the other record fields.
    //  (c) a plain OBJECT details (the most common plugin shape: ~129 plugins
    //      set details:{matched_text:...}). Templates like
    //      trojan_shell_scripts.xml / email_address_found.xml still use
    //      {{#.}}<li>{{url}} ... {{match}}</li>{{/.}} to iterate the root, but
    //      `details` is a single object — so {{#.}} renders once and the
    //      per-item {{url}}/{{match}} would resolve against the details object,
    //      which lacks them, yielding empty <li></li>. Merge the reconstructed
    //      ctx (url from affects, match from matched_text) onto the details
    //      object so those fields resolve. Details-supplied keys win over ctx
    //      (Object.assign target-order) so a plugin that DID set `url`/`match`
    //      directly is never clobbered.
    const d=v.details;
    const ctx=detailsTemplateCtx(v);
    let scopes;
    if(Array.isArray(d)) scopes=[d];
    else if(d && typeof d==='object') scopes=[Object.assign({}, ctx, d)];
    else scopes=[ctx];
    return mustacheRender(nodes, scopes).trim();
  }
  catch(e){ return ''; }
}
// escape for HTML + collapse \n / <br/> into line breaks (DB descriptions carry
// <br/> tags from AWVS). Keep <br/> as a real break, escape everything else.
function escBr(str){
  return esc(str).replace(/&lt;br\/?&gt;/gi,'<br>').replace(/\n/g,'<br>');
}
function vdCell(k,val,mono){return '<div class="vd-cell"><span class="vd-k">'+esc(k)+'</span><span class="vd-v'+(mono?' mono':'')+'">'+esc(val==null?'':val)+'</span></div>';}
// 单条漏洞卡片 markup(扫描详情页:无「来源」行)。平铺与聚合组内共用。
// AI 渗透漏洞来源徽章(scanner / ai-tool / ai-manual);扫描详情漏洞无 provenance → 空串。
function provenanceBadge(p){
  if(!p)return '';
  const map={scanner:[t('vd.provScanner'),'s2'], 'ai-tool':[t('vd.provAiTool'),'st-running'], 'ai-manual':[t('vd.provAiManual'),'st-done']};
  const m=map[p]||map['scanner'];
  return ' <span class="badge '+m[1]+'" style="margin-left:4px">'+m[0]+'</span>';
}
function detVulnCard(v){
  return '<div class="vuln '+sevClass(v.severity)+'"><div class="t">'+sevBadge(v.severity)+' '+vulnTitle(v)+provenanceBadge(v.provenance)+'<span class="tw">'+t('vul.detail')+'</span></div>'+
    vulnUrlRow(v)+
    '<div class="p">'+esc(v.plugin||'')+(v.affects?' · '+esc(v.affects):'')+(v.parameter?' · '+t('misc.paramPrefix')+esc(v.parameter):'')+(v.attackVector?' · '+esc(String(v.attackVector).slice(0,40)):'')+'</div><div class="exp">'+vulnDetail(v)+'</div></div>';
}
// render the scan-detail vulns pane. SERVER-SIDE paginated: fetches one page
// from /api/task/:id/vulns each call (the browser holds only vulTotal + this
// page, never the whole vuln set). Race-safe: a generation token discards a
// fetch superseded by a newer render; after the await we re-check
// hasExpandedDetail() so a card the user opened mid-fetch isn't wiped. We only
// blank to a loading state when the TASK changes (vulLastTask) — same-task
// page nav / live refetch keeps the old content until the new page arrives,
// so there's no flicker during a scan's 500ms-coalesced re-renders.
function renderVulns(){
  const el=$('paneVulns');if(!el)return;
  const task=taskCache[curTask];
  if(!task||!vulTotal){el.innerHTML=empty(t('vul.empty'));vulLastTask=curTask;return;}
  const gbtn='<button class="sec" onclick="vulGroup=!vulGroup;vulPage=0;renderVulns()"'+(vulGroup?' style="background:var(--acc);color:#fff"':'')+'>'+(vulGroup?t('vul.groupOn'):t('vul.groupOff'))+'</button>';
  // task switched: show a loading placeholder immediately so the previous task's
  // vulns never flash; same task: keep current content until the fetch resolves.
  if(vulLastTask!==curTask){el.innerHTML='<div class="toolbar">'+gbtn+'</div>'+empty(t('c.loading'));}
  const gen=++vulFetchGen;
  const qs='page='+vulPage+'&pageSize='+vulPageSize+(vulGroup?'&group=1':'');
  api('/api/task/'+curTask+'/vulns?'+qs).then(data=>{
    if(gen!==vulFetchGen)return;                 // a newer render started — drop stale
    if(hasExpandedDetail()){paneDirty.vulns=true;return;} // card opened mid-fetch — don't wipe
    const items=Array.isArray(data.items)?data.items:[];
    vulTotal=data.vulnTotal||data.total||0;
    if(vulGroup) vulGroupTotal=data.total||0;
    vulPage=clampPage(data.page||0,vulGroup?vulGroupTotal:vulTotal,vulPageSize);
    if(vulGroup){
      el.innerHTML='<div class="toolbar">'+gbtn+'</div>'+
        (items.length?items.map(g=>{
          return '<div class="vgrp '+sevClass(g.sev)+'" data-tid="'+esc(g.typeId)+'"><div class="vgrp-h">'+
            sevBadge(g.sev)+' '+vulnTitle({typeId:g.typeId,name:g.name})+'<span class="vgrp-cnt">×'+(g.total||0)+'</span>'+
            '<span class="muted tiny"> · '+(g.urlCount||0)+t('vul.urls')+'</span><span class="tw">'+t('vul.expand')+'</span></div>'+
            '<div class="vgrp-b" data-loaded="0"></div></div>';
        }).join('')+pagerHtml('vul',vulGroupTotal,vulPageSize,vulPage,t('vul.unitType'),' · '+vulTotal+t('vul.extraVulns')):empty(t('vul.empty')));
    }else{
      el.innerHTML='<div class="toolbar">'+gbtn+'</div>'+
        items.map(v=>detVulnCard(v)).join('')+pagerHtml('vul',vulTotal,vulPageSize,vulPage);
    }
    vulLastTask=curTask;
  }).catch(()=>{ if(gen!==vulFetchGen)return; el.innerHTML='<div class="toolbar">'+gbtn+'</div>'+empty(t('ai.vulnsLoadFail')); });
}
// 组内实例懒加载分页大小(独立于 vulPageSize —— 后者在 grouped 下是「每页多少组」)。
const DET_GROUP_PS=20;
// 首次展开组:拉取该 typeId 在本任务的第一页实例(平铺)并渲染;后续展开不重复拉取。
// 与聚合全局页的 aggGroup* 同构,但走 /api/task/:id/vulns?typeId= 并用 detVulnCard。
async function detGroupExpand(grp){
  const body=grp.querySelector('.vgrp-b');
  if(!body || (body.dataset.loaded && body.dataset.loaded!=='0')) return;
  const typeId=grp.dataset.tid;
  body.innerHTML='<div class="muted tiny" style="padding:6px 2px">'+t('c.loading')+'</div>';
  const data=await api('/api/task/'+curTask+'/vulns?'+detGroupQs(typeId,0));
  const items=Array.isArray(data.items)?data.items:[];
  const total=data.total||items.length;
  body.dataset.loaded=String(items.length);
  body.dataset.page='0';
  body.dataset.total=String(total);
  body.innerHTML=items.map(v=>detVulnCard(v)).join('')+detGroupMoreHtml(total,items.length);
  // 绑组内卡片展开详情(委托处理器只绑在 paneVulns 上,动态插入的卡片需单独绑)。
  body.querySelectorAll('.vuln').forEach(c=>{
    c.onclick=(e)=>{e.stopPropagation();if(e.target.matches('a,input,button'))return;if(window.getSelection().toString())return;const on=c.classList.toggle('open');const tw=c.querySelector('.tw');if(tw)tw.textContent=on?t('vul.collapse'):t('vul.detail');onDetailToggled();};
  });
}
// 「加载更多」:拉下一页实例并追加到组体。
async function detGroupMore(btn){
  const grp=btn.closest('.vgrp');
  const body=grp.querySelector('.vgrp-b');
  const typeId=grp.dataset.tid;
  const page=(+body.dataset.page||0)+1;
  const total=+body.dataset.total||0;
  const loaded=+body.dataset.loaded||0;
  btn.disabled=true; btn.textContent=t('c.loading');
  const data=await api('/api/task/'+curTask+'/vulns?'+detGroupQs(typeId,page));
  const items=Array.isArray(data.items)?data.items:[];
  const more=body.querySelector('.vgrp-more'); if(more) more.remove();
  body.insertAdjacentHTML('beforeend', items.map(v=>detVulnCard(v)).join('')+detGroupMoreHtml(total,loaded+items.length));
  body.dataset.page=String(page);
  body.dataset.loaded=String(loaded+items.length);
  body.querySelectorAll('.vuln').forEach(c=>{ if(!c.onclick) c.onclick=(e)=>{e.stopPropagation();if(e.target.matches('a,input,button'))return;if(window.getSelection().toString())return;const on=c.classList.toggle('open');const tw=c.querySelector('.tw');if(tw)tw.textContent=on?t('vul.collapse'):t('vul.detail');onDetailToggled();}; });
}
// 组内实例请求 query:平铺模式按 typeId 过滤,分页大小=DET_GROUP_PS。
function detGroupQs(typeId,page){
  return 'typeId='+encodeURIComponent(typeId)+'&page='+page+'&pageSize='+DET_GROUP_PS;
}
// 「加载更多」按钮 / 全部已显示提示。
function detGroupMoreHtml(total,loaded){
  if(loaded>=total) return '<div class="muted tiny vgrp-more" style="padding:6px 2px">'+t('vul.allShown')+total+t('c.unit')+'</div>';
  return '<button class="sec vgrp-more" style="margin:6px 0" onclick="detGroupMore(this)">'+t('vul.loadMore')+loaded+'/'+total+')</button>';
}

// scan-detail 技术识别 pane: 从 /api/technologies?taskId= 拉本任务的 wappalyzer
// 指纹聚合结果。与 vulns/pages 不同,技术数据不在 taskCache 里(后端按需聚合),
// 所以 renderTech 是 async + 带内存缓存(_techCache)避免每次刷新都打 API。扫描
// 进行中时,新技术会随页面增加而出现,safeRenderLists 周期性调 renderTech(true)
// 强制刷新缓存。
let _techCache={id:null,data:null,ts:0};
async function renderTech(force){
  const el=$('paneTech');if(!el)return;
  if(!curTask)return;
  // 缓存 5s 内不重复请求,除非 force
  const now=Date.now();
  if(!force&&_techCache.id===curTask&&_techCache.data&&now-_techCache.ts<5000){
    drawTech(_techCache.data);return;
  }
  try{
    const data=await api('/api/technologies?taskId='+curTask);
    _techCache={id:curTask,data,ts:now};
    drawTech(data);
  }catch(e){el.innerHTML=empty(t('tech.loadFail'));}
}
function drawTech(data){
  const el=$('paneTech');
  const techs=(data&&data.technologies)||[];
  $('cTech').textContent=techs.length;
  if(!techs.length){el.innerHTML=empty(t('tech.emptyDetail'));return;}
  el.innerHTML='<div class="muted tiny" style="margin:4px 0 8px">'+t('tech.stat')+techs.length+t('tech.stat2')+data.count+t('tech.stat3')+t('tech.descSource')+'</div>'+
    '<table><thead><tr><th>'+t('tech.thTech')+'</th><th>'+t('tech.thVer')+'</th><th>'+t('tech.thConf')+'</th><th>'+t('tech.thCat')+'</th><th>'+t('tech.thHits')+'</th><th>'+t('tech.thSample')+'</th></tr></thead><tbody>'+
    techs.map(t=>'<tr><td><b>'+esc(t.name)+'</b></td><td>'+(t.version?'<code>'+esc(t.version)+'</code>':'<span class="muted">-</span>')+'</td>'+
    '<td>'+t.confidence+'%</td><td class="tiny">'+esc((t.categories||[]).map(c=>c.name).join(', '))+'</td>'+
    '<td>'+t.hits+'</td><td class="tiny url">'+esc((t.sampleUrls||[]).join(' '))+'</td></tr>').join('')+
    '</tbody></table>';
}


async function renderReports(){
  $('view').innerHTML=pageHead(t('rp.title'),t('rp.desc'),'')+'<div class="card"><h3>'+t('rp.byScan')+'</h3><table><thead><tr><th>'+t('rp.thId')+'</th><th>'+t('rp.thTarget')+'</th><th>'+t('rp.thVulns')+'</th><th>'+t('rp.thReport')+'</th><th>'+t('rp.thUrlList')+'</th></tr></thead><tbody id="rpBody"></tbody></table><div id="rpPager"></div></div><div class="card"><h3>'+t('rp.agg')+'</h3><p class="muted tiny">'+t('rp.aggDesc')+'</p><button class="btn" id="rpAllHtml">'+t('rp.dlHtml')+'</button> <button class="sec" id="rpAllJson">'+t('rp.dlJson')+'</button></div>';
  const ts=await api('/api/tasks'); _rpTasks=ts;
  renderReportsSlice();
  $('rpAllHtml').onclick=()=>dl('/api/report?scope=all&format=html','report-all.html');
  $('rpAllJson').onclick=()=>dl('/api/report?scope=all&format=json','report-all.json');
}
// render the current rpPage slice of _rpTasks into the per-scan report table + pager.
function renderReportsSlice(){
  const ts=_rpTasks, total=ts.length;
  rpPage=clampPage(rpPage,total,rpPageSize);
  const start=rpPage*rpPageSize;
  const slice=ts.slice(start,start+rpPageSize);
  $('rpBody').innerHTML=slice.length?slice.map(t=>'<tr><td>#'+t.id+'</td><td class="url">'+esc(t.target||'')+'</td><td style="color:var(--err);font-weight:700">'+t.vulns+'</td><td><a class="btn sec tiny" data-rp="html" data-id="'+t.id+'">HTML</a> <a class="btn sec tiny" data-rp="json" data-id="'+t.id+'">JSON</a></td><td><button class="sec tiny" data-exp="txt" data-id="'+t.id+'">TXT</button> <button class="sec tiny" data-exp="json" data-id="'+t.id+'">JSON</button> <button class="sec tiny" data-exp="xml" data-id="'+t.id+'">XML</button></td></tr>').join(''):empty(t('rp.empty'));
  const rpPager=$('rpPager'); if(rpPager) rpPager.innerHTML= total?pagerHtml('rp',total,rpPageSize,rpPage):'';
  $('rpBody').querySelectorAll('[data-rp]').forEach(b=>b.onclick=()=>dl('/api/report?taskId='+b.dataset.id+'&format='+b.dataset.rp,'report.'+b.dataset.rp));
  $('rpBody').querySelectorAll('[data-exp]').forEach(b=>b.onclick=()=>fetch('/api/task/'+b.dataset.id+'/export',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({format:b.dataset.exp})}).then(r=>r.blob()).then(blob=>{const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='urls.'+b.dataset.exp;a.click();}));
}
// report-list pager navigation (mirrors scGo; re-slices cached _rpTasks, no re-fetch)
function rpGo(act){const total=_rpTasks.length,pages=Math.max(1,Math.ceil(total/rpPageSize));
  if(act==='first')rpPage=0;else if(act==='last')rpPage=pages-1;else if(act==='next')rpPage=Math.min(rpPage+1,pages-1);else if(act==='prev')rpPage=Math.max(rpPage-1,0);
  renderReportsSlice();}
function rpSize(v){rpPageSize=+v||15;rpPage=0;renderReportsSlice();}
async function dl(url,name){const r=await fetch(url);const blob=await r.blob();const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=name;a.click();}

// ===== Discovery (scope view over targets) =====
async function renderDiscovery(){
  $('view').innerHTML=pageHead(t('dc.title'),t('dc.desc'),'<button class="sec" onclick="location.hash=\'#/targets\'">'+t('dc.editTarget')+'</button>')+'<div class="card"><table><thead><tr><th>'+t('dc.thTarget')+'</th><th>'+t('dc.thInc')+'</th><th>'+t('dc.thExc')+'</th></tr></thead><tbody id="dcBody"></tbody></table></div>';
  _targets=await api('/api/targets');
  $('dcBody').innerHTML=_targets.length?_targets.map(t=>'<tr><td class="url">'+esc(t.address)+'</td><td class="tiny">'+esc((t.includePatterns||[]).join(', ')||'-')+'</td><td class="tiny">'+esc((t.excludePatterns||[]).join(', ')||'-')+'</td></tr>').join(''):empty(t('dc.empty'));
}

// ===== Technologies (wappalyzer fingerprint aggregation) =====
let _techFilterTask='';
async function renderTechnologies(){
  $('view').innerHTML=pageHead(t('tech.title'),t('tech.desc'),'<select id="techFilt" class="sec" style="padding:6px"></select> <button class="sec" onclick="renderTechnologies()">'+t('c.refresh')+'</button>')
    +'<div class="card"><div id="techStats" class="muted tiny" style="margin-bottom:8px"></div><table><thead><tr><th>'+t('tech.thTech')+'</th><th>'+t('tech.thVer')+'</th><th>'+t('tech.thConf')+'</th><th>'+t('tech.thCat')+'</th><th>'+t('tech.thHits')+'</th><th>'+t('tech.thSample')+'</th></tr></thead><tbody id="techBody"></tbody></table></div>';
  const ts=await api('/api/tasks');
  let opts='<option value="">'+t('tech.allTasks')+'</option>'+ts.map(t=>'<option value="'+t.id+'"'+(_techFilterTask==String(t.id)?' selected':'')+'>#'+t.id+' '+esc(t.target||'')+'</option>').join('');
  $('techFilt').innerHTML=opts;
  $('techFilt').onchange=()=>{ _techFilterTask=$('techFilt').value; renderTechnologies(); };
  const url='/api/technologies'+(_techFilterTask?('?taskId='+_techFilterTask):'');
  let data={technologies:[],count:0}; try{ data=await api(url); }catch(e){}
  $('techStats').textContent=t('tech.stat')+data.technologies.length+t('tech.stat2')+data.count+t('tech.stat3');
  $('techBody').innerHTML=data.technologies.length?data.technologies.map(t=>
    '<tr><td><b>'+esc(t.name)+'</b></td><td>'+(t.version?'<code>'+esc(t.version)+'</code>':'<span class="muted">-</span>')+'</td>'
    +'<td>'+t.confidence+'%</td><td class="tiny">'+esc((t.categories||[]).map(c=>c.name).join(', '))+'</td>'
    +'<td>'+t.hits+'</td><td class="tiny url">'+esc((t.sampleUrls||[]).join(' '))+'</td></tr>'
  ).join(''):empty(t('tech.empty'));
}


// ===== Labs (preset + custom) =====
let _labEndpoints=[]; // grouped selectable endpoints for the custom-lab builder
async function renderLabs(){
  $('view').innerHTML=pageHead(t('lab.title'),t('lab.desc'),'<button class="sec" onclick="renderLabs()">'+t('c.refresh')+'</button> <button id="labNew">+ '+t('lab.new')+'</button>')+'<div id="labsGrid" class="row" style="flex-wrap:wrap;gap:12px"></div>';
  $('labNew').onclick=()=>openLabModal();
  let data={presets:[],custom:[]}; try{ data=await api('/api/labs'); }catch(e){}
  const card=(l)=>{
    const key=l.kind==='custom'?('custom:'+l.id):l.name;
    const run=l.running?'<span class="badge ok">'+t('lab.running')+'</span>':'<span class="badge">'+t('lab.stopped')+'</span>';
    const eps=(l.endpoints||[]).map(e=>'<tr><td class="tiny"><code>'+esc(e.path)+'</code></td><td class="tiny muted">'+esc(e.vuln)+'</td></tr>').join('');
    const btns=(l.running
      ?'<button class="danger tiny" data-stop="'+esc(key)+'">'+t('c.stop')+'</button>'
      :'<button class="tiny" data-start="'+esc(key)+'">'+t('c.start')+'</button>')
      +(l.running?'<button class="sec tiny" data-open="'+esc(l.url)+'">'+t('lab.jump')+'</button>':'')
      +'<button class="sec tiny" data-scan="'+esc(key)+'">'+t('lab.scanFrom')+'</button>'
      +'<button class="sec tiny" data-crawl="'+esc(key)+'">'+t('lab.crawlFrom')+'</button>'
      +(l.kind==='custom'?'<button class="danger tiny" data-del="'+esc(l.id)+'">'+t('c.delete')+'</button>':'');
    return '<div class="card" style="flex:1 1 360px;max-width:540px">'
      +'<div style="display:flex;justify-content:space-between;align-items:center"><b>'+esc(l.label||l.name)+(l.kind==='custom'?' <span class="tiny muted">'+t('lab.custom')+'</span>':'')+'</b>'+run+'</div>'
      +'<div class="muted tiny" style="margin:4px 0">'+esc(l.description||((l.categories||[]).join(', ')))+'</div>'
      +'<div class="tiny" style="margin:4px 0">'+t('lab.cat')+esc((l.categories||[]).join(', '))+' · '+(l.endpoints||[]).length+t('lab.eps')+'</div>'
      +'<table style="margin:6px 0"><thead><tr><th class="tiny">'+t('lab.thEp')+'</th><th class="tiny">'+t('lab.thVuln')+'</th></tr></thead><tbody>'+eps+'</tbody></table>'
      +'<div class="row" style="gap:6px">'+btns+'</div></div>';
  };
  const all=(data.presets||[]).map(l=>({...l,kind:'preset'})).concat((data.custom||[]).map(l=>({...l,kind:'custom'})));
  $('labsGrid').innerHTML=all.length?all.map(card).join(''):empty(t('lab.empty'));
  $('labsGrid').querySelectorAll('[data-start]').forEach(b=>b.onclick=async()=>{const key=b.dataset.start;b.disabled=true;b.textContent=t('lab.starting');try{const r=await (key.startsWith('custom:')?api('/api/labs/custom/'+encodeURIComponent(key.slice(7))+'/start',{method:'POST'}):api('/api/labs/'+encodeURIComponent(key)+'/start',{method:'POST'}));if(r&&r.url){$('srvStatus')&&($('srvStatus').textContent=t('lab.started')+r.url);}else if(r&&r.error){alert(r.error);}}catch(e){alert((e&&e.message)||t('lab.startFail'));}renderLabs();});
  $('labsGrid').querySelectorAll('[data-stop]').forEach(b=>b.onclick=async()=>{const key=b.dataset.stop;await (key.startsWith('custom:')?api('/api/labs/custom/'+encodeURIComponent(key.slice(7))+'/stop',{method:'POST'}):api('/api/labs/'+encodeURIComponent(key)+'/stop',{method:'POST'}));renderLabs();});
  $('labsGrid').querySelectorAll('[data-open]').forEach(b=>b.onclick=()=>{window.open(b.dataset.open,'_blank');});
  $('labsGrid').querySelectorAll('[data-scan]').forEach(b=>b.onclick=async()=>{const r=await api('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({lab:b.dataset.scan})});if(r&&r.id){location.hash='#/scans/'+r.id;}else{alert(t('ns.startFail2')+((r&&r.error)||t('ns.unknownErr')));}});
  $('labsGrid').querySelectorAll('[data-crawl]').forEach(b=>b.onclick=async()=>{const r=await api('/api/crawl',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({lab:b.dataset.crawl,crawlerMode:'static',maxPages:20,maxDepth:3})});if(r&&r.id){location.hash='#/scans/'+r.id;}else{alert(t('ns.startFail2')+((r&&r.error)||t('ns.unknownErr')));}});
  $('labsGrid').querySelectorAll('[data-del]').forEach(b=>b.onclick=async()=>{if(!confirm(t('lab.delConfirm')))return;await api('/api/labs/custom/'+encodeURIComponent(b.dataset.del),{method:'DELETE'});renderLabs();});
}
async function loadLabEndpoints(){if(_labEndpoints.length)return;try{_labEndpoints=await api('/api/labs/endpoints');}catch(e){}}
function openLabModal(){
  loadLabEndpoints().then(()=>{
    const cats=_labEndpoints.map(c=>c.category);
    const tree=_labEndpoints.map(c=>'<div style="margin:6px 0"><label style="width:auto"><input type="checkbox" class="labcat" data-cat="'+esc(c.category)+'" style="width:auto" checked> <b>'+esc(c.category)+'</b> <span class="tiny muted">('+c.endpoints.length+')</span></label>'
      +'<div style="margin-left:18px">'+c.endpoints.map(e=>'<div class="tiny"><code>'+esc(e.path)+'</code> <span class="muted">'+esc(e.vuln)+'</span></div>').join('')+'</div></div>').join('');
    modalBox('<h2>'+t('lab.newM')+'</h2>',
      '<fieldset><legend>'+t('lab.fldBasic')+'</legend><label>'+t('lab.nameLbl')+'</label><input id="labName" placeholder="'+t('lab.namePh')+'"></fieldset>'
      +'<fieldset><legend>'+t('lab.fldEndpoints')+'</legend>'+tree+'</fieldset>',
      '<button class="sec" onclick="closeModal()">'+t('c.cancel')+'</button><button id="labSave">'+t('c.create')+'</button>');
    $('labSave').onclick=async()=>{
      const cats=[...document.querySelectorAll('.labcat:checked')].map(c=>c.dataset.cat);
      if(!cats.length){alert(t('lab.needCat'));return;}
      const name=$('labName').value.trim()||t('lab.defaultName');
      const r=await api('/api/labs/custom',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,categories:cats})});
      if(r.error){alert(r.error);return;}
      closeModal();renderLabs();
    };
  });
}
// ===== Scan Profiles =====
let _pluginCatalog=[], _pluginChecked=new Set();
async function renderProfiles(){
  $('view').innerHTML=pageHead(t('pf.title'),t('pf.desc'),'<button id="pfAdd">+ '+t('pf.new')+'</button>')+'<div class="card"><table><thead><tr><th>'+t('pf.thName')+'</th><th>'+t('pf.thDesc')+'</th><th>'+t('pf.thPlugins')+'</th><th>'+t('pf.thOp')+'</th></tr></thead><tbody id="pfBody"></tbody></table></div>';
  $('pfAdd').onclick=()=>openProfileModal();
  _profiles=await api('/api/profiles');
  $('pfBody').innerHTML=_profiles.length?_profiles.map(p=>'<tr><td><b>'+esc(p.name)+'</b></td><td class="muted">'+esc(p.description||'')+'</td><td class="tiny">'+(p.plugins.length?p.plugins.length+t('pf.nSel'):esc(t('pf.autoAll')))+'</td><td><button class="sec tiny" data-edit="'+p.id+'">'+t('c.edit')+'</button> <button class="danger tiny" data-del="'+p.id+'">'+t('c.delete')+'</button></td></tr>').join(''):empty(t('pf.empty'));
  $('pfBody').querySelectorAll('[data-edit]').forEach(b=>b.onclick=()=>{const p=_profiles.find(x=>x.id===b.dataset.edit);openProfileModal(p);});
  $('pfBody').querySelectorAll('[data-del]').forEach(b=>b.onclick=async()=>{if(!confirm(t('pf.delConfirm')))return;await api('/api/profiles/'+b.dataset.del,{method:'DELETE'});renderProfiles();});
}
function openProfileModal(p){
  p=p||{name:'',description:'',plugins:[]};
  _pluginChecked=new Set(p.plugins||[]);
  modalBox('<h2>'+(p.id?t('pf.editM'):t('pf.newM'))+'</h2>',
    '<fieldset><legend>'+t('pf.fldBasic')+'</legend><label>'+t('pf.nameLbl')+'</label><input id="pfName" value="'+esc(p.name)+'"><label>'+t('pf.descLbl')+'</label><input id="pfDesc" value="'+esc(p.description||'')+'"></fieldset>'+
    '<fieldset><legend>'+t('pf.fldPlugins')+' <span id="pluginSelCount" style="font-weight:normal;color:#888"></span></legend><div class="row" style="margin-bottom:6px"><label style="width:auto"><input type="checkbox" id="pluginAuto" style="width:auto" checked onchange="togglePluginPicker()">'+t('pf.autoSel')+'</label></div>'+
    '<div id="pluginPicker" style="display:none"><div class="row" style="margin-bottom:6px"><input id="pluginFilter" placeholder="'+t('pf.filterPh')+'" style="flex:1"><button class="sec" type="button" id="btnPluginAll" style="width:auto">'+t('pf.allBtn')+'</button><button class="sec" type="button" id="btnPluginNone" style="width:auto">'+t('pf.noneBtn')+'</button></div><div id="pluginList" style="border:1px solid var(--bd);background:#fff"></div></div></fieldset>',
    '<button class="sec" onclick="closeModal()">'+t('c.cancel')+'</button><button id="pfSave">'+t('c.save')+'</button>');
  $('pluginFilter').oninput=renderPluginTree;
  $('btnPluginAll').onclick=()=>{for(const g of _pluginCatalog)for(const pl of g.plugins)_pluginChecked.add(pl.rel);renderPluginTree();};
  $('btnPluginNone').onclick=()=>{_pluginChecked.clear();renderPluginTree();};
  togglePluginPicker();
  $('pfSave').onclick=async()=>{
    const body={name:$('pfName').value,description:$('pfDesc').value,plugins:collectPlugins()||[]};
    if(p.id)await api('/api/profiles/'+p.id,{method:'DELETE'});
    await api('/api/profiles',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    closeModal();renderProfiles();
  };
}
async function loadPlugins(){if(_pluginCatalog.length)return;try{const r=await fetch('/api/plugins');_pluginCatalog=await r.json();}catch(e){return;}renderPluginTree();}
// Build a directory tree from plugin rel paths (e.g. Scripts/PerScheme/XSS.script).
// Each node: {name, path, children:[node], plugins:[{rel,title,...}]}.
function buildPluginTree(catalog){
  const root={name:'',path:'',children:{},plugins:[]};
  for(const g of catalog){
    for(const p of g.plugins){
      const parts=p.rel.split('/');let node=root;
      for(let i=0;i<parts.length-1;i++){
        const seg=parts[i];
        if(!node.children[seg])node.children[seg]={name:seg,path:parts.slice(0,i+1).join('/')+'/',children:{},plugins:[]};
        node=node.children[seg];
      }
      node.plugins.push(p);
    }
  }
  (function fin(n){n.children=Object.values(n.children).sort((a,b)=>a.name.localeCompare(b.name));n.plugins=n.plugins.sort((a,b)=>a.rel.localeCompare(b.rel));for(const c of n.children)fin(c);})(root);
  return root;
}
// collect every plugin rel under a tree node (for dir-check toggling)
function treeRelList(node){const out=node.plugins.map(p=>p.rel);for(const c of node.children)out.push(...treeRelList(c));return out;}
function treeSelState(node){
  // 'all' if every descendant checked, 'some' if any, 'none' if zero
  let total=0,sel=0;
  function walk(n){for(const p of n.plugins){total++;if(_pluginChecked.has(p.rel))sel++;}for(const c of n.children)walk(c);}
  walk(node);
  return sel===0?'none':(sel===total?'all':'some');
}
function renderPluginTree(){
  const box=$('pluginList');if(!box)return;
  if(!_pluginCatalog.length){box.innerHTML='<div style="padding:6px;color:#999">'+t('pf.loading')+'</div>';return;}
  const tree=buildPluginTree(_pluginCatalog);
  const f=($('pluginFilter').value||'').toLowerCase().trim();
  // preserve expand/collapse state across re-renders
  const openPaths=new Set();
  box.querySelectorAll('details[data-dpath]').forEach(d=>{if(d.open)openPaths.add(d.dataset.dpath);});
  function matches(p){return !f||p.rel.toLowerCase().indexOf(f)!==-1||(p.title||'').toLowerCase().indexOf(f)!==-1;}
  function hasMatch(node){if(node.plugins.some(matches))return true;for(const c of node.children)if(hasMatch(c))return true;return false;}
  function renderNode(node,depth){
    const kids=node.children.filter(c=>!f||hasMatch(c));
    const plugs=node.plugins.filter(p=>!f||matches(p));
    if(!kids.length&&!plugs.length)return '';
    let h='';
    for(const c of kids){
      const st=treeSelState(c);
      const ck=st==='all'?'checked':'';
      const ind=st==='some'?' data-ind="1"':'';
      const cnt=treeRelList(c).length;
      const open=(f||openPaths.has(c.path))?' open':'';
      h+='<details data-dpath="'+esc(c.path)+'"'+open+' style="margin-left:'+(depth*10)+'px"><summary><span class="caret">▸</span><input type="checkbox" data-dpath="'+esc(c.path)+'" '+ck+ind+' style="width:auto"> '+ic('folder')+' '+esc(c.name)+' <span class="muted tiny">('+cnt+')</span></summary><div style="margin-left:14px">'+renderNode(c,depth+1)+'</div></details>';
    }
    for(const p of plugs){
      const ckd=_pluginChecked.has(p.rel)?'checked':'';
      h+='<label class="pit" style="margin-left:'+(depth*10+8)+'px;display:flex;align-items:center;gap:6px"><input type="checkbox" data-prel="'+esc(p.rel)+'" '+ckd+' style="width:auto"><span>'+escapeHtml(p.title||p.rel)+'</span><small class="muted">'+escapeHtml(p.rel)+'</small></label>';
    }
    return h;
  }
  box.innerHTML=renderNode(tree,0)||'<div style="padding:6px;color:#999">'+t('pf.noMatch')+'</div>';
  // directory checkbox: toggle all descendant plugins
  box.querySelectorAll('input[data-dpath]').forEach(cb=>{
    if(cb.dataset.ind){cb.indeterminate=true;}   // reflect 'some' state
    cb.onchange=()=>{
      const node=findNode(tree,cb.dataset.dpath);
      if(!node)return;
      const rels=treeRelList(node);
      if(cb.checked){for(const r of rels)_pluginChecked.add(r);}else{for(const r of rels)_pluginChecked.delete(r);}
      renderPluginTree();
    };
  });
  // plugin checkbox: toggle single rel
  box.querySelectorAll('input[data-prel]').forEach(cb=>{cb.onchange=()=>{if(cb.checked)_pluginChecked.add(cb.dataset.prel);else _pluginChecked.delete(cb.dataset.prel);renderPluginTree();};});
  updatePluginSelCount();
}
function findNode(node,path){if(node.path===path)return node;for(const c of node.children){const r=findNode(c,path);if(r)return r;}return null;}
function updatePluginSelCount(){const n=_pluginChecked.size;const el=$('pluginSelCount');if(el)el.textContent=n?(t('pf.selected')+n+t('pf.selUnit')):'';}
function collectPlugins(){if($('pluginAuto').checked||!_pluginChecked.size)return null;return [..._pluginChecked];}
function togglePluginPicker(){const auto=$('pluginAuto').checked;$('pluginPicker').style.display=auto?'none':'block';if(!auto){if(_pluginCatalog.length)renderPluginTree();else loadPlugins();}}

// ===== Stub (unsupported settings) =====
function renderStub(title,blurb,hint){
  $('view').innerHTML=pageHead(title,blurb,'')+'<div class="card card-solid" style="text-align:center;padding:40px"><div class="stub-ic">'+ic('settings')+'</div><span class="stub-badge">'+t('stub.unavail')+'</span><p style="max-width:480px;margin:8px auto;color:var(--mut)">'+esc(hint)+'</p></div>';
}

// ===== AI 自动渗透 (真实后端 /api/ai-pentest + SSE 事件流) =====
// Cairn-style 黑板模型: 一个渗透项目 = origin(目标) + goal(目标成果) → 由后端 dispatcher
// 跑 OODA 循环(bootstrap→reason→explore),不断往黑板写入 Fact/Intent,事件经 SSE 实时推前端。
// 数据全部来自后端持久化(data/ai_pentest.json),前端只读写真实 API + 订阅 SSE。
let _aiDetailTab='timeline';   // detail view active tab
let _aiSSE=null;               // EventSource for current detail project
let _aiCur=null;               // current detail project detail cache (project/facts/intents/hints/events)
let _aiNotify=null;            // IM 推送配置(/api/ai-notify)
let _aiLlm=null;               // LLM 配置(/api/ai-pentest/llm-config)
const AI_WORKERS=[['claudecode',''],['llm',''],['mock','']];
const AI_IM_PLATFORMS=[['feishu','飞书 / Lark'],['wecom','企业微信'],['dingtalk','钉钉']];
function platformName(v){const p=AI_IM_PLATFORMS.find(x=>x[0]===v);return p?p[1]:(v||'');}
const AI_STATUS_TXT={active:'running',completed:'done',stopped:'stopped'};
// AI worker 可调用的工具(对应后端 ai_tools.js),仅用于前端展示
const AI_TOOLS=[
  ['search','awvs_crawl','ait.awvs_crawl'],
  ['shield-alert','awvs_scan','ait.awvs_scan'],
  ['list-checks','awvs_list_plugins','ait.awvs_list_plugins'],
  ['play-circle','awvs_run_plugin','ait.awvs_run_plugin'],
  ['layers','awvs_glob','ait.awvs_glob'],
  ['pencil-line','awvs_write_plugin','ait.awvs_write_plugin'],
  ['key-round','awvs_js_leak','ait.awvs_js_leak'],
  ['globe','http','ait.http'],
];
async function aiLoadNotify(force){
  if(_aiNotify&&!force)return _aiNotify;
  try{_aiNotify=await api('/api/ai-notify');}catch(e){_aiNotify={ok:false,config:{enabled:false}};}
  return _aiNotify;
}
async function aiLoadLlm(){
  if(_aiLlm)return _aiLlm;
  try{_aiLlm=await api('/api/ai-pentest/llm-config');}catch(e){_aiLlm={ok:false,config:{}};}
  return _aiLlm;
}
function aiPill(s){const cls=s==='active'?'running':s==='completed'?'done':'stopped';const key=AI_STATUS_TXT[s]||s;return '<span class="pill st-'+cls+'">'+(I18N['st.'+key]?t('st.'+key):s)+'</span>';}
// AI worker 类型 → Lucide icon id(头部卡片图标)。
function aiWorkerIcon(w){return /mock|rule/i.test(w||'')?ic('theater'):/claudecode/i.test(w||'')?ic('zap'):ic('bot');}
function workerLabel(w){if(!w)return '—';if(/claudecode/i.test(w))return 'Claude Code';if(/mock|rule/i.test(w))return t('aiw.mockShort');return w;}
// p 可能是详情对象(intents 是数组)或列表概要(intents 是数字)。
function aiProgress(p){
  const its=p.intents;
  if(Array.isArray(its)){const d=its.filter(i=>i&&i.status==='done').length;return its.length?Math.round(d/its.length*100):(p.status==='completed'?100:0);}
  const n=+its||0,d=p.intentsDone||0;
  return n?Math.round(d/n*100):(p.status==='completed'?100:0);
}
function aiStat(n,l,sub){return '<div class="det-stat"><div class="n">'+n+'</div><div class="l">'+esc(l)+(sub?' · '+esc(sub):'')+'</div></div>';}
// 列表视图 — 从后端拉项目列表(概要)
async function renderAIPentest(){
  let list=[];
  try{const r=await api('/api/ai-pentest');list=(r&&r.projects)||[];}catch(e){list=[];}
  const active=list.filter(p=>p.status==='active').length;
  const done=list.filter(p=>p.status==='completed').length;
  const totalFacts=list.reduce((s,p)=>s+(p.facts||0),0);
  $('view').innerHTML=pageHead(t('ai.title'),t('ai.desc'),
    '<button class="sec" onclick="renderAIPentest()">'+ic('refresh-cw','btn-ic')+' '+t('c.refresh')+'</button> <button id="aiNew">'+ic('plus','btn-ic')+t('ai.new')+'</button> <button class="sec" id="aiLlmCfgBtn">'+ic('settings','btn-ic')+t('ai.llmCfg')+'</button>')+
    '<div class="grid g4" style="margin-bottom:14px">'+
      '<div class="statcard"><div class="n">'+list.length+'</div><div class="l">'+t('ai.projects')+'</div></div>'+
      '<div class="statcard t"><div class="n">'+active+'</div><div class="l">'+t('ai.active')+'</div></div>'+
      '<div class="statcard v"><div class="n">'+totalFacts+'</div><div class="l">'+t('ai.facts')+'</div></div>'+
      '<div class="statcard"><div class="n">'+done+'</div><div class="l">'+t('ai.completed')+'</div></div>'+
    '</div>'+
    '<div class="ai-grid" id="aiGrid"></div>';
  $('aiNew').onclick=()=>openNewAIModal();
  $('aiLlmCfgBtn').onclick=()=>openLlmModal();
  $('aiGrid').innerHTML=list.length?list.map(p=>{
    const pct=aiProgress(p);
    const doneCnt=p.intentsDone||0;
    const claimCnt=(p.intents||0)-doneCnt-((p.intentsUnclaimed)||0);
    return '<div class="ai-card" data-open="'+p.id+'">'+
      '<div class="ai-card-h"><span class="ai-ic">'+aiWorkerIcon(p.worker)+'</span><b>'+esc(p.title)+'</b><span class="ai-corner">'+aiPill(p.status)+'</span></div>'+
      '<div class="ai-goal">'+ic('target','ai-mini-ic')+' '+esc(p.goal)+'</div>'+
      '<div class="ai-orig">'+esc(p.origin)+'</div>'+
      '<div class="ai-bar"><div style="width:'+pct+'%"></div></div>'+
      '<div class="ai-meta">'+
        '<span>'+ic('microscope','ai-mini-ic')+' <b>'+(p.facts||0)+'</b> Fact</span>'+
        '<span>'+ic('compass','ai-mini-ic')+' <b>'+doneCnt+'/'+(p.intents||0)+'</b> Intent</span>'+
        '<span style="margin-left:auto">'+(p.startedAt||'').slice(5,16).replace('T',' ')+'</span>'+
      '</div></div>';
  }).join(''):empty(t('ai.empty'));
  $('aiGrid').querySelectorAll('[data-open]').forEach(c=>c.onclick=()=>{location.hash='#/ai-pentest/'+c.dataset.open;});
}
// 详情视图 — 拉详情 + 订阅 SSE 实时刷新
async function renderAIDetail(id){
  if(_aiSSE){_aiSSE.close();_aiSSE=null;}
  _aiDetailTab='timeline';
  let p;
  try{p=await api('/api/ai-pentest/'+id);}catch(e){p=null;}
  if(!p||!p.project){$('view').innerHTML=pageHead(t('ai.title')+' #'+id,'<a href="#/ai-pentest" class="tiny">'+t('ai.backToList')+'</a>','')+empty(t('ai.notExist'));return;}
  _aiCur=p;
  const proj=p.project;const active=proj.status==='active';
  $('view').innerHTML=pageHead(t('ai.title')+' #'+proj.id,'<a href="#/ai-pentest" class="tiny">'+t('ai.backToList')+'</a> · '+esc(proj.title),
    (active?'<button class="danger" id="aiStopBtn">'+ic('circle-stop','btn-ic')+' '+t('c.stop')+'</button> ':'<button class="sec" id="aiReopenBtn">'+ic('rotate-ccw','btn-ic')+t('ai.reopenLbl')+'</button> ')+
    '<button class="sec" id="aiHintBtn">'+ic('lightbulb','btn-ic')+t('ai.injectHint')+'</button> '+
    '<a class="btn sec" href="#/ai-pentest">'+t('ai.back')+'</a>')+
    '<div class="ai-status-strip '+(active?'':proj.status)+'"><span class="ai-pulse"></span><b>'+(I18N['st.'+(AI_STATUS_TXT[proj.status]||proj.status)]?t('st.'+(AI_STATUS_TXT[proj.status]||proj.status)):proj.status)+'</b><span class="ai-sub">'+t('ai.worker')+esc(proj.worker||'llm')+' · '+(p.intents||[]).filter(i=>i.status==='done').length+'/'+(p.intents||[]).length+t('ai.intentsConv')+'</span></div>'+
    '<div class="ai-layout">'+
      '<div>'+
        '<div class="card" style="padding:10px 14px"><div class="row" style="margin-bottom:4px"><div><label style="color:var(--acc)">'+ic('target')+' Origin</label><div class="url">'+esc(proj.origin)+'</div></div><div><label style="color:var(--acc)">'+ic('flag')+' Goal</label><div class="tiny">'+esc(proj.goal)+'</div></div></div></div>'+
        '<div class="tabs" id="aiTabs" style="margin-top:12px">'+
          '<div class="tab" data-t="timeline">'+t('ai.tabTimeline')+'</div>'+
          '<div class="tab" data-t="talk">'+t('ai.tabTalk')+' <span class="cnt">'+(p.events||[]).filter(e=>e.type==='llm_turn').length+'</span></div>'+
          '<div class="tab" data-t="vulns">'+t('ai.tabVulns')+' <span class="cnt">'+(p.events||[]).filter(e=>e.type==='vuln').length+'</span></div>'+
          '<div class="tab" data-t="facts">'+t('ai.tabFacts')+' <span class="cnt">'+(p.facts||[]).length+'</span></div>'+
          '<div class="tab" data-t="intents">'+t('ai.tabIntents')+' <span class="cnt">'+(p.intents||[]).length+'</span></div>'+
          '<div class="tab" data-t="hints">'+t('ai.tabHints')+' <span class="cnt">'+(p.hints||[]).length+'</span></div>'+
          '<div class="tab" data-t="graph">'+t('ai.tabGraph')+'</div>'+
        '</div>'+
        '<div class="pane"><div class="card ai-feed" id="aiPane"></div></div>'+
      '</div>'+
      '<div class="ai-side">'+
        '<div class="card"><h3 style="margin:0 0 8px">'+t('ai.blackboard')+'</h3>'+
          '<div class="ai-mini">'+
            aiStat((p.facts||[]).length,t('ai.fact'))+
            aiStat((p.events||[]).filter(e=>e.type==='vuln').length,t('dash.vulns'))+
            aiStat((p.intents||[]).filter(i=>i.status==='done').length,t('ai.conv'))+
            aiStat((p.intents||[]).filter(i=>i.status==='claimed').length,t('ai.exploring'))+
          '</div>'+
          '<div class="gbar" style="margin-top:10px"><div id="aiProgBar" style="width:'+aiProgress(p)+'%"></div></div>'+
          '<div class="muted tiny" id="aiProgTxt">'+t('ai.progTxt')+aiProgress(p)+'%</div>'+
        '</div>'+
        '<div class="card"><h3 style="margin:0 0 8px">'+t('ai.toolbox')+'</h3>'+
          '<div class="muted tiny" style="margin-bottom:6px">'+t('ai.toolboxDesc')+'</div>'+
          aiToolboxHtml()+'</div>'+
        '<div class="card"><h3 style="margin:0 0 8px">'+t('ai.notify')+'</h3>'+
          '<div class="muted tiny" id="aiNotifyState">'+t('c.loading')+'</div>'+
          '<button class="sec tiny" style="margin-top:8px" id="aiNotifyCfg">'+t('ai.notifyCfg')+'</button></div>'+
      '</div>'+
    '</div>';
  $('aiTabs').querySelectorAll('.tab').forEach(t=>t.onclick=()=>{_aiDetailTab=t.dataset.t;aiRenderPane();aiSyncTabs();});
  aiRenderPane();aiSyncTabs();
  aiLoadNotify().then(()=>{const el=$('aiNotifyState');if(el){const c=_aiNotify&&_aiNotify.config;el.innerHTML=c&&c.enabled?(ic('check')+t('ai.notifyOn')+(c.webhook?esc(platformName(c.platform))+' '+t('ai.notifyPush'):t('ai.notifyDefault'))):(ic('triangle-alert')+t('ai.notifyOff'));}});
  const ncfg=$('aiNotifyCfg');if(ncfg)ncfg.onclick=()=>{location.hash='#/config';};
  const stopBtn=$('aiStopBtn');if(stopBtn)stopBtn.onclick=async()=>{await api('/api/ai-pentest/'+proj.id+'/stop',{method:'POST'});renderAIDetail(proj.id);};
  const roBtn=$('aiReopenBtn');if(roBtn)roBtn.onclick=async()=>{await api('/api/ai-pentest/'+proj.id+'/start',{method:'POST'});renderAIDetail(proj.id);};
  const hintBtn=$('aiHintBtn');if(hintBtn)hintBtn.onclick=()=>openHintModal(proj.id);
  // 订阅 SSE:黑板事件实时增量刷新(全量重拉详情,简化实现)
  aiSubscribe(proj.id);
}
// SSE 订阅:每来一条事件,标记 dirty,节流重拉详情
function aiSubscribe(id){
  try{
    _aiSSE=new EventSource('/api/ai-pentest/'+id+'/events');
    let dirty=false,timer=null;
    const flush=()=>{timer=null;if(!dirty)return;dirty=false;api('/api/ai-pentest/'+id).then(np=>{if(np&&np.project){_aiCur=np;aiRenderPane();aiSyncTopStats();if(np.project.status!==_aiCur.project.status||(_aiCur&&np.project.status!==_aiCur.project.status)){}}}).catch(()=>{});};
    _aiSSE.onmessage=(e)=>{dirty=true;if(!timer)timer=setTimeout(flush,600);};
    _aiSSE.onerror=()=>{ /* 断线由浏览器自动重连 */ };
  }catch(e){}
}
function aiSyncTopStats(){
  const p=_aiCur;if(!p)return;
  const bar=$('aiProgBar');if(bar)bar.style.width=aiProgress(p)+'%';
  const txt=$('aiProgTxt');if(txt)txt.textContent=t('ai.progTxt')+aiProgress(p)+'%';
  const strip=document.querySelector('.ai-status-strip .ai-sub');if(strip)strip.textContent=t('ai.worker')+(p.project.worker||'llm')+' · '+(p.intents||[]).filter(i=>i.status==='done').length+'/'+(p.intents||[]).length+t('ai.intentsConv');
  const tabs=$('aiTabs');if(tabs){const evs=p.events||[];const t1=tabs.querySelector('[data-t=talk] .cnt');if(t1)t1.textContent=evs.filter(e=>e.type==='llm_turn').length;const t2=tabs.querySelector('[data-t=vulns] .cnt');if(t2)t2.textContent=evs.filter(e=>e.type==='vuln').length;const f=tabs.querySelector('[data-t=facts] .cnt');if(f)f.textContent=(p.facts||[]).length;const i=tabs.querySelector('[data-t=intents] .cnt');if(i)i.textContent=(p.intents||[]).length;}
}
function aiToolboxHtml(){
  return AI_TOOLS.map(it=>'<div class="ai-tool"><span class="ai-tool-ic">'+ic(it[0])+'</span><span class="ai-tool-nm">'+esc(it[1])+'</span><span class="ai-tool-st">'+esc(t(it[2]))+'</span></div>').join('');
}
function aiSyncTabs(){$('aiTabs').querySelectorAll('.tab').forEach(t=>t.classList.toggle('active',t.dataset.t===_aiDetailTab));}
// 渲染当前 tab 内容(数据来自 _aiCur,后端真实结构)
function aiRenderPane(){
  const p=_aiCur;const pane=$('aiPane');if(!pane||!p)return;
  if(_aiDetailTab==='timeline'){
    // 用 events 数组(SSE 已增量刷新),按时间正序渲染,最新在下;展示 tool_call/tool_done 折叠
    const evs=p.events||[];
    pane.innerHTML='<div class="muted tiny" style="margin-bottom:6px">'+t('ai.timelineDesc')+'</div>'+
      (evs.length?evs.map(e=>aiEventHtml(e)).join(''):empty(t('ai.timelineEmpty')));
  }else if(_aiDetailTab==='talk'){
    const turns=(p.events||[]).filter(e=>e.type==='llm_turn');
    pane.innerHTML='<div class="muted tiny" style="margin-bottom:6px">'+t('ai.talkDesc')+'</div>'+
      (turns.length?turns.map(tt=>aiTurnHtml(tt)).join(''):empty(t('ai.talkEmpty')));
  }else if(_aiDetailTab==='vulns'){
    pane.innerHTML='<div class="muted tiny" style="margin-bottom:6px">'+t('ai.vulnsDesc')+'</div><div id="aiVulnList">'+empty(t('c.loading'))+'</div>';
    aiLoadVulns(p.project.id);
  }else if(_aiDetailTab==='facts'){
    const fs=p.facts||[];
    pane.innerHTML=fs.length?fs.slice().reverse().map(f=>aiEventHtml({type:'fact',fact:f})).join(''):empty(t('ai.factsEmpty'));
  }else if(_aiDetailTab==='intents'){
    const order={claimed:0,unclaimed:1,done:2};
    const is=(p.intents||[]).slice().sort((a,b)=>order[a.status]-order[b.status]);
    pane.innerHTML=is.length?is.map(i=>aiEventHtml({type:'intent',intent:i})).join(''):empty(t('ai.intentsEmpty'));
  }else if(_aiDetailTab==='hints'){
    const hs=p.hints||[];
    pane.innerHTML=hs.length?hs.map(h=>aiEventHtml({type:'hint',hint:h})).join(''):empty(t('ai.hintsEmpty')+ic('lightbulb')+t('ai.hintsEmpty2'));
  }else if(_aiDetailTab==='graph'){
    const open=(p.intents||[]).filter(i=>i.status!=='done');
    const chain=['<div class="muted tiny" style="margin-bottom:10px">'+t('ai.graphDesc')+'</div>'];
    chain.push('<div style="text-align:center;margin:6px 0"><div style="display:inline-block;background:var(--acc);color:#fff;padding:9px 18px;border-radius:10px;font-weight:700;box-shadow:0 2px 8px rgba(26,179,148,.25)">Origin<br><span class="tiny">'+esc(p.project.origin)+'</span></div></div>');
    (p.facts||[]).forEach(f=>{
      chain.push('<div style="text-align:center;font-size:16px;color:var(--acc);line-height:1">↓</div>');
      chain.push('<div style="text-align:center;margin:4px 0"><div style="display:inline-block;background:#fff;border:1px solid var(--acc);border-radius:8px;padding:7px 14px;max-width:340px;text-align:left"><b class="tiny" style="color:var(--acc)">'+esc(f.id)+'</b> <span class="tiny muted">'+esc((f.at||'').slice(11,19))+'</span><div class="tiny">'+esc(f.description)+'</div></div></div>');
    });
    chain.push('<div style="text-align:center;font-size:16px;color:var(--mut);line-height:1">↓</div>');
    chain.push('<div style="text-align:center;margin:6px 0"><div style="display:inline-block;background:'+(p.project.status==='completed'?'var(--acc)':'var(--mut)')+';color:#fff;padding:9px 18px;border-radius:10px;font-weight:700">Goal<br><span class="tiny">'+esc(p.project.goal)+'</span></div></div>');
    if(open.length){chain.push('<div class="muted tiny" style="margin:14px 0 6px">'+t('ai.openIntent')+open.length+t('ai.openIntent2')+'</div><div style="display:flex;flex-direction:column;gap:6px">'+open.map(i=>'<div style="background:var(--panel2);border:1px dashed var(--bd);border-radius:7px;padding:6px 10px"><b class="tiny muted">'+esc(i.id)+'</b> <span class="tiny">'+esc(i.description)+'</span></div>').join('')+'</div>');}
    pane.innerHTML=chain.join('');
  }
}
// 单条事件卡片:接受后端黑板事件结构(type: fact/intent/intent_claimed/intent_done/hint/tool_call/tool_done/log/goal/stopped)
function aiEventHtml(e){
  const t=e.type;
  if(t==='fact'){const f=e.fact;const m=f.meta||{};const intent=(m.intent)?'<div class="ai-ex">'+ic('compass')+t('ai.hypothesis')+esc(m.intent)+'</div>':'';const findings=(Array.isArray(m.findings)&&m.findings.length)?'<div class="ai-ex">'+ic('shield-alert')+t('ai.finding')+m.findings.map(x=>esc((x.title||x.typeId)+(x.affects?' @ '+x.affects:'')+(x.severity?(' ['+x.severity+']'):''))).join(' · ')+'</div>':'';const acts=(Array.isArray(m.toolResults)&&m.toolResults.length)?('<details style="margin-top:4px"><summary class="tiny muted" style="cursor:pointer">'+ic('wrench')+t('ai.action')+esc(m.toolResults.length+t('ai.actionUnit'))+'</summary><div class="tiny" style="margin-top:3px">'+m.toolResults.map(x=>'<div><code>'+esc(x.tool)+'</code> '+(x.ok?ic('check'):ic('x'))+' <span class="muted">'+esc(x.summary||'')+'</span></div>').join('')+'</div></details>'):'';return '<div class="ai-ev"><div class="ai-dot fact">'+ic('microscope')+'</div><div class="ai-body"><div class="ai-et"><b>'+t('ai.fact')+'</b> <code>'+esc(f.id)+'</code><span style="margin-left:auto">'+esc((f.at||'').slice(11,19))+'</span></div><div class="ai-ed">'+esc(f.description)+'</div>'+intent+findings+acts+(f.from&&f.from.length?'<div class="ai-ex">← '+f.from.map(esc).join(', ')+'</div>':'')+'</div></div>';}
  if(t==='intent'){const i=e.intent;const icEl=i.status==='done'?ic('circle-check'):i.status==='claimed'?ic('loader-circle'):ic('circle-dot');const cls=i.status==='done'?'intent-done':'intent';const badge=' <span class="badge '+(i.status==='done'?'st-done':i.status==='claimed'?'st-running':'s0')+'">'+({done:t('ai.intDone'),claimed:t('ai.intExploring'),unclaimed:t('ai.intUnclaimed')}[i.status]||i.status)+'</span>';return '<div class="ai-ev"><div class="ai-dot '+cls+'">'+icEl+'</div><div class="ai-body"><div class="ai-et"><b>'+t('ai.intentLbl')+'</b> <code>'+esc(i.id)+'</code>'+badge+'</div><div class="ai-ed">'+esc(i.description)+'</div>'+(i.from&&i.from.length?'<div class="ai-ex">← '+i.from.map(esc).join(', ')+(i.worker?' · '+esc(i.worker):' · '+t('ai.noClaim'))+'</div>':'')+'</div></div>';}
  if(t==='intent_claimed'){return '<div class="ai-ev"><div class="ai-dot intent">'+ic('loader-circle')+'</div><div class="ai-body"><div class="ai-et"><b>'+t('ai.intentLbl')+'</b> <code>'+esc(e.intent.id)+'</code> <span class="badge st-running">'+t('ai.intClaimed')+'</span></div><div class="ai-ed tiny">'+esc(e.intent.description)+'</div><div class="ai-ex">'+t('ai.worker')+esc(e.intent.worker)+'</div></div></div>';}
  if(t==='intent_done'){const i=e.intent;return '<div class="ai-ev"><div class="ai-dot intent-done">'+ic('circle-check')+'</div><div class="ai-body"><div class="ai-et"><b>'+t('ai.intentLbl')+'</b> <code>'+esc(i.id)+'</code> <span class="badge st-done">'+t('ai.intDone')+'</span></div><div class="ai-ed tiny">'+esc(i.description)+'</div>'+(e.fact?'<div class="ai-ex">→ '+t('ai.fact')+' '+esc(e.fact.id)+'</div>':'')+'</div></div>';}
  if(t==='hint'){const h=e.hint;return '<div class="ai-ev"><div class="ai-dot hint">'+ic('lightbulb')+'</div><div class="ai-body"><div class="ai-et"><b>'+t('ai.hintLbl')+'</b> <code>'+esc(h.id)+'</code></div><div class="ai-ed">'+esc(h.content)+'</div><div class="ai-ex">'+t('ai.by2')+esc(h.creator)+'</div></div></div>';}
  if(t==='tool_call'){const a=e.args;return '<div class="ai-ev"><div class="ai-dot system">'+ic('wrench')+'</div><div class="ai-body"><div class="ai-et"><b>'+t('ai.toolCallLbl')+'</b> <code>'+esc(e.tool)+'</code><span class="tiny muted" style="margin:0 6px">'+t('ai.by')+'</span><code class="tiny">'+esc(workerLabel(e.worker))+'</code><span style="margin-left:auto">'+esc((e.at||'').slice(11,19))+'</span></div><details><summary class="tiny muted" style="cursor:pointer">'+esc(e.tool)+' '+esc(JSON.stringify(a).slice(0,80))+'</summary><pre class="tiny" style="margin-top:4px;background:var(--panel2);padding:6px;border-radius:4px;overflow:auto">'+esc(JSON.stringify(a,null,2))+'</pre></details></div></div>';}
  if(t==='tool_done'){const okEl=e.ok?ic('check'):ic('x');return '<div class="ai-ev"><div class="ai-dot system">'+okEl+'</div><div class="ai-body"><div class="ai-et"><b>'+t('ai.toolDoneLbl')+'</b> <code>'+esc(e.tool)+'</code> <span class="tiny muted">'+t('ai.by2')+esc(workerLabel(e.worker))+'</span> <span class="tiny muted">'+(e.ms||0)+'ms</span></div><div class="ai-ed tiny">'+esc(e.summary||'')+'</div></div></div>';}
  if(t==='goal'){return '<div class="ai-ev"><div class="ai-dot fact">'+ic('flag')+'</div><div class="ai-body"><div class="ai-et"><b>'+t('ai.goalReached')+'</b></div><div class="ai-ed">'+t('ai.goalReachedDesc')+'</div></div></div>';}
  if(t==='stopped'){return '<div class="ai-ev"><div class="ai-dot system">'+ic('circle-stop')+'</div><div class="ai-body"><div class="ai-et"><b>'+t('ai.stoppedEv')+'</b></div></div></div>';}
  if(t==='llm_turn'){const ph={bootstrap:t('ai.phaseBoot'),reason:t('ai.phaseReason'),explore:t('ai.phaseExplore')}[e.phase]||e.phase;return '<div class="ai-ev"><div class="ai-dot system">'+ic('message-square')+'</div><div class="ai-body"><div class="ai-et"><b>'+t('ai.turn')+'</b> <span class="badge st-running">'+esc(ph)+'</span> <code class="tiny">'+esc(e.worker||'')+'</code><span style="margin-left:auto">'+esc((e.at||'').slice(11,19))+'</span></div><div class="ai-ed tiny muted">'+esc((e.response||e.error||'').slice(0,160))+'</div></div></div>';}
  if(t==='vuln'){const v=e.vuln||{};const sev='<span class="badge '+(v.severity==='critical'||v.severity==='high'?'st-stopped':v.severity==='medium'?'s2':'s0')+'">'+esc(v.severity||'info')+'</span>';return '<div class="ai-ev"><div class="ai-dot system">'+ic('shield-alert')+'</div><div class="ai-body"><div class="ai-et"><b>'+t('nav.vulnerabilities')+'</b> '+sev+' '+esc(v.title||v.name||v.typeId||'')+' '+provenanceBadge(v.provenance)+'<span class="tiny muted" style="margin:0 6px">'+t('ai.by')+'</span><code class="tiny">'+esc(workerLabel(e.worker))+'</code><span style="margin-left:auto">'+esc((v.affects||'').slice(0,40))+'</span></div><div class="ai-ed tiny">'+esc(v.affects||'')+(v.parameter?' · '+esc(v.parameter):'')+'</div></div></div>';}
  // log / default
  if(t==='log'||!t){return '<div class="ai-ev"><div class="ai-dot system">'+ic('circle-dot')+'</div><div class="ai-body"><div class="ai-ed tiny muted">'+esc(e.msg||'')+'</div></div></div>';}
  return '';
}
// llm_turn 对话卡片(system/prompt/response 可折叠,与 tool_call 的 <details> 风格一致)
function aiTurnHtml(tt){
  const phaseBadge={bootstrap:t('ai.phaseBoot'),reason:t('ai.phaseReason'),explore:t('ai.phaseExplore')}[tt.phase]||tt.phase;
  const okMark=tt.ok===false?'<span class="badge st-stopped">'+t('ai.turnFail')+'</span>':'';
  const roundTag=(tt.phase==='explore'&&tt.round!=null)?' · R'+tt.round:'';
  return '<div class="ai-ev"><div class="ai-dot system">'+ic('message-square')+'</div><div class="ai-body">'+
    '<div class="ai-et"><b>'+t('ai.turn')+'</b> <span class="badge st-running">'+esc(phaseBadge)+'</span> <code class="tiny">'+esc(tt.worker||'')+'/'+esc(tt.model||'')+'</code>'+roundTag+' '+okMark+'<span style="margin-left:auto">'+esc((tt.at||'').slice(11,19))+'</span></div>'+
    '<details><summary class="tiny muted" style="cursor:pointer">'+ic('list-checks')+' '+t('ai.promptLbl')+'</summary><pre class="tiny" style="margin-top:4px;background:var(--panel2);padding:6px;border-radius:4px;overflow:auto;white-space:pre-wrap;word-break:break-word">'+esc(tt.prompt||'')+'</pre></details>'+
    '<details open><summary class="tiny muted" style="cursor:pointer;margin-top:4px">'+ic('message-square')+' '+t('ai.responseLbl')+'</summary><pre class="tiny" style="margin-top:4px;background:var(--panel2);padding:6px;border-radius:4px;overflow:auto;white-space:pre-wrap;word-break:break-word">'+esc(tt.response||tt.error||'')+'</pre></details>'+
    '</div></div>';
}
// 漏洞列表:拉 /api/ai-pentest/:id/vulns(后端经 vuln_db 富化)后渲染。
// 复用与扫描详情完全一致的卡片(detVulnCard + vulnDetail + wireVulnCards),保证
// AI 渗透的漏洞展示与「以前一样」——同样的严重度徽章/URL 行/详情表格(类型/名称/
// CVSS/插件/URL/影响/参数/攻击载荷)、漏洞描述/影响/修复建议/漏洞详情模板/参考链接/
// HTTP 请求-响应,点开折叠。
async function aiLoadVulns(pid){
  const el=$('aiVulnList');if(!el)return;
  let data;try{data=await api('/api/ai-pentest/'+pid+'/vulns');}catch(e){el.innerHTML=empty(t('ai.vulnsLoadFail'));return;}
  const vs=(data&&data.vulns)||[];
  if(!vs.length){el.innerHTML=empty(t('ai.vulnsEmpty'));return;}
  el.innerHTML=vs.map(v=>detVulnCard(v)).join('');
  wireVulnCards(el);
}
// 新建 AI 渗透模态框:Origin/Goal/Hints + 工具范围 + LLM 配置入口 + 推送
async function openNewAIModal(){
  // 预加载配置(LLM/推送),回填表单默认值
  await Promise.all([aiLoadLlm(),aiLoadNotify()]);
  const ll=(_aiLlm&&_aiLlm.config)||{provider:'openai',base_url:'',api_key:'',model:''};
  const cc=(_aiLlm&&_aiLlm.claude)||{available:false};
  const nc=(_aiNotify&&_aiNotify.config)||{enabled:false,platform:'feishu',webhook:'',secret:'',atAll:false,events:{fact:true,goal:true,stopped:true}};
  const hasLlm=!!(ll.api_key&&ll.base_url);
  // claudecode worker 仅在本机装了 claude CLI + 有 ANTHROPIC 认证时可选;否则灰掉。
  const ccOpt='<option value="claudecode"'+(cc.available?'':' disabled')+'>'+t('aiM.ccOpt')+(cc.available?'':t('aiM.ccNotDet'))+t('aiM.ccDet')+'</option>';
  modalBox('<h2>'+t('aiM.title')+'</h2>',
    '<fieldset><legend>'+t('aiM.fldOrigin')+'</legend><label>'+t('aiM.selTarget')+'</label><select id="aiTgt"><option value="">'+t('aiM.manual')+'</option></select>'+
    '<label>'+t('aiM.orUrl')+'</label><input id="aiOrigin" placeholder="'+t('aiM.originPh')+'"></fieldset>'+
    '<fieldset><legend>'+t('aiM.fldGoal')+'</legend>'+
    '<div class="row" style="margin-bottom:6px"><button class="sec" type="button" style="width:auto" data-goal="'+t('aiM.goalFlag')+'">'+t('aiM.goalFlag')+'</button><button class="sec" type="button" style="width:auto" data-goal="'+t('aiM.goalShell')+'">'+t('aiM.goalShell')+'</button><button class="sec" type="button" style="width:auto" data-goal="'+t('aiM.goalVuln')+'">'+t('aiM.goalVuln')+'</button></div>'+
    '<textarea id="aiGoal" rows="2" placeholder="'+t('aiM.goalPh')+'"></textarea></fieldset>'+
    '<fieldset><legend>'+t('aiM.fldHints')+'</legend><textarea id="aiHints" rows="3" placeholder="'+t('aiM.hintsPh')+'"></textarea></fieldset>'+
    '<fieldset><legend>'+t('aiM.fldEngine')+'</legend>'+
    '<div class="muted tiny" style="margin-bottom:6px">'+t('aiM.engineDesc')+'</div>'+
    '<div class="row"><div><label>'+t('aiM.workerType')+'</label><select id="aiWorker">'+ccOpt+AI_WORKERS.map(w=>'<option value="'+w[0]+'">'+t('aiw.'+w[0])+'</option>').join('')+'</select></div>'+
    '<div><label>'+t('aiM.llmState')+'</label><div class="tiny" style="margin-top:4px">'+(hasLlm?(ic('check')+t('aiM.llmOk')+esc(ll.provider)+t('aiM.llmOk2')+esc(ll.model||t('aiM.llmDefault'))):(ic('triangle-alert')+t('aiM.llmNone')))+' <a href="#" id="aiCfgLlm" class="tiny">'+t('aiM.cfg')+'</a></div></div></div>'+
    '<fieldset><legend>'+t('aiM.fldTools')+'</legend>'+
    '<div class="muted tiny" style="margin-bottom:6px">'+t('aiM.toolsDesc')+'</div>'+
    AI_TOOLS.map(it=>'<label style="width:auto;margin-right:10px"><input type="checkbox" class="aiToolChk" value="'+it[1]+'" style="width:auto" checked> '+it[0]+' '+esc(it[1])+'</label>').join('')+'</fieldset>'+
    '<fieldset><legend>'+t('aiM.fldNotify')+'</legend>'+
    '<div class="muted tiny" style="margin-bottom:6px">'+t('aiM.notifyDesc')+'</div>'+
    '<label style="width:auto"><input type="checkbox" id="aiNotifyOn" style="width:auto"'+(nc.enabled?' checked':'')+'> '+t('aiM.enablePush')+'</label>'+
    '<div class="row" style="margin-top:6px"><div><label>'+t('aiM.platform')+'</label><select id="aiNotifyPlat">'+AI_IM_PLATFORMS.map(p=>'<option value="'+p[0]+'"'+(nc.platform===p[0]?' selected':'')+'>'+p[1]+'</option>').join('')+'</select></div></div>'+
    '<label>'+t('aiM.webhook')+'</label><input id="aiNotifyWebhook" value="'+esc(nc.webhook||'')+'" placeholder="'+t('aiM.webhookPh')+'">'+
    '<label>'+t('aiM.secret')+'</label><input id="aiNotifySecret" value="'+esc(nc.secret||'')+'" placeholder="'+t('aiM.secretPh')+'">'+
    '<label style="width:auto;margin-top:6px"><input type="checkbox" id="aiNotifyAtAll" style="width:auto"'+(nc.atAll?' checked':'')+'> '+t('aiM.atAll')+'</label></fieldset>',
    '<button class="sec" onclick="closeModal()">'+t('c.cancel')+'</button><button class="sec" id="aiNotifyTest">'+ic('bell','btn-ic')+t('aiM.testPush')+'</button><button id="aiStart">'+ic('play','btn-ic')+t('aiM.start')+'</button>');
  api('/api/targets').then(ts=>{const sel=$('aiTgt');(ts||[]).forEach(t=>{const o=document.createElement('option');o.value=t.address;o.text=t.address;sel.appendChild(o);});});
  $('aiTgt').onchange=()=>{if($('aiTgt').value)$('aiOrigin').value=$('aiTgt').value;};
  document.querySelectorAll('[data-goal]').forEach(b=>b.onclick=()=>$('aiGoal').value=b.dataset.goal);
  $('aiCfgLlm').onclick=(e)=>{e.preventDefault();closeModal();openLlmModal();};
  $('aiNotifyTest').onclick=async()=>{
    await saveAiNotifyFromModal();
    const r=await api('/api/ai-notify/test',{method:'POST'});
    alert(r&&r.ok?(t('aiM.testSent')):t('aiM.testFail')+((r&&r.error)||(r&&r.stderr)||t('aiM.testFail2')));
  };
  $('aiStart').onclick=async()=>{
    const origin=$('aiOrigin').value.trim()||$('aiTgt').value;
    const goal=$('aiGoal').value.trim();
    if(!origin){alert(t('aiM.noOrigin'));return;}
    if(!goal){alert(t('aiM.noGoal'));return;}
    await saveAiNotifyFromModal();
    const hints=$('aiHints').value.split('\n').map(s=>s.trim()).filter(Boolean);
    const toolsSel=Array.from(document.querySelectorAll('.aiToolChk:checked')).map(c=>c.value);
    const body={origin,goal,hints,worker:$('aiWorker').value,tools:toolsSel};
    const r=await api('/api/ai-pentest',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    if(!r||!r.id){alert(t('aiM.createFail')+((r&&r.error)||t('aiM.unknownErr')));return;}
    closeModal();
    $('srvStatus').textContent=t('aiM.started')+r.id+t('aiM.started2');
    location.hash='#/ai-pentest/'+r.id;
  };
}
// 注入 Hint 模态框
function openHintModal(pid){
  modalBox('<h2>'+ic('lightbulb')+t('hint.title')+'</h2>',
    '<div class="muted tiny" style="margin-bottom:8px">'+t('hint.desc')+'</div>'+
    '<textarea id="hintContent" rows="3" placeholder="'+t('hint.ph')+'"></textarea>'+
    '<div class="row" style="margin-top:6px"><input id="hintCreator" placeholder="'+t('hint.creator')+'" style="flex:1"></div>',
    '<button class="sec" onclick="closeModal()">'+t('c.cancel')+'</button><button id="hintSubmit">'+t('hint.submit')+'</button>');
  $('hintSubmit').onclick=async()=>{
    const c=$('hintContent').value.trim();if(!c){alert(t('hint.empty'));return;}
    const r=await api('/api/ai-pentest/'+pid+'/hint',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({content:c,creator:$('hintCreator').value.trim()||'analyst'})});
    closeModal();
    if(r&&r.id)renderAIDetail(pid);
    else alert(t('hint.fail'));
  };
}
// LLM 配置模态框
async function openLlmModal(){
  await aiLoadLlm();
  const ll=(_aiLlm&&_aiLlm.config)||{provider:'openai',base_url:'',api_key:'',model:''};
  const cc=(_aiLlm&&_aiLlm.claude)||{available:false,bin:'claude',hasAuth:false,envSet:false};
  modalBox('<h2>'+ic('settings')+t('llmM.title')+'</h2>',
    '<div class="muted tiny" style="margin-bottom:8px">'+t('llmM.desc')+'</div>'+
    '<fieldset><legend>'+t('llmM.ccTitle')+'</legend><div class="tiny" style="margin-bottom:6px">'+(cc.available?(ic('check')+t('llmM.ccReady')+esc(cc.bin)+t('llmM.ccReady2')):(ic('triangle-alert')+t('llmM.ccNotReady')+(cc.hasAuth?'':t('llm.noKey'))+(cc.envSet?'':t('llm.noBase'))+(!cc.hasAuth&&!cc.envSet?'':'; bin='+esc(cc.bin))))+'</div>'+
    '<label>'+t('llmM.ccModel')+'</label><input id="llmCcModel" value="'+esc(ll.ccModel||'')+'" placeholder="'+t('llm.ccModelPh')+'"></fieldset>'+
    '<fieldset><legend>'+t('llmM.llmTitle')+'</legend>'+
    '<div class="row"><div><label>'+t('llmM.provider')+'</label><select id="llmProvider"><option value="openai"'+(ll.provider==='openai'?' selected':'')+'>'+t('llm.providerOpenai')+'</option><option value="anthropic"'+(ll.provider==='anthropic'?' selected':'')+'>'+t('llm.providerAnthropic')+'</option></select></div>'+
    '<div><label>'+t('llmM.model')+'</label><input id="llmModel" value="'+esc(ll.model||'')+'" placeholder="'+t('llm.modelPh')+'"></div></div>'+
    '<label>'+t('llmM.baseUrl')+'</label><input id="llmBaseUrl" value="'+esc(ll.base_url||'')+'" placeholder="'+t('llm.baseUrlPh')+'">'+
    '<label>'+t('llmM.apiKey')+'</label><input id="llmApiKey" type="password" value="'+esc(ll.api_key||'')+'" placeholder="sk-..."></fieldset>',
    '<button class="sec" onclick="closeModal()">'+t('c.cancel')+'</button><button id="llmSave">'+t('llmM.save')+'</button>');
  $('llmSave').onclick=async()=>{
    const body={provider:$('llmProvider').value,base_url:$('llmBaseUrl').value.trim(),api_key:$('llmApiKey').value.trim(),model:$('llmModel').value.trim(),ccModel:$('llmCcModel')?$('llmCcModel').value.trim():''};
    const r=await api('/api/ai-pentest/llm-config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    closeModal();
    _aiLlm=r;
    if(body.api_key&&body.base_url)$('srvStatus').textContent=t('llm.saved');
    else if(body.ccModel)$('srvStatus').textContent=t('llm.ccModelSaved');
    else $('srvStatus').textContent=t('llm.savedRule');
  };
}
// 从新建模态框读取推送配置并 POST 到后端持久化
async function saveAiNotifyFromModal(){
  const cfg={enabled:$('aiNotifyOn')?$('aiNotifyOn').checked:false,
    platform:($('aiNotifyPlat')?$('aiNotifyPlat').value:'feishu'),
    webhook:($('aiNotifyWebhook')?$('aiNotifyWebhook').value:'').trim(),
    secret:($('aiNotifySecret')?$('aiNotifySecret').value:'').trim(),
    atAll:$('aiNotifyAtAll')?$('aiNotifyAtAll').checked:false,
    events:((_aiNotify&&_aiNotify.config&&_aiNotify.config.events)||{fact:true,goal:true,stopped:true})};
  try{const r=await api('/api/ai-notify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(cfg)});_aiNotify=r;}catch(e){}
}

// ===== 全局配置页(分组 Tab) =====
// 把散落在「代理设置」「AI 渗透通知」「常规设置」里的全局配置统一收口到一个 Tab 页,
// 分组:LLM / 推送 / 代理 / 运行时信息。每个 Tab 复用各已有 render 函数,集中入口。
let _cfgTab='llm';
const CFG_TABS=[['llm','cfg.tabLlm'],['notify','cfg.tabNotify'],['email','cfg.tabEmail'],['extensions','cfg.tabExt'],['proxy','cfg.tabProxy']];
let _emailCfg=null;
let _extCfg=null;
async function aiLoadEmail(){if(_emailCfg)return _emailCfg;try{_emailCfg=await api('/api/email');}catch(e){_emailCfg={ok:false,config:{}};}return _emailCfg;}
async function aiLoadExt(){try{_extCfg=await api('/api/ai-extensions');}catch(e){_extCfg={ok:false,mcp:[],skills:[]};}return _extCfg;}
async function renderConfig(){
  await Promise.all([aiLoadLlm(),aiLoadNotify(),aiLoadEmail(),aiLoadExt(),(async()=>{try{_status=await api('/api/status');}catch(e){}})()]);
  const tabBtns=CFG_TABS.map(it=>'<div class="cfg-tab'+(it[0]===_cfgTab?' active':'')+'" data-t="'+it[0]+'">'+esc(t(it[1]))+'</div>').join('');
  let pane;
  if(_cfgTab==='llm') pane=cfgLlmPane();
  else if(_cfgTab==='notify') pane=cfgNotifyPane();
  else if(_cfgTab==='email') pane=cfgEmailPane();
  else if(_cfgTab==='extensions') pane=cfgExtPane();
  else pane=cfgProxyPane();
  $('view').innerHTML=pageHead(t('cfg.title'),t('cfg.desc'),'<button class="sec" onclick="renderConfig()">'+t('c.refresh')+'</button>')+
    '<div class="cfg-layout"><div class="cfg-tabs" id="cfgTabs">'+tabBtns+'</div><div class="cfg-pane" id="cfgPane">'+pane+'</div></div>'+
    '<span id="cfgMsg" class="muted tiny"></span>';
  document.querySelectorAll('.cfg-tab').forEach(b=>b.onclick=()=>{_cfgTab=b.dataset.t;renderConfig();});
  if(_cfgTab==='llm') wireCfgLlm();
  else if(_cfgTab==='notify') wireCfgNotify();
  else if(_cfgTab==='email') wireCfgEmail();
  else if(_cfgTab==='extensions') wireCfgExt();
  else if(_cfgTab==='proxy') wireCfgProxy();
}
// --- LLM tab ---
function cfgLlmPane(){
  const ll=(_aiLlm&&_aiLlm.config)||{provider:'openai',base_url:'',api_key:'',model:''};
  const cc=(_aiLlm&&_aiLlm.claude)||{available:false,bin:'claude',hasAuth:false,envSet:false};
  const ccState=cc.available?(ic('check')+t('llm.ccReady')+esc(cc.bin)+t('llm.ccReady2')):(ic('triangle-alert')+t('llm.ccNotReady')+(cc.hasAuth?'':t('llm.noKey'))+(cc.envSet?'':t('llm.noBase'))+(!cc.hasAuth&&!cc.envSet?'':'; bin='+esc(cc.bin)));
  const hasLlm=!!(ll.api_key&&ll.base_url);
  return '<div class="card"><h3>'+t('llm.ccTitle')+'</h3><div class="tiny muted" style="margin-bottom:8px">'+ccState+'</div>'+
    '<label>'+t('llm.ccModel')+'</label><input id="llmCcModel" value="'+esc(ll.ccModel||'')+'" placeholder="'+t('llm.ccModelPh')+'"></div>'+
    '<div class="card"><h3>'+t('llm.llmTitle')+(hasLlm?' <span class="pill st-done">'+t('llm.configured')+'</span>':' <span class="pill st-stopped">'+t('llm.notConfigured')+'</span>')+'</h3>'+
    '<div class="row"><div><label>'+t('llm.provider')+'</label><select id="llmProvider"><option value="openai"'+(ll.provider==='openai'?' selected':'')+'>'+t('llm.providerOpenai')+'</option><option value="anthropic"'+(ll.provider==='anthropic'?' selected':'')+'>'+t('llm.providerAnthropic')+'</option></select></div>'+
    '<div><label>'+t('llm.model')+'</label><input id="llmModel" value="'+esc(ll.model||'')+'" placeholder="'+t('llm.modelPh')+'"></div></div>'+
    '<label>'+t('llm.baseUrl')+'</label><input id="llmBaseUrl" value="'+esc(ll.base_url||'')+'" placeholder="'+t('llm.baseUrlPh')+'">'+
    '<label>'+t('llm.apiKey')+'</label><input id="llmApiKey" type="password" value="'+esc(ll.api_key||'')+'" placeholder="sk-...">'+
    '<div class="row" style="margin-top:10px"><button id="cfgLlmSave">'+t('c.save')+'</button><button class="sec" id="cfgLlmTest">'+t('llm.testConn')+'</button></div>'+
    '<div id="cfgLlmTestMsg" class="muted tiny" style="margin-top:6px"></div></div>';
}
function wireCfgLlm(){
  $('cfgLlmSave').onclick=async()=>{
    const body={provider:$('llmProvider').value,base_url:$('llmBaseUrl').value.trim(),api_key:$('llmApiKey').value.trim(),model:$('llmModel').value.trim(),ccModel:$('llmCcModel')?$('llmCcModel').value.trim():''};
    const r=await api('/api/ai-pentest/llm-config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    _aiLlm=r;$('cfgMsg').textContent=(r&&r.ok)?t('llm.saved'):t('llm.saveFail');
    setTimeout(()=>renderConfig(),300);
  };
  $('cfgLlmTest').onclick=async()=>{
    $('cfgLlmTestMsg').textContent=t('llm.testing');
    const r=await api('/api/ai-pentest/llm-test',{method:'POST'});
    if(r&&r.ok) $('cfgLlmTestMsg').textContent=t('llm.testOk')+esc(r.model||'')+t('llm.testOk2')+esc((r.reply||'').slice(0,80));
    else $('cfgLlmTestMsg').textContent=t('llm.testFail')+esc((r&&r.error)||t('llm.testFail2'));
  };
}
// --- 推送 tab ---
function cfgNotifyPane(){
  const nc=(_aiNotify&&_aiNotify.config)||{enabled:false,platform:'feishu',mode:'webhook',webhook:'',secret:'',atAll:false,events:{fact:true,goal:true,stopped:true}};
  const isFeishu=nc.platform==='feishu';
  const mode=isFeishu?(nc.mode||'webhook'):'webhook';
  const appBound=!!(nc.feishuAppId&&nc.feishuAppSecret&&nc.feishuOpenId);
  const modeSel=isFeishu?('<div class="row" style="margin-top:6px"><div><label>'+t('notify.mode')+'</label><select id="cfgAnMode"><option value="webhook"'+(mode==='webhook'?' selected':'')+'>'+t('notify.modeWebhook')+'</option><option value="app"'+(mode==='app'?' selected':'')+'>'+t('notify.modeApp')+'</option></select></div></div>'):'';
  const webhookFields='<label>'+t('notify.webhook')+'</label><input id="cfgAnWebhook" value="'+esc(nc.webhook||'')+'" placeholder="'+t('notify.webhookPh')+'">'+
    '<label>'+t('notify.secret')+'</label><input id="cfgAnSecret" value="'+esc(nc.secret||'')+'" placeholder="'+t('notify.secretPh')+'">';
  const appFields='<div class="muted tiny" id="cfgAnAppState" style="margin-top:4px">'+(appBound?t('notify.appBound'):t('notify.appUnbound'))+'</div>'+
    '<div class="row" style="margin-top:6px"><button type="button" class="sec" id="cfgAnQrGen">'+ic('qr-code','btn-ic')+(appBound?t('notify.qrRegen'):t('notify.qrGen'))+'</button></div>'+
    '<div id="cfgAnQrBox" style="margin-top:10px;text-align:center"></div>';
  return '<div class="card"><div class="muted tiny" style="margin-bottom:10px"><span class="stub-badge">'+t('notify.principle')+'</span>'+t('notify.principleDesc')+'</div>'+
    '<div class="row"><div><label>'+t('notify.enableLbl')+'</label><label style="width:auto"><input type="checkbox" id="cfgAnOn" style="width:auto"'+(nc.enabled?' checked':'')+'> '+t('notify.enable')+'</label></div>'+
    '<div><label>'+t('notify.platform')+'</label><select id="cfgAnPlat">'+AI_IM_PLATFORMS.map(p=>'<option value="'+p[0]+'"'+(nc.platform===p[0]?' selected':'')+'>'+p[1]+'</option>').join('')+'</select></div></div>'+
    modeSel+
    '<div id="cfgAnModeFields">'+(mode==='app'?appFields:webhookFields)+'</div>'+
    '<label style="width:auto;margin-top:8px"><input type="checkbox" id="cfgAnAtAll" style="width:auto"'+(nc.atAll?' checked':'')+'> '+t('notify.atAll')+'</label>'+
    '<fieldset style="margin-top:10px"><legend>'+t('notify.events')+'</legend>'+
    '<label style="width:auto"><input type="checkbox" class="cfgAnEvt" data-k="fact" style="width:auto"'+(nc.events&&nc.events.fact!==false?' checked':'')+'> '+t('notify.evtFact')+'</label> &nbsp;'+
    '<label style="width:auto"><input type="checkbox" class="cfgAnEvt" data-k="goal" style="width:auto"'+(nc.events&&nc.events.goal!==false?' checked':'')+'> '+t('notify.evtGoal')+'</label> &nbsp;'+
    '<label style="width:auto"><input type="checkbox" class="cfgAnEvt" data-k="stopped" style="width:auto"'+(nc.events&&nc.events.stopped!==false?' checked':'')+'> '+t('notify.evtStopped')+'</label></fieldset>'+
    '<div class="row" style="margin-top:10px"><button id="cfgAnSave">'+t('c.save')+'</button><button class="sec" id="cfgAnTest">'+ic('bell','btn-ic')+t('notify.testBtn')+'</button></div>'+
    '<div id="cfgAnTestMsg" class="muted tiny" style="margin-top:6px"></div></div>';
}
let _cfgNotifyQrTimer=null;
function wireCfgNotify(){
  const collect=()=>{
    const plat=$('cfgAnPlat').value;
    const mode=(plat==='feishu'&&$('cfgAnMode'))?$('cfgAnMode').value:'webhook';
    const base=(_aiNotify&&_aiNotify.config)||{};
    const cfg={enabled:$('cfgAnOn').checked,platform:plat,mode:plat==='feishu'?mode:'webhook',
      webhook:mode==='webhook'?($('cfgAnWebhook')?$('cfgAnWebhook').value:'').trim():(base.webhook||''),
      secret:mode==='webhook'?($('cfgAnSecret')?$('cfgAnSecret').value:'').trim():(base.secret||''),
      atAll:$('cfgAnAtAll').checked,
      feishuAppId:base.feishuAppId||'',feishuAppSecret:base.feishuAppSecret||'',feishuOpenId:base.feishuOpenId||'',feishuIsLark:!!base.feishuIsLark,
      events:{fact:document.querySelector('.cfgAnEvt[data-k=fact]').checked,goal:document.querySelector('.cfgAnEvt[data-k=goal]').checked,stopped:document.querySelector('.cfgAnEvt[data-k=stopped]').checked}};
    return cfg;
  };
  const stopQrPoll=()=>{if(_cfgNotifyQrTimer){clearTimeout(_cfgNotifyQrTimer);_cfgNotifyQrTimer=null;}};
  const pollQr=async(token)=>{
    stopQrPoll();
    try{
      const r=await api('/api/ai-notify/feishu/qrcode/poll',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token})});
      if(r&&r.ok&&r.done){
        const box=$('cfgAnQrBox');if(box)box.innerHTML='<div class="tiny" style="color:var(--ok,#2a8)">'+t('notify.qrDone')+'</div>';
        const st=$('cfgAnAppState');if(st)st.textContent=t('notify.appBound');
        await aiLoadNotify(true);
        return;
      }
      if(r&&r.ok&&!r.done){_cfgNotifyQrTimer=setTimeout(()=>pollQr(token),2500);return;}
      const box=$('cfgAnQrBox');if(box)box.innerHTML='<div class="tiny" style="color:var(--err,#a33)">'+esc((r&&r.error)||t('notify.qrExpire'))+'</div>';
    }catch(e){_cfgNotifyQrTimer=setTimeout(()=>pollQr(token),2500);}
  };
  const wireMode=()=>{
    const modeSel=$('cfgAnMode');
    if(modeSel)modeSel.onchange=()=>{rerenderFields();};
    const gen=$('cfgAnQrGen');
    if(gen)gen.onclick=async()=>{
      stopQrPoll();
      const box=$('cfgAnQrBox');if(box)box.innerHTML='<div class="muted tiny">'+t('notify.qrGen')+'…</div>';
      try{
        const r=await api('/api/ai-notify/feishu/qrcode/start',{method:'POST'});
        if(!r||!r.ok){if(box)box.innerHTML='<div class="tiny" style="color:var(--err,#a33)">'+t('notify.qrFail')+esc((r&&r.error)||'')+'</div>';return;}
        if(box)box.innerHTML='<img src="'+r.qr+'" width="240" height="240" alt="qr"><div class="muted tiny" style="margin-top:6px">'+t('notify.qrWait')+'</div>';
        pollQr(r.token);
      }catch(e){if(box)box.innerHTML='<div class="tiny" style="color:var(--err,#a33)">'+t('notify.qrFail')+esc(e.message||e)+'</div>';}
    };
  };
  const rerenderFields=()=>{
    const plat=$('cfgAnPlat').value;
    const mode=(plat==='feishu'&&$('cfgAnMode'))?$('cfgAnMode').value:'webhook';
    const nc=(_aiNotify&&_aiNotify.config)||{};
    const isFeishu=plat==='feishu';
    let modeSel='';
    if(isFeishu){modeSel='<div class="row" style="margin-top:6px"><div><label>'+t('notify.mode')+'</label><select id="cfgAnMode"><option value="webhook"'+(mode==='webhook'?' selected':'')+'>'+t('notify.modeWebhook')+'</option><option value="app"'+(mode==='app'?' selected':'')+'>'+t('notify.modeApp')+'</option></select></div></div>';}
    const webhookFields='<label>'+t('notify.webhook')+'</label><input id="cfgAnWebhook" value="'+esc(nc.webhook||'')+'" placeholder="'+t('notify.webhookPh')+'"><label>'+t('notify.secret')+'</label><input id="cfgAnSecret" value="'+esc(nc.secret||'')+'" placeholder="'+t('notify.secretPh')+'">';
    const appBound=!!(nc.feishuAppId&&nc.feishuAppSecret&&nc.feishuOpenId);
    const appFields='<div class="muted tiny" id="cfgAnAppState" style="margin-top:4px">'+(appBound?t('notify.appBound'):t('notify.appUnbound'))+'</div><div class="row" style="margin-top:6px"><button type="button" class="sec" id="cfgAnQrGen">'+ic('qr-code','btn-ic')+(appBound?t('notify.qrRegen'):t('notify.qrGen'))+'</button></div><div id="cfgAnQrBox" style="margin-top:10px;text-align:center"></div>';
    $('cfgAnModeFields').outerHTML='<div id="cfgAnModeFields">'+(isFeishu?modeSel:'')+(mode==='app'?appFields:webhookFields)+'</div>';
    wireMode();
  };
  const plat=$('cfgAnPlat');if(plat)plat.onchange=()=>{rerenderFields();};
  wireMode();
  $('cfgAnSave').onclick=async()=>{const r=await api('/api/ai-notify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(collect())});$('cfgMsg').textContent=(r&&r.ok)?t('notify.saved'):t('llm.saveFail');_aiNotify=r;};
  $('cfgAnTest').onclick=async()=>{$('cfgAnTestMsg').textContent=t('notify.testing');await api('/api/ai-notify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(collect())});const r=await api('/api/ai-notify/test',{method:'POST'});if(r&&r.ok) $('cfgAnTestMsg').textContent=t('notify.testOk');else $('cfgAnTestMsg').textContent=t('notify.testFail')+esc((r&&r.error)||t('notify.testFail2'));};
}
// --- 代理 tab ---
function cfgProxyPane(){
  return '<div class="card"><h3>'+t('px.cur')+'</h3><div id="cfgProxyCur" class="muted">'+t('px.loading')+'</div></div>'+
    '<div class="card"><h3>'+t('px.cfg')+'</h3>'+
    '<div class="row"><div><label>'+t('px.scheme')+'</label><select id="cfgPxScheme"><option value="http">http</option><option value="socks5">socks5</option><option value="socks5h">'+t('px.schemeSocks5h')+'</option></select></div>'+
    '<div><label>'+t('px.host')+'</label><input id="cfgPxHost" placeholder="'+t('px.hostPh')+'"></div>'+
    '<div><label>'+t('px.port')+'</label><input id="cfgPxPort" type="number" placeholder="'+t('px.portPh')+'"></div></div>'+
    '<div class="row"><div><label>'+t('px.user')+'</label><input id="cfgPxUser" placeholder="'+t('px.userPh')+'"></div><div><label>'+t('px.pass')+'</label><input id="cfgPxPass" type="password" placeholder=""></div></div>'+
    '<div class="row" style="margin-top:10px"><button id="cfgPxSave">'+t('c.save')+'</button><button class="sec" id="cfgPxTest">'+t('px.test')+'</button><button class="sec" id="cfgPxClear">'+t('px.clear')+'</button></div>'+
    '<p class="muted tiny" style="margin-top:8px">'+t('px.hint')+'</p></div>';
}
function wireCfgProxy(){
  let cur=null;
  api('/api/proxy').then(r=>{cur=r.proxyUrl||null;$('cfgProxyCur').textContent=cur?(t('px.enabled')+cur):t('px.disabled');cfgFillProxy(r.proxyUrl);}).catch(()=>{$('cfgProxyCur').textContent=t('px.disabled');});
  const build=()=>{const scheme=$('cfgPxScheme').value;const host=$('cfgPxHost').value.trim();if(!host){alert(t('px.hostReq'));return false;}const port=$('cfgPxPort').value.trim();const user=$('cfgPxUser').value;const pass=$('cfgPxPass').value;const auth=(user||pass)?(encodeURIComponent(user)+(pass?':'+encodeURIComponent(pass):'')+'@'):'';return scheme+'://'+auth+host+(port?':'+port:'');};
  $('cfgPxSave').onclick=async()=>{const u=build();if(u===false)return;const r=await api('/api/proxy',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({proxyUrl:u})});if(r&&r.error){$('cfgMsg').textContent=t('px.fail')+r.error;return;}cur=r.proxyUrl||null;$('cfgProxyCur').textContent=cur?(t('px.enabled')+cur):t('px.disabled');$('cfgMsg').textContent=t('px.saved');};
  $('cfgPxClear').onclick=async()=>{await api('/api/proxy',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({proxyUrl:''})});cur=null;$('cfgProxyCur').textContent=t('px.disabled');$('cfgMsg').textContent=t('px.cleared');};
  $('cfgPxTest').onclick=async()=>{const u=build();if(u===false)return;$('cfgMsg').textContent=t('px.testing');const r=await api('/api/proxy/test?proxyUrl='+encodeURIComponent(u));if(r&&r.ok)$('cfgMsg').textContent=t('px.ok')+r.status+t('px.ok2')+(r.elapsedMs||0)+t('px.ok3');else $('cfgMsg').textContent=t('px.fail')+((r&&r.error)||('HTTP '+(r&&r.status))||t('email.testFail2'));};
}
function cfgFillProxy(url){if(!url)return;try{const u=new URL(url);const proto=u.protocol.replace(/:$/,'');const sel=$('cfgPxScheme');for(const o of sel.options){if(o.value===proto){sel.value=o.value;break;}}$('cfgPxHost').value=u.hostname;$('cfgPxPort').value=u.port||'';$('cfgPxUser').value=u.username?decodeURIComponent(u.username):'';$('cfgPxPass').value=u.password?decodeURIComponent(u.password):'';}catch(e){}}
// --- 运行时 tab ---
function cfgRuntimePane(){
  const st=_status||{};
  return '<div class="card"><h3>'+t('rt.title')+'</h3><div class="kv">'+
    kv(t('rt.version'),st.version)+kv(t('rt.root'),st.projectRoot)+kv(t('rt.port'),st.port)+kv(t('rt.testServer'),st.testServer?t('rt.enabled'):t('rt.disabled'))+
    kv(t('rt.targetCount'),st.targetCount)+kv(t('rt.profileCount'),st.profileCount)+'</div></div>'+
    '<div class="card"><h3>'+t('rt.cmdTitle')+'</h3><div class="det">node runtime/run.js --webui [--webui-port P] [--serve]</div></div>';
}
// --- 邮件 tab ---
function cfgEmailPane(){
  const e=(_emailCfg&&_emailCfg.config)||{enabled:false,host:'',port:25,secure:false,user:'',pass:'',from:'',to:'',events:{scanDone:true,highVuln:true}};
  return '<div class="card"><div class="muted tiny" style="margin-bottom:10px"><span class="stub-badge">'+t('email.zeroDep')+'</span>'+t('email.desc')+'</div>'+
    '<label style="width:auto"><input type="checkbox" id="emOn" style="width:auto"'+(e.enabled?' checked':'')+'> '+t('email.enable')+'</label>'+
    '<div class="row" style="margin-top:8px"><div><label>'+t('email.host')+'</label><input id="emHost" value="'+esc(e.host||'')+'" placeholder="'+t('email.hostPh')+'"></div>'+
    '<div><label>'+t('email.port')+'</label><input id="emPort" type="number" value="'+esc(e.port||25)+'" placeholder="'+t('email.portPh')+'"></div></div>'+
    '<div class="row"><div><label>'+t('email.secure')+'</label><select id="emSecure"><option value="0"'+(!e.secure?' selected':'')+'>'+t('email.secureNone')+'</option><option value="1"'+(e.secure?' selected':'')+'>'+t('email.secureTls')+'</option></select></div>'+
    '<div><label>'+t('email.from')+'</label><input id="emFrom" value="'+esc(e.from||'')+'" placeholder="'+t('email.fromPh')+'"></div></div>'+
    '<div class="row"><div><label>'+t('email.user')+'</label><input id="emUser" value="'+esc(e.user||'')+'" placeholder="'+t('email.userPh')+'"></div>'+
    '<div><label>'+t('email.pass')+'</label><input id="emPass" type="password" value="'+esc(e.pass||'')+'" placeholder="'+t('email.passPh')+'"></div></div>'+
    '<label>'+t('email.to')+'</label><input id="emTo" value="'+esc(e.to||'')+'" placeholder="'+t('email.toPh')+'">'+
    '<fieldset style="margin-top:10px"><legend>'+t('email.events')+'</legend>'+
    '<label style="width:auto"><input type="checkbox" id="emEvtDone" style="width:auto"'+(e.events&&e.events.scanDone!==false?' checked':'')+'> '+t('email.evtDone')+'</label> &nbsp;'+
    '<label style="width:auto"><input type="checkbox" id="emEvtHigh" style="width:auto"'+(e.events&&e.events.highVuln!==false?' checked':'')+'> '+t('email.evtHigh')+'</label></fieldset>'+
    '<div class="row" style="margin-top:10px"><button id="emSave">'+t('c.save')+'</button><button class="sec" id="emTest">'+ic('mail','btn-ic')+t('email.testBtn')+'</button></div>'+
    '<div id="emTestMsg" class="muted tiny" style="margin-top:6px"></div></div>';
}
function wireCfgEmail(){
  $('emSave').onclick=async()=>{
    const body={enabled:$('emOn').checked,host:$('emHost').value.trim(),port:+$('emPort').value||25,secure:$('emSecure').value==='1',from:$('emFrom').value.trim(),user:$('emUser').value.trim(),pass:$('emPass').value,to:$('emTo').value.trim(),events:{scanDone:$('emEvtDone').checked,highVuln:$('emEvtHigh').checked}};
    const r=await api('/api/email',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    _emailCfg=r;$('cfgMsg').textContent=(r&&r.ok)?t('email.saved'):t('email.saveFail')+((r&&r.error)||'');
    setTimeout(()=>renderConfig(),300);
  };
  $('emTest').onclick=async()=>{
    $('emTestMsg').textContent=t('email.sending');
    const body={host:$('emHost').value.trim(),port:+$('emPort').value||25,secure:$('emSecure').value==='1',from:$('emFrom').value.trim(),user:$('emUser').value.trim(),pass:$('emPass').value,to:$('emTo').value.trim()};
    const r=await api('/api/email/test',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    if(r&&r.ok)$('emTestMsg').textContent=t('email.testOk');
    else $('emTestMsg').textContent=t('email.testFail')+esc((r&&r.error)||t('email.testFail2'));
  };
}
// --- MCP/技能 tab ---
// 渲染 MCP 服务器列表 + Skills 列表,支持增删改/启用/测试连接(列出工具)。
function cfgExtPane(){
  const ext=_extCfg||{mcp:[],skills:[]};
  const mcpRows=(ext.mcp||[]).map((m,i)=>extMcpRow(m,i)).join('')||'<div class="muted tiny">'+t('ext.noMcp')+'</div>';
  const skillRows=(ext.skills||[]).map((s,i)=>extSkillRow(s,i)).join('')||'<div class="muted tiny">'+t('ext.noSkill')+'</div>';
  return '<div class="card"><h3>'+t('ext.mcpTitle')+' <span class="muted tiny">'+t('ext.mcpSub')+'</span></h3>'+
    '<div class="muted tiny" style="margin-bottom:8px">'+t('ext.mcpDesc')+'</div>'+
    '<div id="extMcpList">'+mcpRows+'</div>'+
    '<div style="margin-top:6px"><button class="sec" id="extMcpAdd">'+t('ext.mcpAdd')+'</button></div></div>'+
    '<div class="card"><h3>'+t('ext.skillTitle')+' <span class="muted tiny">'+t('ext.skillSub')+'</span></h3>'+
    '<div class="muted tiny" style="margin-bottom:8px">'+t('ext.skillDesc')+'</div>'+
    '<div id="extSkillList">'+skillRows+'</div>'+
    '<div style="margin-top:6px"><button class="sec" id="extSkillAdd">'+t('ext.skillAdd')+'</button></div></div>'+
    '<div class="row" style="margin-top:10px"><button id="extSave">'+t('ext.saveAll')+'</button><span style="flex:1"></span><span id="extMsg" class="muted tiny"></span></div>';
}
function extMcpRow(m,i){
  const types=[['stdio','stdio'],['http','http'],['sse','sse']];
  const typeOpts=types.map(it=>'<option value="'+it[0]+'"'+(m.type===it[0]?' selected':'')+'>'+it[1]+'</option>').join('');
  const isHttp=m.type==='http'||m.type==='sse';
  return '<div class="ext-row" data-i="'+i+'" style="border:1px solid var(--bd);border-radius:7px;padding:8px;margin-bottom:8px">'+
    '<div class="row" style="margin-bottom:6px"><div><label>'+t('ext.nameId')+'</label><input class="m-name" value="'+esc(m.name||'')+'" placeholder="'+t('ext.namePh')+'"></div>'+
    '<div><label>'+t('ext.type')+'</label><select class="m-type">'+typeOpts+'</select></div></div>'+
    (isHttp?'<label>'+t('ext.url')+'</label><input class="m-url" value="'+esc(m.url||'')+'" placeholder="'+t('ext.urlPh')+'">':
    '<div class="row"><div><label>'+t('ext.command')+'</label><input class="m-command" value="'+esc(m.command||'')+'" placeholder="'+t('ext.commandPh')+'"></div>'+
    '<div><label>'+t('ext.args')+'</label><input class="m-args" value="'+esc((m.args||[]).join(' '))+'" placeholder="'+t('ext.argsPh')+'"></div></div>'+
    '<label>'+t('ext.env')+'</label><textarea class="m-env" rows="2" placeholder="'+t('ext.envPh')+'">'+esc(Object.keys(m.env||{}).map(k=>k+'='+(m.env[k]||'')).join('\n'))+'</textarea>')+
    '<div style="margin-top:6px"><label style="width:auto"><input type="checkbox" class="m-enabled" style="width:auto"'+(m.enabled!==false?' checked':'')+'> '+t('c.enabled')+'</label> &nbsp;'+
    '<button class="sec ext-mcp-test" data-i="'+i+'">'+t('ext.testList')+'</button> '+
    '<button class="sec danger ext-mcp-del" data-i="'+i+'">'+t('ext.del')+'</button></div>'+
    '<div class="ext-test-msg muted tiny" style="margin-top:4px"></div></div>';
}
function extSkillRow(s,i){
  return '<div class="ext-row" data-i="'+i+'" style="border:1px solid var(--bd);border-radius:7px;padding:8px;margin-bottom:8px">'+
    '<div class="row" style="margin-bottom:6px"><div><label>'+t('ext.skillName')+'</label><input class="s-name" value="'+esc(s.name||'')+'" placeholder="'+t('ext.skillNamePh')+'"></div>'+
    '<div><label style="width:auto;margin-top:22px"><input type="checkbox" class="s-enabled" style="width:auto"'+(s.enabled!==false?' checked':'')+'> '+t('c.enabled')+'</label></div></div>'+
    '<label>'+t('ext.skillBody')+'</label><textarea class="s-body" rows="3" placeholder="'+t('ext.skillBodyPh')+'">'+esc(s.body||'')+'</textarea>'+
    '<div style="margin-top:6px"><button class="sec danger ext-skill-del" data-i="'+i+'">'+t('ext.del')+'</button></div></div>';
}
function extCollect(){
  const mcp=[];document.querySelectorAll('#extMcpList .ext-row').forEach(r=>{
    const type=r.querySelector('.m-type').value;const name=r.querySelector('.m-name').value.trim()||('mcp'+(mcp.length+1));
    const id=name.replace(/[^a-zA-Z0-9_-]/g,'_');
    if(type==='http'||type==='sse'){mcp.push({id,name,type,url:r.querySelector('.m-url').value.trim(),enabled:r.querySelector('.m-enabled').checked});}
    else{const env={};r.querySelector('.m-env').value.split('\n').forEach(l=>{const c=l.indexOf('=');if(c>0)env[l.slice(0,c).trim()]=l.slice(c+1);});mcp.push({id,name,type:'stdio',command:r.querySelector('.m-command').value.trim(),args:r.querySelector('.m-args').value.split(/\s+/).filter(Boolean),env,enabled:r.querySelector('.m-enabled').checked});}
  });
  const skills=[];document.querySelectorAll('#extSkillList .ext-row').forEach(r=>{
    const name=r.querySelector('.s-name').value.trim()||('skill'+(skills.length+1));
    skills.push({id:name.replace(/[^a-zA-Z0-9_-]/g,'_'),name,body:r.querySelector('.s-body').value,enabled:r.querySelector('.s-enabled').checked});
  });
  return {mcp,skills};
}
function wireCfgExt(){
  $('extMcpAdd').onclick=()=>{_extCfg=_extCfg||{mcp:[],skills:[]};_extCfg.mcp=_extCfg.mcp||[];_extCfg.mcp.push({id:'mcp'+(_extCfg.mcp.length+1),name:'',type:'stdio',command:'',args:[],env:{},enabled:true});const el=$('extMcpList');el.insertAdjacentHTML('beforeend',extMcpRow(_extCfg.mcp[_extCfg.mcp.length-1],_extCfg.mcp.length-1));wireExtRowEvents();};
  $('extSkillAdd').onclick=()=>{_extCfg=_extCfg||{mcp:[],skills:[]};_extCfg.skills=_extCfg.skills||[];_extCfg.skills.push({id:'skill'+(_extCfg.skills.length+1),name:'',body:'',enabled:true});const el=$('extSkillList');el.insertAdjacentHTML('beforeend',extSkillRow(_extCfg.skills[_extCfg.skills.length-1],_extCfg.skills.length-1));wireExtRowEvents();};
  $('extSave').onclick=async()=>{const body=extCollect();const r=await api('/api/ai-extensions',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});_extCfg=r;$('extMsg').textContent=(r&&r.ok)?(t('ext.saved')+(r.mcp||[]).length+t('ext.saved2')+(r.skills||[]).length+t('ext.saved3')):t('ext.saveFail');setTimeout(()=>renderConfig(),400);};
  wireExtRowEvents();
}
function wireExtRowEvents(){
  document.querySelectorAll('.ext-mcp-del').forEach(b=>b.onclick=()=>{b.closest('.ext-row').remove();});
  document.querySelectorAll('.ext-skill-del').forEach(b=>b.onclick=()=>{b.closest('.ext-row').remove();});
  document.querySelectorAll('.ext-mcp-test').forEach(b=>b.onclick=async()=>{
    const row=b.closest('.ext-row');const msg=row.querySelector('.ext-test-msg');msg.textContent=t('ext.testConn');
    const cur=extCollect();const i=+b.dataset.i;const srv=cur.mcp[i];if(!srv){msg.textContent=t('ext.invalid');return;}
    await api('/api/ai-extensions',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(cur)});
    const r=await api('/api/ai-extensions/mcp/'+encodeURIComponent(srv.id)+'/test',{method:'POST'});
    if(r&&r.ok){const n=(r.tools||[]).length;msg.innerHTML=ic('check')+t('ext.testOk')+n+t('ext.testOk2')+(r.tools||[]).map(it=>esc(it.name)).slice(0,8).join(', ')+(n>8?' …':'');}
    else msg.textContent=esc((r&&r.error)||t('ext.testFail'));
  });
}


// ===== New Scan modal (replaces the old config drawer) =====
function openNewScanModal(prefill){
  prefill=prefill||{};
  modalBox('<h2>'+t('ns.title')+'</h2>',
    '<fieldset><legend>'+t('ns.fldTarget')+'</legend><label>'+t('ns.selTarget')+'</label><select id="nsTarget"><option value="">'+t('ns.manual')+'</option></select>'+
    '<label>'+t('ns.orAddr')+'</label><input id="nsAddr" placeholder="'+t('ns.addrPh')+'"><label><input type="checkbox" id="useTestServer" style="width:auto"> '+t('ns.useTest')+'</label></fieldset>'+
    '<fieldset><legend>'+t('ns.fldScan')+'</legend><select id="nsProfile"></select><div id="nsProfileNote" class="muted tiny" style="margin-top:4px"></div>'+
    '<div class="row" style="margin:8px 0 6px"><label style="width:auto"><input type="checkbox" id="pluginAuto" style="width:auto" checked onchange="togglePluginPicker()">'+t('ns.autoSel')+'</label></div>'+
    '<div id="pluginPicker" style="display:none"><div class="row" style="margin-bottom:6px"><input id="pluginFilter" placeholder="'+t('pf.filterPh')+'" style="flex:1"><button class="sec" type="button" id="btnPluginAll" style="width:auto">'+t('pf.allBtn')+'</button><button class="sec" type="button" id="btnPluginNone" style="width:auto">'+t('pf.noneBtn')+'</button></div><div id="pluginList" style="border:1px solid var(--bd);background:#fff"></div></div></fieldset>'+
    '<fieldset><legend>'+t('ns.fldCrawler')+'</legend><div class="row"><div><label>'+t('ns.mode')+'</label><select id="crawlerMode"><option value="dynamic">'+t('ns.modeDynamic')+'</option><option value="static">'+t('ns.modeStatic')+'</option></select></div><div><label>'+t('ns.apiEnum')+'</label><select id="apiEnum"><option value="1">'+t('ns.apiYes')+'</option><option value="0">'+t('ns.apiNo')+'</option></select></div></div>'+
    '<div class="row" style="margin:6px 0"><label style="width:auto"><input type="checkbox" id="discoverParentDirs" style="width:auto" checked>'+t('ns.discoverParent')+'</label></div>'+
    '<div class="row" style="margin:6px 0"><label style="width:auto"><input type="checkbox" id="postScanDiscover" style="width:auto" checked>'+t('ns.postScan')+'</label></div>'+
    '<div class="row3" style="margin-top:6px"><div><label>'+t('ns.backfillLimit')+'</label><input id="postScanDiscoverLimit" type="number" value="20" min="1" title="'+t('ns.backfillLimitTitle')+'"></div><div><label>'+t('ns.backfillRounds')+'</label><input id="postScanDiscoverDepth" type="number" value="1" min="1" max="5" title="'+t('ns.backfillRoundsTitle')+'"></div><div></div></div>'+
    '<div class="row3"><div><label>'+t('ns.pages')+'</label><input id="maxPages" type="number" value="40"></div><div><label>'+t('ns.depth')+'</label><input id="maxDepth" type="number" value="3"></div><div><label>'+t('ns.concurrency')+'</label><input id="concurrency" type="number" value="4"></div></div>'+
    '<div class="row3" style="margin-top:6px"><div><label>'+t('ns.timeout')+'</label><input id="timeoutMs" type="number" value="30000" min="1000" step="1000" title="'+t('ns.timeoutTitle')+'"></div><div><label>&nbsp;</label><span class="muted tiny" style="display:block;padding-top:9px">'+t('ns.timeoutHint')+'</span></div><div></div></div></fieldset>'+
    '<fieldset><legend>'+t('ns.fldScope')+'</legend><label>'+t('tm.include')+'</label><input id="includePatterns" placeholder="'+t('ns.incPh')+'"><label>'+t('tm.exclude')+'</label><input id="excludePatterns" placeholder="'+t('ns.excPh')+'" value="'+esc((window.DEFAULT_EXCLUDE_PATTERNS||[]).join(','))+'"></fieldset>'+
    '<fieldset><legend>'+t('ns.fldReq')+'</legend><div class="row"><div><label>'+t('ns.method')+'</label><select id="reqMethod"><option>GET</option><option>POST</option><option>PUT</option><option>DELETE</option><option>HEAD</option><option>OPTIONS</option><option>PATCH</option></select></div><div><label>&nbsp;</label><span class="muted tiny" style="display:block;padding-top:9px">'+t('ns.reqSeedHint')+'</span></div></div>'+
    '<label>'+t('ns.customHeaders')+'</label><textarea id="reqHeaders" rows="3" placeholder="'+t('ns.headersPh')+'"></textarea>'+
    '<label>'+t('ns.reqBody')+'</label><textarea id="reqBody" rows="3" placeholder="'+t('ns.bodyPh')+'"></textarea></fieldset>'+
    '<fieldset><legend>'+t('ns.fldAuth')+'</legend>'+authFieldsHtml(prefill.auth||null)+'</fieldset>'+
    '<fieldset><legend>'+t('ns.fldProxy')+'</legend><div id="nsProxyState" class="muted tiny" style="margin-bottom:6px">'+t('px.loading')+'</div>'+
    '<div><label><input type="radio" name="nsProxyMode" value="global" checked style="width:auto">'+t('px.global')+'</label></div>'+
    '<div><label><input type="radio" name="nsProxyMode" value="custom" style="width:auto">'+t('px.custom')+'</label></div>'+
    '<div id="nsProxyCustom" style="display:none;margin-left:18px"><label>'+t('px.proxyUrl')+'</label><input id="nsProxyUrl" placeholder="'+t('px.proxyUrlPh')+'"></div>'+
    '<div><label><input type="radio" name="nsProxyMode" value="none" style="width:auto">'+t('px.none')+'</label></div></fieldset>',
    '<button class="sec" onclick="closeModal()">'+t('c.cancel')+'</button><button class="sec" id="nsScanOnly">'+ic('shield-alert','btn-ic')+t('ns.scanOnly')+'</button><button class="sec" id="nsCrawlOnly">'+ic('search','btn-ic')+t('ns.crawlOnly')+'</button><button id="nsCrawl">'+ic('play','btn-ic')+t('ns.crawlScan')+'</button>');
  // populate target + profile selects
  api('/api/targets').then(ts=>{_targets=ts;const sel=$('nsTarget');ts.forEach(t=>{const o=document.createElement('option');o.value=t.id;o.text=t.address;sel.appendChild(o);});if(prefill.targetId){sel.value=prefill.targetId;sel.onchange();}});
  api('/api/profiles').then(ps=>{_profiles=ps;const sel=$('nsProfile');ps.forEach(p=>{const o=document.createElement('option');o.value=p.id;o.text=p.name+(p.plugins.length?(' · '+t('pf.nSel')):' · '+t('pf.autoAll'));sel.appendChild(o);});if(_profiles.length){sel.value=_profiles[0].id;sel.onchange();}});
  $('nsTarget').onchange=()=>{const t=_targets.find(x=>x.id===$('nsTarget').value)||[];if(t&&t.address){$('nsAddr').value=t.address;$('includePatterns').value=(t.includePatterns||[]).join(',');$('excludePatterns').value=(t.excludePatterns||[]).join(',');$('authType').value=(t.auth&&t.auth.type)||'';renderAuthFromObj(t.auth);}};
  $('nsProfile').onchange=()=>{const p=(_profiles.length?_profiles:[]).find(x=>x.id===$('nsProfile').value);$('nsProfileNote').textContent=p?(p.plugins.length?(t('ns.selAllPlugins')+p.plugins.length+t('ns.selPlugins2')):t('ns.autoAll2')):'';
    // prefill the plugin tree with this profile's selection (so user can view/edit)
    _pluginChecked=new Set(p?p.plugins||[]:[]);if(!_pluginCatalog.length){loadPlugins();}else if($('pluginList'))renderPluginTree();};
  // plugin tree controls
  $('pluginFilter').oninput=renderPluginTree;
  $('btnPluginAll').onclick=()=>{for(const g of _pluginCatalog)for(const pl of g.plugins)_pluginChecked.add(pl.rel);renderPluginTree();};
  $('btnPluginNone').onclick=()=>{_pluginChecked.clear();renderPluginTree();};
  togglePluginPicker();   // start in auto mode (tree hidden); load plugins on demand
  // proxy mode radios: toggle the custom-proxy URL input on "custom"
  function syncNsProxy(){const mode=([...'nsProxyMode'].length&&document.querySelector('input[name="nsProxyMode"]:checked'))?document.querySelector('input[name="nsProxyMode"]:checked').value:'global';const c=$('nsProxyCustom');if(c)c.style.display=(mode==='custom')?'':'none';}
  document.querySelectorAll('input[name="nsProxyMode"]').forEach(r=>r.onchange=syncNsProxy);
  api('/api/proxy').then(r=>{const s=$('nsProxyState');if(s)s.textContent=r&&r.proxyUrl?(t('px.curGlobal')+r.proxyUrl):t('px.noGlobal');}).catch(()=>{});
  // defaults
  if(prefill.targetId){const t=_targets.find(x=>x.id===prefill.targetId);if(t)$('nsAddr').value=t.address;}
  renderAuthFromObj(prefill.auth||null);
  // 预填种子请求信息（来自 URL 列表「以此请求新建扫描」）。
  // 注意:method/headers/body 只在「仅扫描」模式下生效(见 startScanFromModal 的 scanOnly 分支)。
  if(prefill.url&&$('nsAddr')){$('nsAddr').value=prefill.url;$('nsTarget').value='';}
  if(prefill.method&&$('reqMethod')){const m=prefill.method.toUpperCase();const o=[...$('reqMethod').options].find(x=>x.value===m);if(o)$('reqMethod').value=m;}
  if(prefill.headers!=null&&$('reqHeaders')){$('reqHeaders').value=headersToLines(prefill.headers);}
  if(prefill.body&&$('reqBody')){$('reqBody').value=prefill.body;}
  if(prefill.url){const so=$('nsScanOnly');if(so){so.style.outline='2px solid #1ab394';}const ss=$('srvStatus');if(ss)ss.textContent=t('ns.prefilled');}
  $('nsCrawl').onclick=()=>startScanFromModal(false,false);
  $('nsCrawlOnly').onclick=()=>startScanFromModal(true,false);
  $('nsScanOnly').onclick=()=>startScanFromModal(false,true);
}
async function startScanFromModal(onlyCrawl,scanOnly){
  const tid=$('nsTarget').value;const tgt=tid?_targets.find(x=>x.id===tid):null;
  const pid=$('nsProfile').value;const p=pid?_profiles.find(x=>x.id===pid):null;
  const useTest=$('useTestServer').checked;
  const addr=useTest?'':($('nsAddr').value.trim()||(tgt?tgt.address:''));
  if(!useTest&&!addr){alert(t('ns.noAddr'));return;}
  // plugin selection: if "auto" on, use the profile as-is (profile.plugins:[] => server auto-select);
  // if off, use the tree selection (collectPlugins) which the user may have edited from the profile's preset.
  let plugins;
  if($('pluginAuto').checked){plugins=p?p.plugins:[];}
  else{plugins=collectPlugins();}
  plugins=plugins&&plugins.length?plugins:null;   // null/empty => server auto-select
  const auth=collectAuthFromModal();
  const reqHeaders=collectReqHeaders();
  const reqMethod=$('reqMethod')?($('reqMethod').value||'GET'):'GET';
  const reqBody=$('reqBody')?$('reqBody').value:'';
  const body={target:addr,useTestServer:useTest,crawlerMode:$('crawlerMode').value,apiEnum:$('apiEnum').value==='1',
    maxPages:+$('maxPages').value,maxDepth:+$('maxDepth').value,concurrency:+$('concurrency').value,timeoutMs:+$('timeoutMs').value,
    includePatterns:splitCsv($('includePatterns').value),excludePatterns:splitCsv($('excludePatterns').value),
    discoverParentDirs:$('discoverParentDirs')?$('discoverParentDirs').checked:true,
    postScanDiscover:$('postScanDiscover')?$('postScanDiscover').checked:true,
    postScanDiscoverLimit:+$('postScanDiscoverLimit').value,postScanDiscoverDepth:+$('postScanDiscoverDepth').value,
    plugins:plugins,auth:auth,autoScan:!onlyCrawl};
  const path=scanOnly?'/api/scan':'/api/crawl';
  // 自定义方法/请求体/请求头:scan-only 用作种子请求;crawl 模式用作爬虫的
  // 初始 seed 请求(后续链接抓取仍走 GET)。之前 crawl 模式丢掉这些字段,导致
  // 用户设的 POST 在爬取里变成了 GET。
  body.method=reqMethod;body.data=reqBody||null;body.headers=reqHeaders;
  // per-task proxy override: 'global' (default) -> omit (server uses globalProxy);
  // 'custom' -> body.proxyUrl; 'none' -> body.noProxy=true (force direct)
  const pxMode=document.querySelector('input[name="nsProxyMode"]:checked');
  if(pxMode){
    if(pxMode.value==='custom'){const u=($('nsProxyUrl')?$('nsProxyUrl').value.trim():'');if(!u){alert(t('px.urlReq'));return;}body.proxyUrl=u;}
    else if(pxMode.value==='none'){body.noProxy=true;}
  }
  closeModal();
  $('srvStatus').textContent=t('ns.starting');
  const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const res=await r.json();
  if(res.id){$('srvStatus').textContent=t('ns.started')+res.id+t('ns.started2');location.hash='#/scans/'+res.id;}
  else{$('srvStatus').textContent=t('ns.startFail');alert(t('ns.startFail2')+(res.error||t('ns.unknownErr')));}
}

// ===== auth (modal-scoped, reusable for target + new-scan) =====
function authFieldsHtml(auth){
  const at=auth&&auth.type?auth.type:'';
  let h='<select id="authType" onchange="renderAuthFromObj()"><option value=""'+(!at?' selected':'')+'>'+t('auth.none')+'</option><option value="form"'+(at==='form'?' selected':'')+'>'+t('auth.form')+'</option><option value="basic"'+(at==='basic'?' selected':'')+'>'+t('auth.basic')+'</option><option value="digest"'+(at==='digest'?' selected':'')+'>'+t('auth.digest')+'</option><option value="jwt"'+(at==='jwt'?' selected':'')+'>'+t('auth.jwt')+'</option><option value="token"'+(at==='token'?' selected':'')+'>'+t('auth.token')+'</option><option value="cookie"'+(at==='cookie'?' selected':'')+'>'+t('auth.cookie')+'</option><option value="header"'+(at==='header'?' selected':'')+'>'+t('auth.header')+'</option></select><div id="authFields"></div>';
  return h;
}
function renderAuthFromObj(auth){
  // read type from the select (modal) and pre-fill values from the auth arg
  auth=auth||currentAuthPrefill();
  const tp=$('authType')?$('authType').value:'';
  let h='';
  if(tp==='basic'||tp==='digest')h='<div class="row"><div><label>'+t('auth.user')+'</label><input id="auUser" value="'+esc(auth&&auth.username||'admin')+'"></div><div><label>'+t('auth.pass')+'</label><input id="auPass" value="'+esc(auth&&auth.password||'admin')+'"></div></div>';
  else if(tp==='jwt')h='<label>'+t('auth.tokenLbl')+'</label><input id="auToken" value="'+esc(auth&&auth.token||'')+'">';
  else if(tp==='token'){h='<label>'+t('auth.headerLbl')+'</label><input id="auHeader" value="'+esc(auth&&auth.header||'X-Api-Key')+'"><label>'+t('auth.value')+'</label><input id="auToken" value="'+esc(auth&&auth.value||'')+'">';}
  else if(tp==='cookie')h='<label>'+t('auth.cookieLbl')+'</label><input id="auCookie" value="'+esc(auth&&auth.cookies||'')+'">';
  else if(tp==='form'){h='<label>'+t('auth.loginUrl')+'</label><input id="auLoginUrl" value="'+esc(auth&&auth.loginUrl||'/login')+'"><div class="row"><div><label>'+t('auth.method')+'</label><select id="auMethod"><option'+((!auth||auth.method==='post')?' selected':'')+'>post</option><option'+(auth&&auth.method==='get'?' selected':'')+'>get</option></select></div><div><label>'+t('auth.validUrl')+'</label><input id="auValidUrl" value="'+esc(auth&&auth.validUrl||'')+'"></div></div><label>'+t('auth.fields')+'</label><input id="auFields" value="'+esc(auth&&auth.fields?Object.keys(auth.fields).map(k=>k+'='+auth.fields[k]).join(','):'')+'">';}
  else if(tp==='header')h='<label>'+t('auth.headerLines')+'</label><textarea id="auHeaders" rows="2">'+esc(auth&&auth.headers?auth.headers.join('\n'):'')+'</textarea>';
  if($('authFields'))$('authFields').innerHTML=h;
}
function currentAuthPrefill(){return window._authPrefill||null}
function collectAuthFromModal(){const t=$('authType')?$('authType').value:'';if(!t)return null;const a={type:t};
  if(t==='basic'||t==='digest'){a.username=$('auUser')?$('auUser').value:'';a.password=$('auPass')?$('auPass').value:'';}
  else if(t==='jwt'){a.token=$('auToken')?$('auToken').value:'';}
  else if(t==='token'){a.header=$('auHeader')?$('auHeader').value:'Authorization';a.value=$('auToken')?$('auToken').value:'';}
  else if(t==='cookie'){a.cookies=$('auCookie')?$('auCookie').value:'';}
  else if(t==='form'){a.loginUrl=$('auLoginUrl')?$('auLoginUrl').value:'/login';a.method=$('auMethod')?$('auMethod').value:'post';a.fields=pf($('auFields')?$('auFields').value:'');a.validUrl=$('auValidUrl')?$('auValidUrl').value:'';}
  else if(t==='header'){a.headers=($('auHeaders')?$('auHeaders').value:'').split('\n').map(s=>s.trim()).filter(Boolean);}return a;}
function kv(k,v){return '<div class="k">'+esc(k)+'</div><div class="v">'+esc(v==null?'':v)+'</div>';}
function pf(s){const o={};for(const kv of s.split(',')){const e=kv.indexOf('=');if(e>0)o[kv.slice(0,e).trim()]=kv.slice(e+1).trim();}return o;}
// collect custom request headers from the 请求 textarea -> ["Name: value", ...]
// (the raw "Name: value" shape that scanner.fetch expects, matching body.headers elsewhere)
function collectReqHeaders(){const el=$('reqHeaders');if(!el)return [];return el.value.split('\n').map(s=>s.trim()).filter(Boolean);}

// ===== modal helpers =====
function modalBox(head,body,foot){$('modalBox').innerHTML='<div class="modal-head">'+head+'<span class="x" onclick="closeModal()">×</span></div><div class="modal-body">'+body+'</div><div class="modal-foot">'+foot+'</div>';$('modal').classList.add('show');}
function closeModal(){$('modal').classList.remove('show');$('modalBox').innerHTML='';}
$('modal').addEventListener('click',(e)=>{if(e.target===$('modal'))closeModal();});

// ===== wiring =====
$('btnNewScan').onclick=()=>openNewScanModal();
// No auto-refresh polling: lists/dashboard/vulnerabilities used to re-render every
// 2.5s via setInterval(router), which flickered the page and reset scroll/expand
// state. Now views only refresh on explicit user action — navigating (hash change
// -> router), the 刷新 buttons on each list page, or the SSE live stream for an
// open scan-detail (vulns/progress push as they happen, not on a timer).
router();

