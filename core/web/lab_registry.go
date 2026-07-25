/**
* @Author: shaochuyu
* @Date: 7/25/2026
*
* Lab registry: the catalog of built-in (preset) vulnerable endpoints grouped
* by category, plus persistence of user-assembled "custom" labs. Each lab, once
* started, is served by the lab server (lab_server.go) on a dedicated listener.
*
* This file owns the static catalog + JSON persistence of custom labs only — it
* knows nothing about HTTP serving. The server side (how an endpoint behaves on
* the wire) lives in lab_server.go.
 */
package web

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// labCategory groups endpoints by the vulnerability class they exercise.
// `category` is the stable key the front-end groups/selects on; `vuln` is the
// human label shown in the endpoint table.
type labEndpoint struct {
	Path     string `json:"path"`
	Vuln     string `json:"vuln"`
	Plugin   string `json:"plugin"`   // wscan plugin name this endpoint is meant to trigger
	Category string `json:"category"` // group key, duplicated here for custom-lab assembly
}

// labCategoryCatalog is one top-level group in the endpoint picker.
type labCategoryCatalog struct {
	Category  string        `json:"category"`
	Endpoints []labEndpoint `json:"endpoints"`
}

// presetLab is a built-in lab bundle: a name + the categories it spans. The
// actual endpoint list is resolved from the catalog at serve time.
type presetLab struct {
	Name        string   `json:"name"`
	Label       string   `json:"label"`
	Description string   `json:"description"`
	Categories  []string `json:"categories"`
}

// customLabDef is a user-assembled lab (name + chosen categories) persisted to
// disk. `ID` is assigned at creation; the live running state lives in the
// labManager, not here.
type customLabDef struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Categories []string `json:"categories"`
}

var labCatalogOnce sync.Once

// labCatalogAll returns the flattened preset catalog. Built once (it's static).
func labCatalogAll() []labCategoryCatalog {
	c := []labCategoryCatalog{
		{
			Category: "SQL注入",
			Endpoints: []labEndpoint{
				{Path: "/sqli/error.php?id=1", Vuln: "报错注入", Plugin: "sqldet", Category: "SQL注入"},
				{Path: "/sqli/boolean.php?id=1", Vuln: "布尔盲注", Plugin: "sqldet", Category: "SQL注入"},
				{Path: "/sqli/time.php?id=1", Vuln: "时间盲注", Plugin: "sqldet", Category: "SQL注入"},
			},
		},
		{
			Category: "XSS",
			Endpoints: []labEndpoint{
				{Path: "/xss/reflected.php?q=test", Vuln: "反射型 XSS", Plugin: "xss", Category: "XSS"},
				{Path: "/xss/attr.php?name=abc", Vuln: "属性注入 XSS", Plugin: "xss", Category: "XSS"},
				{Path: "/xss/href.php?u=http://x", Vuln: "javascript: 协议 XSS", Plugin: "xss", Category: "XSS"},
			},
		},
		{
			Category: "命令注入",
			Endpoints: []labEndpoint{
				{Path: "/cmdi/ping.php?host=127.0.0.1", Vuln: "Shell 命令注入", Plugin: "cmd-injection", Category: "命令注入"},
			},
		},
		{
			Category: "路径穿越",
			Endpoints: []labEndpoint{
				{Path: "/lfi/read.php?file=report.txt", Vuln: "本地文件包含/穿越", Plugin: "path_traversal", Category: "路径穿越"},
			},
		},
		{
			Category: "开放重定向",
			Endpoints: []labEndpoint{
				{Path: "/redirect/go.php?url=/home", Vuln: "未校验重定向", Plugin: "redirect", Category: "开放重定向"},
			},
		},
		{
			Category: "CRLF注入",
			Endpoints: []labEndpoint{
				{Path: "/crlf/set.php?q=hello", Vuln: "响应头 CRLF 注入", Plugin: "crlf-injection", Category: "CRLF注入"},
			},
		},
		{
			Category: "JSONP",
			Endpoints: []labEndpoint{
				{Path: "/jsonp/data.php?callback=cb", Vuln: "JSONP 劫持", Plugin: "jsonp", Category: "JSONP"},
			},
		},
		{
			Category: "敏感文件",
			Endpoints: []labEndpoint{
				{Path: "/.env", Vuln: "环境配置泄露", Plugin: "sensitivefile", Category: "敏感文件"},
			},
		},
		{
			Category: "安全基线",
			Endpoints: []labEndpoint{
				{Path: "/baseline/error.php", Vuln: "应用错误信息泄露", Plugin: "baseline", Category: "安全基线"},
				{Path: "/baseline/cors.php", Vuln: "CORS 配置错误", Plugin: "baseline", Category: "安全基线"},
			},
		},
	}
	return c
}

// presetLabs returns the built-in lab bundles (whole catalog + a per-class one).
func presetLabs() []presetLab {
	all := labCatalogAll()
	cats := make([]string, 0, len(all))
	for _, c := range all {
		cats = append(cats, c.Category)
	}
	perClass := make([]presetLab, 0, len(all))
	for _, c := range all {
		perClass = append(perClass, presetLab{
			Name:        slug(c.Category),
			Label:       c.Category + " 靶场",
			Description: c.Category + " 类漏洞演示靶场",
			Categories:  []string{c.Category},
		})
	}
	return append([]presetLab{{
		Name:        "all",
		Label:       "综合靶场 (全部类别)",
		Description: "覆盖 SQL注入/XSS/命令注入/路径穿越/重定向/CRLF/JSONP/敏感文件/基线 的综合靶场",
		Categories:  cats,
	}}, perClass...)
}

// endpointsFor returns the concrete endpoint list for a set of categories.
// Order is stable (catalog order) so a started lab always serves the same URLs.
func endpointsFor(cats []string) []labEndpoint {
	want := map[string]bool{}
	for _, c := range cats {
		want[c] = true
	}
	var out []labEndpoint
	for _, c := range labCatalogAll() {
		if !want[c.Category] {
			continue
		}
		out = append(out, c.Endpoints...)
	}
	return out
}

// slug turns a Chinese category into an ascii id ("SQL注入" -> "sqli").
// Falls back to lowercased bytes for unknown labels.
func slug(name string) string {
	switch name {
	case "SQL注入":
		return "sqli"
	case "命令注入":
		return "cmdi"
	case "路径穿越":
		return "lfi"
	case "开放重定向":
		return "redirect"
	case "敏感文件":
		return "sensitive"
	case "安全基线":
		return "baseline"
	case "CRLF注入":
		return "crlf"
	}
	b := []byte(name)
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			out = append(out, c)
		} else if c >= 'A' && c <= 'Z' {
			out = append(out, c+32)
		}
	}
	if len(out) == 0 {
		return "lab"
	}
	return string(out)
}

// ---- custom lab persistence ----

var (
	customLabMu  sync.Mutex
	customLoaded bool
	customCache  []customLabDef
)

func customLabsFile() string { return filepath.Join(dataDir, "webui_labs.json") }

func loadCustomLabs() []customLabDef {
	customLabMu.Lock()
	defer customLabMu.Unlock()
	if !customLoaded {
		customLoaded = true
		ensureDataDir()
		if b, err := os.ReadFile(customLabsFile()); err == nil {
			_ = json.Unmarshal(b, &customCache)
		}
		if customCache == nil {
			customCache = []customLabDef{}
		}
	}
	out := make([]customLabDef, len(customCache))
	copy(out, customCache)
	return out
}

func addCustomLab(def customLabDef) {
	customLabMu.Lock()
	defer customLabMu.Unlock()
	customLoaded = true
	ensureDataDir()
	customCache = append(customCache, def)
	_ = writeJSONFile(customLabsFile(), customCache)
}

func deleteCustomLab(id string) bool {
	customLabMu.Lock()
	defer customLabMu.Unlock()
	customLoaded = true
	out := customCache[:0]
	removed := false
	for _, d := range customCache {
		if d.ID == id {
			removed = true
			continue
		}
		out = append(out, d)
	}
	if removed {
		customCache = out
		_ = writeJSONFile(customLabsFile(), customCache)
	}
	return removed
}

func findCustomLab(id string) (customLabDef, bool) {
	for _, d := range loadCustomLabs() {
		if d.ID == id {
			return d, true
		}
	}
	return customLabDef{}, false
}

// catalogForFrontend returns the endpoint picker tree (category -> endpoints),
// sorted by category for a stable UI order.
func catalogForFrontend() []labCategoryCatalog {
	out := labCatalogAll()
	sort.SliceStable(out, func(i, j int) bool { return out[i].Category < out[j].Category })
	return out
}

// suppress unused-warning when this file is compiled into a build that doesn't
// (yet) reference a helper: keep the package self-contained.
var _ = presetLabs
