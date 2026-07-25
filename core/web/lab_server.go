/**
* @Author: shaochuyu
* @Date: 7/25/2026
*
* Lab server: an in-process HTTP server that hosts the vulnerable endpoints a
* lab exposes. Each running lab gets its own *http.Server on an auto-assigned
* port; labManager tracks the live instances (preset + custom) and shuts them
* down on stop.
*
* The endpoints are deliberately small and naive — they exist only to be
* detected by wscan plugins, so each handler mirrors exactly the behavior the
* corresponding plugin's CheckAction probes for (reflection for XSS, a SQL
* error string for error-based sqli, an echo of a computed value for cmd
* injection, etc.). No real storage, no templating — just enough surface to
* trip the detector.
 */
package web

import (
	"context"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// runningLab is a live lab instance: the listener address + the server to shut
// down. labManager owns these.
type runningLab struct {
	key     string // preset name or "custom:<id>"
	addr    string // host:port
	url     string // http://host:port/
	server  *http.Server
	plugins []string
}

// labManager owns the lifecycle of all running labs.
type labManager struct {
	srv  *Server
	port int // next port to try when starting a lab

	// running labs keyed by key (preset name or "custom:<id>")
	mu   sync.RWMutex
	labs map[string]*runningLab
}

// netListen wraps net.Listen so the caller doesn't need to import net itself.
func netListen(addr string) (net.Listener, error) {
	return net.Listen("tcp", addr)
}

func newLabManager(srv *Server) *labManager {
	_ = srv

	return &labManager{srv: srv, port: 18080, labs: map[string]*runningLab{}}
}

// listRunning returns a snapshot for the labs GET endpoint. `presets` and
// `custom` are the catalog definitions; this annotates each with its live
// running/url state.
func (m *labManager) listForFrontend() (presets, custom []map[string]any) {
	presets = make([]map[string]any, 0)
	for _, p := range presetLabs() {
		eps := endpointsFor(p.Categories)
		row := map[string]any{
			"name":        p.Name,
			"label":       p.Label,
			"description": p.Description,
			"categories":  p.Categories,
			"endpoints":   endpointRows(eps),
			"running":     m.isRunning(p.Name),
			"url":         m.urlOf(p.Name),
		}
		presets = append(presets, row)
	}
	custom = make([]map[string]any, 0)
	for _, d := range loadCustomLabs() {
		key := "custom:" + d.ID
		eps := endpointsFor(d.Categories)
		row := map[string]any{
			"id":          d.ID,
			"name":        d.Name,
			"label":       d.Name,
			"description": strings.Join(d.Categories, ", "),
			"categories":  d.Categories,
			"endpoints":   endpointRows(eps),
			"running":     m.isRunning(key),
			"url":         m.urlOf(key),
		}
		custom = append(custom, row)
	}
	return
}

func endpointRows(eps []labEndpoint) []map[string]any {
	out := make([]map[string]any, 0, len(eps))
	for _, e := range eps {
		out = append(out, map[string]any{"path": e.Path, "vuln": e.Vuln})
	}
	return out
}

func (m *labManager) isRunning(key string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.labs[key]
	return ok
}

func (m *labManager) urlOf(key string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if l, ok := m.labs[key]; ok {
		return l.url
	}
	return ""
}

// start spins up an http.Server for the given key + endpoint set and returns
// the base URL. startedLabs are tracked so stop() can shut them down. Ports
// are assigned sequentially from m.port, incrementing on EADDRINUSE-style bind
// failures.
func (m *labManager) start(key string, eps []labEndpoint) (string, error) {
	m.mu.Lock()
	if l, ok := m.labs[key]; ok {
		m.mu.Unlock()
		return l.url, nil // already running
	}
	m.mu.Unlock()

	// Build a path -> handler map and dispatch ourselves; http.ServeMux is
	// avoided because its trailing-slash / path-cleaning behavior issues 301
	// redirects that interfere with the exact endpoint paths the scanner
	// requests (e.g. /sqli/error.php).
	handlers := map[string]http.HandlerFunc{}
	handlers["/"] = m.labIndex(eps)
	for _, e := range eps {
		// endpoints are registered by path only (the query string is part of
		// the endpoint spec but dispatch matches on path only).
		path := e.Path
		if i := strings.IndexByte(path, '?'); i >= 0 {
			path = path[:i]
		}
		if path == "" || path == "/" {
			continue
		}
		handlers[path] = m.labHandler(e)
	}
	dispatch := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h, ok := handlers[r.URL.Path]; ok {
			h(w, r)
			return
		}
		http.NotFound(w, r)
	})

	port := m.port
	var srv *http.Server
	var addr string
	for tries := 0; tries < 200; tries++ {
		addr = fmt.Sprintf("127.0.0.1:%d", port)
		candidate := &http.Server{Addr: addr, Handler: dispatch}
		ln, err := netListen(addr)
		if err != nil {
			port++
			continue
		}
		srv = candidate
		go func() { _ = candidate.Serve(ln) }()
		_ = ln // keep

		m.port = port + 1
		break
	}
	if srv == nil {
		return "", fmt.Errorf("no free port to start the lab")
	}
	baseURL := "http://" + addr + "/"
	rl := &runningLab{key: key, addr: addr, url: baseURL, server: srv}

	m.mu.Lock()
	m.labs[key] = rl
	m.mu.Unlock()
	return baseURL, nil
}

func (m *labManager) stop(key string) {
	m.mu.Lock()
	rl, ok := m.labs[key]
	if ok {
		delete(m.labs, key)
	}
	m.mu.Unlock()
	if ok {
		_ = rl.server.Shutdown(context.Background())
	}
}

// labIndex renders a simple listing of the lab's endpoints with links, so a
// user who clicks "跳转到靶场" sees something usable.
func (m *labManager) labIndex(eps []labEndpoint) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		var b strings.Builder
		b.WriteString("<!doctype html><meta charset=utf-8><title>WScan 靶场</title>")
		b.WriteString("<style>body{font-family:system-ui,sans-serif;max-width:760px;margin:40px auto;padding:0 16px;color:#222}code{background:#f3f4f6;padding:1px 4px;border-radius:3px}a{color:#0051D2;text-decoration:none}a:hover{text-decoration:underline}li{margin:6px 0}</style>")
		b.WriteString("<h1>WScan 漏洞靶场</h1><p>下方为本靶场暴露的可测端点。直接访问即可触发对应漏洞，供插件检测验证。</p><ul>")
		for _, e := range eps {
			b.WriteString("<li><code>" + html.EscapeString(e.Path) + "</code> — " + html.EscapeString(e.Vuln) + " <a href=\"" + html.EscapeString(e.Path) + "\" target=\"_blank\">打开</a></li>")
		}
		b.WriteString("</ul><p style=\"color:#888;font-size:12px;margin-top:32px\">由 WScan WebUI 内置靶场服务提供。</p>")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(b.String()))
	}
}

// labHandler dispatches one vulnerable endpoint to its concrete implementation.
func (m *labManager) labHandler(e labEndpoint) http.HandlerFunc {
	switch e.Category {
	case "SQL注入":
		switch {
		case strings.HasPrefix(e.Path, "/sqli/error"):
			return m.sqliError
		case strings.HasPrefix(e.Path, "/sqli/boolean"):
			return m.sqliBoolean
		case strings.HasPrefix(e.Path, "/sqli/time"):
			return m.sqliTime
		}
	case "XSS":
		switch {
		case strings.HasPrefix(e.Path, "/xss/reflected"):
			return m.xssReflected("q")
		case strings.HasPrefix(e.Path, "/xss/attr"):
			return m.xssAttr("name")
		case strings.HasPrefix(e.Path, "/xss/href"):
			return m.xssHref("u")
		}
	case "命令注入":
		return m.cmdiPing("host")
	case "路径穿越":
		return m.lfiRead("file")
	case "开放重定向":
		return m.openRedirect("url")
	case "CRLF注入":
		return m.crlfSet("q")
	case "JSONP":
		return m.jsonpData("callback")
	case "敏感文件":
		return m.sensitiveEnv
	case "安全基线":
		switch {
		case strings.HasPrefix(e.Path, "/baseline/error"):
			return m.baselineError
		case strings.HasPrefix(e.Path, "/baseline/cors"):
			return m.baselineCORS
		}
	}
	// default: echo the query so the endpoint at least returns something
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("lab endpoint: " + e.Path + "\n"))
	}
}

// ---- SQL注入 ----

// sqliError: reflects the id into a MySQL query and, when the payload triggers
// a syntax error, returns a MySQL error string the sqldet error-based detector
// matches against (db_errors.yaml / application_errors.yaml).
func (m *labManager) sqliError(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		id = "1"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// simulate: SELECT * FROM products WHERE id = <id>
	if containsAny(id, "'", "\"", "extractvalue", "sleep", "benchmark", "union", "cast(", "convert(") {
		// treat as a malformed/error-triggering query
		http.Error(w, "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '"+html.EscapeString(id)+"' at line 1", http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, "<html><body><h1>Product #%s</h1><p>Sample product.</p></body></html>", html.EscapeString(id))
}

// sqliBoolean: returns a full list for the "true" condition and an empty list
// for the "false" condition, so boolean-based detection sees a measurable
// page-similarity delta between AND 1=1 and AND 1=2.
func (m *labManager) sqliBoolean(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		id = "1"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	lower := strings.ToLower(id)
	falseCond := strings.Contains(lower, "and 0") || strings.Contains(lower, "and+0") ||
		(strings.Contains(lower, "and") && containsAny(lower, "!=,", "<>", "=0"))
	if falseCond {
		fmt.Fprintf(w, "<html><body><h1>Products</h1><p>No products found.</p></body></html>")
		return
	}
	fmt.Fprintf(w, "<html><body><h1>Products</h1><ul>"+
		"<li>Product A - $10</li><li>Product B - $20</li><li>Product C - $30</li>"+
		"<li>Product D - $40</li><li>Product E - $50</li></ul></body></html>")
}

// sqliTime: sleeps for N seconds when the payload carries a SLEEP/pg_sleep/
// waitfor delay directive, so time-based detection measures a measurable delay.
func (m *labManager) sqliTime(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		id = "1"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if secs := sleepSeconds(id); secs > 0 {
		time.Sleep(time.Duration(secs) * time.Second)
	}
	fmt.Fprintf(w, "<html><body><h1>Product #%s</h1><p>Delayed query result.</p></body></html>", html.EscapeString(id))
}

// ---- XSS ----

// xssReflected echoes the param verbatim into HTML text — the classic
// reflected XSS the xss plugin's html-context branch detects.
func (m *labManager) xssReflected(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get(param)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<html><body><h1>Search</h1><p>Results for: %s</p></body></html>", q)
	}
}

// xssAttr reflects the param into an attribute value without escaping, so the
// attribute-context branch fires ("><svg ...).
func (m *labManager) xssAttr(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get(param)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<html><body><input value=\"%s\"></body></html>", v)
	}
}

// xssHref reflects the param into an href verbatim — the javascript: protocol
// branch of the xss plugin.
func (m *labManager) xssHref(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get(param)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<html><body><a href=\"%s\">link</a></body></html>", v)
	}
}

// ---- 命令注入 ----

// cmdiPing simulates `ping <host>` and, when the payload runs an echo, computes
// and echoes the md5 so cmd-injection's md5/echo VerifyResult is present.
func (m *labManager) cmdiPing(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get(param)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if host == "" {
			host = "127.0.0.1"
		}
		// if the payload contains an echo marker `echo <md5>`, reflect the md5
		if md5 := echoMD5(host); md5 != "" {
			fmt.Fprintf(w, "PING %s ...\n%s\n--- ping statistics ---\n1 packets transmitted\n", host, md5)
			return
		}
		// arithmetic payloads: response.write(a*b) / {{a+b}} — echo the result
		if res := arithResult(host); res != "" {
			fmt.Fprintf(w, "%s\n", res)
			return
		}
		fmt.Fprintf(w, "PING %s (127.0.0.1) 56(84) bytes of data.\n64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.1 ms\n\n--- ping statistics ---\n1 packets transmitted, 1 received\n", html.EscapeString(host))
	}
}

// ---- 路径穿越 ----

// lfiRead serves a named text file, but when the `file` param escapes the
// directory (../, /etc/passwd, file://, php://) it returns /etc/passwd content
// so the path_traversal regexes match.
func (m *labManager) lfiRead(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f := r.URL.Query().Get(param)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if f == "" {
			f = "report.txt"
		}
		lower := strings.ToLower(f)
		if strings.Contains(f, "../") || strings.HasPrefix(f, "/etc/") ||
			strings.HasPrefix(lower, "file://") || strings.HasPrefix(lower, "php://") ||
			strings.Contains(f, "..%2f") {
			w.Write([]byte("root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/sbin/nologin\ndaemon:x:2:2:daemon:/sbin:/sbin/nologin\n"))
			return
		}
		fmt.Fprintf(w, "Monthly report for %s\n--------------------------\nRevenue: $120,000\nExpenses: $ 80,000\nProfit:  $ 40,000\n", html.EscapeString(f))
	}
}

// ---- 开放重定向 ----

// openRedirect redirects to the `url` param without validation — the redirect
// plugin's 3xx + Location-host-match check.
func (m *labManager) openRedirect(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := r.URL.Query().Get(param)
		if u == "" {
			http.NotFound(w, r)
			return
		}
		// only redirect to absolute external targets to actually trip the detector;
		// local paths are kept as a normal 302 to a relative URL (harmless).
		if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "//") {
			http.Redirect(w, r, u, http.StatusFound)
			return
		}
		http.Redirect(w, r, u, http.StatusFound)
	}
}

// ---- CRLF 注入 ----

// crlfSet: when the payload decodes to a CRLF sequence carrying a custom header
// (Dalfoxcrlf / Set-Crlf-Cookie), the response echoes it back as a real header.
func (m *labManager) crlfSet(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get(param)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// decode common CRLF encodings
		decoded := crlfDecode(q)
		if h, v, ok := splitInjectedHeader(decoded); ok {
			w.Header().Set(h, v)
		}
		fmt.Fprintf(w, "<html><body><p>Hello, you searched: %s</p></body></html>", html.EscapeString(q))
	}
}

// ---- JSONP ----

// jsonpData wraps the response in the callback function named by the `callback`
// param — the jsonp plugin verifies the body starts with "<cb>(".
func (m *labManager) jsonpData(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cb := r.URL.Query().Get(param)
		if cb == "" {
			cb = "callback"
		}
		// sanitize loosely so we produce a syntactically valid JS call
		cb = strings.Map(func(r rune) rune {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
				return r
			}
			return '_'
		}, cb)
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		fmt.Fprintf(w, "%s({\"user\":\"alice\",\"email\":\"alice@example.com\",\"balance\":1234.56});", cb)
	}
}

// ---- 敏感文件 ----

// sensitiveEnv serves a realistic .env body so the sensitivefile plugin's
// content-verification regex matches.
func (m *labManager) sensitiveEnv(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte("APP_ENV=production\nAPP_DEBUG=true\nAPP_KEY=base64:QkRjVWJqaE5OVzV6Y2k5dQ==\nDB_HOST=127.0.0.1\nDB_DATABASE=webapp\nDB_PASSWORD=s3cr3t-pw\nREDIS_HOST=127.0.0.1\nMAIL_HOST=smtp.example.com\nMAIL_PORT=587\nMAIL_DRIVER=smtp\nCACHE_DRIVER=redis\nQUEUE_DRIVER=database\n"))
}

// ---- 安全基线 ----

// baselineError returns a stack-trace-style application error body, which the
// baseline ApplicationErrorScanRule matches.
func (m *labManager) baselineError(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte("<html><body><h1>Internal Server Error</h1><pre>Traceback (most recent call last):\n  File \"/app/handlers.py\", line 42, in handler\n    return db.query('SELECT * FROM users WHERE id=' + uid)\n  File \"/app/db.py\", line 18, in query\nYou have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '' at line 1\njava.lang.NumberFormatException: For input string: 'abc'\n</pre></body></html>"))
}

// baselineCORS responds with Access-Control-Allow-Origin: * plus credentials,
// the cross-domain misconfiguration the baseline plugin flags.
func (m *labManager) baselineCORS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Write([]byte("<html><body><h1>API</h1><p>{\"status\":\"ok\"}</p></body></html>"))
}

// ---- helpers ----

func containsAny(s string, subs ...string) bool {
	lower := strings.ToLower(s)
	for _, sub := range subs {
		if strings.Contains(lower, sub) {
			return true
		}
	}
	return false
}

// sleepSeconds extracts the number of seconds from a time-based SQL payload so
// the lab handler can sleep that long (capped to avoid hanging the UI).
func sleepSeconds(payload string) int {
	lower := strings.ToLower(payload)
	// SLEEP(N) / pg_sleep(N) / sleep(N)
	re := regexp.MustCompile(`(?:sleep|pg_sleep)\s*\(\s*(\d+)\s*\)`)
	if m := re.FindStringSubmatch(lower); len(m) == 2 {
		if n, err := strconv.Atoi(m[1]); err == nil && n > 0 && n <= 30 {
			return n
		}
	}
	// waitfor delay '0:0:N'
	re2 := regexp.MustCompile(`waitfor\s+delay\s*'0:0:(\d+)'`)
	if m := re2.FindStringSubmatch(lower); len(m) == 2 {
		if n, err := strconv.Atoi(m[1]); err == nil && n > 0 && n <= 30 {
			return n
		}
	}
	// BENCHMARK(N, ...) — treat a large N as a couple seconds.
	if strings.Contains(lower, "benchmark(") {
		return 2
	}
	return 0
}

// echoMD5 detects an `echo <hex32>` / `echo <md5>` payload in the host value and
// returns that md5, so cmd-injection's Suffix/Value echo VerifyResult is echoed.
func echoMD5(s string) string {
	re := regexp.MustCompile(`echo[ %s]*([0-9a-fA-F]{32})`)
	m := re.FindStringSubmatch(s)
	if len(m) == 2 {
		return m[1]
	}
	return ""
}

// arithResult evaluates response.write(a*b) / {{a+b}} style payloads and
// returns the computed result string, mirroring the cmd-injection arithmetic
// VerifyResult.
func arithResult(s string) string {
	// response.write(A*B)
	if m := regexp.MustCompile(`response\.write\(\s*(\d+)\s*\*\s*(\d+)\s*\)`).FindStringSubmatch(s); len(m) == 3 {
		a, _ := strconv.Atoi(m[1])
		b, _ := strconv.Atoi(m[2])
		return strconv.Itoa(a * b)
	}
	// {{A+B}} / {{= A+B}} / {{A*B}}
	if m := regexp.MustCompile(`\{\{=?\s*(\d+)\s*([+*])\s*(\d+)\s*\}\}`).FindStringSubmatch(s); len(m) == 4 {
		a, _ := strconv.Atoi(m[1])
		b, _ := strconv.Atoi(m[3])
		if m[2] == "+" {
			return strconv.Itoa(a + b)
		}
		return strconv.Itoa(a * b)
	}
	return ""
}

// crlfDecode turns percent-encoded CR/LF sequences back into raw bytes so the
// injected header can be re-emitted.
func crlfDecode(s string) string {
	s = strings.ReplaceAll(s, "%0d%0a", "\r\n")
	s = strings.ReplaceAll(s, "%0D%0A", "\r\n")
	s = strings.ReplaceAll(s, "%0d", "\r")
	s = strings.ReplaceAll(s, "%0a", "\n")
	s = strings.ReplaceAll(s, "%0D", "\r")
	s = strings.ReplaceAll(s, "%0A", "\n")
	return s
}

// splitInjectedHeader parses the first "Name: value" pair that appears after a
// CRLF in the decoded payload, returning the header name + value to re-emit.
func splitInjectedHeader(decoded string) (string, string, bool) {
	idx := strings.IndexAny(decoded, "\r\n")
	rest := decoded
	if idx >= 0 {
		rest = decoded[idx:]
		rest = strings.TrimLeft(rest, "\r\n")
	}
	if rest == "" {
		return "", "", false
	}
	if c := strings.Index(rest, ":"); c > 0 {
		name := strings.TrimSpace(rest[:c])
		val := strings.TrimSpace(rest[c+1:])
		// trim trailing crlf / further injected content
		if i := strings.IndexAny(val, "\r\n"); i >= 0 {
			val = strings.TrimSpace(val[:i])
		}
		if name == "" {
			return "", "", false
		}
		return name, val, true
	}
	return "", "", false
}

var _ = exec.Command // reserved for a future "real exec" demo variant
var _ = url.Parse    // reserved
