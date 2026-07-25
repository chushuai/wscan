/**
* @Author: shaochuyu
* @Date: 7/25/2026
*
* WebUI: an HTTP server that exposes a REST API + embedded SPA for managing
* WScan crawl/scan tasks in a browser. Modeled on the AWVS runtime web UI but
* backed by WScan's own collector + dispatcher.
 */
package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/urfave/cli/v2"

	"wscan/core/collector"
	"wscan/core/collector/basiccrawler"
	"wscan/core/crawler"
	"wscan/core/ctrl"
	"wscan/core/entry"
	"wscan/core/model"
	"wscan/core/output"
	"wscan/core/plugins"
	"wscan/core/plugins/base"
	"wscan/core/reverse"

	logger "wscan/core/utils/log"
	"wscan/core/utils/printer"
)

// taskStatus mirrors the status strings the front-end expects:
// created / running / done / error / paused / stopped.
type taskStatus string

const (
	statusCreated taskStatus = "created"
	statusRunning taskStatus = "running"
	statusDone    taskStatus = "done"
	statusError   taskStatus = "error"
	statusStopped taskStatus = "stopped"
)

// scanTask is the unit of work tracked by the WebUI task manager.
type scanTask struct {
	mu sync.RWMutex

	id        string
	name      string
	target    string
	taskType  string // "crawl" or "scan"
	startedAt time.Time

	status     taskStatus
	errMsg     string
	crawled    int
	progress   map[string]any
	resultPath string

	vulns []*model.WebVuln
	pages []map[string]any

	dispatcher *ctrl.Dispatcher
	cancel     context.CancelFunc
	runDone    chan struct{}

	subs  map[chan map[string]any]struct{}
	subMu sync.Mutex
}

// progress snapshot returned to the front-end "progress" field.
func (t *scanTask) progressMap() map[string]any {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.progress != nil {
		return t.progress
	}
	return map[string]any{}
}

func (t *scanTask) emit(ev map[string]any) {
	t.subMu.Lock()
	defer t.subMu.Unlock()
	for ch := range t.subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

// toFrontTask builds the task summary object consumed by the SPA.
func (t *scanTask) toFrontTask() map[string]any {
	t.mu.RLock()
	defer t.mu.RUnlock()
	started := ""
	if !t.startedAt.IsZero() {
		started = t.startedAt.Format("2006-01-02T15:04:05")
	}
	return map[string]any{
		"id":        t.id,
		"name":      t.name,
		"target":    t.target,
		"type":      t.taskType,
		"status":    string(t.status),
		"vulns":     len(t.vulns),
		"vulnCount": len(t.vulns),
		"crawled":   t.crawled,
		"startedAt": started,
		"progress":  t.progress,
	}
}

// toFrontTaskDetail is the full task object (with pages) for /api/task/:id.
func (t *scanTask) toFrontTaskDetail() map[string]any {
	t.mu.RLock()
	defer t.mu.RUnlock()
	started := ""
	if !t.startedAt.IsZero() {
		started = t.startedAt.Format("2006-01-02T15:04:05")
	}
	return map[string]any{
		"id":        t.id,
		"name":      t.name,
		"target":    t.target,
		"type":      t.taskType,
		"status":    string(t.status),
		"vulns":     len(t.vulns),
		"vulnCount": len(t.vulns),
		"crawled":   t.crawled,
		"startedAt": started,
		"progress":  t.progress,
		"pages":     t.pages,
	}
}

// webPrinter collects Vuln + CrawlerResult events from the dispatcher into the
// task, and pushes live events to any open SSE subscribers.
type webPrinter struct {
	printer.Printer
	task *scanTask
}

func (*webPrinter) AddInterceptor(func(any) (any, error)) printer.Printer { return nil }
func (*webPrinter) Close() error                                          { return nil }

func (p *webPrinter) Print(res any) error {
	switch v := res.(type) {
	case *model.Vuln:
		wv := v.ToWebVuln()
		p.task.mu.Lock()
		p.task.vulns = append(p.task.vulns, wv)
		p.task.mu.Unlock()
		p.task.emit(map[string]any{"type": "vuln"})
	case *model.CrawlerResult:
		page := crawlerResultToPage(v)
		p.task.mu.Lock()
		p.task.pages = append(p.task.pages, page)
		p.task.crawled = len(p.task.pages)
		p.task.mu.Unlock()
		p.task.emit(map[string]any{"type": "page", "page": page})
	case *model.StatisticRecord:
		p.task.mu.Lock()
		p.task.progress = map[string]any{
			"phase":     "scanning",
			"done":      v.NumScannedUrls,
			"total":     v.NumFoundUrls,
			"elapsedMs": time.Since(p.task.startedAt).Milliseconds(),
		}
		p.task.mu.Unlock()
		p.task.emit(map[string]any{"type": "progress", "progress": p.task.progressMap()})
	}
	return nil
}

func crawlerResultToPage(c *model.CrawlerResult) map[string]any {
	headers := map[string]any{}
	for k, v := range c.Headers {
		headers[k] = v
	}
	return map[string]any{
		"url":         c.Url,
		"method":      c.Method,
		"source":      c.Source,
		"status":      0,
		"http":        map[string]any{"request": map[string]any{"method": c.Method, "uri": c.Url, "headers": headers, "body": c.Data}},
		"params":      []any{},
		"depth":       0,
		"title":       "",
		"isSoft404":   false,
		"contentType": "",
	}
}

// ---- task manager ----

type taskManager struct {
	mu    sync.RWMutex
	tasks map[string]*scanTask
	order []string // task ids in creation order (newest-first is enforced in list)
}

func newTaskManager() *taskManager { return &taskManager{tasks: map[string]*scanTask{}} }

func (m *taskManager) add(t *scanTask) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tasks[t.id] = t
	m.order = append(m.order, t.id)
}

func (m *taskManager) get(id string) (*scanTask, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.tasks[id]
	return t, ok
}

func (m *taskManager) list() []*scanTask {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*scanTask, 0, len(m.order))
	// newest first
	for i := len(m.order) - 1; i >= 0; i-- {
		if t, ok := m.tasks[m.order[i]]; ok {
			out = append(out, t)
		}
	}
	return out
}

func (m *taskManager) delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tasks[id]
	if !ok {
		return fmt.Errorf("task not found")
	}
	t.mu.RLock()
	st := t.status
	t.mu.RUnlock()
	if st == statusRunning {
		return fmt.Errorf("cannot delete a running task; stop it first")
	}
	delete(m.tasks, id)
	for i, oid := range m.order {
		if oid == id {
			m.order = append(m.order[:i], m.order[i+1:]...)
			break
		}
	}
	unpersistScan(id)
	return nil
}

// allVulns returns every vuln across every task, tagged with its taskId.
func (m *taskManager) allVulns() []map[string]any {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []map[string]any
	for _, id := range m.order {
		t := m.tasks[id]
		if t == nil {
			continue
		}
		t.mu.RLock()
		for _, v := range t.vulns {
			row := webVulnToFront(v)
			row["taskId"] = id
			out = append(out, row)
		}
		t.mu.RUnlock()
	}
	return out
}

// ---- server ----

// Server is the WebUI HTTP server. Holds a single global config + reverse
// platform (mirrors the mcp server) so every scan task reuses them.
type Server struct {
	cfg     *entry.CliEntryConfig
	reverse *reverse.Reverse
	mgr     *taskManager
	plugins []pluginEntry
	labs    *labManager
}

type pluginEntry struct {
	Rel   string `json:"rel"`
	Title string `json:"title"`
}

// StartWebUIServer loads config, builds the plugin catalog, and serves the
// WebUI on host:port. Blocks until the server exits.
func StartWebUIServer(c *cli.Context) error {
	cfg, err := entry.LoadOrGenConfig(c)
	if err != nil {
		logger.Fatal(err)
	}
	rv := reverse.NewReverse(cfg.Reverse)

	srv := &Server{
		cfg:     cfg,
		reverse: rv,
		mgr:     newTaskManager(),
	}
	srv.mgr.rehydrateScans()
	srv.labs = newLabManager(srv)
	srv.plugins = buildPluginCatalog()

	addr := fmt.Sprintf("%s:%d", c.String("webui-host"), c.Int("webui-port"))
	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	logger.Printf("WScan WebUI serving at http://%s", addr)
	s := &http.Server{Addr: addr, Handler: mux}
	if err := s.ListenAndServe(); err != nil {
		return err
	}
	return nil
}

func buildPluginCatalog() []pluginEntry {
	var out []pluginEntry
	for _, p := range plugins.All() {
		name := p.DefaultConfig().BaseConfig().Name
		out = append(out, pluginEntry{Rel: name, Title: name})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Rel < out[j].Rel })
	return out
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func readJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(r.Body)
	dec.UseNumber()
	return dec.Decode(dst)
}

func (s *Server) registerRoutes(mux *http.ServeMux) {
	// static SPA assets (embedded)
	mux.HandleFunc("/", s.handleStatic)

	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/tasks", s.handleTasks)
	mux.HandleFunc("/api/tasks/delete", s.handleTasksDelete)
	mux.HandleFunc("/api/task/", s.handleTask) // /api/task/:id ...
	mux.HandleFunc("/api/scan", s.handleScan)
	mux.HandleFunc("/api/crawl", s.handleCrawl)
	mux.HandleFunc("/api/plugins", s.handlePlugins)
	mux.HandleFunc("/api/profiles", s.handleProfiles)
	mux.HandleFunc("/api/profiles/", s.handleProfile)
	mux.HandleFunc("/api/proxy", s.handleProxy)
	mux.HandleFunc("/api/proxy/test", s.handleProxyTest)
	mux.HandleFunc("/api/vulnerabilities", s.handleVulnerabilities)
	mux.HandleFunc("/api/targets", s.handleTargets)
	mux.HandleFunc("/api/targets/", s.handleTarget)
	mux.HandleFunc("/api/targets/bulk", s.handleTargetsBulk)
	mux.HandleFunc("/api/labs", s.handleLabs)
	mux.HandleFunc("/api/labs/", s.handleLabAction)
	mux.HandleFunc("/api/target-groups", s.handleTargetGroups)
	mux.HandleFunc("/api/target-groups/", s.handleTargetGroup)
	mux.HandleFunc("/api/report", s.handleReport)
}

// ---- status / tasks ----

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.mgr.mu.RLock()
	taskCount := len(s.mgr.tasks)
	s.mgr.mu.RUnlock()
	writeJSON(w, map[string]any{
		"targetCount":  len(s.targets()),
		"taskCount":    taskCount,
		"profileCount": len(s.profiles()),
		"version":      "1.0.46",
	})
}

// ---- targets (lightweight CRUD over the in-memory store) ----

func (s *Server) handleTargets(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var body struct {
			Address         string         `json:"address"`
			Description     string         `json:"description"`
			Criticality     string         `json:"criticality"`
			IncludePatterns []string       `json:"includePatterns"`
			ExcludePatterns []string       `json:"excludePatterns"`
			Auth            map[string]any `json:"auth"`
		}
		if err := readJSON(r, &body); err != nil {
			writeJSON(w, map[string]any{"error": err.Error()})
			return
		}
		t := map[string]any{
			"id":              newID(),
			"address":         body.Address,
			"description":     body.Description,
			"criticality":     body.Criticality,
			"includePatterns": body.IncludePatterns,
			"excludePatterns": body.ExcludePatterns,
			"auth":            body.Auth,
			"groups":          []string{},
			"vulnBreakdown":   map[string]int{},
		}
		s.addTarget(t)
		writeJSON(w, t)
		return
	}
	writeJSON(w, s.targets())
}

func (s *Server) handleTargetsBulk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Targets []map[string]any `json:"targets"`
		Groups  []string         `json:"groups"`
	}
	if err := readJSON(r, &body); err != nil {
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}
	created := 0
	newIDs := []string{}
	for _, trow := range body.Targets {
		addr, _ := trow["address"].(string)
		if addr == "" {
			continue
		}
		id := newID()
		t := map[string]any{
			"id":            id,
			"address":       addr,
			"description":   trow["description"],
			"groups":        append([]string{}, body.Groups...),
			"vulnBreakdown": map[string]int{},
		}
		s.addTarget(t)
		newIDs = append(newIDs, id)
		created++
	}
	// Add the freshly created targets as members of each selected group.
	for _, gid := range body.Groups {
		g := s.groupRaw(gid)
		if g == nil {
			continue
		}
		existing, _ := g["members"].([]string)
		set := map[string]struct{}{}
		for _, m := range existing {
			set[m] = struct{}{}
		}
		merged := append([]string{}, existing...)
		for _, id := range newIDs {
			if _, ok := set[id]; !ok {
				merged = append(merged, id)
				set[id] = struct{}{}
			}
		}
		s.updateGroup(gid, map[string]any{"members": merged})
	}
	writeJSON(w, map[string]any{"created": created})
}

func (s *Server) handleTarget(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/targets/")
	if id == "bulk" {
		s.handleTargetsBulk(w, r)
		return
	}
	if r.Method == http.MethodDelete {
		writeJSON(w, map[string]any{"ok": s.deleteTarget(id)})
		return
	}
	if r.Method == http.MethodPut {
		var body map[string]any
		if err := readJSON(r, &body); err != nil {
			writeJSON(w, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, map[string]any{"ok": s.updateTarget(id, body)})
		return
	}
	http.NotFound(w, r)
}

func (s *Server) handleTargetGroups(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var body struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		}
		if err := readJSON(r, &body); err != nil {
			writeJSON(w, map[string]any{"error": err.Error()})
			return
		}
		if body.Name == "" {
			writeJSON(w, map[string]any{"error": "name is required"})
			return
		}
		g := s.createGroup(body.Name, body.Description)
		writeJSON(w, s.groupForFrontend(g))
		return
	case http.MethodGet, "":
		writeJSON(w, s.groups())
		return
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleTargetGroup routes /api/target-groups/<id> for GET (not used by the SPA
// yet), PUT (update name/description or members), and DELETE.
func (s *Server) handleTargetGroup(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/target-groups/")
	if id == "" {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodPut:
		var body map[string]any
		if err := readJSON(r, &body); err != nil {
			writeJSON(w, map[string]any{"error": err.Error()})
			return
		}
		// members arrive from the SPA as an array of id strings; normalize to []string.
		if raw, ok := body["members"]; ok {
			var arr []string
			if list, ok := raw.([]any); ok {
				for _, m := range list {
					arr = append(arr, fmt.Sprint(m))
				}
			}
			body["members"] = arr
		}
		g := s.updateGroup(id, body)
		if g == nil {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, s.groupForFrontend(g))
		return
	case http.MethodDelete:
		writeJSON(w, map[string]any{"ok": s.deleteGroup(id)})
		return
	default:
		http.NotFound(w, r)
	}
}

// ---- labs (preset + custom vulnerable targets) ----

// handleLabs handles GET /api/labs (list presets + custom) and POST /api/labs
// (no-op alias) and GET /api/labs/endpoints (the endpoint picker tree) and
// POST /api/labs/custom (create a custom lab).
func (s *Server) handleLabs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("endpoints") == "1" || strings.HasSuffix(r.URL.Path, "/endpoints") {
		writeJSON(w, catalogForFrontend())
		return
	}
	switch r.Method {
	case http.MethodPost:
		// create a custom lab: {name, categories}
		var body struct {
			Name       string   `json:"name"`
			Categories []string `json:"categories"`
		}
		if err := readJSON(r, &body); err != nil {
			writeJSON(w, map[string]any{"error": err.Error()})
			return
		}
		if body.Name == "" {
			body.Name = "自定义靶场"
		}
		if len(body.Categories) == 0 {
			writeJSON(w, map[string]any{"error": "至少选择一个类别"})
			return
		}
		def := customLabDef{ID: newID(), Name: body.Name, Categories: body.Categories}
		addCustomLab(def)
		writeJSON(w, map[string]any{"id": def.ID, "name": def.Name, "categories": def.Categories})
	case http.MethodGet, "":
		presets, custom := s.labs.listForFrontend()
		writeJSON(w, map[string]any{"presets": presets, "custom": custom})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleLabAction routes /api/labs/<key>/{start,stop} and
// /api/labs/custom/<id>/{start,stop} and DELETE /api/labs/custom/<id>.
func (s *Server) handleLabAction(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/labs/")
	if rest == "" {
		http.NotFound(w, r)
		return
	}
	// /api/labs/endpoints — the custom-lab builder's endpoint picker tree.
	if rest == "endpoints" {
		writeJSON(w, catalogForFrontend())
		return
	}
	parts := strings.SplitN(rest, "/", 3)
	// shapes:
	//   labs/<preset>/start|stop
	//   labs/custom/<id>/start|stop   (DELETE on labs/custom/<id>)
	var key, action string
	if parts[0] == "custom" {
		if len(parts) < 3 {
			// labs/custom/<id> with no action → DELETE handled below
			if len(parts) == 2 && r.Method == http.MethodDelete {
				deleteCustomLab(parts[1])
				writeJSON(w, map[string]any{"ok": true})
				return
			}
			http.NotFound(w, r)
			return
		}
		key = "custom:" + parts[1]
		action = parts[2]
	} else {
		if len(parts) < 2 {
			http.NotFound(w, r)
			return
		}
		key = parts[0]
		action = parts[1]
	}

	switch action {
	case "start":
		eps := s.endpointsForKey(key)
		if len(eps) == 0 {
			writeJSON(w, map[string]any{"error": "unknown lab"})
			return
		}
		u, err := s.labs.start(key, eps)
		if err != nil {
			writeJSON(w, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, map[string]any{"url": u, "running": true})
	case "stop":
		s.labs.stop(key)
		writeJSON(w, map[string]any{"ok": true})
	default:
		http.NotFound(w, r)
	}
}

// endpointsForKey resolves a lab key (preset name or "custom:<id>") to its
// concrete endpoint list from the catalog / persisted custom def.
func (s *Server) endpointsForKey(key string) []labEndpoint {
	if strings.HasPrefix(key, "custom:") {
		def, ok := findCustomLab(strings.TrimPrefix(key, "custom:"))
		if !ok {
			return nil
		}
		return endpointsFor(def.Categories)
	}
	for _, p := range presetLabs() {
		if p.Name == key {
			return endpointsFor(p.Categories)
		}
	}
	return nil
}

// ---- tasks list ----

func (s *Server) handleTasks(w http.ResponseWriter, r *http.Request) {
	tasks := s.mgr.list()
	out := make([]map[string]any, 0, len(tasks))
	for _, t := range tasks {
		out = append(out, t.toFrontTask())
	}
	writeJSON(w, out)
}

func (s *Server) handleTasksDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		IDs []string `json:"ids"`
	}
	if err := readJSON(r, &body); err != nil {
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}
	var deleted, skipped []map[string]any
	for _, id := range body.IDs {
		if err := s.mgr.delete(id); err != nil {
			skipped = append(skipped, map[string]any{"id": id, "reason": err.Error()})
		} else {
			deleted = append(deleted, map[string]any{"id": id})
		}
	}
	writeJSON(w, map[string]any{"deleted": deleted, "skipped": skipped})
}

// handleTask routes /api/task/:id and /api/task/:id/<sub>.
func (s *Server) handleTask(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/task/")
	parts := strings.SplitN(rest, "/", 2)
	id := parts[0]
	if id == "" {
		http.NotFound(w, r)
		return
	}
	t, ok := s.mgr.get(id)
	if !ok {
		writeJSON(w, map[string]any{"error": "task not found"})
		return
	}
	sub := ""
	if len(parts) == 2 {
		sub = parts[1]
	}

	switch sub {
	case "":
		if r.Method == http.MethodDelete {
			if err := s.mgr.delete(id); err != nil {
				writeJSON(w, map[string]any{"error": err.Error()})
				return
			}
			writeJSON(w, map[string]any{"ok": true})
			return
		}
		writeJSON(w, t.toFrontTaskDetail())
	case "vulns":
		s.handleTaskVulns(w, r, t)
	case "url":
		// no-op stub: front-end uses it for delete-invalid/rescan; we accept and
		// respond so the UI doesn't error, though WScan doesn't track per-URL state.
		writeJSON(w, map[string]any{"removed": 0})
	case "rescan":
		writeJSON(w, map[string]any{"ok": true})
	case "export":
		s.handleTaskExport(w, r, t)
	case "pause":
		s.controlTask(t, "pause")
		writeJSON(w, map[string]any{"ok": true})
	case "resume":
		s.controlTask(t, "resume")
		writeJSON(w, map[string]any{"ok": true})
	case "stop":
		s.controlTask(t, "stop")
		writeJSON(w, map[string]any{"ok": true})
	case "events":
		s.handleTaskEvents(w, r, t)
	default:
		http.NotFound(w, r)
	}
}

// handleTaskVulns supports flat + grouped pagination + typeId filtering, mirroring
// the AWVS runtime's /api/task/:id/vulns contract that the SPA relies on.
func (s *Server) handleTaskVulns(w http.ResponseWriter, r *http.Request, t *scanTask) {
	q := r.URL.Query()
	page := atoiDefault(q.Get("page"), 0)
	size := atoiDefault(q.Get("pageSize"), 15)
	if size <= 0 {
		size = 15
	}
	typeID := q.Get("typeId")
	sev := q.Get("severity")
	grouped := q.Get("group") == "1"

	t.mu.RLock()
	all := make([]*model.WebVuln, len(t.vulns))
	copy(all, t.vulns)
	t.mu.RUnlock()

	// filter
	var filtered []*model.WebVuln
	for _, v := range all {
		if typeID != "" && vulnTypeID(v) != typeID {
			continue
		}
		if sev != "" && !sevMatch(v.Severity, sev) {
			continue
		}
		filtered = append(filtered, v)
	}

	if grouped {
		// group by typeId, page over groups (sorted by severity desc)
		groups := groupVulns(filtered)
		total := len(groups)
		start := page * size
		if start > total {
			start = total
		}
		end := start + size
		if end > total {
			end = total
		}
		slice := groups[start:end]
		items := make([]map[string]any, 0, len(slice))
		for _, g := range slice {
			items = append(items, map[string]any{
				"typeId":   g.typeID,
				"name":     g.name,
				"sev":      string(g.sev),
				"total":    g.total,
				"urlCount": len(g.urls),
			})
		}
		writeJSON(w, map[string]any{
			"items":     items,
			"total":     total,
			"page":      page,
			"vulnTotal": len(filtered),
		})
		return
	}

	// flat
	sort.SliceStable(filtered, func(i, j int) bool {
		return sevRank(filtered[i].Severity) > sevRank(filtered[j].Severity)
	})
	total := len(filtered)
	start := page * size
	if start > total {
		start = total
	}
	end := start + size
	if end > total {
		end = total
	}
	slice := filtered[start:end]
	items := make([]map[string]any, 0, len(slice))
	for _, v := range slice {
		items = append(items, webVulnToFront(v))
	}
	writeJSON(w, map[string]any{
		"items":     items,
		"total":     total,
		"page":      page,
		"vulnTotal": total,
	})
}

func (s *Server) handleTaskExport(w http.ResponseWriter, r *http.Request, t *scanTask) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Format string `json:"format"`
	}
	_ = readJSON(r, &body)
	t.mu.RLock()
	pages := append([]map[string]any(nil), t.pages...)
	t.mu.RUnlock()

	switch body.Format {
	case "json":
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="urls.json"`)
		_ = json.NewEncoder(w).Encode(pages)
	case "txt":
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Disposition", `attachment; filename="urls.txt"`)
		for _, p := range pages {
			if u, ok := p["url"].(string); ok {
				_, _ = io.WriteString(w, u+"\n")
			}
		}
	default:
		w.Header().Set("Content-Type", "text/xml")
		w.Header().Set("Content-Disposition", `attachment; filename="urls.xml"`)
		_, _ = io.WriteString(w, "<?xml version=\"1.0\"?>\n<urls>\n")
		for _, p := range pages {
			if u, ok := p["url"].(string); ok {
				_, _ = io.WriteString(w, "  <url>"+u+"</url>\n")
			}
		}
		_, _ = io.WriteString(w, "</urls>\n")
	}
}

// controlTask best-effort pauses/resumes/stops a running task. Pause/resume are
// advisory (WScan's dispatcher has no native pause); stop cancels the context.
func (s *Server) controlTask(t *scanTask, action string) {
	switch action {
	case "pause":
		t.mu.Lock()
		if t.status == statusRunning {
			t.status = "paused"
		}
		t.mu.Unlock()
		t.emit(map[string]any{"type": "paused"})
	case "resume":
		t.mu.Lock()
		if t.status == "paused" {
			t.status = statusRunning
		}
		t.mu.Unlock()
		t.emit(map[string]any{"type": "resumed"})
	case "stop":
		t.mu.Lock()
		if t.status == statusRunning || t.status == "paused" {
			t.status = statusStopped
			if t.cancel != nil {
				t.cancel()
			}
		}
		t.mu.Unlock()
		persistScan(t.toRecord())
		t.emit(map[string]any{"type": "stopped"})
	}
}

// handleTaskEvents streams live task events as an SSE feed.
func (s *Server) handleTaskEvents(w http.ResponseWriter, r *http.Request, t *scanTask) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	ch := make(chan map[string]any, 64)
	t.subMu.Lock()
	if t.subs == nil {
		t.subs = map[chan map[string]any]struct{}{}
	}
	t.subs[ch] = struct{}{}
	t.subMu.Unlock()

	defer func() {
		t.subMu.Lock()
		delete(t.subs, ch)
		t.subMu.Unlock()
		close(ch)
	}()

	// initial start event
	_, _ = io.WriteString(w, "data: "+mustJSON(map[string]any{"type": "start"})+"\n\n")
	flusher.Flush()

	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-heartbeat.C:
			_, _ = io.WriteString(w, ": ping\n\n")
			flusher.Flush()
		case ev := <-ch:
			_, _ = io.WriteString(w, "data: "+mustJSON(ev)+"\n\n")
			flusher.Flush()
		}
	}
}

// ---- scan / crawl ----

type scanRequest struct {
	Target          string         `json:"target"`
	UseTestServer   bool           `json:"useTestServer"`
	CrawlerMode     string         `json:"crawlerMode"`
	MaxPages        int            `json:"maxPages"`
	MaxDepth        int            `json:"maxDepth"`
	Concurrency     int            `json:"concurrency"`
	Plugins         []string       `json:"plugins"`
	Auth            map[string]any `json:"auth"`
	Method          string         `json:"method"`
	Data            *string        `json:"data"`
	Headers         []string       `json:"headers"`
	IncludePatterns []string       `json:"includePatterns"`
	ExcludePatterns []string       `json:"excludePatterns"`
	ProxyURL        string         `json:"proxyUrl"`
	NoProxy         bool           `json:"noProxy"`
	AutoScan        bool           `json:"autoScan"`
	Lab             string         `json:"lab"`
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req scanRequest
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}
	if req.Lab != "" {
		if u, ok := s.resolveLabTarget(req.Lab); ok {
			req.Target = u
		}
	}
	if req.Target == "" {
		writeJSON(w, map[string]any{"error": "target is required"})
		return
	}
	req.AutoScan = true
	req.CrawlerMode = "static"
	id := s.startScan(req)
	writeJSON(w, map[string]any{"id": id})
}

func (s *Server) handleCrawl(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req scanRequest
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}
	if req.Lab != "" {
		if u, ok := s.resolveLabTarget(req.Lab); ok {
			req.Target = u
		}
	}
	if req.Target == "" {
		writeJSON(w, map[string]any{"error": "target is required"})
		return
	}
	if !req.AutoScan {
		req.AutoScan = true
	}
	if req.CrawlerMode == "" {
		req.CrawlerMode = "static"
	}
	id := s.startScan(req)
	writeJSON(w, map[string]any{"id": id})
}

// resolveLabTarget maps a lab key (preset name or "custom:<id>") to the running
// lab's base URL, auto-starting it if needed. Returns the URL plus ok=false if
// the key is unknown.
func (s *Server) resolveLabTarget(key string) (string, bool) {
	eps := s.endpointsForKey(key)
	if len(eps) == 0 {
		return "", false
	}
	if u := s.labs.urlOf(key); u != "" {
		return u, true
	}
	u, err := s.labs.start(key, eps)
	if err != nil {
		return "", false
	}
	return u, true
}

// startScan validates the request, builds a per-task config clone, constructs the
// right collector, and launches the dispatcher in a goroutine. Returns the id.
func (s *Server) startScan(req scanRequest) string {
	id := newID()
	target := req.Target

	// per-task config clone so proxy/plugin/header overrides don't leak
	cfg := s.cfg.Clone()

	// proxy override
	if req.NoProxy {
		cfg.HTTP.Proxy = ""
	} else if req.ProxyURL != "" {
		cfg.HTTP.Proxy = req.ProxyURL
	}

	// custom request headers ("Name: value")
	for _, h := range req.Headers {
		k, v, ok := splitHeader(h)
		if !ok {
			continue
		}
		if cfg.HTTP.DefaultHeaders == nil {
			cfg.HTTP.DefaultHeaders = map[string]string{}
		}
		cfg.HTTP.DefaultHeaders[k] = v
	}
	if cfg.HTTP.DefaultHeaders != nil {
		cfg.HTTP.WroteBack()
	}

	// plugin selection: empty/nil => keep config defaults; otherwise enable only
	// the named plugins and disable the rest.
	if len(req.Plugins) > 0 {
		applyPluginSelection(cfg, req.Plugins)
	}

	taskType := "crawl"
	if req.CrawlerMode == "static" && req.Method != "" && req.Data != nil {
		taskType = "scan"
	}

	t := &scanTask{
		id:        id,
		name:      target,
		target:    target,
		taskType:  taskType,
		status:    statusCreated,
		startedAt: time.Now(),
		runDone:   make(chan struct{}),
	}
	s.mgr.add(t)

	go s.runScan(t, cfg, req)
	return id
}

// runScan builds the collector + dispatcher and runs the task to completion,
// updating status and emitting done/error events. Safe to run concurrently.
func (s *Server) runScan(t *scanTask, cfg *entry.CliEntryConfig, req scanRequest) {
	t.mu.Lock()
	t.status = statusRunning
	t.progress = map[string]any{"phase": "crawl"}
	t.mu.Unlock()
	t.emit(map[string]any{"type": "progress", "progress": t.progressMap()})

	ctx, cancel := context.WithCancel(context.Background())
	t.mu.Lock()
	t.cancel = cancel
	t.mu.Unlock()

	defer func() {
		cancel()
		close(t.runDone)
	}()

	// build the collector
	var col collector.Fitter
	switch req.CrawlerMode {
	case "dynamic", "browser":
		maxConc := req.Concurrency
		if maxConc <= 0 {
			maxConc = 5
		}
		maxDepth := req.MaxDepth
		if maxDepth <= 0 {
			maxDepth = 10
		}
		maxVisit := req.MaxPages
		if maxVisit <= 0 {
			maxVisit = 200
		}
		col = basiccrawler.NewBasicCrawlerCollector(cfg.HTTP, &crawler.Config{
			Proxy:           cfg.HTTP.Proxy,
			ExecPath:        cfg.Crawler.BrowserConfig.ExecPath,
			DisableHeadless: cfg.Crawler.BrowserConfig.DisableHeadless,
			Browser:         true,
			MaxConcurrent:   maxConc,
			MaxDepth:        maxDepth,
			MaxCountOfURLs:  maxVisit,
			Restrictions:    cfg.Crawler.Restriction,
		})
	default: // static / basic
		maxDepth := req.MaxDepth
		if maxDepth <= 0 {
			maxDepth = cfg.Crawler.BasicCrawler.MaxDepth
		}
		col = basiccrawler.NewBasicCrawlerCollector(cfg.HTTP, &crawler.Config{
			Proxy:                cfg.HTTP.Proxy,
			Browser:              false,
			MaxConcurrent:        5,
			MaxDepth:             maxDepth,
			Restrictions:         cfg.Crawler.Restriction,
			AllowVisitParentPath: cfg.Crawler.BasicCrawler.AllowVisitParentPath,
		})
	}

	taskChan, err := col.FitOut(ctx, []string{t.target})
	if err != nil {
		t.mu.Lock()
		t.status = statusError
		t.errMsg = err.Error()
		t.mu.Unlock()
		t.emit(map[string]any{"type": "error", "message": err.Error()})
		return
	}

	multi := printer.NewMultiPrinter()
	multi.AddPrinters([]printer.Printer{&webPrinter{task: t}, output.NewStdoutPrinter()})

	disp := ctrl.NewDispatcher(&cfg.Config, multi, s.reverse)
	disp.Init(false)
	t.mu.Lock()
	t.dispatcher = disp
	t.mu.Unlock()

	// completion watcher: emit done/error when the dispatcher finishes.
	go func() {
		disp.Run(taskChan, !req.AutoScan)
		disp.Release()
		t.mu.Lock()
		if t.status == statusRunning || t.status == "paused" {
			if t.errMsg != "" {
				t.status = statusError
			} else {
				t.status = statusDone
			}
		}
		t.progress = map[string]any{
			"phase":     "scanning",
			"done":      len(t.vulns),
			"total":     len(t.pages),
			"elapsedMs": time.Since(t.startedAt).Milliseconds(),
		}
		st := t.status
		t.mu.Unlock()
		// Persist the finished scan so it survives a restart.
		persistScan(t.toRecord())
		if st == statusDone {
			t.emit(map[string]any{"type": "done"})
		} else if st == statusError {
			t.emit(map[string]any{"type": "error", "message": t.errMsg})
		}
	}()
}

// ---- plugins ----

func (s *Server) handlePlugins(w http.ResponseWriter, r *http.Request) {
	// single-group catalog (WScan plugins are flat; the SPA's tree builder handles
	// a flat list fine — every leaf lives at the root).
	writeJSON(w, []map[string]any{
		{"group": "Plugins", "plugins": s.plugins},
	})
}

// ---- profiles ----

// profiles are persisted in-memory (JSON file under data/). They are a named
// selection of plugin rels; the SPA treats an empty plugin list as "auto".
func (s *Server) profiles() []map[string]any {
	return loadProfiles()
}

func (s *Server) handleProfiles(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var body struct {
			Name        string   `json:"name"`
			Description string   `json:"description"`
			Plugins     []string `json:"plugins"`
		}
		if err := readJSON(r, &body); err != nil {
			writeJSON(w, map[string]any{"error": err.Error()})
			return
		}
		p := map[string]any{
			"id":          newID(),
			"name":        body.Name,
			"description": body.Description,
			"plugins":     body.Plugins,
		}
		if err := appendProfile(p); err != nil {
			writeJSON(w, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, p)
		return
	}
	writeJSON(w, s.profiles())
}

func (s *Server) handleProfile(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/profiles/")
	if id == "" {
		http.NotFound(w, r)
		return
	}
	if r.Method == http.MethodDelete {
		writeJSON(w, map[string]any{"ok": deleteProfile(id)})
		return
	}
	http.NotFound(w, r)
}

// ---- proxy ----

func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var body struct {
			ProxyURL string `json:"proxyUrl"`
		}
		if err := readJSON(r, &body); err != nil {
			writeJSON(w, map[string]any{"error": err.Error()})
			return
		}
		s.cfg.HTTP.Proxy = body.ProxyURL
		writeJSON(w, map[string]any{"proxyUrl": body.ProxyURL})
		return
	}
	writeJSON(w, map[string]any{"proxyUrl": s.cfg.HTTP.Proxy})
}

func (s *Server) handleProxyTest(w http.ResponseWriter, r *http.Request) {
	u := r.URL.Query().Get("proxyUrl")
	if u == "" {
		writeJSON(w, map[string]any{"ok": false, "error": "proxyUrl is required"})
		return
	}
	tr := &http.Transport{}
	start := time.Now()
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	req, err := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	defer resp.Body.Close()
	writeJSON(w, map[string]any{"ok": resp.StatusCode < 500, "status": resp.StatusCode, "elapsedMs": time.Since(start).Milliseconds()})
}

// ---- aggregated vulnerabilities ----

func (s *Server) handleVulnerabilities(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	all := s.mgr.allVulns()

	if q.Get("summary") == "1" {
		summary := map[string]any{"total": len(all), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
		for _, v := range all {
			switch strings.ToLower(fmt.Sprint(v["severity"])) {
			case "critical":
				summary["critical"] = summary["critical"].(int) + 1
			case "high":
				summary["high"] = summary["high"].(int) + 1
			case "medium", "moderate":
				summary["medium"] = summary["medium"].(int) + 1
			case "low":
				summary["low"] = summary["low"].(int) + 1
			default:
				summary["info"] = summary["info"].(int) + 1
			}
		}
		writeJSON(w, summary)
		return
	}

	page := atoiDefault(q.Get("page"), 0)
	size := atoiDefault(q.Get("pageSize"), 15)
	if size <= 0 {
		size = 15
	}
	sev := q.Get("severity")
	typeID := q.Get("typeId")
	grouped := q.Get("group") == "1"

	var filtered []map[string]any
	for _, v := range all {
		if sev != "" && !sevMatch(model.SeverityLevel(fmt.Sprint(v["severity"])), sev) {
			continue
		}
		if typeID != "" && fmt.Sprint(v["typeId"]) != typeID {
			continue
		}
		filtered = append(filtered, v)
	}

	if grouped {
		groups := groupFrontVulns(filtered)
		total := len(groups)
		start := page * size
		if start > total {
			start = total
		}
		end := start + size
		if end > total {
			end = total
		}
		slice := groups[start:end]
		items := make([]map[string]any, 0, len(slice))
		for _, g := range slice {
			items = append(items, map[string]any{
				"typeId":   g.typeID,
				"name":     g.name,
				"sev":      g.sev,
				"total":    g.total,
				"urlCount": g.urlCount,
			})
		}
		writeJSON(w, map[string]any{"items": items, "total": total, "page": page, "vulnTotal": len(filtered)})
		return
	}

	sort.SliceStable(filtered, func(i, j int) bool {
		return sevRank(model.SeverityLevel(fmt.Sprint(filtered[i]["severity"]))) > sevRank(model.SeverityLevel(fmt.Sprint(filtered[j]["severity"])))
	})
	total := len(filtered)
	start := page * size
	if start > total {
		start = total
	}
	end := start + size
	if end > total {
		end = total
	}
	writeJSON(w, map[string]any{"items": filtered[start:end], "total": total, "page": page, "vulnTotal": total})
}

// ---- report ----

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	format := q.Get("format")
	if format == "" {
		format = "html"
	}
	all := s.mgr.allVulns()
	switch format {
	case "json":
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="report.json"`)
		_ = json.NewEncoder(w).Encode(all)
	default:
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Disposition", `attachment; filename="report.html"`)
		_, _ = w.Write(output.GetHTMLTemplate())
		// append vulns the same way the HTML printer would
		for _, v := range all {
			data, _ := json.Marshal(v)
			_, _ = io.WriteString(w, "<script class='web-vulns'>webVulns.push("+string(data)+")</script>\n")
		}
		_, _ = io.WriteString(w, "<script class='scan-summary'>scanSummary={}</script>\n")
	}
}

// ---- helpers ----

func atoiDefault(s string, d int) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return d
		}
		n = n*10 + int(c-'0')
	}
	if s == "" {
		return d
	}
	return n
}

func splitHeader(h string) (string, string, bool) {
	idx := strings.Index(h, ":")
	if idx <= 0 {
		return "", "", false
	}
	return strings.TrimSpace(h[:idx]), strings.TrimSpace(h[idx+1:]), true
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// vulnTypeID is the stable per-type key the SPA groups on (plugin/category).
func vulnTypeID(v *model.WebVuln) string {
	if v.Plugin != "" {
		return v.Plugin
	}
	return "vuln"
}

func sevMatch(s model.SeverityLevel, want string) bool {
	return strings.EqualFold(string(s), want) ||
		(want == "medium" && strings.EqualFold(string(s), "moderate"))
}

func sevRank(s model.SeverityLevel) int {
	switch s {
	case model.SeverityCritical:
		return 4
	case model.SeverityHigh:
		return 3
	case model.SeverityMedium:
		return 2
	case model.SeverityLow:
		return 1
	default:
		return 0
	}
}

type vulnGroup struct {
	typeID   string
	name     string
	sev      model.SeverityLevel
	total    int
	urls     map[string]struct{}
	urlCount int
}

func groupVulns(vs []*model.WebVuln) []vulnGroup {
	idx := map[string]*vulnGroup{}
	var order []string
	for _, v := range vs {
		tid := vulnTypeID(v)
		g, ok := idx[tid]
		if !ok {
			name := tid
			if e := lookupVulnDB(tid); e != nil && e.Name != "" {
				name = e.Name
			}
			g = &vulnGroup{typeID: tid, name: name, sev: v.Severity, urls: map[string]struct{}{}}
			idx[tid] = g
			order = append(order, tid)
		}
		g.total++
		if v.Target.URL != "" {
			g.urls[v.Target.URL] = struct{}{}
		}
		if sevRank(v.Severity) > sevRank(g.sev) {
			g.sev = v.Severity
		}
	}
	out := make([]vulnGroup, 0, len(order))
	for _, tid := range order {
		g := idx[tid]
		g.urlCount = len(g.urls)
		out = append(out, *g)
	}
	sort.SliceStable(out, func(i, j int) bool { return sevRank(out[i].sev) > sevRank(out[j].sev) })
	return out
}

func groupFrontVulns(vs []map[string]any) []vulnGroup {
	idx := map[string]*vulnGroup{}
	var order []string
	for _, v := range vs {
		tid := fmt.Sprint(v["typeId"])
		g, ok := idx[tid]
		if !ok {
			name := tid
			if e := lookupVulnDB(tid); e != nil && e.Name != "" {
				name = e.Name
			}
			g = &vulnGroup{typeID: tid, name: name, sev: model.SeverityLevel(fmt.Sprint(v["severity"])), urls: map[string]struct{}{}}
			idx[tid] = g
			order = append(order, tid)
		}
		g.total++
		if u, ok := v["target"].(string); ok && u != "" {
			g.urls[u] = struct{}{}
		}
		if sevRank(model.SeverityLevel(fmt.Sprint(v["severity"]))) > sevRank(g.sev) {
			g.sev = model.SeverityLevel(fmt.Sprint(v["severity"]))
		}
	}
	out := make([]vulnGroup, 0, len(order))
	for _, tid := range order {
		g := idx[tid]
		g.urlCount = len(g.urls)
		out = append(out, *g)
	}
	sort.SliceStable(out, func(i, j int) bool { return sevRank(out[i].sev) > sevRank(out[j].sev) })
	return out
}

// webVulnToFront maps a model.WebVuln into the richer record shape the SPA's
// vuln detail renderer expects (typeId/severity/plugin/affects/parameter/etc.).
// The vuln type id (Binding.ID == vulndb xml stem) is used to look up the
// embedded vuln DB and fill in description/impact/recommendation/cvss/tags/
// references when present, so the detail pane shows the full advisory text.
func webVulnToFront(v *model.WebVuln) map[string]any {
	typeID := vulnTypeID(v)
	row := map[string]any{
		"typeId":    typeID,
		"name":      v.Plugin,
		"severity":  string(v.Severity),
		"plugin":    v.Plugin,
		"target":    v.Target.URL,
		"affects":   v.Detail.Addr,
		"parameter": paramKey(v),
		"taskId":    "",
	}
	if entry := lookupVulnDB(typeID); entry != nil {
		if entry.Name != "" {
			row["name"] = entry.Name
		}
		if entry.Description != "" {
			row["description"] = entry.Description
		}
		if entry.Impact != "" {
			row["impact"] = entry.Impact
		}
		if entry.Recommendation != "" {
			row["recommendation"] = entry.Recommendation
		}
		if entry.CVSS2 != "" {
			row["cvss2"] = entry.CVSS2
		}
		if entry.CVSS3 != "" {
			row["cvss3"] = entry.CVSS3
		}
		if entry.CVSS4 != "" {
			row["cvss4"] = entry.CVSS4
		}
		if entry.DetailsTemplate != "" {
			row["detailsTemplate"] = entry.DetailsTemplate
		}
		if len(entry.Tags) > 0 {
			row["tags"] = entry.Tags
		}
		if len(entry.References) > 0 {
			refs := make([]map[string]any, 0, len(entry.References))
			for _, r := range entry.References {
				refs = append(refs, map[string]any{"title": r.Title, "url": r.URL})
			}
			row["references"] = refs
		}
	}
	if len(v.Detail.SnapShot) > 0 {
		if req, res, ok := parseSnapShot(v.Detail.SnapShot[0]); ok {
			row["request"] = req
			row["response"] = res
		}
	}
	if v.Detail.Payload != "" {
		row["attackVector"] = v.Detail.Payload
	}
	if v.Detail.Extra != nil {
		if d, ok := v.Detail.Extra["detail"]; ok {
			row["details"] = d
		}
	}
	return row
}

// parseSnapShot turns a single SnapShot entry (as produced by model.Vuln.ToWebVuln:
// a []any{"<raw HTTP request>", "<raw HTTP response>"}) into the request/response
// object shape the SPA's httpSec() renderer expects: {method,uri,version,headers,body}
// and {status,reason,headers,body}. Snapshots can also be a single combined string;
// we split on the blank-line boundary between request and response as a fallback.
func parseSnapShot(shot any) (req, res map[string]any, ok bool) {
	parts := snapshotStrings(shot)
	if len(parts) == 0 {
		return nil, nil, false
	}
	if len(parts) >= 2 {
		req = parseRawRequest(parts[0])
		res = parseRawResponse(parts[1])
		return req, res, true
	}
	// Single string: split request/response on the first blank line after the
	// request body (best-effort — covers dumps that concatenate the two).
	req = parseRawRequest(parts[0])
	if req != nil {
		if raw, _ := req["__raw"].(string); raw != "" {
			delete(req, "__raw")
			if idx := strings.Index(raw, "\r\n\r\n"); idx >= 0 {
				rest := raw[idx+4:]
				if r := parseRawResponse(rest); r != nil {
					res = r
				}
			} else if idx := strings.Index(raw, "\n\n"); idx >= 0 {
				rest := raw[idx+2:]
				if r := parseRawResponse(rest); r != nil {
					res = r
				}
			}
		}
	}
	return req, res, req != nil
}

// snapshotStrings normalizes a SnapShot entry into raw HTTP text strings:
// either a []any/[]string{request, response} or a single string.
func snapshotStrings(shot any) []string {
	switch s := shot.(type) {
	case []string:
		out := make([]string, 0, len(s))
		for _, v := range s {
			out = append(out, v)
		}
		return out
	case []any:
		out := make([]string, 0, len(s))
		for _, v := range s {
			if str, ok := v.(string); ok {
				out = append(out, str)
			}
		}
		return out
	case string:
		return []string{s}
	}
	return nil
}

// parseRawRequest parses a raw HTTP request dump into {method,uri,version,headers,body}.
// headers is a map[string][]string. Returns nil if the request line cannot be parsed.
func parseRawRequest(raw string) map[string]any {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	// split head/body
	var head, body string
	if idx := strings.Index(raw, "\r\n\r\n"); idx >= 0 {
		head, body = raw[:idx], raw[idx+4:]
	} else if idx := strings.Index(raw, "\n\n"); idx >= 0 {
		head, body = raw[:idx], raw[idx+2:]
	} else {
		head = raw
	}
	lines := splitLines(head)
	if len(lines) == 0 {
		return nil
	}
	fields := strings.Fields(lines[0])
	if len(fields) < 3 {
		return nil
	}
	headers := map[string]any{}
	for _, l := range lines[1:] {
		if l == "" {
			continue
		}
		if i := strings.IndexByte(l, ':'); i >= 0 {
			k := strings.TrimSpace(l[:i])
			v := strings.TrimSpace(l[i+1:])
			if k == "" {
				continue
			}
			if cur, exists := headers[k]; exists {
				if arr, ok := cur.([]string); ok {
					headers[k] = append(arr, v)
				} else if s, ok := cur.(string); ok {
					headers[k] = []string{s, v}
				}
			} else {
				headers[k] = v
			}
		}
	}
	row := map[string]any{
		"method":  fields[0],
		"uri":     fields[1],
		"version": fields[2],
		"headers": headers,
	}
	if body != "" {
		row["body"] = body
	}
	return row
}

// parseRawResponse parses a raw HTTP response dump into {status,reason,version,headers,body}.
func parseRawResponse(raw string) map[string]any {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var head, body string
	if idx := strings.Index(raw, "\r\n\r\n"); idx >= 0 {
		head, body = raw[:idx], raw[idx+4:]
	} else if idx := strings.Index(raw, "\n\n"); idx >= 0 {
		head, body = raw[:idx], raw[idx+2:]
	} else {
		head = raw
	}
	lines := splitLines(head)
	if len(lines) == 0 {
		return nil
	}
	fields := strings.SplitN(lines[0], " ", 3)
	if len(fields) < 2 {
		return nil
	}
	version := fields[0]
	statusStr := fields[1]
	reason := ""
	if len(fields) >= 3 {
		reason = fields[2]
	}
	status := 0
	_ = json.Unmarshal([]byte(statusStr), &status)
	headers := map[string]any{}
	for _, l := range lines[1:] {
		if l == "" {
			continue
		}
		if i := strings.IndexByte(l, ':'); i >= 0 {
			k := strings.TrimSpace(l[:i])
			v := strings.TrimSpace(l[i+1:])
			if k == "" {
				continue
			}
			if cur, exists := headers[k]; exists {
				if arr, ok := cur.([]string); ok {
					headers[k] = append(arr, v)
				} else if s, ok := cur.(string); ok {
					headers[k] = []string{s, v}
				}
			} else {
				headers[k] = v
			}
		}
	}
	row := map[string]any{
		"status":  status,
		"reason":  reason,
		"version": version,
		"headers": headers,
	}
	if body != "" {
		row["body"] = body
	}
	return row
}

// splitLines splits on CRLF or LF, dropping trailing empties.
func splitLines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	parts := strings.Split(s, "\n")
	for len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	return parts
}


func paramKey(v *model.WebVuln) string {
	if len(v.Target.Params) > 0 && len(v.Target.Params[0].Path) > 0 {
		return v.Target.Params[0].Path[0]
	}
	return ""
}

// applyPluginSelection enables only the named plugins in a config clone.
func applyPluginSelection(cfg *entry.CliEntryConfig, names []string) {
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	for name, pc := range cfg.Config.Plugins {
		if pc == nil || pc.BaseConfig() == nil {
			continue
		}
		pc.BaseConfig().Enabled = want[name]
	}
}

// stub to keep the base import referenced if future per-plugin introspection is
// added (Binding/Severity come from fingers, not the plugin interface).
var _ = base.PluginBaseConfig{}
