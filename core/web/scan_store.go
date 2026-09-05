/**
* @Author: shaochuyu
* @Date: 7/25/2026
*
* On-disk persistence of finished scan-task metadata + their collected vulns, so
* the WebUI's scan/vuln history survives a server restart. Only terminal tasks
* (done/error/stopped) are persisted; running tasks stay in-memory until they
* finish. Loaded once at startup and re-saved whenever a task completes.
 */
package web

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"wscan/core/fingerprint"
	"wscan/core/model"
)

const scansFile = "webui_scans.json"

var (
	scanMu      sync.Mutex
	scanCache   []scanRecord
	scansLoaded bool
)

// scanRecord is the persisted shape of one completed scan: its front-facing
// summary plus the raw vulns (re-projected on load).
type scanRecord struct {
	ID        string                `json:"id"`
	Name      string                `json:"name"`
	Target    string                `json:"target"`
	TaskType  string                `json:"taskType"`
	Status    string                `json:"status"`
	ErrMsg    string                `json:"errMsg,omitempty"`
	Crawled   int                   `json:"crawled"`
	StartedAt time.Time             `json:"startedAt"`
	Vulns     []*model.WebVuln      `json:"vulns"`
	Pages     []map[string]any      `json:"pages,omitempty"`
	Progress  map[string]any        `json:"progress,omitempty"`
	Req       map[string]any        `json:"req,omitempty"`
	TechPages []fingerprint.AggPage `json:"techPages,omitempty"`
}

// scansLocked populates scanCache from disk on first use. Caller holds scanMu.
func scansLocked() {
	if scansLoaded {
		return
	}
	scansLoaded = true
	ensureDataDir()
	b, err := os.ReadFile(filepath.Join(dataDir, scansFile))
	if err == nil {
		_ = json.Unmarshal(b, &scanCache)
	}
	if scanCache == nil {
		scanCache = []scanRecord{}
	}
}

// loadScanRecords returns the persisted scan records (newest-first). Loaded once
// at server startup to rehydrate the task manager.
func loadScanRecords() []scanRecord {
	scanMu.Lock()
	defer scanMu.Unlock()
	scansLocked()
	out := make([]scanRecord, len(scanCache))
	copy(out, scanCache)
	return out
}

// saveScanRecordsLocked writes the cache to disk. Caller holds scanMu.
func saveScanRecordsLocked() {
	ensureDataDir()
	_ = writeJSONFile(filepath.Join(dataDir, scansFile), scanCache)
}

// persistScan upserts a completed task's record into the cache + disk. The
// caller passes the task's summary fields and its vuln slice.
func persistScan(rec scanRecord) {
	scanMu.Lock()
	defer scanMu.Unlock()
	scansLocked()
	found := false
	for i, r := range scanCache {
		if r.ID == rec.ID {
			scanCache[i] = rec
			found = true
			break
		}
	}
	if !found {
		scanCache = append(scanCache, rec)
	}
	saveScanRecordsLocked()
}

// unpersistScan drops a scan record by id (used on task delete).
func unpersistScan(id string) {
	scanMu.Lock()
	defer scanMu.Unlock()
	scansLocked()
	out := scanCache[:0]
	removed := false
	for _, r := range scanCache {
		if r.ID == id {
			removed = true
			continue
		}
		out = append(out, r)
	}
	if removed {
		scanCache = out
		saveScanRecordsLocked()
	}
}

// rehydrateScans rebuilds in-memory scanTask entries from persisted records so
// /api/tasks, /api/vulnerabilities and per-task detail keep working after a
// restart. Only the persisted (terminal) tasks come back; running tasks from a
// previous process are lost by design.
//
// Records are appended into m.order in oldest-first order (matching startScan's
// add()), so taskManager.list()'s newest-first reverse traversal keeps working.
func (m *taskManager) rehydrateScans() {
	records := loadScanRecords()
	// 按开始时间升序(最旧在前)append 进 m.order,与 startScan 的 add() 保持一致:
	// taskManager.list() 倒序遍历 m.order(最新在前),所以 order 必须是正序。
	// 磁盘是 append 顺序(最旧在前),这里先按时间稳定排序兜底(防止落盘顺序被
	// upsert 打乱),再正序 append —— 之前误把排序结果当倒序、又叠加 list() 的
	// 倒序遍历,导致重启后任务列表变成「最旧在前」。
	sort.Slice(records, func(i, j int) bool { return records[i].StartedAt.Before(records[j].StartedAt) })
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range records {
		if _, exists := m.tasks[r.ID]; exists {
			continue
		}
		t := &scanTask{
			id:        r.ID,
			name:      r.Name,
			target:    r.Target,
			taskType:  r.TaskType,
			startedAt: r.StartedAt,
			status:    taskStatus(r.Status),
			errMsg:    r.ErrMsg,
			crawled:   r.Crawled,
			progress:  r.Progress,
			vulns:     r.Vulns,
			pages:     r.Pages,
			techPages: r.TechPages,
			runDone:   make(chan struct{}),
		}
		if r.Req != nil {
			t.req = scanRequest{
				Target:          strVal(r.Req["target"]),
				Mode:            strVal(r.Req["mode"]),
				Listen:          strVal(r.Req["listen"]),
				CrawlerMode:     strVal(r.Req["crawlerMode"]),
				MaxPages:        intVal(r.Req["maxPages"]),
				MaxDepth:        intVal(r.Req["maxDepth"]),
				Concurrency:     intVal(r.Req["concurrency"]),
				Plugins:         strSlice(r.Req["plugins"]),
				Auth:            mapVal(r.Req["auth"]),
				Method:          strVal(r.Req["method"]),
				Headers:         strSlice(r.Req["headers"]),
				IncludePatterns: strSlice(r.Req["includePatterns"]),
				ExcludePatterns: strSlice(r.Req["excludePatterns"]),
				ProxyURL:        strVal(r.Req["proxyUrl"]),
				NoProxy:         boolVal(r.Req["noProxy"]),
				AutoScan:        boolVal(r.Req["autoScan"]),
				Lab:             strVal(r.Req["lab"]),
			}
			if d, ok := r.Req["data"]; ok {
				if s, ok := d.(string); ok {
					t.req.Data = &s
				}
			}
		}
		// mark runDone as already closed — these tasks are terminal.
		close(t.runDone)
		m.tasks[r.ID] = t
		m.order = append(m.order, r.ID)
	}
}

// toRecord snapshots a scanTask into a persistable scanRecord.
func (t *scanTask) toRecord() scanRecord {
	t.mu.RLock()
	defer t.mu.RUnlock()
	rec := scanRecord{
		ID:        t.id,
		Name:      t.name,
		Target:    t.target,
		TaskType:  t.taskType,
		Status:    string(t.status),
		ErrMsg:    t.errMsg,
		Crawled:   t.crawled,
		StartedAt: t.startedAt,
		Vulns:     t.vulns,
		Pages:     t.pages,
		Progress:  t.progress,
		TechPages: t.techPages,
	}
	// 把 scanRequest 序列化成 map,落到记录里(过滤掉敏感原文后由前端展示)。
	if b, err := json.Marshal(t.req); err == nil {
		var m map[string]any
		if err := json.Unmarshal(b, &m); err == nil {
			rec.Req = m
		}
	}
	return rec
}

// 以下 helper 仅供 rehydrateScans 从持久化的 map[string]any 还原 scanRequest 用。
func strVal(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func intVal(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case int64:
		return int(n)
	}
	return 0
}

func boolVal(v any) bool {
	if b, ok := v.(bool); ok {
		return b
	}
	return false
}

func strSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func mapVal(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return nil
}
