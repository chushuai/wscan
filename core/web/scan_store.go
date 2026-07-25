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
	ID        string           `json:"id"`
	Name      string           `json:"name"`
	Target    string           `json:"target"`
	TaskType  string           `json:"taskType"`
	Status    string           `json:"status"`
	ErrMsg    string           `json:"errMsg,omitempty"`
	Crawled   int              `json:"crawled"`
	StartedAt time.Time        `json:"startedAt"`
	Vulns     []*model.WebVuln `json:"vulns"`
	Pages     []map[string]any `json:"pages,omitempty"`
	Progress  map[string]any   `json:"progress,omitempty"`
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
func (m *taskManager) rehydrateScans() {
	records := loadScanRecords()
	// newest-first: records on disk are append-order (oldest first), so reverse.
	sort.Slice(records, func(i, j int) bool { return records[i].StartedAt.After(records[j].StartedAt) })
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
			runDone:   make(chan struct{}),
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
	return scanRecord{
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
	}
}
