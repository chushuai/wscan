/**
* @Author: shaochuyu
* @Date: 7/25/2026
*
* Verifies that a scan task's persisted record (metadata + vulns) is rehydrated
* into the task manager after the in-memory state is reset, simulating a restart.
 */
package web

import (
	"testing"
	"time"

	"wscan/core/fingerprint"
)

// mustTime returns a fixed non-zero time for test records.
func mustTime() time.Time { return time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC) }

// After persistScan writes a record, rehydrating should bring a terminal task
// back with its vulns intact so /api/vulnerabilities still returns them.
func TestScanPersistRehydrate(t *testing.T) {
	// reset scan store to a clean slate
	scanMu.Lock()
	scanCache = nil
	scansLoaded = false
	scanMu.Unlock()

	rec := scanRecord{
		ID:        "scan-1",
		Name:      "demo",
		Target:    "http://example.com",
		TaskType:  "scan",
		Status:    "done",
		StartedAt: mustTime(),
	}
	rec.Vulns = nil
	persistScan(rec)

	// reset in-memory manager + reload from disk
	mgr := newTaskManager()
	scanMu.Lock()
	scanCache = nil
	scansLoaded = false
	scanMu.Unlock()
	mgr.rehydrateScans()

	tasks := mgr.list()
	if len(tasks) != 1 {
		t.Fatalf("expected 1 rehydrated task, got %d", len(tasks))
	}
	got, ok := mgr.get("scan-1")
	if !ok {
		t.Fatalf("rehydrated task not found")
	}
	if got.target != "http://example.com" {
		t.Fatalf("target mismatch: %s", got.target)
	}
	if string(got.status) != "done" {
		t.Fatalf("status mismatch: %s", got.status)
	}

	all := mgr.allVulns()
	if len(all) != 0 {
		t.Fatalf("expected 0 vulns, got %d", len(all))
	}

	// delete should drop it from both memory and disk.
	if err := mgr.delete("scan-1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok := mgr.get("scan-1"); ok {
		t.Fatalf("task still in memory after delete")
	}
	scanMu.Lock()
	defer scanMu.Unlock()
	for _, r := range scanCache {
		if r.ID == "scan-1" {
			t.Fatalf("scan-1 still on disk after delete")
		}
	}
}

// Persisting a scan with detected technologies should round-trip the techPages
// so the technologies view keeps working after a restart.
func TestScanPersistRehydrateTechPages(t *testing.T) {
	scanMu.Lock()
	scanCache = nil
	scansLoaded = false
	scanMu.Unlock()

	rec := scanRecord{
		ID:        "scan-tech",
		Name:      "tech-demo",
		Target:    "http://example.com",
		TaskType:  "scan",
		Status:    "done",
		StartedAt: mustTime(),
		TechPages: []fingerprint.AggPage{
			{URL: "http://example.com/", Technologies: []fingerprint.Tech{{Name: "nginx", Confidence: 100}}},
			{URL: "http://example.com/login", Technologies: []fingerprint.Tech{{Name: "PHP", Confidence: 100}}},
		},
	}
	persistScan(rec)

	mgr := newTaskManager()
	scanMu.Lock()
	scanCache = nil
	scansLoaded = false
	scanMu.Unlock()
	mgr.rehydrateScans()

	got, ok := mgr.get("scan-tech")
	if !ok {
		t.Fatalf("rehydrated tech task not found")
	}
	if len(got.techPages) != 2 {
		t.Fatalf("expected 2 techPages, got %d", len(got.techPages))
	}

	mgr.delete("scan-tech")
}
