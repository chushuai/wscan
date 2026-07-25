/**
* @Author: shaochuyu
* @Date: 7/25/2026
*
* In-memory persistence of scan targets + scan profiles for the WebUI. Stored
* as simple JSON files under ./data so the UI's target/profile CRUD survives
* restarts. The scanner itself is stateless; these are UI convenience stores.
 */
package web

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

const dataDir = "data"

var (
	targetMu      sync.Mutex
	profileMu     sync.Mutex
	targetCache   []map[string]any
	targetsLoaded bool
)

func ensureDataDir() {
	_ = os.MkdirAll(dataDir, 0o755)
}

// targets returns the persisted target list (address + description + scope).
func (s *Server) targets() []map[string]any {
	targetMu.Lock()
	defer targetMu.Unlock()
	s.targetsLocked()
	out := make([]map[string]any, len(targetCache))
	copy(out, targetCache)
	return out
}

// targetsLocked populates targetCache on first use. Caller must hold targetMu.
func (s *Server) targetsLocked() {
	if targetsLoaded {
		return
	}
	targetsLoaded = true
	ensureDataDir()
	b, err := os.ReadFile(filepath.Join(dataDir, "webui_targets.json"))
	if err == nil {
		_ = json.Unmarshal(b, &targetCache)
	}
	if targetCache == nil {
		targetCache = []map[string]any{}
	}
}

// loadProfilesLocked reads the persisted profile list from disk WITHOUT taking
// the lock — used by helpers that already hold profileMu.
func loadProfilesLocked() []map[string]any {
	ensureDataDir()
	b, err := os.ReadFile(filepath.Join(dataDir, "webui_profiles.json"))
	if err != nil {
		return []map[string]any{}
	}
	var out []map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return []map[string]any{}
	}
	if out == nil {
		out = []map[string]any{}
	}
	return out
}

// loadProfiles reads the persisted profile list from disk.
func loadProfiles() []map[string]any {
	profileMu.Lock()
	defer profileMu.Unlock()
	return loadProfilesLocked()
}

func appendProfile(p map[string]any) error {
	profileMu.Lock()
	defer profileMu.Unlock()
	list := loadProfilesLocked()
	list = append(list, p)
	return writeJSONFile(filepath.Join(dataDir, "webui_profiles.json"), list)
}

func deleteProfile(id string) bool {
	profileMu.Lock()
	defer profileMu.Unlock()
	list := loadProfilesLocked()
	out := list[:0]
	removed := false
	for _, p := range list {
		if fmt.Sprint(p["id"]) == id {
			removed = true
			continue
		}
		out = append(out, p)
	}
	if !removed {
		return false
	}
	_ = writeJSONFile(filepath.Join(dataDir, "webui_profiles.json"), out)
	return true
}

func writeJSONFile(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// addTarget appends a target to the in-memory + on-disk store.
func (s *Server) addTarget(t map[string]any) {
	targetMu.Lock()
	defer targetMu.Unlock()
	s.targetsLocked()
	targetCache = append(targetCache, t)
	ensureDataDir()
	_ = writeJSONFile(filepath.Join(dataDir, "webui_targets.json"), targetCache)
}

func (s *Server) deleteTarget(id string) bool {
	targetMu.Lock()
	defer targetMu.Unlock()
	s.targetsLocked()
	out := targetCache[:0]
	removed := false
	for _, t := range targetCache {
		if fmt.Sprint(t["id"]) == id {
			removed = true
			continue
		}
		out = append(out, t)
	}
	if removed {
		targetCache = out
		_ = writeJSONFile(filepath.Join(dataDir, "webui_targets.json"), targetCache)
	}
	return removed
}

func (s *Server) updateTarget(id string, body map[string]any) bool {
	targetMu.Lock()
	defer targetMu.Unlock()
	s.targetsLocked()
	for _, t := range targetCache {
		if fmt.Sprint(t["id"]) == id {
			for k, v := range body {
				t[k] = v
			}
			_ = writeJSONFile(filepath.Join(dataDir, "webui_targets.json"), targetCache)
			return true
		}
	}
	return false
}
