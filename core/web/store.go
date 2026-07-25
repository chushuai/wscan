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
	groupMu       sync.Mutex
	targetCache   []map[string]any
	targetsLoaded bool
	groupCache    []map[string]any
	groupsLoaded  bool
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

// ---- target groups ----

// toInt converts a numeric value (including json.Number) to an int.
func toInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	case json.Number:
		i, err := n.Int64()
		return int(i), err == nil
	}
	return 0, false
}

// groupForFrontend computes the UI-facing view of a group: member count and
// the summed vuln breakdown across its members.
func (s *Server) groupForFrontend(g map[string]any) map[string]any {
	memberIDs := groupMemberIDs(g)
	breakdown := map[string]int{}
	for _, id := range memberIDs {
		for _, t := range s.targets() {
			if fmt.Sprint(t["id"]) == id {
				if vb, ok := t["vulnBreakdown"].(map[string]any); ok {
					for k, v := range vb {
						if n, ok := toInt(v); ok {
							breakdown[k] += n
						}
					}
				}
				break
			}
		}
	}
	out := map[string]any{
		"id":            g["id"],
		"name":          g["name"],
		"description":   g["description"],
		"members":       memberIDs,
		"memberCount":   len(memberIDs),
		"vulnBreakdown": breakdown,
	}
	return out
}

// groupMemberIDs normalizes a group's "members" field (which may be []string
// when freshly created in memory or []any after a JSON reload) to []string.
func groupMemberIDs(g map[string]any) []string {
	raw := g["members"]
	switch v := raw.(type) {
	case []string:
		return append([]string{}, v...)
	case []any:
		out := make([]string, 0, len(v))
		for _, m := range v {
			out = append(out, fmt.Sprint(m))
		}
		return out
	}
	return []string{}
}

// groupsLocked loads groupCache from disk on first use. Caller must hold groupMu.
func (s *Server) groupsLocked() {
	if groupsLoaded {
		return
	}
	groupsLoaded = true
	ensureDataDir()
	b, err := os.ReadFile(filepath.Join(dataDir, "webui_groups.json"))
	if err == nil {
		_ = json.Unmarshal(b, &groupCache)
	}
	if groupCache == nil {
		groupCache = []map[string]any{}
	}
}

// groups returns the persisted group list projected for the frontend.
func (s *Server) groups() []map[string]any {
	groupMu.Lock()
	defer groupMu.Unlock()
	s.groupsLocked()
	out := make([]map[string]any, 0, len(groupCache))
	for _, g := range groupCache {
		out = append(out, s.groupForFrontend(g))
	}
	return out
}

// groupRaw returns the raw stored group matching id (or nil).
func (s *Server) groupRaw(id string) map[string]any {
	groupMu.Lock()
	defer groupMu.Unlock()
	s.groupsLocked()
	for _, g := range groupCache {
		if fmt.Sprint(g["id"]) == id {
			return g
		}
	}
	return nil
}

// saveGroupsLocked writes groupCache to disk. Caller must hold groupMu.
func saveGroupsLocked() {
	ensureDataDir()
	_ = writeJSONFile(filepath.Join(dataDir, "webui_groups.json"), groupCache)
}

// createGroup appends a new group and persists it.
func (s *Server) createGroup(name, description string) map[string]any {
	groupMu.Lock()
	defer groupMu.Unlock()
	s.groupsLocked()
	g := map[string]any{
		"id":          newID(),
		"name":        name,
		"description": description,
		"members":     []string{},
	}
	groupCache = append(groupCache, g)
	saveGroupsLocked()
	return g
}

// updateGroup merges body into the stored group with the given id.
func (s *Server) updateGroup(id string, body map[string]any) map[string]any {
	groupMu.Lock()
	defer groupMu.Unlock()
	s.groupsLocked()
	for _, g := range groupCache {
		if fmt.Sprint(g["id"]) == id {
			for k, v := range body {
				g[k] = v
			}
			saveGroupsLocked()
			return g
		}
	}
	return nil
}

// deleteGroup removes the group with the given id.
func (s *Server) deleteGroup(id string) bool {
	groupMu.Lock()
	defer groupMu.Unlock()
	s.groupsLocked()
	out := groupCache[:0]
	removed := false
	for _, g := range groupCache {
		if fmt.Sprint(g["id"]) == id {
			removed = true
			continue
		}
		out = append(out, g)
	}
	if removed {
		groupCache = out
		saveGroupsLocked()
	}
	return removed
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
		// Drop the deleted id from any group it belonged to.
		s.removeTargetFromGroupsLocked(id)
	}
	return removed
}

// removeTargetFromGroupsLocked prunes a target id from every group's members.
// Caller may hold targetMu; groupMu is taken here independently.
func (s *Server) removeTargetFromGroupsLocked(id string) {
	groupMu.Lock()
	defer groupMu.Unlock()
	s.groupsLocked()
	changed := false
	for _, g := range groupCache {
		members, _ := g["members"].([]string)
		filtered := members[:0]
		drop := false
		for _, m := range members {
			if m == id {
				drop = true
				continue
			}
			filtered = append(filtered, m)
		}
		if drop {
			g["members"] = filtered
			changed = true
		}
	}
	if changed {
		saveGroupsLocked()
	}
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
