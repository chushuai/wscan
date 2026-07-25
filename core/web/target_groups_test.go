/**
* @Author: shaochuyu
* @Date: 7/25/2026
*
* Handler-level coverage for the target-groups CRUD API. Uses httptest against
* the real mux so the route + store + JSON projection are exercised together.
 */
package web

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

// newTestServer wires a Server with its route mux, pointed at a temp data dir
// so tests never touch the real ./data store.
func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	dir := t.TempDir()
	t.Cleanup(func() { _ = resetGroupStore(filepath.Join(dir, "webui_groups.json")) })
	srv := &Server{mgr: newTaskManager()}
	mux := http.NewServeMux()
	srv.registerRoutes(mux)
	return httptest.NewServer(mux)
}

func resetGroupStore(_ string) error {
	groupMu.Lock()
	defer groupMu.Unlock()
	groupCache = nil
	groupsLoaded = false
	return nil
}

func doJSON(t *testing.T, s *httptest.Server, method, path string, body any) map[string]any {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, s.URL+path, rdr)
	if err != nil {
		t.Fatalf("new req: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	if out == nil {
		out = map[string]any{"_status": resp.StatusCode, "_body": string(raw)}
	}
	out["_status"] = resp.StatusCode
	return out
}

// Create a group, add members via PUT, then GET and assert the members and
// memberCount are persisted and projected back to the SPA shape.
func TestTargetGroupCreateAddMembersPersist(t *testing.T) {
	s := newTestServer(t)
	defer s.Close()

	// Create a target first so it can become a member.
	tg := doJSON(t, s, "POST", "/api/targets", map[string]any{"address": "http://example.com"})
	tid, _ := tg["id"].(string)
	if tid == "" {
		t.Fatalf("no target id: %v", tg)
	}

	// Create a group.
	g := doJSON(t, s, "POST", "/api/target-groups", map[string]any{"name": "g1", "description": "d"})
	if g["name"] != "g1" {
		t.Fatalf("create group response: %v", g)
	}
	gid, _ := g["id"].(string)
	if gid == "" {
		t.Fatalf("no group id: %v", g)
	}
	if g["memberCount"].(float64) != 0 {
		t.Fatalf("expected 0 members, got %v", g["memberCount"])
	}

	// Add the target as a member.
	upd := doJSON(t, s, "PUT", "/api/target-groups/"+gid, map[string]any{"members": []string{tid}})
	if upd["memberCount"].(float64) != 1 {
		t.Fatalf("expected 1 member after add, got %v", upd["memberCount"])
	}

	// Re-GET the list and confirm it survives (in-memory cache persists).
	resp, _ := http.Get(s.URL + "/api/target-groups")
	defer resp.Body.Close()
	var groups []map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&groups)
	found := false
	for _, gr := range groups {
		if gr["id"] == gid {
			found = true
			if gr["memberCount"].(float64) != 1 {
				t.Fatalf("GET list memberCount wrong: %v", gr["memberCount"])
			}
			mem, _ := gr["members"].([]any)
			if len(mem) != 1 || mem[0] != tid {
				t.Fatalf("GET list members wrong: %v", mem)
			}
		}
	}
	if !found {
		t.Fatalf("group %s not found in list", gid)
	}

	// Reload the store from disk to confirm persistence beyond the cache.
	groupMu.Lock()
	groupCache = nil
	groupsLoaded = false
	groupMu.Unlock()
	resp2, _ := http.Get(s.URL + "/api/target-groups")
	defer resp2.Body.Close()
	var groups2 []map[string]any
	_ = json.NewDecoder(resp2.Body).Decode(&groups2)
	for _, gr := range groups2 {
		if gr["id"] == gid {
			if gr["memberCount"].(float64) != 1 {
				t.Fatalf("post-reload memberCount wrong: %v", gr["memberCount"])
			}
		}
	}
}

// Deleting a target should prune it from any group's members.
func TestDeleteTargetPrunesGroupMembers(t *testing.T) {
	s := newTestServer(t)
	defer s.Close()

	tg := doJSON(t, s, "POST", "/api/targets", map[string]any{"address": "http://ex2.com"})
	tid, _ := tg["id"].(string)

	g := doJSON(t, s, "POST", "/api/target-groups", map[string]any{"name": "g2"})
	gid, _ := g["id"].(string)

	doJSON(t, s, "PUT", "/api/target-groups/"+gid, map[string]any{"members": []string{tid}})

	doJSON(t, s, "DELETE", "/api/targets/"+tid, nil)

	resp, _ := http.Get(s.URL + "/api/target-groups")
	defer resp.Body.Close()
	var groups []map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&groups)
	for _, gr := range groups {
		if gr["id"] == gid {
			if gr["memberCount"].(float64) != 0 {
				t.Fatalf("expected pruned to 0, got %v", gr["memberCount"])
			}
		}
	}
}
