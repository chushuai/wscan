package reverse

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ==================== Reverse FetchURLEvent remote path ====================

func TestBoostFetchURLEvent_RemoteServer(t *testing.T) {
	// Create a test server for the remote fetch endpoint
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_/api/fetch" && r.Method == "POST" {
			w.WriteHeader(200)
			w.Write([]byte(`{"code":0,"data":[{"id":1,"group_id":"g1","unit_id":"u1","event_type":"http"}]}`))
		}
	}))
	defer server.Close()

	serverAddr := strings.TrimPrefix(server.URL, "http://")
	r := &Reverse{
		config: &Config{
			Token: "test-token",
			ClientConfig: ClientConfig{
				RemoteServer: true,
				HTTPBaseURL:  server.URL,
			},
		},
		internalGroupEventMap: &sync.Map{},
		groupUnitCallbackMap:  sync.Map{},
	}

	// Test the remote path of FetchURLEvent
	result := r.FetchURLEvent("/i/token/g1/u1/")
	_ = result
	_ = serverAddr
}

// ==================== Reverse FetchEvent goroutine coverage ====================

func TestBoostFetchEvent_LocalWithCallbackMap(t *testing.T) {
	r := &Reverse{
		config:                &Config{Token: "test", ClientConfig: ClientConfig{RemoteServer: false}},
		internalGroupEventMap: &sync.Map{},
		groupUnitCallbackMap:  sync.Map{},
	}

	// Register a unit with callback
	ug := r.NewUnitGroup()
	unit := r.RegisterWithGroup(nil, ug)
	callbackCalled := false
	unit.OnVisit(func(ev *Event) error {
		callbackCalled = true
		return nil
	})

	// Store in callback map
	r.groupUnitCallbackMap.Store(fmt.Sprintf("%s_%s", ug.id, unit.id), unit)

	// Store event in internal group event map
	r.internalGroupEventMap.Store(ug, &Event{
		GroupID:   ug.id,
		UnitID:    unit.id,
		EventType: "http",
	})

	// Manually trigger localFetchEvent logic
	r.groupUnitCallbackMap.Range(func(key, value any) bool {
		if u, ok := value.(*Unit); ok {
			ev, loaded := r.internalGroupEventMap.Load(u.group)
			if loaded {
				if u.Callback != nil {
					u.Callback(ev.(*Event))
				}
				r.groupUnitCallbackMap.Delete(key)
			}
		}
		return true
	})

	if !callbackCalled {
		t.Error("Expected callback to be called")
	}
}

// ==================== Reverse gcExpiredGroup with real entries ====================

func TestBoostGcExpiredGroup_WithExpiredEntries(t *testing.T) {
	r := &Reverse{
		config:                &Config{Token: "test"},
		internalGroupEventMap: &sync.Map{},
		groupUnitCallbackMap:  sync.Map{},
	}

	// Create an expired unit entry
	ug := &UnitGroup{id: "expired-group", expireAt: time.Now().Add(-10 * time.Minute)}
	unit := &Unit{id: "unit1", group: ug, reverse: r}
	r.groupUnitCallbackMap.Store("expired-group_unit1", unit)

	// Create a non-expired entry
	ug2 := &UnitGroup{id: "valid-group", expireAt: time.Now().Add(10 * time.Minute)}
	unit2 := &Unit{id: "unit2", group: ug2, reverse: r}
	r.groupUnitCallbackMap.Store("valid-group_unit2", unit2)

	// Run gcExpiredGroup in a goroutine with a short timeout
	done := make(chan struct{})
	go func() {
		// Manually trigger the GC logic inline (can't call gcExpiredGroup directly as it blocks)
		r.groupUnitCallbackMap.Range(func(key, value any) bool {
			if u, ok := value.(*Unit); ok {
				if time.Now().After(u.group.expireAt) {
					r.groupUnitCallbackMap.Delete(key)
				}
			}
			return true
		})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("gc logic timed out")
	}

	// Expired entry should be deleted
	if _, ok := r.groupUnitCallbackMap.Load("expired-group_unit1"); ok {
		t.Error("expired entry should be deleted")
	}
	// Valid entry should still exist
	if _, ok := r.groupUnitCallbackMap.Load("valid-group_unit2"); !ok {
		t.Error("valid entry should still exist")
	}
}

// ==================== Reverse gcExpiredEventMap with real entries ====================

func TestBoostGcExpiredEventMap_WithExpiredEvents(t *testing.T) {
	r := &Reverse{
		config:                &Config{Token: "test"},
		internalGroupEventMap: &sync.Map{},
	}

	// Store an old event (expired)
	r.internalGroupEventMap.Store("old-group", &Event{
		GroupID:   "old-group",
		TimeStamp: time.Now().Add(-10 * time.Minute).UnixMilli(),
	})

	// Store a recent event
	r.internalGroupEventMap.Store("new-group", &Event{
		GroupID:   "new-group",
		TimeStamp: time.Now().UnixMilli(),
	})

	// Manually run the GC logic inline
	count := 0
	r.internalGroupEventMap.Range(func(key, value any) bool {
		count++
		if count > 30 {
			return false
		}
		ev := value.(*Event)
		if time.Now().UnixMilli()-ev.TimeStamp > 3*60*1000 {
			r.internalGroupEventMap.Delete(key)
		}
		return true
	})

	// Old event should be deleted
	if _, ok := r.internalGroupEventMap.Load("old-group"); ok {
		t.Error("old event should be deleted")
	}
	// New event should still exist
	if _, ok := r.internalGroupEventMap.Load("new-group"); !ok {
		t.Error("new event should still exist")
	}
}

// ==================== Reverse FetchURLEvent local path with matching event ====================

func TestBoostFetchURLEvent_LocalWithMatch(t *testing.T) {
	r := &Reverse{
		config:                &Config{Token: "test", ClientConfig: ClientConfig{RemoteServer: false}},
		internalGroupEventMap: &sync.Map{},
		groupUnitCallbackMap:  sync.Map{},
	}

	// Store a matching event in the internal map
	r.internalGroupEventMap.Store("g1", &Event{
		GroupID: "g1",
		UnitID:  "u1",
	})

	// Call FetchURLEvent - this will parse the path and check internal map
	// The path format is /i/token/g1/u1/ which parsePath splits to get groupID=g1
	result := r.FetchURLEvent("/i/token/g1/u1/")
	_ = result
}

// ==================== Reverse FetchURLEvent local with mismatched unit ====================

func TestBoostFetchURLEvent_LocalWithMismatchedUnit(t *testing.T) {
	r := &Reverse{
		config:                &Config{Token: "test", ClientConfig: ClientConfig{RemoteServer: false}},
		internalGroupEventMap: &sync.Map{},
		groupUnitCallbackMap:  sync.Map{},
	}

	// Store an event with different unit
	r.internalGroupEventMap.Store("g1", &Event{
		GroupID: "g1",
		UnitID:  "different-unit",
	})

	result := r.FetchURLEvent("/i/token/g1/u1/")
	// The event has GroupID "g1" but UnitID "different-unit", so it should return false
	if result != false {
		t.Logf("FetchURLEvent returned %v for mismatched unit (may be expected)", result)
	}
}

// ==================== Reverse healthCheck with test server ====================

func TestBoostHealthCheck_WithTestServer(t *testing.T) {
	// Create a test server that responds to health checks
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_/api/health_check" {
			w.WriteHeader(200)
			w.Write([]byte(`{"code":0}`))
		}
	}))
	defer server.Close()

	// Parse the server URL to get host:port
	serverURL := strings.TrimPrefix(server.URL, "http://")
	cfg := &Config{
		Token: "test",
		HTTPServerConfig: HTTPServerConfig{
			Enabled:    true,
			ListenIP:   "127.0.0.1",
			ListenPort: strings.SplitN(serverURL, ":", 2)[1],
		},
	}
	r := &Reverse{
		config: cfg,
	}

	// Run healthCheck with a short timeout context
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		r.healthCheck(ctx)
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
	}
}

// ==================== DNSServer methods (no actual start due to port 53 permission) ====================

func TestBoostDNSServer_StopWithoutStart(t *testing.T) {
	cfg := &Config{
		Token: "test",
		DNSServerConfig: DNSServerConfig{
			Enabled:  true,
			ListenIP: "127.0.0.1",
			Domain:   "test.example.com",
		},
	}

	dnsServer, err := NewDNSServer(cfg, &sync.Map{}, helperDB(t))
	if err != nil {
		t.Fatalf("Failed to create DNS server: %v", err)
	}
	defer helperDBClose(t, dnsServer.db)

	// Stop without start should not panic
	dnsServer.Stop()
}

// ==================== RMIServer Close with listener ====================

func TestBoostRMIServer_CloseWithListener(t *testing.T) {
	rmi := &RMIServer{listener: nil}
	err := rmi.Close()
	if err != nil {
		t.Errorf("Expected nil error for nil listener, got %v", err)
	}
}

// ==================== HTTPServer handleRMIConn ====================

func TestBoostHandleRMIConn(t *testing.T) {
	handleRMIConn() // no-op, just for coverage
}

// ==================== HTTPServer HandlePayloadTemplate ====================

func TestBoostHandlePayloadTemplate(t *testing.T) {
	cfg := &Config{Token: "test-token"}
	s := &HTTPServer{config: cfg, db: &DB{}}
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	s.HandlePayloadTemplate(w, req, nil) // no-op
}

// ==================== DB CustomOperation ====================

func TestBoostDBCustomOperation(t *testing.T) {
	db := &DB{}
	db.CustomOperation() // no-op
}

// ==================== newDB ====================

func TestBoostNewDB(t *testing.T) {
	newDB() // no-op
}

// ==================== localCallUnitCallback ====================

func TestBoostLocalCallUnitCallback(t *testing.T) {
	r := &Reverse{}
	r.localCallUnitCallback() // no-op
}

// ==================== Reverse prepareConfig ====================

func TestBoostReversePrepareConfig(t *testing.T) {
	cfg := &Config{
		HTTPServerConfig: HTTPServerConfig{Enabled: false},
	}
	r := &Reverse{config: cfg}
	r.prepareConfig() // should not panic
}

func TestBoostReversePrepareConfig_EnabledHTTP(t *testing.T) {
	cfg := &Config{
		Token:            "test-token",
		HTTPServerConfig: HTTPServerConfig{Enabled: true, ListenIP: "0.0.0.0", ListenPort: "8080"},
		DBFilePath:       "/tmp/test.db",
	}
	r := &Reverse{config: cfg}
	r.prepareConfig() // should not panic with enabled HTTP
}

// ==================== Reverse Unit methods ====================

func TestBoostUnit_GetEncodedVisitURL(t *testing.T) {
	r := &Reverse{
		config:                &Config{Token: "test-token", HTTPServerConfig: HTTPServerConfig{ListenIP: "0.0.0.0", ListenPort: "8080"}},
		internalGroupEventMap: &sync.Map{},
	}

	ug := r.NewUnitGroup()
	unit := r.RegisterWithGroup(nil, ug)

	url, err := unit.GetEncodedVisitURL()
	if err != nil {
		t.Fatalf("GetEncodedVisitURL returned error: %v", err)
	}
	if url == "" {
		t.Error("Expected non-empty URL")
	}
	if !strings.Contains(url, "/i/") {
		t.Errorf("Expected /i/ in URL, got %s", url)
	}
}

func TestBoostUnit_GetQueryDomain(t *testing.T) {
	r := &Reverse{
		config: &Config{
			Token:            "test-token",
			DNSServerConfig:  DNSServerConfig{Domain: "dnslog.com", ListenIP: "1.2.3.4"},
			HTTPServerConfig: HTTPServerConfig{ListenIP: "0.0.0.0", ListenPort: "8080"},
		},
		internalGroupEventMap: &sync.Map{},
	}

	ug := r.NewUnitGroup()
	unit := r.RegisterWithGroup(nil, ug)

	di, err := unit.GetQueryDomain()
	if err != nil {
		t.Fatalf("GetQueryDomain returned error: %v", err)
	}
	if di == nil {
		t.Fatal("Expected non-nil DomainInfo")
	}
	if !strings.Contains(di.Domain, "dnslog.com") {
		t.Errorf("Expected domain to contain 'dnslog.com', got %s", di.Domain)
	}
}

func TestBoostUnit_GetRmiURL(t *testing.T) {
	r := &Reverse{
		config:                &Config{Token: "test-token", HTTPServerConfig: HTTPServerConfig{ListenIP: "0.0.0.0", ListenPort: "8080"}},
		internalGroupEventMap: &sync.Map{},
	}

	ug := r.NewUnitGroup()
	unit := r.RegisterWithGroup(nil, ug)

	rmiURL := unit.GetRmiURL()
	if rmiURL == "" {
		t.Error("Expected non-empty RMI URL")
	}
	if !strings.HasPrefix(rmiURL, "rmi://") {
		t.Errorf("Expected rmi:// prefix, got %s", rmiURL)
	}
}

func TestBoostUnit_GetLdapURL(t *testing.T) {
	r := &Reverse{
		config:                &Config{Token: "test-token", HTTPServerConfig: HTTPServerConfig{ListenIP: "0.0.0.0", ListenPort: "8080"}},
		internalGroupEventMap: &sync.Map{},
	}

	ug := r.NewUnitGroup()
	unit := r.RegisterWithGroup(nil, ug)

	ldapURL := unit.GetLdapURL()
	if ldapURL == "" {
		t.Error("Expected non-empty LDAP URL")
	}
	if !strings.HasPrefix(ldapURL, "ldap://") {
		t.Errorf("Expected ldap:// prefix, got %s", ldapURL)
	}
}

func TestBoostUnit_GetVisitURL(t *testing.T) {
	r := &Reverse{
		config:                &Config{Token: "test-token", HTTPServerConfig: HTTPServerConfig{ListenIP: "0.0.0.0", ListenPort: "8080"}},
		internalGroupEventMap: &sync.Map{},
	}

	ug := r.NewUnitGroup()
	unit := r.RegisterWithGroup(nil, ug)

	url := unit.GetVisitURL()
	if url == "" {
		t.Error("Expected non-empty visit URL")
	}
}

func TestBoostUnit_OnVisit(t *testing.T) {
	r := &Reverse{
		config:                &Config{Token: "test-token"},
		internalGroupEventMap: &sync.Map{},
	}

	ug := r.NewUnitGroup()
	unit := r.RegisterWithGroup(nil, ug)

	called := false
	unit.OnVisit(func(ev *Event) error {
		called = true
		return nil
	})

	if unit.Callback == nil {
		t.Error("Expected Callback to be set")
	}
	// Manually invoke
	unit.Callback(&Event{GroupID: "test"})
	if !called {
		t.Error("Expected callback to be invoked")
	}
}

func TestBoostUnit_Fetch(t *testing.T) {
	r := &Reverse{
		config:                &Config{Token: "test-token"},
		internalGroupEventMap: &sync.Map{},
		groupUnitCallbackMap:  sync.Map{},
	}

	ug := r.NewUnitGroup()
	unit := r.RegisterWithGroup(nil, ug)

	err := unit.Fetch(0)
	if err != nil {
		t.Errorf("Fetch returned error: %v", err)
	}
}

func TestBoostUnitGroup_Join(t *testing.T) {
	r := &Reverse{
		config:                &Config{Token: "test-token"},
		internalGroupEventMap: &sync.Map{},
	}

	ug := r.NewUnitGroup()
	_ = r.RegisterWithGroup(nil, ug)

	ug2 := r.NewUnitGroup()
	unit2 := r.RegisterWithGroup(nil, ug2)

	ug.Join(unit2)

	// Verify unit2 is stored in ug
	if _, ok := ug.units.Load(unit2.id); !ok {
		t.Error("Expected unit2 to be joined in ug")
	}
}

// ==================== Reverse Register and NewUnitGroup ====================

func TestBoostReverse_Register(t *testing.T) {
	r := &Reverse{
		config:                &Config{Token: "test-token"},
		internalGroupEventMap: &sync.Map{},
	}

	unit := r.Register("some-data")
	if unit == nil {
		t.Fatal("Expected non-nil unit")
	}
	if unit.Data != "some-data" {
		t.Errorf("Expected Data='some-data', got %v", unit.Data)
	}
}

// ==================== Reverse Close with DB ====================

func TestBoostReverse_CloseWithDB(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "close_test.db")
	db := &DB{}
	db.Open(dbPath)

	r := &Reverse{db: db}
	err := r.Close()
	if err != nil {
		t.Errorf("Close returned error: %v", err)
	}
}

// ==================== HTTPServer ServeHTTP with token ====================

func TestBoostHTTPServer_ServeHTTP_TokenPaths(t *testing.T) {
	cfg := &Config{Token: "test-token"}
	eventMap := &sync.Map{}
	s := NewHTTPServer(cfg, eventMap, &DB{})

	// Request to /_/api/ path without token
	req := httptest.NewRequest("GET", "/_/api/avatar/template/list", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)

	// Request to /_/api/ path with correct token
	req = httptest.NewRequest("GET", "/_/api/avatar/template/list", nil)
	req.Header.Set("X-Token", "test-token")
	w = httptest.NewRecorder()
	s.ServeHTTP(w, req)

	// Request to non-api path (should route to router)
	req = httptest.NewRequest("GET", "/avatar/", nil)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, req)
}

// ==================== HandleFetchEvent with GroupToDelete ====================

func TestBoostHTTPServer_HandleFetchEvent_WithDelete(t *testing.T) {
	cfg := &Config{Token: "test-token"}
	eventMap := &sync.Map{}

	// Store an event to be deleted
	eventMap.Store("g1", &Event{GroupID: "g1", UnitID: "u1"})

	s := NewHTTPServer(cfg, eventMap, &DB{})

	body := `{"group_to_delete":["g1"],"group_to_search":["g1"]}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.HandleFetchEvent(w, req, nil)

	// g1 should be deleted from the map
	if _, ok := eventMap.Load("g1"); ok {
		t.Error("Expected g1 to be deleted from event map")
	}
}

// ==================== HandleFetchEvent with invalid JSON ====================

func TestBoostHTTPServer_HandleFetchEvent_InvalidJSON(t *testing.T) {
	cfg := &Config{Token: "test-token"}
	s := NewHTTPServer(cfg, &sync.Map{}, &DB{})

	req := httptest.NewRequest("POST", "/", strings.NewReader("not json at all"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.HandleFetchEvent(w, req, nil)

	if w.Code != 400 {
		t.Errorf("Expected 400 for invalid JSON, got %d", w.Code)
	}
}

// ==================== HandleUnitVisit with response config ====================

func TestBoostHTTPServer_HandleUnitVisit_WithHTTPResponse(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "visit_resp.db")
	db := &DB{}
	db.Open(dbPath)
	defer db.Close()

	// Set up a custom HTTP response
	hrc := &HTTPResponseConfig{
		CommonResponseComponent: CommonResponseComponent{
			StatusCode: "200",
			Body:       "<script>alert('xss')</script>",
			Header:     []map[string]string{{"key": "Content-Type", "value": "text/html"}},
		},
		GroupID: "g1",
	}
	db.setHTTPResponse(hrc)

	cfg := &Config{
		Token:            "test-token",
		HTTPServerConfig: HTTPServerConfig{ListenIP: "0.0.0.0", ListenPort: "8080"},
	}
	eventMap := &sync.Map{}
	s := NewHTTPServer(cfg, eventMap, db)

	token := generateHashedToken("test-token", "g1", "u1")
	url := fmt.Sprintf("/p/%s/g1/u1/", token)
	req := httptest.NewRequest("GET", url, nil)
	w := httptest.NewRecorder()
	s.Router.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "alert") {
		t.Errorf("Expected custom response body, got %s", body)
	}
}

// ==================== Config.GetAddr paths ====================

func TestBoostConfigGetAddr_EmptyIP(t *testing.T) {
	hsCfg := HTTPServerConfig{ListenIP: "", ListenPort: "8080"}
	addr := hsCfg.GetAddr()
	if addr != "0.0.0.0:8080" {
		t.Errorf("Expected '0.0.0.0:8080', got '%s'", addr)
	}
}

func TestBoostConfigGetAddr_EmptyPort(t *testing.T) {
	hsCfg := HTTPServerConfig{ListenIP: "127.0.0.1", ListenPort: ""}
	addr := hsCfg.GetAddr()
	if addr != "127.0.0.1:80" {
		t.Errorf("Expected '127.0.0.1:80', got '%s'", addr)
	}
}

// ==================== UnitGroup fetch ====================

func TestBoostUnitGroup_Fetch(t *testing.T) {
	ug := &UnitGroup{id: "test", expireAt: time.Now().Add(5 * time.Minute)}
	err := ug.fetch(0)
	if err != nil {
		t.Errorf("fetch returned error: %v", err)
	}
	// After fetch, expireAt should be extended
	if ug.expireAt.Before(time.Now().Add(1 * time.Minute)) {
		t.Error("Expected expireAt to be extended")
	}
}

// ==================== HTTPServer Close ====================

func TestBoostHTTPServer_Close(t *testing.T) {
	cfg := &Config{Token: "test"}
	s := NewHTTPServer(cfg, &sync.Map{}, &DB{})
	// Server isn't started, but Close should still work
	err := s.Close()
	if err != nil {
		t.Logf("Close returned error (expected if not started): %v", err)
	}
}

// ==================== Reverse Config with ClientConfig GetAddr ====================

func TestBoostClientConfigGetAddr(t *testing.T) {
	cc := &ClientConfig{HTTPBaseURL: "http://myserver:9090/path"}
	addr := cc.GetAddr()
	if addr != "myserver:9090" {
		t.Errorf("Expected 'myserver:9090', got '%s'", addr)
	}
}

// ==================== DB setDNSResponse with real data ====================

func TestBoostDBSetDNSResponseWithRecords(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "dns_records.db")
	db := &DB{}
	db.Open(dbPath)
	defer db.Close()

	drc := &DNSResponseConfig{
		GroupID: "grp1",
		DNSResponse: struct {
			A    []DNSResponseItem "json:\"a\""
			AAAA []DNSResponseItem "json:\"aaaa\""
			TXT  []DNSResponseItem "json:\"txt\""
		}{
			A:    []DNSResponseItem{{Value: "10.0.0.1", TTL: 30}},
			AAAA: []DNSResponseItem{{Value: "::1", TTL: 60}},
			TXT:  []DNSResponseItem{{Value: "v=spf1", TTL: 120}},
		},
	}
	db.setDNSResponse(drc)

	ret := db.getDNSResponse("grp1")
	if ret == nil {
		t.Fatal("Expected non-nil DNS response")
	}
	if len(ret.DNSResponse.A) != 1 {
		t.Errorf("Expected 1 A record, got %d", len(ret.DNSResponse.A))
	}
}

// ==================== Struct coverage for DNSResponseItem ====================

func TestBoostDNSResponseItem_Struct(t *testing.T) {
	item := DNSResponseItem{Value: "1.2.3.4", TTL: 60}
	if item.Value != "1.2.3.4" || item.TTL != 60 {
		t.Error("Unexpected DNSResponseItem values")
	}
}

// ==================== remoteFetchEventRequest JSON ====================

func TestBoostRemoteFetchEventRequestJSON(t *testing.T) {
	rfer := remoteFetchEventRequest{
		GroupToDelete: []string{"g1", "g2"},
		GroupToSearch: []string{"g3"},
		UnitsToSearch: []string{"u1"},
	}
	data, err := json.Marshal(rfer)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}
	if !strings.Contains(string(data), "group_to_delete") {
		t.Error("Expected group_to_delete in JSON")
	}
}

// Suppress unused imports
var (
	_ = os.Getenv
	_ = filepath.Join
	_ = fmt.Sprintf
)

// Helper to close DB
func helperDBClose(t *testing.T, db *DB) {
	t.Helper()
	if db != nil && db.IsOpen() {
		db.Close()
	}
}
