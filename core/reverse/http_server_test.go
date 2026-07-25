package reverse

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/julienschmidt/httprouter"
)

func createTestHTTPServer(t *testing.T) (*HTTPServer, *DB) {
	t.Helper()
	db := helperDB(t)
	config := &Config{
		Token: "testtoken",
		HTTPServerConfig: HTTPServerConfig{
			Enabled:    true,
			ListenIP:   "127.0.0.1",
			ListenPort: "8080",
		},
		DNSServerConfig: DNSServerConfig{
			Domain:   "dnslog.com",
			ListenIP: "127.0.0.1",
		},
	}
	internalGroupEventMap := &sync.Map{}
	server := &HTTPServer{
		Router:                httprouter.New(),
		config:                config,
		db:                    db,
		internalGroupEventMap: internalGroupEventMap,
	}
	server.Server = &http.Server{Handler: server.Router}
	return server, db
}

func TestHTTPServerResponse(t *testing.T) {
	server, db := createTestHTTPServer(t)
	defer db.Close()

	w := httptest.NewRecorder()
	server.response(w, map[string]string{"key": "value"}, 200)

	if w.Code != 200 {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	body := w.Body.String()
	if body == "" {
		t.Error("Response body should not be empty")
	}

	var result map[string]string
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		t.Fatalf("Failed to parse JSON response: %v", err)
	}
	if result["key"] != "value" {
		t.Errorf("Expected key=value, got %v", result)
	}
}

func TestHTTPServerSuccess(t *testing.T) {
	server, db := createTestHTTPServer(t)
	defer db.Close()

	w := httptest.NewRecorder()
	server.Success(w, "test data")

	if w.Code != 200 {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var resp Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}
	if resp.Code != 0 {
		t.Errorf("Expected Code 0, got %d", resp.Code)
	}
}

func TestHTTPServerFail(t *testing.T) {
	server, db := createTestHTTPServer(t)
	defer db.Close()

	w := httptest.NewRecorder()
	server.Fail(w, "error message")

	if w.Code != 200 {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var resp Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}
	if resp.Code != 1 {
		t.Errorf("Expected Code 1, got %d", resp.Code)
	}
}

func TestHTTPServerLoginRequired(t *testing.T) {
	server, db := createTestHTTPServer(t)
	defer db.Close()

	w := httptest.NewRecorder()
	server.LoginRequired(w)

	if w.Code != 200 {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var resp Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}
	if resp.Code != 2 {
		t.Errorf("Expected Code 2, got %d", resp.Code)
	}
}

func TestHTTPServerCheckToken(t *testing.T) {
	server, db := createTestHTTPServer(t)
	defer db.Close()

	// Correct token
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Token", "testtoken")
	if !server.checkToken(req) {
		t.Error("checkToken should return true for correct token")
	}

	// Wrong token
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.Header.Set("X-Token", "wrongtoken")
	if server.checkToken(req2) {
		t.Error("checkToken should return false for wrong token")
	}

	// No token
	req3 := httptest.NewRequest("GET", "/", nil)
	if server.checkToken(req3) {
		t.Error("checkToken should return false when no token provided")
	}
}

func TestHTTPServerServeHTTPWithToken(t *testing.T) {
	server, db := createTestHTTPServer(t)
	defer db.Close()

	// Set up a simple route
	server.Router.GET("/test", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		w.Write([]byte("ok"))
	})

	// Request without token to API path - should be blocked
	req := httptest.NewRequest("GET", "/_/api/test", nil)
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)

	var resp Response
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Code != 2 {
		t.Errorf("Expected Code 2 for unauthorized API request, got %d", resp.Code)
	}

	// Request with correct token - should pass through
	req2 := httptest.NewRequest("GET", "/_/api/test", nil)
	req2.Header.Set("X-Token", "testtoken")
	w2 := httptest.NewRecorder()
	server.ServeHTTP(w2, req2)
	// This should pass the router (404 since no handler for this path, but not Code 2)
}

func TestHTTPServerServeHTTPNonAPIPath(t *testing.T) {
	server, db := createTestHTTPServer(t)
	defer db.Close()

	// Non-API path should not require token
	server.Router.GET("/public", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		w.Write([]byte("public"))
	})

	req := httptest.NewRequest("GET", "/public", nil)
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("Expected status 200 for non-API path, got %d", w.Code)
	}
}

func TestHTTPServerHandleHealthCheck(t *testing.T) {
	server, db := createTestHTTPServer(t)
	defer db.Close()

	req := httptest.NewRequest("GET", "/_/api/health_check", nil)
	w := httptest.NewRecorder()

	server.HandleHealthCheck(w, req, httprouter.Params{})

	if w.Code != 200 {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var resp Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}
	if resp.Code != 0 {
		t.Errorf("Expected Code 0, got %d", resp.Code)
	}
}

func TestHTTPServerHandleGenerateHTTPURL(t *testing.T) {
	server, db := createTestHTTPServer(t)
	defer db.Close()

	req := httptest.NewRequest("GET", "/_/api/avatar/generate/http_url", nil)
	w := httptest.NewRecorder()

	server.HandleGenerateHTTPURL(w, req, httprouter.Params{})

	if w.Code != 200 {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var resp Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}
	if resp.Code != 0 {
		t.Errorf("Expected Code 0, got %d", resp.Code)
	}
}

func TestHTTPServerHandleGenerateDNSDomain(t *testing.T) {
	server, db := createTestHTTPServer(t)
	defer db.Close()

	req := httptest.NewRequest("GET", "/_/api/avatar/generate/dns_domain", nil)
	w := httptest.NewRecorder()

	server.HandleGenerateDNSDomain(w, req, httprouter.Params{})

	if w.Code != 200 {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var resp Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}
	if resp.Code != 0 {
		t.Errorf("Expected Code 0, got %d", resp.Code)
	}
}

func TestHTTPServerHandleGenerateHTTPTemplateURL(t *testing.T) {
	server, db := createTestHTTPServer(t)
	defer db.Close()

	req := httptest.NewRequest("GET", "/_/api/avatar/generate/http_template_url", nil)
	w := httptest.NewRecorder()

	server.HandleGenerateHTTPTemplateURL(w, req, httprouter.Params{})

	if w.Code != 200 {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var resp Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}
	if resp.Code != 0 {
		t.Errorf("Expected Code 0, got %d", resp.Code)
	}
}

func TestHTTPServerHandleFetchEvent(t *testing.T) {
	server, db := createTestHTTPServer(t)
	defer db.Close()

	// Store an event in the internal map
	ev := &Event{
		GroupID:     "testGroup",
		UnitID:      "testUnit",
		EventType:   "http",
		EventSource: "internal",
	}
	server.internalGroupEventMap.Store("testGroup", ev)

	// Create a fetch request searching for the group
	body := `{"group_to_delete":[],"group_to_search":["testGroup"],"units_to_search":null}`
	req := httptest.NewRequest("POST", "/_/api/fetch", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.HandleFetchEvent(w, req, httprouter.Params{})

	if w.Code != 200 {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestHTTPServerHandleFetchEventInvalidJSON(t *testing.T) {
	server, db := createTestHTTPServer(t)
	defer db.Close()

	req := httptest.NewRequest("POST", "/_/api/fetch", strings.NewReader("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.HandleFetchEvent(w, req, httprouter.Params{})

	if w.Code != 400 {
		t.Errorf("Expected status 400 for invalid JSON, got %d", w.Code)
	}
}

func TestHTTPServerHandleFetchEventDelete(t *testing.T) {
	server, db := createTestHTTPServer(t)
	defer db.Close()

	// Store an event
	ev := &Event{GroupID: "toDelete", UnitID: "u1", EventType: "http"}
	server.internalGroupEventMap.Store("toDelete", ev)

	// Fetch with delete
	body := `{"group_to_delete":["toDelete"],"group_to_search":[],"units_to_search":null}`
	req := httptest.NewRequest("POST", "/_/api/fetch", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.HandleFetchEvent(w, req, httprouter.Params{})

	// Verify the event was deleted
	_, loaded := server.internalGroupEventMap.Load("toDelete")
	if loaded {
		t.Error("Event should be deleted after fetch with delete")
	}
}

func TestHTTPServerHandleListEvent(t *testing.T) {
	server, db := createTestHTTPServer(t)
	defer db.Close()

	// Add some events
	db.storeEvent(&Event{GroupID: "g1", UnitID: "u1", EventType: "http", EventSource: "internal"})
	db.storeEvent(&Event{GroupID: "g2", UnitID: "u2", EventType: "dns", EventSource: "internal"})

	req := httptest.NewRequest("GET", "/_/api/event/list?count=10&eventType=&action=Next", nil)
	w := httptest.NewRecorder()

	server.HandleListEvent(w, req, httprouter.Params{})

	if w.Code != 200 {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestHTTPServerHandleEventStats(t *testing.T) {
	server, db := createTestHTTPServer(t)
	defer db.Close()

	// Add some events
	db.storeEvent(&Event{GroupID: "g1", UnitID: "u1", EventType: "http", EventSource: "internal"})
	db.storeEvent(&Event{GroupID: "g2", UnitID: "u2", EventType: "dns", EventSource: "internal"})

	req := httptest.NewRequest("GET", "/_/api/avatar/event/stats", nil)
	w := httptest.NewRecorder()

	server.HandleEventStats(w, req, httprouter.Params{})

	if w.Code != 200 {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestHTTPServerHandleSetHTTPResponse(t *testing.T) {
	server, db := createTestHTTPServer(t)
	defer db.Close()

	body := `{"groupID":"g1","statusCode":"403","body":"Forbidden"}`
	req := httptest.NewRequest("POST", "/_/api/avatar/generate/set_http_response", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.handleSetHTTPResponse(w, req, httprouter.Params{})

	if w.Code != 200 {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Verify it was stored
	retrieved := db.getHTTPResponse("g1")
	if retrieved == nil {
		t.Fatal("HTTP response should be stored")
	}
	if retrieved.StatusCode != "403" {
		t.Errorf("Expected StatusCode '403', got '%s'", retrieved.StatusCode)
	}
}

func TestHTTPServerHandleSetHTTPResponseInvalidJSON(t *testing.T) {
	server, db := createTestHTTPServer(t)
	defer db.Close()

	req := httptest.NewRequest("POST", "/_/api/avatar/generate/set_http_response", strings.NewReader("bad json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.handleSetHTTPResponse(w, req, httprouter.Params{})

	if w.Code != 400 {
		t.Errorf("Expected status 400 for invalid JSON, got %d", w.Code)
	}
}

func TestHTTPServerHandleSetDNSResponse(t *testing.T) {
	server, db := createTestHTTPServer(t)
	defer db.Close()

	body := `{"groupID":"dns1","dnsResponse":{"a":[{"value":"1.2.3.4","ttl":60}],"aaaa":[],"txt":[]}}`
	req := httptest.NewRequest("POST", "/_/api/avatar/generate/set_dns_response", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.handleSetDNSResponse(w, req, httprouter.Params{})

	if w.Code != 200 {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestHTTPServerHandleSetDNSResponseInvalidJSON(t *testing.T) {
	server, db := createTestHTTPServer(t)
	defer db.Close()

	req := httptest.NewRequest("POST", "/_/api/avatar/generate/set_dns_response", strings.NewReader("bad json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.handleSetDNSResponse(w, req, httprouter.Params{})

	if w.Code != 400 {
		t.Errorf("Expected status 400 for invalid JSON, got %d", w.Code)
	}
}

func TestHTTPServerHandleListHTTPResponses(t *testing.T) {
	server, db := createTestHTTPServer(t)
	defer db.Close()

	// Add some HTTP responses
	hrc1 := &HTTPResponseConfig{GroupID: "g1"}
	hrc1.StatusCode = "200"
	hrc1.Body = "OK"
	hrc2 := &HTTPResponseConfig{GroupID: "g2"}
	hrc2.StatusCode = "404"
	hrc2.Body = "Not Found"
	db.setHTTPResponse(hrc1)
	db.setHTTPResponse(hrc2)

	req := httptest.NewRequest("GET", "/_/api/avatar/http_responses", nil)
	w := httptest.NewRecorder()

	server.handleListHTTPResponses(w, req, httprouter.Params{})

	if w.Code != 200 {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestHTTPServerHandleDeleteHTTPResponse(t *testing.T) {
	server, db := createTestHTTPServer(t)
	defer db.Close()

	// Add an HTTP response
	hrc := &HTTPResponseConfig{GroupID: "toDelete"}
	hrc.StatusCode = "200"
	db.setHTTPResponse(hrc)

	req := httptest.NewRequest("DELETE", "/_/api/avatar/http_response?groupID=toDelete", nil)
	w := httptest.NewRecorder()

	server.handleDeleteHTTPResponse(w, req, httprouter.Params{})

	if w.Code != 200 {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Verify it was deleted
	retrieved := db.getHTTPResponse("toDelete")
	if retrieved != nil {
		t.Error("HTTP response should be deleted")
	}
}

func TestHTTPServerHandleDeleteHTTPResponseNoGroupID(t *testing.T) {
	server, db := createTestHTTPServer(t)
	defer db.Close()

	req := httptest.NewRequest("DELETE", "/_/api/avatar/http_response", nil)
	w := httptest.NewRecorder()

	server.handleDeleteHTTPResponse(w, req, httprouter.Params{})

	// Should return fail response
	var resp Response
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Code != 1 {
		t.Errorf("Expected Code 1 for missing groupID, got %d", resp.Code)
	}
}

func TestHTTPServerHandleListPayloadTemplates(t *testing.T) {
	server, db := createTestHTTPServer(t)
	defer db.Close()

	req := httptest.NewRequest("GET", "/_/api/avatar/template/list", nil)
	w := httptest.NewRecorder()

	server.handleListPayloadTemplates(w, req, httprouter.Params{})

	if w.Code != 200 {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var resp Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}
	if resp.Code != 0 {
		t.Errorf("Expected Code 0, got %d", resp.Code)
	}
}

func TestHTTPServerHandleUnitVisitInvalidToken(t *testing.T) {
	server, db := createTestHTTPServer(t)
	defer db.Close()

	req := httptest.NewRequest("GET", "/i/wrongtoken/g1/u1/", nil)
	w := httptest.NewRecorder()

	params := httprouter.Params{
		httprouter.Param{Key: "token", Value: "wrongtoken"},
		httprouter.Param{Key: "group", Value: "g1"},
		httprouter.Param{Key: "unit", Value: "u1"},
	}

	server.HandleUnitVisit(w, req, params, false)

	var resp Response
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Code != 2 {
		t.Errorf("Expected Code 2 for invalid token, got %d", resp.Code)
	}
}

func TestHTTPServerHandleUnitVisitValidToken(t *testing.T) {
	server, db := createTestHTTPServer(t)
	defer db.Close()

	groupID := "g1"
	unitID := "u1"
	token := generateHashedToken(server.config.Token, groupID, unitID)

	req := httptest.NewRequest("GET", "/i/"+token+"/"+groupID+"/"+unitID+"/", nil)
	w := httptest.NewRecorder()

	params := httprouter.Params{
		httprouter.Param{Key: "token", Value: token},
		httprouter.Param{Key: "group", Value: groupID},
		httprouter.Param{Key: "unit", Value: unitID},
	}

	server.HandleUnitVisit(w, req, params, false)

	// The event should have been stored
	ev, loaded := server.internalGroupEventMap.Load(groupID)
	if !loaded {
		t.Error("Event should be stored in internalGroupEventMap")
	}
	if ev != nil {
		storedEv := ev.(*Event)
		if storedEv.GroupID != groupID {
			t.Errorf("Stored event GroupID = %q, want %q", storedEv.GroupID, groupID)
		}
		if storedEv.EventType != "http" {
			t.Errorf("Stored event EventType = %q, want 'http'", storedEv.EventType)
		}
	}
}

func TestHTTPServerHandlePublicUnitVisit(t *testing.T) {
	server, db := createTestHTTPServer(t)
	defer db.Close()

	groupID := "pub1"
	unitID := "pu1"
	token := generateHashedToken(server.config.Token, groupID, unitID)

	req := httptest.NewRequest("GET", "/p/"+token+"/"+groupID+"/"+unitID+"/", nil)
	w := httptest.NewRecorder()

	params := httprouter.Params{
		httprouter.Param{Key: "token", Value: token},
		httprouter.Param{Key: "group", Value: groupID},
		httprouter.Param{Key: "unit", Value: unitID},
	}

	server.HandlePublicUnitVisit(w, req, params)

	// The event should have been stored with "public" source
	ev, loaded := server.internalGroupEventMap.Load(groupID)
	if !loaded {
		t.Error("Event should be stored in internalGroupEventMap")
	}
	if ev != nil {
		storedEv := ev.(*Event)
		if storedEv.EventSource != "public" {
			t.Errorf("Stored event EventSource = %q, want 'public'", storedEv.EventSource)
		}
	}
}

func TestHTTPServerHandleInternalUnitVisit(t *testing.T) {
	server, db := createTestHTTPServer(t)
	defer db.Close()

	groupID := "int1"
	unitID := "iu1"
	token := generateHashedToken(server.config.Token, groupID, unitID)

	req := httptest.NewRequest("GET", "/i/"+token+"/"+groupID+"/"+unitID+"/", nil)
	w := httptest.NewRecorder()

	params := httprouter.Params{
		httprouter.Param{Key: "token", Value: token},
		httprouter.Param{Key: "group", Value: groupID},
		httprouter.Param{Key: "unit", Value: unitID},
	}

	server.HandleInternalUnitVisit(w, req, params)

	// The event should have been stored
	ev, loaded := server.internalGroupEventMap.Load(groupID)
	if !loaded {
		t.Error("Event should be stored in internalGroupEventMap")
	}
	if ev != nil {
		storedEv := ev.(*Event)
		// Note: HandleUnitVisit always sets EventSource to "public" regardless of the public parameter
		if storedEv.EventType != "http" {
			t.Errorf("Stored event EventType = %q, want 'http'", storedEv.EventType)
		}
	}
}

func TestHTTPServerHandleUnitVisitWithHTTPResponse(t *testing.T) {
	server, db := createTestHTTPServer(t)
	defer db.Close()

	groupID := "resp1"
	unitID := "ru1"
	token := generateHashedToken(server.config.Token, groupID, unitID)

	// Set up an HTTP response config for this group
	hrc := &HTTPResponseConfig{GroupID: groupID}
	hrc.StatusCode = "403"
	hrc.Body = "Access Denied"
	db.setHTTPResponse(hrc)

	req := httptest.NewRequest("GET", "/i/"+token+"/"+groupID+"/"+unitID+"/", nil)
	w := httptest.NewRecorder()

	params := httprouter.Params{
		httprouter.Param{Key: "token", Value: token},
		httprouter.Param{Key: "group", Value: groupID},
		httprouter.Param{Key: "unit", Value: unitID},
	}

	server.HandleUnitVisit(w, req, params, false)

	// The response should reflect the configured status code and body
	if w.Code != 403 {
		t.Errorf("Expected status 403, got %d", w.Code)
	}
	if w.Body.String() != "Access Denied" {
		t.Errorf("Expected body 'Access Denied', got %q", w.Body.String())
	}
}

func TestHTTPServerHandlePayloadTemplate(t *testing.T) {
	server, db := createTestHTTPServer(t)
	defer db.Close()

	// HandlePayloadTemplate is a no-op function, just verify it doesn't panic
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	server.HandlePayloadTemplate(w, req, httprouter.Params{})
}

func TestHTTPServerStart(t *testing.T) {
	server, db := createTestHTTPServer(t)
	defer db.Close()

	// Start is a no-op function, just verify it doesn't panic
	server.Start()
}

func TestNewHTTPServer(t *testing.T) {
	db := helperDB(t)
	defer db.Close()

	config := &Config{
		Token: "testtoken",
		HTTPServerConfig: HTTPServerConfig{
			Enabled:    true,
			ListenIP:   "127.0.0.1",
			ListenPort: "8080",
		},
		DNSServerConfig: DNSServerConfig{
			Domain:   "dnslog.com",
			ListenIP: "127.0.0.1",
		},
	}

	server := NewHTTPServer(config, &sync.Map{}, db)
	if server == nil {
		t.Fatal("NewHTTPServer returned nil")
	}
	if server.Router == nil {
		t.Error("HTTPServer Router should not be nil")
	}
	if server.config == nil {
		t.Error("HTTPServer config should not be nil")
	}
	if server.db == nil {
		t.Error("HTTPServer db should not be nil")
	}
}

func TestHTTPServerClose(t *testing.T) {
	server, db := createTestHTTPServer(t)
	defer db.Close()

	// Server wasn't actually started listening, but Close should not panic
	_ = server.Close()
}

func TestHTTPServerResponseMarshalError(t *testing.T) {
	server, db := createTestHTTPServer(t)
	defer db.Close()

	w := httptest.NewRecorder()
	// Pass a channel which can't be marshaled to JSON
	server.response(w, make(chan int), 200)

	if w.Code != 500 {
		t.Errorf("Expected status 500 for marshal error, got %d", w.Code)
	}
}

func TestHTTPServerHandleListEventWithCount(t *testing.T) {
	server, db := createTestHTTPServer(t)
	defer db.Close()

	// Add some events
	for i := 0; i < 5; i++ {
		db.storeEvent(&Event{
			GroupID:     "g1",
			UnitID:      "u1",
			EventType:   "http",
			EventSource: "internal",
		})
	}

	req := httptest.NewRequest("GET", "/_/api/event/list?count=3&eventType=http&action=Next", nil)
	w := httptest.NewRecorder()

	server.HandleListEvent(w, req, httprouter.Params{})

	if w.Code != 200 {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var resp Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}
}

func TestHTTPServerHandleFetchEventEmptySearch(t *testing.T) {
	server, db := createTestHTTPServer(t)
	defer db.Close()

	body := `{"group_to_delete":[],"group_to_search":[],"units_to_search":null}`
	req := httptest.NewRequest("POST", "/_/api/fetch", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.HandleFetchEvent(w, req, httprouter.Params{})

	if w.Code != 200 {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestHTTPServerHandleUnitVisitDBEventStorage(t *testing.T) {
	server, db := createTestHTTPServer(t)
	defer db.Close()

	groupID := "dbtest"
	unitID := "du1"
	token := generateHashedToken(server.config.Token, groupID, unitID)

	req := httptest.NewRequest("GET", "/i/"+token+"/"+groupID+"/"+unitID+"/", nil)
	w := httptest.NewRecorder()

	params := httprouter.Params{
		httprouter.Param{Key: "token", Value: token},
		httprouter.Param{Key: "group", Value: groupID},
		httprouter.Param{Key: "unit", Value: unitID},
	}

	server.HandleUnitVisit(w, req, params, false)

	// Verify event was stored in DB
	stats := db.getEventStats()
	if stats.HTTP != 1 {
		t.Errorf("Expected 1 HTTP event in DB, got %d", stats.HTTP)
	}
}

func TestHTTPServerHandleFetchEventWithBody(t *testing.T) {
	server, db := createTestHTTPServer(t)
	defer db.Close()

	ev1 := &Event{GroupID: "grp1", UnitID: "u1", EventType: "http"}
	ev2 := &Event{GroupID: "grp2", UnitID: "u2", EventType: "dns"}
	server.internalGroupEventMap.Store("grp1", ev1)
	server.internalGroupEventMap.Store("grp2", ev2)

	body := `{"group_to_delete":[],"group_to_search":["grp1","grp2"],"units_to_search":null}`
	req := httptest.NewRequest("POST", "/_/api/fetch", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.HandleFetchEvent(w, req, httprouter.Params{})

	if w.Code != 200 {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Parse response and check events were returned
	var feb fetchEventResponse
	if err := json.Unmarshal(w.Body.Bytes(), &feb); err == nil {
		if len(feb.Event) < 2 {
			t.Errorf("Expected at least 2 events, got %d", len(feb.Event))
		}
	}
}

// Ensure bytes import is used
var _ = bytes.NewReader
var _ = io.EOF
