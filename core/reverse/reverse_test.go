package reverse

import (
	"sync"
	"testing"
)

func TestReverseConfig(t *testing.T) {
	r := &Reverse{
		config: &Config{
			Token: "test_token",
		},
	}

	cfg := r.Config()
	if cfg.Token != "test_token" {
		t.Errorf("Expected token 'test_token', got '%s'", cfg.Token)
	}
}

func TestReverseConfigNil(t *testing.T) {
	r := &Reverse{}
	cfg := r.Config()
	if cfg != nil {
		t.Error("Expected nil config")
	}
}

func TestReverseCloseWithDB(t *testing.T) {
	db := helperDB(t)
	r := &Reverse{db: db}

	err := r.Close()
	if err != nil {
		t.Fatalf("Close error: %v", err)
	}

	if db.IsOpen() {
		t.Error("DB should be closed after Reverse.Close()")
	}
}

func TestReverseCloseNilDB(t *testing.T) {
	r := &Reverse{}

	err := r.Close()
	if err != nil {
		t.Fatalf("Close with nil db should return nil, got %v", err)
	}
}

func TestNewReverseDisabled(t *testing.T) {
	c := &Config{
		DBFilePath: "",
		DNSServerConfig: DNSServerConfig{
			ListenIP: "127.0.0.1",
			Domain:   "dnslog.com",
			Enabled:  false,
		},
		HTTPServerConfig: HTTPServerConfig{
			ListenPort: "0",
			Enabled:    false,
		},
	}

	reverse := NewReverse(c)
	if reverse != nil {
		t.Error("NewReverse should return nil when both servers are disabled")
	}
}

func TestNewReverseDisabledWithRemote(t *testing.T) {
	c := &Config{
		DBFilePath: "",
		Token:      "testtoken",
		DNSServerConfig: DNSServerConfig{
			ListenIP: "127.0.0.1",
			Domain:   "dnslog.com",
			Enabled:  false,
		},
		HTTPServerConfig: HTTPServerConfig{
			ListenPort: "0",
			Enabled:    false,
		},
		ClientConfig: ClientConfig{
			RemoteServer: true,
			HTTPBaseURL:  "http://127.0.0.1:88",
		},
	}

	reverse := NewReverse(c)
	if reverse == nil {
		t.Error("NewReverse should not return nil when RemoteServer is true")
	}
}

func TestReverseInternalGroupEventMap(t *testing.T) {
	eventMap := &sync.Map{}
	r := &Reverse{
		config:                &Config{Token: "test"},
		internalGroupEventMap: eventMap,
	}

	ev := &Event{GroupID: "g1", UnitID: "u1", EventType: "http"}
	r.internalGroupEventMap.Store("g1", ev)

	loaded, ok := r.internalGroupEventMap.Load("g1")
	if !ok {
		t.Error("Should be able to load stored event")
	}
	if loaded.(*Event).GroupID != "g1" {
		t.Errorf("Loaded event GroupID = %q, want 'g1'", loaded.(*Event).GroupID)
	}
}

func TestReverseGroupUnitCallbackMap(t *testing.T) {
	r := &Reverse{
		config:                &Config{Token: "test"},
		internalGroupEventMap: &sync.Map{},
	}

	ug := &UnitGroup{id: "testGroup"}
	unit := &Unit{id: "testUnit", group: ug, reverse: r}

	r.groupUnitCallbackMap.Store("testGroup_testUnit", unit)

	loaded, ok := r.groupUnitCallbackMap.Load("testGroup_testUnit")
	if !ok {
		t.Error("Should be able to load stored unit")
	}
	if loaded.(*Unit).id != "testUnit" {
		t.Errorf("Loaded unit id = %q, want 'testUnit'", loaded.(*Unit).id)
	}
}
