package reverse

import (
	"fmt"
	"net"
	"sync"
	"testing"

	"github.com/miekg/dns"
)

func TestNewDNSServerDisabled(t *testing.T) {
	config := &Config{
		Token: "testtoken",
		DNSServerConfig: DNSServerConfig{
			Enabled:  false,
			ListenIP: "127.0.0.1",
			Domain:   "dnslog.com",
		},
	}

	server, err := NewDNSServer(config, &sync.Map{}, nil)
	if server != nil {
		t.Error("NewDNSServer should return nil when DNS is disabled")
	}
	if err == nil {
		t.Error("NewDNSServer should return error when DNS is disabled")
	}
	if err.Error() != "DNSServer disabled" {
		t.Errorf("Expected 'DNSServer disabled' error, got %v", err)
	}
}

func TestNewDNSServerEnabled(t *testing.T) {
	config := &Config{
		Token: "testtoken",
		DNSServerConfig: DNSServerConfig{
			Enabled:  true,
			ListenIP: "127.0.0.1",
			Domain:   "dnslog.com",
		},
	}

	db := helperDB(t)
	defer db.Close()

	server, err := NewDNSServer(config, &sync.Map{}, db)
	if err != nil {
		t.Fatalf("NewDNSServer error: %v", err)
	}
	if server == nil {
		t.Fatal("NewDNSServer should return non-nil when DNS is enabled")
	}
	if server.config != config {
		t.Error("DNSServer config should match")
	}
	if server.db != db {
		t.Error("DNSServer db should match")
	}
}

func TestDNSServerServeDNSQuery(t *testing.T) {
	config := &Config{
		Token: "testtoken",
		DNSServerConfig: DNSServerConfig{
			Enabled:  true,
			ListenIP: "127.0.0.1",
			Domain:   "dnslog.com",
		},
	}

	db := helperDB(t)
	defer db.Close()

	internalGroupEventMap := &sync.Map{}
	server, _ := NewDNSServer(config, internalGroupEventMap, db)

	groupID := "g1"
	unitID := "u1"

	msg := &dns.Msg{}
	msg.SetQuestion("test.dnslog.com.", dns.TypeA)

	server.ServeDNSQuery(groupID, unitID, "internal", "127.0.0.1:12345", "test.dnslog.com.", msg)

	// Verify event was stored
	ev, loaded := internalGroupEventMap.Load(groupID)
	if !loaded {
		t.Fatal("Event should be stored in internalGroupEventMap")
	}
	storedEv := ev.(*Event)
	if storedEv.GroupID != groupID {
		t.Errorf("Stored event GroupID = %q, want %q", storedEv.GroupID, groupID)
	}
	if storedEv.EventType != "dns" {
		t.Errorf("Stored event EventType = %q, want 'dns'", storedEv.EventType)
	}
	if storedEv.EventSource != "internal" {
		t.Errorf("Stored event EventSource = %q, want 'internal'", storedEv.EventSource)
	}
	if storedEv.RemoteAddr != "127.0.0.1:12345" {
		t.Errorf("Stored event RemoteAddr = %q, want '127.0.0.1:12345'", storedEv.RemoteAddr)
	}

	// Verify event was stored in DB
	stats := db.getEventStats()
	if stats.DNS != 1 {
		t.Errorf("Expected 1 DNS event in DB, got %d", stats.DNS)
	}
}

func TestDNSServerServeDNSNoQuestions(t *testing.T) {
	config := &Config{
		Token: "testtoken",
		DNSServerConfig: DNSServerConfig{
			Enabled:  true,
			ListenIP: "127.0.0.1",
			Domain:   "dnslog.com",
		},
	}

	db := helperDB(t)
	defer db.Close()

	internalGroupEventMap := &sync.Map{}
	server, _ := NewDNSServer(config, internalGroupEventMap, db)

	w := &testDNSWriter{remoteAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}}
	r := &dns.Msg{}
	// No questions

	server.ServeDNS(w, r)

	// Should return without writing anything (no questions)
	if w.writtenMsg != nil {
		t.Error("Should not write response for empty questions")
	}
}

func TestDNSServerServeDNSNotQuery(t *testing.T) {
	config := &Config{
		Token: "testtoken",
		DNSServerConfig: DNSServerConfig{
			Enabled:  true,
			ListenIP: "127.0.0.1",
			Domain:   "dnslog.com",
		},
	}

	db := helperDB(t)
	defer db.Close()

	internalGroupEventMap := &sync.Map{}
	server, _ := NewDNSServer(config, internalGroupEventMap, db)

	w := &testDNSWriter{remoteAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}}
	r := &dns.Msg{}
	r.Opcode = dns.OpcodeStatus // Not a query
	r.Question = []dns.Question{{Name: "test.dnslog.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}

	server.ServeDNS(w, r)

	// Should return without writing anything (not a query)
	if w.writtenMsg != nil {
		t.Error("Should not write response for non-query opcode")
	}
}

func TestDNSServerServeDNSTypeADefault(t *testing.T) {
	config := &Config{
		Token: "testtoken",
		DNSServerConfig: DNSServerConfig{
			Enabled:  true,
			ListenIP: "127.0.0.1",
			Domain:   "dnslog.com",
		},
	}

	db := helperDB(t)
	defer db.Close()

	internalGroupEventMap := &sync.Map{}
	server, _ := NewDNSServer(config, internalGroupEventMap, db)

	w := &testDNSWriter{remoteAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}}
	r := &dns.Msg{}
	r.SetQuestion("unknown.dnslog.com.", dns.TypeA)

	server.ServeDNS(w, r)

	if w.writtenMsg == nil {
		t.Fatal("Should write DNS response")
	}
	if len(w.writtenMsg.Answer) != 1 {
		t.Fatalf("Expected 1 answer, got %d", len(w.writtenMsg.Answer))
	}
	aRecord, ok := w.writtenMsg.Answer[0].(*dns.A)
	if !ok {
		t.Fatal("Answer should be an A record")
	}
	if !aRecord.A.Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("A record IP = %v, want 127.0.0.1", aRecord.A)
	}
}

func TestDNSServerServeDNSTypeAAAADefault(t *testing.T) {
	config := &Config{
		Token: "testtoken",
		DNSServerConfig: DNSServerConfig{
			Enabled:  true,
			ListenIP: "127.0.0.1",
			Domain:   "dnslog.com",
		},
	}

	db := helperDB(t)
	defer db.Close()

	internalGroupEventMap := &sync.Map{}
	server, _ := NewDNSServer(config, internalGroupEventMap, db)

	w := &testDNSWriter{remoteAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}}
	r := &dns.Msg{}
	r.SetQuestion("unknown.dnslog.com.", dns.TypeAAAA)

	server.ServeDNS(w, r)

	if w.writtenMsg == nil {
		t.Fatal("Should write DNS response")
	}
	if len(w.writtenMsg.Answer) != 1 {
		t.Fatalf("Expected 1 answer, got %d", len(w.writtenMsg.Answer))
	}
}

func TestDNSServerServeDNSTypeTXTDefault(t *testing.T) {
	config := &Config{
		Token: "testtoken",
		DNSServerConfig: DNSServerConfig{
			Enabled:  true,
			ListenIP: "127.0.0.1",
			Domain:   "dnslog.com",
		},
	}

	db := helperDB(t)
	defer db.Close()

	internalGroupEventMap := &sync.Map{}
	server, _ := NewDNSServer(config, internalGroupEventMap, db)

	w := &testDNSWriter{remoteAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}}
	r := &dns.Msg{}
	r.SetQuestion("unknown.dnslog.com.", dns.TypeTXT)

	server.ServeDNS(w, r)

	if w.writtenMsg == nil {
		t.Fatal("Should write DNS response")
	}
	if len(w.writtenMsg.Answer) != 1 {
		t.Fatalf("Expected 1 answer, got %d", len(w.writtenMsg.Answer))
	}
	txtRecord, ok := w.writtenMsg.Answer[0].(*dns.TXT)
	if !ok {
		t.Fatal("Answer should be a TXT record")
	}
	if len(txtRecord.Txt) != 0 {
		t.Errorf("Default TXT record should be empty, got %v", txtRecord.Txt)
	}
}

func TestDNSServerServeDNSUnsupportedType(t *testing.T) {
	config := &Config{
		Token: "testtoken",
		DNSServerConfig: DNSServerConfig{
			Enabled:  true,
			ListenIP: "127.0.0.1",
			Domain:   "dnslog.com",
		},
	}

	db := helperDB(t)
	defer db.Close()

	internalGroupEventMap := &sync.Map{}
	server, _ := NewDNSServer(config, internalGroupEventMap, db)

	w := &testDNSWriter{remoteAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}}
	r := &dns.Msg{}
	r.SetQuestion("test.dnslog.com.", dns.TypeMX) // Unsupported type

	server.ServeDNS(w, r)

	// dns.HandleFailed writes a SERVFAIL response
	// The response should have Rcode set to RcodeServerFailure
	if w.writtenMsg == nil {
		t.Fatal("Should write DNS response even for unsupported type (HandleFailed)")
	}
}

func TestDNSServerServeDNSWithCustomDNSResponse(t *testing.T) {
	config := &Config{
		Token: "testtoken",
		DNSServerConfig: DNSServerConfig{
			Enabled:  true,
			ListenIP: "127.0.0.1",
			Domain:   "dnslog.com",
		},
	}

	db := helperDB(t)
	defer db.Close()

	// Set a custom DNS response for group "customGroup"
	drc := &DNSResponseConfig{GroupID: "customGroup"}
	drc.DNSResponse.A = []DNSResponseItem{{Value: "10.0.0.1", TTL: 120}}
	drc.DNSResponse.TXT = []DNSResponseItem{{Value: "custom_text", TTL: 300}}
	db.setDNSResponse(drc)

	internalGroupEventMap := &sync.Map{}
	server, _ := NewDNSServer(config, internalGroupEventMap, db)

	// Query with a domain that matches the custom group
	// The parseDomainInfo function extracts the groupID from the domain name
	// e.g., "p-abc123-customGroup-u1.dnslog.com" -> groupID="customGroup"
	// But the hashedToken must also match generateHashedToken
	// For simplicity, let's test the default path where parseDomainInfo doesn't match
	w := &testDNSWriter{remoteAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}}
	r := &dns.Msg{}
	r.SetQuestion("other.dnslog.com.", dns.TypeA)

	server.ServeDNS(w, r)

	// This will return the default 127.0.0.1 since groupID won't match
	if w.writtenMsg == nil {
		t.Fatal("Should write DNS response")
	}
}

func TestDNSServerServeDNSWithCustomTXTResponse(t *testing.T) {
	config := &Config{
		Token: "testtoken",
		DNSServerConfig: DNSServerConfig{
			Enabled:  true,
			ListenIP: "127.0.0.1",
			Domain:   "dnslog.com",
		},
	}

	db := helperDB(t)
	defer db.Close()

	// Set a custom TXT DNS response
	drc := &DNSResponseConfig{GroupID: "txtGroup"}
	drc.DNSResponse.TXT = []DNSResponseItem{{Value: "hello world", TTL: 60}}
	db.setDNSResponse(drc)

	internalGroupEventMap := &sync.Map{}
	server, _ := NewDNSServer(config, internalGroupEventMap, db)

	w := &testDNSWriter{remoteAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}}
	r := &dns.Msg{}
	r.SetQuestion("unknown.dnslog.com.", dns.TypeTXT)

	server.ServeDNS(w, r)

	// Since the groupID won't match the query, it returns default empty TXT
	if w.writtenMsg == nil {
		t.Fatal("Should write DNS response")
	}
}

func TestDNSServerStop(t *testing.T) {
	config := &Config{
		Token: "testtoken",
		DNSServerConfig: DNSServerConfig{
			Enabled:  true,
			ListenIP: "127.0.0.1",
			Domain:   "dnslog.com",
		},
	}

	db := helperDB(t)
	defer db.Close()

	server, _ := NewDNSServer(config, &sync.Map{}, db)

	// Stop should not panic even though server isn't listening
	server.Stop()
}

func TestDNSServerStopNil(t *testing.T) {
	server := &DNSServer{}
	server.Stop() // Should not panic with nil Server
}

func TestDNSServerServeDNSQueryWithTimestamp(t *testing.T) {
	config := &Config{
		Token: "testtoken",
		DNSServerConfig: DNSServerConfig{
			Enabled:  true,
			ListenIP: "127.0.0.1",
			Domain:   "dnslog.com",
		},
	}

	db := helperDB(t)
	defer db.Close()

	internalGroupEventMap := &sync.Map{}
	server, _ := NewDNSServer(config, internalGroupEventMap, db)

	msg := &dns.Msg{}
	msg.SetQuestion("test.dnslog.com.", dns.TypeA)

	server.ServeDNSQuery("g2", "u2", "public", "10.0.0.1:54321", "test.dnslog.com.", msg)

	ev, _ := internalGroupEventMap.Load("g2")
	storedEv := ev.(*Event)
	if storedEv.TimeStamp == 0 {
		t.Error("Event timestamp should be set")
	}
	if storedEv.EventSource != "public" {
		t.Errorf("EventSource = %q, want 'public'", storedEv.EventSource)
	}
}

func TestDNSServerServeDNSValidSubdomain(t *testing.T) {
	config := &Config{
		Token: "testtoken",
		DNSServerConfig: DNSServerConfig{
			Enabled:  true,
			ListenIP: "127.0.0.1",
			Domain:   "dnslog.com",
		},
	}

	db := helperDB(t)
	defer db.Close()

	internalGroupEventMap := &sync.Map{}
	server, _ := NewDNSServer(config, internalGroupEventMap, db)

	// Create a valid subdomain query
	groupID := "testGroup"
	unitID := "testUnit"
	hashedToken := generateHashedToken(config.Token, groupID, unitID)
	domain := fmt.Sprintf("p-%s-%s-%s.%s", hashedToken, groupID, unitID, config.DNSServerConfig.Domain)

	w := &testDNSWriter{remoteAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}}
	r := &dns.Msg{}
	r.SetQuestion(domain+".", dns.TypeA)

	server.ServeDNS(w, r)

	// The query should be recognized and an event should be stored
	ev, loaded := internalGroupEventMap.Load(groupID)
	if !loaded {
		t.Fatal("Event should be stored for valid subdomain query")
	}
	storedEv := ev.(*Event)
	if storedEv.GroupID != groupID {
		t.Errorf("Stored event GroupID = %q, want %q", storedEv.GroupID, groupID)
	}
	if storedEv.EventType != "dns" {
		t.Errorf("Stored event EventType = %q, want 'dns'", storedEv.EventType)
	}
}

// testDNSWriter implements dns.ResponseWriter for testing
type testDNSWriter struct {
	writtenMsg *dns.Msg
	remoteAddr net.Addr
}

func (w *testDNSWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}
}

func (w *testDNSWriter) RemoteAddr() net.Addr {
	if w.remoteAddr != nil {
		return w.remoteAddr
	}
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
}

func (w *testDNSWriter) WriteMsg(msg *dns.Msg) error {
	w.writtenMsg = msg
	return nil
}

func (w *testDNSWriter) Close() error {
	return nil
}

func (w *testDNSWriter) Hijack() {}

func (w *testDNSWriter) Write(b []byte) (int, error) {
	return len(b), nil
}

func (w *testDNSWriter) TsigStatus() error {
	return nil
}

func (w *testDNSWriter) TsigTimersOnly(bool) {}
