package reverse

import (
	"net"
	"sync"
	"testing"
	"time"
)

func TestNewPeekConn(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	pc := NewPeekConn(server)
	if pc == nil {
		t.Fatal("NewPeekConn returned nil")
	}
	if pc.r == nil {
		t.Error("PeekConn reader is nil")
	}
	if pc.Conn == nil {
		t.Error("PeekConn underlying Conn is nil")
	}
}

func TestPeekConnRead(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	pc := NewPeekConn(server)

	// Write data from client side
	go func() {
		client.Write([]byte("hello world"))
		client.Close()
	}()

	buf := make([]byte, 11)
	n, err := pc.Read(buf)
	if err != nil {
		t.Fatalf("PeekConn.Read error: %v", err)
	}
	if n != 11 {
		t.Errorf("PeekConn.Read returned %d bytes, want 11", n)
	}
	if string(buf[:n]) != "hello world" {
		t.Errorf("PeekConn.Read data = %q, want %q", string(buf[:n]), "hello world")
	}
}

func TestPeekConnPeek(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	pc := NewPeekConn(server)

	// Write data from client side
	go func() {
		client.Write([]byte("hello world"))
	}()

	// Peek should read without consuming
	peeked, err := pc.Peek(5)
	if err != nil {
		t.Fatalf("PeekConn.Peek error: %v", err)
	}
	if string(peeked) != "hello" {
		t.Errorf("PeekConn.Peek data = %q, want %q", string(peeked), "hello")
	}

	// After Peek, Read should still return all data including peeked bytes
	buf := make([]byte, 11)
	n, err := pc.Read(buf)
	if err != nil {
		t.Fatalf("PeekConn.Read after Peek error: %v", err)
	}
	if string(buf[:n]) != "hello world" {
		t.Errorf("PeekConn.Read after Peek data = %q, want %q", string(buf[:n]), "hello world")
	}
}

func TestNewListener(t *testing.T) {
	// Create a simple listener
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer lis.Close()

	// Create a minimal Reverse struct for NewListener
	r := &Reverse{
		config: &Config{
			Token: "testtoken",
		},
		internalGroupEventMap: &sync.Map{},
	}

	// We need LDAP and RMI servers for the Listener to work
	// Create a temp db for them
	db := &DB{}
	dbPath := t.TempDir() + "/test_listener.db"
	if err := db.Open(dbPath); err != nil {
		t.Fatalf("Failed to open db: %v", err)
	}
	defer db.Close()

	r.db = db
	r.reverseLdapServer = NewLdapServer(r.config, r.internalGroupEventMap, db)
	r.reverseRMIServer = NewRMIServer(r.config, r.internalGroupEventMap, db)

	wrappedListener := NewListener(lis, r)
	if wrappedListener == nil {
		t.Fatal("NewListener returned nil")
	}
	if wrappedListener.peekConnChan == nil {
		t.Error("Listener peekConnChan is nil")
	}

	// Clean up
	wrappedListener.Listener.Close()
}

func TestListenerAcceptHTTP(t *testing.T) {
	// Create a listener
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}

	db := &DB{}
	dbPath := t.TempDir() + "/test_accept.db"
	if err := db.Open(dbPath); err != nil {
		t.Fatalf("Failed to open db: %v", err)
	}
	defer db.Close()

	r := &Reverse{
		config: &Config{
			Token: "testtoken",
		},
		internalGroupEventMap: &sync.Map{},
		db:                    db,
	}
	r.reverseLdapServer = NewLdapServer(r.config, r.internalGroupEventMap, db)
	r.reverseRMIServer = NewRMIServer(r.config, r.internalGroupEventMap, db)

	wrappedListener := NewListener(lis, r)
	defer wrappedListener.Listener.Close()

	// Connect and send HTTP data (not starting with 0x30 or 'J')
	go func() {
		conn, err := net.Dial("tcp", lis.Addr().String())
		if err != nil {
			t.Errorf("Failed to dial: %v", err)
			return
		}
		defer conn.Close()
		// Send an HTTP-like request starting with 'G' (GET)
		conn.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
	}()

	// Accept should return the connection
	conn, err := wrappedListener.Accept()
	if err != nil {
		t.Fatalf("Listener.Accept error: %v", err)
	}
	if conn == nil {
		t.Fatal("Listener.Accept returned nil connection")
	}
	conn.Close()
}

func TestListenerAcceptLDAP(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}

	db := &DB{}
	dbPath := t.TempDir() + "/test_ldap_accept.db"
	if err := db.Open(dbPath); err != nil {
		t.Fatalf("Failed to open db: %v", err)
	}
	defer db.Close()

	r := &Reverse{
		config: &Config{
			Token: "testtoken",
		},
		internalGroupEventMap: &sync.Map{},
		db:                    db,
	}
	r.reverseLdapServer = NewLdapServer(r.config, r.internalGroupEventMap, db)
	r.reverseRMIServer = NewRMIServer(r.config, r.internalGroupEventMap, db)

	wrappedListener := NewListener(lis, r)
	defer wrappedListener.Listener.Close()

	// Connect and send LDAP-like data (starting with 0x30)
	go func() {
		conn, err := net.Dial("tcp", lis.Addr().String())
		if err != nil {
			t.Errorf("Failed to dial: %v", err)
			return
		}
		defer conn.Close()
		// LDAP starts with 0x30
		conn.Write([]byte{0x30, 0x0c, 0x02, 0x01})
		// Give some time for the handler to process
		time.Sleep(100 * time.Millisecond)
	}()

	// The LDAP connection should NOT appear on peekConnChan
	// Wait a short time and verify the HTTP accept channel doesn't get it
	done := make(chan struct{})
	go func() {
		select {
		case <-wrappedListener.peekConnChan:
			t.Error("LDAP connection should not be sent to peekConnChan")
		case <-time.After(200 * time.Millisecond):
			// Expected: no connection on peekConnChan
		}
		close(done)
	}()
	<-done
}

func TestPeekConnReadAfterClose(t *testing.T) {
	server, client := net.Pipe()
	pc := NewPeekConn(server)

	// Close the client side to cause EOF on server side
	client.Close()

	buf := make([]byte, 10)
	_, err := pc.Read(buf)
	if err == nil {
		t.Error("Expected error reading from closed connection")
	}
}

func TestPeekConnMultipleReads(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	pc := NewPeekConn(server)

	go func() {
		client.Write([]byte("part1"))
		client.Write([]byte("part2"))
	}()

	buf1 := make([]byte, 5)
	n1, err := pc.Read(buf1)
	if err != nil {
		t.Fatalf("First Read error: %v", err)
	}
	if string(buf1[:n1]) != "part1" {
		t.Errorf("First Read = %q, want %q", string(buf1[:n1]), "part1")
	}

	buf2 := make([]byte, 5)
	n2, err := pc.Read(buf2)
	if err != nil {
		t.Fatalf("Second Read error: %v", err)
	}
	if string(buf2[:n2]) != "part2" {
		t.Errorf("Second Read = %q, want %q", string(buf2[:n2]), "part2")
	}
}

func TestPeekConnPeekThenRead(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	pc := NewPeekConn(server)

	go func() {
		client.Write([]byte("abcdefghij"))
	}()

	// Peek first 3 bytes
	peeked, err := pc.Peek(3)
	if err != nil {
		t.Fatalf("Peek error: %v", err)
	}
	if string(peeked) != "abc" {
		t.Errorf("Peek = %q, want %q", string(peeked), "abc")
	}

	// Read should include the peeked data
	buf := make([]byte, 10)
	n, err := pc.Read(buf)
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}
	if string(buf[:n]) != "abcdefghij" {
		t.Errorf("Read = %q, want %q", string(buf[:n]), "abcdefghij")
	}
}

// Ensure bufio.Reader is properly initialized
func TestPeekConnBufioReader(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	pc := NewPeekConn(server)

	// Verify that the reader is a bufio.Reader
	if pc.r == nil {
		t.Fatal("PeekConn.r (bufio.Reader) should not be nil")
	}

	// The reader should have a default buffered size
	// Write some data and peek to verify buffering works
	go func() {
		client.Write([]byte("test"))
	}()

	peeked, err := pc.Peek(4)
	if err != nil {
		t.Fatalf("Peek error: %v", err)
	}
	if string(peeked) != "test" {
		t.Errorf("Peek = %q, want %q", string(peeked), "test")
	}
}
