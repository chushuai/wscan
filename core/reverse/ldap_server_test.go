package reverse

import (
	"net"
	"sync"
	"testing"
)

func TestNewLdapServer(t *testing.T) {
	config := &Config{Token: "test"}
	internalGroupEventMap := &sync.Map{}
	db := helperDB(t)
	defer db.Close()

	server := NewLdapServer(config, internalGroupEventMap, db)
	if server == nil {
		t.Fatal("NewLdapServer returned nil")
	}
	if server.config != config {
		t.Error("LdapServer config should match")
	}
	if server.db != db {
		t.Error("LdapServer db should match")
	}
	if server.internalGroupEventMap != internalGroupEventMap {
		t.Error("LdapServer internalGroupEventMap should match")
	}
}

func TestLdapServerHandleClose(t *testing.T) {
	config := &Config{
		Token: "testtoken",
		HTTPServerConfig: HTTPServerConfig{
			ListenIP:   "127.0.0.1",
			ListenPort: "8080",
		},
	}
	db := helperDB(t)
	defer db.Close()
	internalGroupEventMap := &sync.Map{}

	server := NewLdapServer(config, internalGroupEventMap, db)

	// Create a pipe connection
	serverConn, clientConn := net.Pipe()

	pc := NewPeekConn(serverConn)

	// Close the client side so the Handle will get EOF
	clientConn.Close()

	// Handle should not panic when connection is closed
	server.Handle(pc)
}

func TestLdapServerHandleNonLDAPData(t *testing.T) {
	config := &Config{
		Token: "testtoken",
		HTTPServerConfig: HTTPServerConfig{
			ListenIP:   "127.0.0.1",
			ListenPort: "8080",
		},
	}
	db := helperDB(t)
	defer db.Close()
	internalGroupEventMap := &sync.Map{}

	server := NewLdapServer(config, internalGroupEventMap, db)

	serverConn, clientConn := net.Pipe()
	pc := NewPeekConn(serverConn)

	// Send non-LDAP data and close
	go func() {
		clientConn.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
		clientConn.Close()
	}()

	// Handle should not panic
	server.Handle(pc)
}
