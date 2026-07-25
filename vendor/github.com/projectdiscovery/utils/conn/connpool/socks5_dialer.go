package connpool

import (
	"context"
	"fmt"
	"net"
	"net/url"

	"golang.org/x/net/proxy"
)

// socks5WrapperDialer adapts a golang.org/x/net/proxy.Dialer to our Dialer interface.
type socks5WrapperDialer struct {
	dialer proxy.Dialer
}

func (s *socks5WrapperDialer) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := s.dialer.Dial(network, address)
	if err != nil {
		return nil, fmt.Errorf("failed to connect via SOCKS5 proxy: %w", err)
	}
	return conn, nil
}

// NewCreateSOCKS5Dialer creates a Dialer that routes connections via a SOCKS5 proxy.
// socks5ProxyURLStr should be of the form: socks5://user:pass@host:port
func NewCreateSOCKS5Dialer(socks5ProxyURLStr string) (Dialer, error) {
	proxyURL, err := url.Parse(socks5ProxyURLStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse proxy URL: %v", err)
	}
	if proxyURL.Scheme != "socks5" {
		return nil, fmt.Errorf("unsupported proxy scheme: %s, only socks5 is supported", proxyURL.Scheme)
	}

	var auth *proxy.Auth
	if proxyURL.User != nil {
		username := proxyURL.User.Username()
		password, hasPassword := proxyURL.User.Password()
		if hasPassword {
			auth = &proxy.Auth{User: username, Password: password}
		} else {
			auth = &proxy.Auth{User: username}
		}
	}

	// Create the SOCKS5 dialer
	socks5ProxyDialer, err := proxy.SOCKS5("tcp", proxyURL.Host, auth, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("failed to create SOCKS5 proxy dialer: %w", err)
	}

	return &socks5WrapperDialer{dialer: socks5ProxyDialer}, nil
}
