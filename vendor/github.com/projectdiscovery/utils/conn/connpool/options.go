package connpool

// Option configures OneTimePool at construction time.
type Option func(*OneTimePool) error

// WithDialer sets a custom Dialer used by the pool to establish connections.
func WithDialer(d Dialer) Option {
	return func(p *OneTimePool) error {
		p.mx.Lock()
		p.Dialer = d
		p.mx.Unlock()
		return nil
	}
}

// WithProxy configures a SOCKS5 proxy using the provided URL string
// Example: socks5://user:pass@127.0.0.1:1080
func WithProxy(proxyURL string) Option {
	return func(p *OneTimePool) error {
		d, err := NewCreateSOCKS5Dialer(proxyURL)
		if err != nil {
			return err
		}
		p.mx.Lock()
		p.Dialer = d
		p.mx.Unlock()
		return nil
	}
}
