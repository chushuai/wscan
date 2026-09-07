package reverse

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"wscan/core/utils"
)

// ManagementStatus is the safe, WebUI-facing status of a reverse platform.
type ManagementStatus struct {
	Enabled         bool   `json:"enabled"`
	Remote          bool   `json:"remote"`
	Address         string `json:"address"`
	HTTPEnabled     bool   `json:"http_enabled"`
	DNSEnabled      bool   `json:"dns_enabled"`
	TokenConfigured bool   `json:"token_configured"`
}

type ManagementTestResult struct {
	OK        bool   `json:"ok"`
	Status    int    `json:"status,omitempty"`
	ElapsedMs int64  `json:"elapsed_ms,omitempty"`
	Error     string `json:"error,omitempty"`
}

// ValidateForManagement validates configuration without starting listeners.
func (c *Config) ValidateForManagement() error {
	if c == nil {
		return fmt.Errorf("reverse config is required")
	}
	if c.ClientConfig.RemoteServer {
		if c.Token == "" {
			return fmt.Errorf("token is required for remote server")
		}
		u, err := url.Parse(c.ClientConfig.HTTPBaseURL)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("client.http_base_url must be an absolute http(s) URL")
		}
		return nil
	}
	if !c.HTTPServerConfig.Enabled && !c.DNSServerConfig.Enabled {
		return fmt.Errorf("enable HTTP or DNS server first")
	}
	if c.DBFilePath == "" {
		return fmt.Errorf("db_file_path is required for local server")
	}
	if c.HTTPServerConfig.Enabled {
		if _, _, err := net.SplitHostPort(net.JoinHostPort(c.HTTPServerConfig.ListenIP, c.HTTPServerConfig.ListenPort)); err != nil && c.HTTPServerConfig.ListenPort != "" {
			return fmt.Errorf("invalid HTTP listen address: %v", err)
		}
	}
	return nil
}

func (c *Config) ManagementStatus(enabled bool) ManagementStatus {
	address := c.GetAddr()
	if c.ClientConfig.RemoteServer {
		address = c.ClientConfig.HTTPBaseURL
	}
	return ManagementStatus{Enabled: enabled, Remote: c.ClientConfig.RemoteServer, Address: address,
		HTTPEnabled: c.HTTPServerConfig.Enabled, DNSEnabled: c.DNSServerConfig.Enabled, TokenConfigured: c.Token != ""}
}

// Test performs a non-mutating health/connection check.
func (c *Config) Test(ctx context.Context) ManagementTestResult {
	start := time.Now()
	if err := c.ValidateForManagement(); err != nil {
		return ManagementTestResult{Error: err.Error(), ElapsedMs: time.Since(start).Milliseconds()}
	}
	if !c.ClientConfig.RemoteServer {
		return ManagementTestResult{OK: true, ElapsedMs: time.Since(start).Milliseconds()}
	}
	u := strings.TrimRight(c.ClientConfig.HTTPBaseURL, "/") + "/_/api/health_check"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return ManagementTestResult{Error: err.Error()}
	}
	if c.Token != "" {
		req.Header.Set("X-Token", c.Token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ManagementTestResult{Error: err.Error(), ElapsedMs: time.Since(start).Milliseconds()}
	}
	defer resp.Body.Close()
	return ManagementTestResult{OK: resp.StatusCode < 400, Status: resp.StatusCode, ElapsedMs: time.Since(start).Milliseconds()}
}

// NewPayload creates a callback payload using the same token scheme as the Avatar UI.
func (r *Reverse) NewPayload(kind string) map[string]any {
	c := r.config
	group := utils.RandLowLetterNumber(4)
	addr := c.GetAddr()
	if c.ClientConfig.RemoteServer {
		addr = c.ClientConfig.HTTPBaseURL
	}
	base := map[string]any{"type": kind, "group_id": group}
	switch kind {
	case "http":
		base["url"] = fmt.Sprintf("http://%s/p/%s/%s/", addr, generateHashedToken(c.Token, group, ""), group)
	case "http_template":
		base["url"] = fmt.Sprintf("http://%s/t/%s/%s/", addr, generateHashedToken(c.Token, group, ""), group)
	case "dns":
		base["prefix"] = fmt.Sprintf("p-%s-%s", generateHashedToken(c.Token, group, ""), group)
		base["root"] = c.DNSServerConfig.Domain
		base["domain"] = fmt.Sprintf("%s.%s", base["prefix"], c.DNSServerConfig.Domain)
	case "rmi", "ldap":
		base["address"] = addr
		base["token"] = generateHashedToken(c.Token, group, "")
	default:
		return nil
	}
	return base
}

// ListEvents exposes persisted local events to the WebUI. Remote event retrieval
// remains tied to active groups and is intentionally not guessed here.
func (r *Reverse) ListEvents(eventType string, count int) ([]*Event, int, error) {
	if r == nil || r.db == nil {
		return []*Event{}, 0, fmt.Errorf("local event database is unavailable")
	}
	if count <= 0 || count > 200 {
		count = 50
	}
	events, total := r.db.listEvent(eventType, "", count, "Next")
	return events, total, nil
}

func (r *Reverse) EventStats() (*EventStats, error) {
	if r == nil || r.db == nil {
		return &EventStats{}, fmt.Errorf("local event database is unavailable")
	}
	return r.db.getEventStats(), nil
}
