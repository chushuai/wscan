package reverse

import (
	"testing"
)

func TestHTTPServerConfigGetAddr(t *testing.T) {
	tests := []struct {
		name     string
		config   HTTPServerConfig
		expected string
	}{
		{
			name:     "defaults",
			config:   HTTPServerConfig{},
			expected: "0.0.0.0:80",
		},
		{
			name: "custom ip and port",
			config: HTTPServerConfig{
				ListenIP:   "127.0.0.1",
				ListenPort: "8080",
			},
			expected: "127.0.0.1:8080",
		},
		{
			name: "only ip set",
			config: HTTPServerConfig{
				ListenIP: "10.0.0.1",
			},
			expected: "10.0.0.1:80",
		},
		{
			name: "only port set",
			config: HTTPServerConfig{
				ListenPort: "9090",
			},
			expected: "0.0.0.0:9090",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.GetAddr()
			if got != tt.expected {
				t.Errorf("HTTPServerConfig.GetAddr() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestConfigGetAddr(t *testing.T) {
	tests := []struct {
		name     string
		config   Config
		expected string
	}{
		{
			name: "remote server uses client config",
			config: Config{
				ClientConfig: ClientConfig{
					RemoteServer: true,
					HTTPBaseURL:  "http://remote.example.com:9999",
				},
				HTTPServerConfig: HTTPServerConfig{
					ListenIP:   "127.0.0.1",
					ListenPort: "8080",
				},
			},
			expected: "remote.example.com:9999",
		},
		{
			name: "local server uses http server config",
			config: Config{
				ClientConfig: ClientConfig{
					RemoteServer: false,
				},
				HTTPServerConfig: HTTPServerConfig{
					ListenIP:   "192.168.1.1",
					ListenPort: "3000",
				},
			},
			expected: "192.168.1.1:3000",
		},
		{
			name: "local server with empty config uses defaults",
			config: Config{
				ClientConfig: ClientConfig{
					RemoteServer: false,
				},
				HTTPServerConfig: HTTPServerConfig{},
			},
			expected: "0.0.0.0:80",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.GetAddr()
			if got != tt.expected {
				t.Errorf("Config.GetAddr() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestClientConfigGetAddr(t *testing.T) {
	tests := []struct {
		url      string
		expected string
	}{
		{"http://127.0.0.1:88", "127.0.0.1:88"},
		{"http://127.0.0.1", "127.0.0.1"},
		{"http://example.com:8080", "example.com:8080"},
		{"https://secure.example.com:443", "secure.example.com:443"},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			cc := ClientConfig{HTTPBaseURL: tt.url}
			addr := cc.GetAddr()
			if addr != tt.expected {
				t.Errorf("ClientConfig.GetAddr(%s) = %q, want %q", tt.url, addr, tt.expected)
			}
		})
	}
}

func TestResolveConfig(t *testing.T) {
	rc := ResolveConfig{
		Type:   "A",
		Record: "test.example.com",
		Value:  "1.2.3.4",
		TTL:    300,
	}
	if rc.Type != "A" {
		t.Errorf("Expected Type 'A', got '%s'", rc.Type)
	}
	if rc.Record != "test.example.com" {
		t.Errorf("Expected Record 'test.example.com', got '%s'", rc.Record)
	}
	if rc.Value != "1.2.3.4" {
		t.Errorf("Expected Value '1.2.3.4', got '%s'", rc.Value)
	}
	if rc.TTL != 300 {
		t.Errorf("Expected TTL 300, got %d", rc.TTL)
	}
}

func TestEventStruct(t *testing.T) {
	ev := Event{
		ID:          1,
		GroupID:     "grp1",
		UnitID:      "unit1",
		TimeStamp:   1700000000000,
		EventSource: "internal",
		EventType:   "http",
		Request:     "GET / HTTP/1.1",
		RemoteAddr:  "10.0.0.1:12345",
	}
	if ev.GroupID != "grp1" {
		t.Errorf("Expected GroupID 'grp1', got '%s'", ev.GroupID)
	}
	if ev.EventType != "http" {
		t.Errorf("Expected EventType 'http', got '%s'", ev.EventType)
	}
}

func TestHTTPResponseConfig(t *testing.T) {
	hrc := HTTPResponseConfig{
		GroupID: "testGroup",
	}
	hrc.StatusCode = "403"
	hrc.Body = "Forbidden"
	if hrc.GroupID != "testGroup" {
		t.Errorf("Expected GroupID 'testGroup', got '%s'", hrc.GroupID)
	}
	if hrc.StatusCode != "403" {
		t.Errorf("Expected StatusCode '403', got '%s'", hrc.StatusCode)
	}
}

func TestDNSResponseConfig(t *testing.T) {
	drc := DNSResponseConfig{
		GroupID: "dnsGroup",
	}
	drc.DNSResponse.A = []DNSResponseItem{{Value: "1.2.3.4", TTL: 60}}
	if drc.GroupID != "dnsGroup" {
		t.Errorf("Expected GroupID 'dnsGroup', got '%s'", drc.GroupID)
	}
	if len(drc.DNSResponse.A) != 1 {
		t.Fatalf("Expected 1 A record, got %d", len(drc.DNSResponse.A))
	}
	if drc.DNSResponse.A[0].Value != "1.2.3.4" {
		t.Errorf("Expected A record '1.2.3.4', got '%s'", drc.DNSResponse.A[0].Value)
	}
}

func TestCommonResponseComponent(t *testing.T) {
	comp := CommonResponseComponent{
		StatusCode: "200",
		Header:     []map[string]string{{"key": "Content-Type", "value": "text/html"}},
		Body:       "<h1>Hello</h1>",
	}
	if comp.StatusCode != "200" {
		t.Errorf("Expected StatusCode '200', got '%s'", comp.StatusCode)
	}
	if comp.Body != "<h1>Hello</h1>" {
		t.Errorf("Expected Body '<h1>Hello</h1>', got '%s'", comp.Body)
	}
}

func TestPayloadTemplateStruct(t *testing.T) {
	pt := PayloadTemplate{
		Name:        "xss",
		Description: "xss test",
		Suffix:      "x.js",
	}
	pt.StatusCode = "200"
	pt.Body = "alert(1)"
	if pt.Name != "xss" {
		t.Errorf("Expected Name 'xss', got '%s'", pt.Name)
	}
	if pt.Suffix != "x.js" {
		t.Errorf("Expected Suffix 'x.js', got '%s'", pt.Suffix)
	}
}

func TestListEventResp(t *testing.T) {
	resp := ListEventResp{
		Events: []*Event{{GroupID: "g1"}, {GroupID: "g2"}},
		Total:  2,
	}
	if resp.Total != 2 {
		t.Errorf("Expected Total 2, got %d", resp.Total)
	}
	if len(resp.Events) != 2 {
		t.Errorf("Expected 2 events, got %d", len(resp.Events))
	}
}

func TestResponseBase(t *testing.T) {
	rb := ResponseBase{Code: 0}
	if rb.Code != 0 {
		t.Errorf("Expected Code 0, got %d", rb.Code)
	}
}

func TestResponse(t *testing.T) {
	r := Response{
		ResponseBase: ResponseBase{Code: 1},
		Data:         "error msg",
	}
	if r.Code != 1 {
		t.Errorf("Expected Code 1, got %d", r.Code)
	}
}

func TestEventStatsStruct(t *testing.T) {
	stats := EventStats{
		HTTP:  10,
		DNS:   5,
		RMI:   3,
		LDAP:  1,
		Total: 19,
	}
	if stats.HTTP != 10 || stats.DNS != 5 || stats.RMI != 3 || stats.LDAP != 1 || stats.Total != 19 {
		t.Errorf("EventStats values don't match expected: %+v", stats)
	}
}

func TestRMIServerConfig(t *testing.T) {
	rsc := RMIServerConfig{
		Enabled:    true,
		ListenIP:   "0.0.0.0",
		ListenPort: "1099",
	}
	if !rsc.Enabled {
		t.Error("Expected Enabled to be true")
	}
	if rsc.ListenPort != "1099" {
		t.Errorf("Expected ListenPort '1099', got '%s'", rsc.ListenPort)
	}
}

func TestDNSServerConfig(t *testing.T) {
	dsc := DNSServerConfig{
		Enabled:            true,
		ListenIP:           "0.0.0.0",
		Domain:             "dnslog.com",
		IsDomainNameServer: true,
		Resolve: []ResolveConfig{
			{Type: "A", Record: "test.dnslog.com", Value: "10.0.0.1", TTL: 300},
		},
	}
	if !dsc.Enabled {
		t.Error("Expected Enabled to be true")
	}
	if dsc.Domain != "dnslog.com" {
		t.Errorf("Expected Domain 'dnslog.com', got '%s'", dsc.Domain)
	}
	if !dsc.IsDomainNameServer {
		t.Error("Expected IsDomainNameServer to be true")
	}
	if len(dsc.Resolve) != 1 {
		t.Errorf("Expected 1 resolve config, got %d", len(dsc.Resolve))
	}
}
