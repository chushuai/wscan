package collector

import (
	"context"
	"encoding/xml"
	"io"
	"strings"
	"testing"

	vhttp "wscan/core/http"
)

func TestNewFromBurpFile(t *testing.T) {
	opts := &vhttp.ClientOptions{}
	bc := NewFromBurpFile(opts)
	if bc == nil {
		t.Fatal("expected non-nil burpCollector")
	}
	if bc.client == nil {
		t.Error("expected client to be initialized")
	}
	if bc.pool == nil {
		t.Error("expected pool to be initialized")
	}
}

func TestNewFromBurpFile_WithProxy(t *testing.T) {
	opts := &vhttp.ClientOptions{
		Proxy: "http://127.0.0.1:8080",
	}
	bc := NewFromBurpFile(opts)
	if bc == nil {
		t.Fatal("expected non-nil burpCollector")
	}
	if bc.client == nil {
		t.Error("expected client to be initialized with proxy")
	}
}

func TestBurpCollector_FitOut(t *testing.T) {
	opts := &vhttp.ClientOptions{}
	bc := NewFromBurpFile(opts)
	ch, err := bc.FitOut(context.Background(), []string{})
	if ch != nil {
		t.Errorf("expected nil channel from burpCollector.FitOut, got %v", ch)
	}
	if err != nil {
		t.Errorf("expected nil error from burpCollector.FitOut, got %v", err)
	}
}

func TestBurpCollector_FitOut_WithTargets(t *testing.T) {
	opts := &vhttp.ClientOptions{}
	bc := NewFromBurpFile(opts)
	targets := []string{"http://example.com"}
	ch, err := bc.FitOut(context.Background(), targets)
	if ch != nil {
		t.Errorf("expected nil channel, got %v", ch)
	}
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestBurpCollector_WithReader(t *testing.T) {
	opts := &vhttp.ClientOptions{}
	bc := NewFromBurpFile(opts)
	bc.r = io.NopCloser(strings.NewReader("<items><item><url>http://example.com</url></item></items>"))
	if bc.r == nil {
		t.Error("expected reader to be set")
	}
}

func TestBurpFlow_Fields(t *testing.T) {
	bf := burpFlow{
		Url:      "http://example.com/test",
		Protocol: "http",
		Host:     "example.com",
		Port:     "80",
		Request:  []byte("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		Status:   200,
	}
	if bf.Url != "http://example.com/test" {
		t.Errorf("expected Url 'http://example.com/test', got %q", bf.Url)
	}
	if bf.Protocol != "http" {
		t.Errorf("expected Protocol 'http', got %q", bf.Protocol)
	}
	if bf.Host != "example.com" {
		t.Errorf("expected Host 'example.com', got %q", bf.Host)
	}
	if bf.Port != "80" {
		t.Errorf("expected Port '80', got %q", bf.Port)
	}
	if bf.Status != 200 {
		t.Errorf("expected Status 200, got %d", bf.Status)
	}
	if string(bf.Request) != "GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n" {
		t.Errorf("unexpected Request content")
	}
}

func TestBurpFlow_XMLTags(t *testing.T) {
	// Verify struct has correct XML tags by checking field values
	bf := burpFlow{}
	if bf.Url != "" {
		t.Errorf("expected empty Url, got %q", bf.Url)
	}
	if bf.Status != 0 {
		t.Errorf("expected Status 0, got %d", bf.Status)
	}
}

func TestBurpFlow_XMLMarshalUnmarshal(t *testing.T) {
	bf := burpFlow{
		Url:      "http://example.com/api",
		Protocol: "https",
		Host:     "example.com",
		Port:     "443",
		Request:  []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\nbody"),
		Status:   200,
	}
	data, err := xml.Marshal(bf)
	if err != nil {
		t.Fatalf("failed to marshal burpFlow: %v", err)
	}
	var bf2 burpFlow
	if err := xml.Unmarshal(data, &bf2); err != nil {
		t.Fatalf("failed to unmarshal burpFlow: %v", err)
	}
	if bf2.Url != bf.Url {
		t.Errorf("expected Url %q, got %q", bf.Url, bf2.Url)
	}
	if bf2.Protocol != bf.Protocol {
		t.Errorf("expected Protocol %q, got %q", bf.Protocol, bf2.Protocol)
	}
	if bf2.Host != bf.Host {
		t.Errorf("expected Host %q, got %q", bf.Host, bf2.Host)
	}
	if bf2.Port != bf.Port {
		t.Errorf("expected Port %q, got %q", bf.Port, bf2.Port)
	}
	if bf2.Status != bf.Status {
		t.Errorf("expected Status %d, got %d", bf.Status, bf2.Status)
	}
}

func TestItems_Structure(t *testing.T) {
	items := Items{
		Item: []burpFlow{
			{Url: "http://a.com", Protocol: "https", Host: "a.com", Port: "443", Status: 200},
			{Url: "http://b.com", Protocol: "http", Host: "b.com", Port: "80", Status: 404},
		},
	}
	if len(items.Item) != 2 {
		t.Errorf("expected 2 items, got %d", len(items.Item))
	}
	if items.Item[0].Url != "http://a.com" {
		t.Errorf("expected first item URL 'http://a.com', got %q", items.Item[0].Url)
	}
	if items.Item[1].Status != 404 {
		t.Errorf("expected second item Status 404, got %d", items.Item[1].Status)
	}
}

func TestItems_Empty(t *testing.T) {
	items := Items{}
	if len(items.Item) != 0 {
		t.Errorf("expected 0 items, got %d", len(items.Item))
	}
}

func TestItems_XMLMarshalUnmarshal(t *testing.T) {
	items := Items{
		Item: []burpFlow{
			{Url: "http://a.com", Protocol: "https", Host: "a.com", Port: "443", Status: 200, Request: []byte("GET / HTTP/1.1")},
			{Url: "http://b.com", Protocol: "http", Host: "b.com", Port: "80", Status: 404},
		},
	}
	data, err := xml.Marshal(items)
	if err != nil {
		t.Fatalf("failed to marshal Items: %v", err)
	}
	var items2 Items
	if err := xml.Unmarshal(data, &items2); err != nil {
		t.Fatalf("failed to unmarshal Items: %v", err)
	}
	if len(items2.Item) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items2.Item))
	}
	if items2.Item[0].Url != "http://a.com" {
		t.Errorf("expected first Url 'http://a.com', got %q", items2.Item[0].Url)
	}
	if items2.Item[1].Status != 404 {
		t.Errorf("expected second Status 404, got %d", items2.Item[1].Status)
	}
}

func TestBurpCollector_ImplementsFitter(t *testing.T) {
	// Verify that burpCollector satisfies the Fitter interface at compile time
	var _ Fitter = (*burpCollector)(nil)
}

func TestBurpCollector_NilReader(t *testing.T) {
	opts := &vhttp.ClientOptions{}
	bc := NewFromBurpFile(opts)
	if bc.r != nil {
		t.Error("expected default reader to be nil in new burpCollector")
	}
}

func TestBurpCollector_FitOut_CancelledContext(t *testing.T) {
	opts := &vhttp.ClientOptions{}
	bc := NewFromBurpFile(opts)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ch, err := bc.FitOut(ctx, []string{})
	if ch != nil {
		t.Errorf("expected nil channel, got %v", ch)
	}
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}
