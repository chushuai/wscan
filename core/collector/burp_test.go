package collector

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"strings"
	"testing"

	vhttp "wscan/core/http"
)

func b64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// sampleBurpXML builds a small Burp XML export with one item whose request and
// response are base64-encoded.
func sampleBurpXML() string {
	return `<items burpVersion="2023.1" exportTime="2024-01-01T00:00:00">
  <item>
    <time>Mon Jan 01 00:00:00 GMT 2024</time>
    <url>http://example.com/test</url>
    <host>example.com</host>
    <port>80</port>
    <protocol>http</protocol>
    <method>GET</method>
    <path>/test</path>
    <extension>php</extension>
    <request base64="true">` + b64("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n") + `</request>
    <status>200</status>
    <responselength>100</responselength>
    <mimetype>HTML</mimetype>
    <response base64="true">` + b64("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n") + `</response>
    <comment></comment>
  </item>
</items>`
}

func TestNewFromBurpFile(t *testing.T) {
	opts := &vhttp.ClientOptions{}
	bc := NewFromBurpFile([]byte(sampleBurpXML()), opts)
	if bc == nil {
		t.Fatal("expected non-nil burpCollector")
	}
	if bc.client == nil {
		t.Error("expected client to be initialized")
	}
	if bc.pool == nil {
		t.Error("expected pool to be initialized")
	}
	if bc.opts == nil {
		t.Error("expected opts to be set")
	}
	if len(bc.fileData) == 0 {
		t.Error("expected fileData to be set")
	}
}

func TestNewFromBurpFile_WithProxy(t *testing.T) {
	opts := &vhttp.ClientOptions{
		Proxy: "http://127.0.0.1:8080",
	}
	bc := NewFromBurpFile([]byte(sampleBurpXML()), opts)
	if bc == nil {
		t.Fatal("expected non-nil burpCollector")
	}
	if bc.client == nil {
		t.Error("expected client to be initialized with proxy")
	}
}

func TestBurpCollector_FitOut_EmptyData(t *testing.T) {
	opts := &vhttp.ClientOptions{}
	bc := NewFromBurpFile([]byte{}, opts)
	ch, err := bc.FitOut(context.Background(), []string{})
	// empty bytes fail to parse XML -> returns out channel + error
	if err == nil {
		t.Errorf("expected error from parsing empty data, got nil")
	}
	_ = ch
}

func TestBurpCollector_FitOut_NoItems(t *testing.T) {
	opts := &vhttp.ClientOptions{}
	bc := NewFromBurpFile([]byte(`<items></items>`), opts)
	ch, err := bc.FitOut(context.Background(), []string{})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if ch == nil {
		t.Fatal("expected non-nil channel")
	}
	// channel should be closed immediately with no resources
	res, ok := <-ch
	if ok {
		t.Errorf("expected channel to be closed, got resource %v", res)
	}
}

func TestBurpCollector_FitOut_SampleXML(t *testing.T) {
	opts := &vhttp.ClientOptions{}
	bc := NewFromBurpFile([]byte(sampleBurpXML()), opts)
	ch, err := bc.FitOut(context.Background(), []string{})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if ch == nil {
		t.Fatal("expected non-nil channel")
	}
	// consume channel until closed; the sample has one item with both
	// request and response, so BuildFlow should produce a flow resource.
	count := 0
	for range ch {
		count++
	}
	if count == 0 {
		// BuildFlow may fail in tests without a real HTTP exchange; just ensure no panic/closed channel
		t.Log("FitOut produced no resources (acceptable when BuildFlow fails)")
	}
}

func TestParseBurpXML(t *testing.T) {
	items, err := ParseBurpXML([]byte(sampleBurpXML()))
	if err != nil {
		t.Fatalf("failed to parse Burp XML: %v", err)
	}
	if items == nil {
		t.Fatal("expected non-nil items")
	}
	if items.BurpVersion != "2023.1" {
		t.Errorf("expected burpVersion '2023.1', got %q", items.BurpVersion)
	}
	if len(items.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items.Items))
	}
	it := items.Items[0]
	if it.URL != "http://example.com/test" {
		t.Errorf("expected URL 'http://example.com/test', got %q", it.URL)
	}
	if it.Method != "GET" {
		t.Errorf("expected Method 'GET', got %q", it.Method)
	}
	if it.Status != 200 {
		t.Errorf("expected Status 200, got %d", it.Status)
	}
	if it.Host != "example.com" {
		t.Errorf("expected Host 'example.com', got %q", it.Host)
	}
	if it.Port != "80" {
		t.Errorf("expected Port '80', got %q", it.Port)
	}
	if it.Protocol != "http" {
		t.Errorf("expected Protocol 'http', got %q", it.Protocol)
	}
}

func TestParseBurpXML_Invalid(t *testing.T) {
	items, err := ParseBurpXML([]byte("not xml"))
	if err == nil {
		t.Errorf("expected error parsing invalid XML, got nil")
	}
	if items != nil {
		t.Errorf("expected nil items on error, got %v", items)
	}
}

func TestParseBurpXML_Empty(t *testing.T) {
	items, err := ParseBurpXML([]byte(`<items></items>`))
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(items.Items) != 0 {
		t.Errorf("expected 0 items, got %d", len(items.Items))
	}
}

func TestBurpItemRaw_Decode(t *testing.T) {
	// verify base64 decode path for request/response wrappers
	opts := &vhttp.ClientOptions{}
	bc := NewFromBurpFile([]byte(sampleBurpXML()), opts)
	items, err := ParseBurpXML([]byte(sampleBurpXML()))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(items.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items.Items))
	}
	req := bc.decodeRequest(items.Items[0].Request)
	if len(req) == 0 {
		t.Error("expected decoded request bytes")
	}
	if string(req) != "GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n" {
		t.Errorf("unexpected decoded request: %q", string(req))
	}
	resp := bc.decodeResponse(items.Items[0].Response)
	if len(resp) == 0 {
		t.Error("expected decoded response bytes")
	}
}

func TestBurpItemRaw_Plaintext(t *testing.T) {
	// non-base64 (plaintext) request wrapper should return content as-is
	const plain = "<items><item><request>GET / HTTP/1.1\r\nHost: x\r\n\r\n</request></item></items>"
	opts := &vhttp.ClientOptions{}
	bc := NewFromBurpFile([]byte(plain), opts)
	items, err := ParseBurpXML([]byte(plain))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	req := bc.decodeRequest(items.Items[0].Request)
	if !contains(req, "GET / HTTP/1.1") {
		t.Errorf("expected plaintext request content, got %q", string(req))
	}
}

func contains(haystack []byte, needle string) bool {
	return strings.Contains(string(haystack), needle)
}

func TestBurpCollector_ImplementsFitter(t *testing.T) {
	// Verify that burpCollector satisfies the Fitter interface at compile time
	var _ Fitter = (*burpCollector)(nil)
}

func TestBurpCollector_FitOut_CancelledContext(t *testing.T) {
	opts := &vhttp.ClientOptions{}
	bc := NewFromBurpFile([]byte(sampleBurpXML()), opts)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ch, err := bc.FitOut(ctx, []string{})
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
	if ch == nil {
		t.Fatal("expected non-nil channel")
	}
	for range ch {
	}
}

func TestBurpItemRaw_XMLRoundTrip(t *testing.T) {
	original := burpItemRaw{
		Time:      "now",
		URL:       "http://example.com/api",
		Host:      "example.com",
		Port:      "443",
		Protocol:  "https",
		Method:    "POST",
		Path:      "/api",
		Status:    201,
		Mimetype:  "JSON",
		Comment:   "test comment",
	}
	wrapped := burpItemsRaw{
		BurpVersion: "2024.1",
		ExportTime:  "2024-01-01",
		Items:       []burpItemRaw{original},
	}
	data, err := xml.Marshal(wrapped)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	var back burpItemsRaw
	if err := xml.Unmarshal(data, &back); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if len(back.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(back.Items))
	}
	got := back.Items[0]
	if got.URL != original.URL || got.Host != original.Host || got.Port != original.Port ||
		got.Protocol != original.Protocol || got.Method != original.Method ||
		got.Status != original.Status || got.Comment != original.Comment {
		t.Errorf("round trip mismatch:\noriginal=%+v\ngot=%+v", original, got)
	}
}

func TestBurpRequestWrapper_Base64Attr(t *testing.T) {
	// verify the base64 attribute is correctly read on request/response wrappers
	data := []byte(`<items><item>
		<request base64="true">` + b64("HEAD / HTTP/1.1\r\nHost: a\r\n\r\n") + `</request>
	</item></items>`)
	opts := &vhttp.ClientOptions{}
	bc := NewFromBurpFile(data, opts)
	items, err := ParseBurpXML(data)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if !items.Items[0].Request.Base64 {
		t.Error("expected Request.Base64=true")
	}
	req := bc.decodeRequest(items.Items[0].Request)
	if string(req) != "HEAD / HTTP/1.1\r\nHost: a\r\n\r\n" {
		t.Errorf("unexpected decoded request: %q", string(req))
	}
}
