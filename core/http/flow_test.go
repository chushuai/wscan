package http

import (
	"net/url"
	"testing"
)

func TestFlow_Seconds(t *testing.T) {
	u, _ := url.Parse("http://example.com")
	f := &Flow{
		Request: &Request{
			url:       u,
			TimeStamp: 1000000,
		},
		Response: &Response{
			TimeStamp: 1002000,
		},
	}
	// 2000ms / 1000 = 2 seconds
	seconds := f.Seconds()
	if seconds != 2 {
		t.Errorf("Seconds() = %d, want %d", seconds, 2)
	}
}

func TestFlow_Seconds_Zero(t *testing.T) {
	u, _ := url.Parse("http://example.com")
	f := &Flow{
		Request: &Request{
			url:       u,
			TimeStamp: 1000000,
		},
		Response: &Response{
			TimeStamp: 1000000,
		},
	}
	if f.Seconds() != 0 {
		t.Errorf("Seconds() should be 0 when timestamps are equal, got %d", f.Seconds())
	}
}

func TestAddFlow(t *testing.T) {
	u, _ := url.Parse("http://example.com")
	var flows []*Flow
	maxSize := 3

	for i := 0; i < 5; i++ {
		f := &Flow{
			Request:  &Request{url: u, TimeStamp: int64(i)},
			Response: &Response{TimeStamp: int64(i)},
		}
		flows = AddFlow(flows, f, maxSize)
	}

	// Should only keep the last maxSize items
	if len(flows) != maxSize {
		t.Errorf("expected %d flows, got %d", maxSize, len(flows))
	}
}

func TestAddFlow_UnderMaxSize(t *testing.T) {
	u, _ := url.Parse("http://example.com")
	var flows []*Flow
	maxSize := 10

	for i := 0; i < 5; i++ {
		f := &Flow{
			Request:  &Request{url: u, TimeStamp: int64(i)},
			Response: &Response{TimeStamp: int64(i)},
		}
		flows = AddFlow(flows, f, maxSize)
	}

	if len(flows) != 5 {
		t.Errorf("expected 5 flows, got %d", len(flows))
	}
}

func TestBuildFlow(t *testing.T) {
	request := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	response := "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"

	flow := BuildFlow(request, response)
	if flow == nil {
		t.Fatal("BuildFlow() returned nil")
	}
	if flow.Request == nil {
		t.Error("BuildFlow() flow.Request is nil")
	}
	if flow.Response == nil {
		t.Error("BuildFlow() flow.Response is nil")
	}
}

func TestBuildFlow_InvalidRequest(t *testing.T) {
	request := "INVALID REQUEST"
	response := "HTTP/1.1 200 OK\r\n\r\n"

	flow := BuildFlow(request, response)
	// Should return nil for invalid request
	if flow != nil {
		t.Error("BuildFlow() should return nil for invalid request")
	}
}

func TestBuildFlow_InvalidResponse(t *testing.T) {
	request := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	response := "INVALID RESPONSE"

	flow := BuildFlow(request, response)
	// Should return nil for invalid response
	if flow != nil {
		t.Error("BuildFlow() should return nil for invalid response")
	}
}

func TestRequest_DeepClone(t *testing.T) {
	u, _ := url.Parse("http://example.com/path?q=1")
	r := &Request{
		Method:    "GET",
		url:       u,
		Header:    map[string][]string{"Content-Type": {"text/html"}},
		TimeStamp: 12345,
		bodyParams: map[string]*Parameter{
			"key1": {Key: "key1", Value: "val1"},
		},
		queryParams: map[string]*Parameter{
			"q": {Key: "q", Value: "1"},
		},
	}

	cloned := r.DeepClone()

	if cloned == r {
		t.Error("DeepClone should return a different pointer")
	}
	if cloned.Method != r.Method {
		t.Errorf("cloned Method = %q, want %q", cloned.Method, r.Method)
	}
	if cloned.url.String() != r.url.String() {
		t.Errorf("cloned URL = %q, want %q", cloned.url.String(), r.url.String())
	}

	// Verify independence
	cloned.Method = "POST"
	if r.Method != "GET" {
		t.Error("modifying clone should not affect original")
	}
}

func TestRequest_Timestamp(t *testing.T) {
	r := &Request{TimeStamp: 12345}
	if r.Timestamp() != 12345 {
		t.Errorf("Timestamp() = %d, want %d", r.Timestamp(), 12345)
	}
}

func TestRequest_String(t *testing.T) {
	r := &Request{}
	if r.String() != "" {
		t.Errorf("Request.String() should return empty string, got %q", r.String())
	}
}

func TestFlow_DeepClone(t *testing.T) {
	u, _ := url.Parse("http://example.com")
	f := &Flow{
		Request:   &Request{url: u, TimeStamp: 100},
		Response:  &Response{TimeStamp: 200},
		TimeStamp: 150,
	}

	cloned := f.DeepClone()
	if cloned == nil {
		t.Fatal("DeepClone() returned nil")
	}

	clonedFlow, ok := cloned.(*Flow)
	if !ok {
		t.Fatal("DeepClone() should return *Flow")
	}

	if clonedFlow.TimeStamp != f.TimeStamp {
		t.Errorf("cloned TimeStamp = %d, want %d", clonedFlow.TimeStamp, f.TimeStamp)
	}
}

func TestFlow_Name(t *testing.T) {
	f := &Flow{}
	if f.Name() != "" {
		t.Errorf("Flow.Name() should return empty string, got %q", f.Name())
	}
}

func TestFlow_String(t *testing.T) {
	f := &Flow{}
	if f.String() != "" {
		t.Errorf("Flow.String() should return empty string, got %q", f.String())
	}
}

func TestFlow_Timestamp(t *testing.T) {
	f := &Flow{TimeStamp: 99999}
	if f.Timestamp() != 99999 {
		t.Errorf("Flow.Timestamp() = %d, want %d", f.Timestamp(), 99999)
	}
}

func TestFlow_Type(t *testing.T) {
	f := &Flow{}
	if f.Type() != 0 {
		t.Errorf("Flow.Type() should return 0, got %d", f.Type())
	}
}
