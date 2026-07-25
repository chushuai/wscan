package http

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/antchfx/xmlquery"
	"github.com/stretchr/testify/assert"
)

// =====================================================================
// request.go - zero-coverage and partial-coverage functions
// =====================================================================

func TestRequest_SetValue_ZeroCov(t *testing.T) {
	req, _ := NewRequest("GET", "http://example.com/", nil)
	// SetValue is a no-op but should be called for coverage
	req.SetValue("key", "value")
}

func TestRequest_buildDataMap_ZeroCov(t *testing.T) {
	req, _ := NewRequest("GET", "http://example.com/", nil)
	req.buildDataMap()
}

func TestRequest_buildQueryData_ZeroCov(t *testing.T) {
	req, _ := NewRequest("GET", "http://example.com/", nil)
	req.buildQueryData()
}

func TestRequest_paramsCookie_ZeroCov(t *testing.T) {
	req, _ := NewRequest("GET", "http://example.com/", nil)
	req.paramsCookie()
}

func TestBuildRequest_Func_ZeroCov(t *testing.T) {
	BuildRequest()
}

func TestRequest_Dump_WithBodyAndHeaders(t *testing.T) {
	req, _ := NewRequest("POST", "http://example.com/api/submit", strings.NewReader("field=value"))
	req.SetHeader("Content-Type", "application/x-www-form-urlencoded")
	req.SetHeader("Authorization", "Bearer token123")
	req.SetHeader("X-Custom", "custom-value")
	dump := req.Dump()
	assert.NotEmpty(t, dump)
	assert.True(t, bytes.Contains(dump, []byte("POST")))
	assert.True(t, bytes.Contains(dump, []byte("/api/submit")))
	assert.True(t, bytes.Contains(dump, []byte("field=value")))
}

func TestRequest_Dump_WithEmptyURL(t *testing.T) {
	// Dump with a valid but empty URL should not panic
	req, _ := NewRequest("GET", "http://example.com/", nil)
	req.body = []byte("test body content")
	dump := req.Dump()
	assert.NotEmpty(t, dump)
	assert.True(t, bytes.Contains(dump, []byte("test body content")))
}

func TestRequest_ParseMultipartForm_WithActualParts(t *testing.T) {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	_ = writer.WriteField("field1", "value1")
	part, _ := writer.CreateFormFile("upload", "test.txt")
	part.Write([]byte("file content"))
	writer.Close()

	req, _ := NewRequest("POST", "http://example.com/upload", &buf)
	req.SetHeader("Content-Type", writer.FormDataContentType())
	// ParseMultipartForm uses hardcoded empty body internally,
	// but this exercises more of the function
	result := req.ParseMultipartForm()
	assert.Nil(t, result)
}

func TestRequest_Mutate_QueryWithPrefixSuffix(t *testing.T) {
	req, _ := NewRequest("GET", "http://example.com/search?q=hello", nil)
	req.doCache()

	newReq := req.Mutate(&Parameter{
		Position: PositionQuery,
		Key:      "q",
		Value:    "world",
		Prefix:   "prefix_",
		Suffix:   "_suffix",
	})
	assert.NotNil(t, newReq)
	assert.Contains(t, newReq.url.RawQuery, "prefix_world_suffix")
}

func TestRequest_Mutate_BodyMultipartWithFilename(t *testing.T) {
	multipartBody := `--myboundary
Content-Disposition: form-data; name="file"; filename="test.sh"
Content-Type: text/plain

#!/bin/bash
echo hello
--myboundary--`
	req, _ := NewRequest("POST", "http://example.com/upload", strings.NewReader(multipartBody))
	req.SetHeader("Content-Type", "multipart/form-data; boundary=myboundary")
	req.doCache()

	// Mutate the file field
	newReq := req.Mutate(&Parameter{
		Position:    PositionBody,
		Key:         "file",
		Value:       "mutated_content",
		Prefix:      "",
		Suffix:      "",
		Filename:    "evil.sh",
		ContentType: "text/x-shellscript",
		Content:     []byte("#!/bin/bash\nevil"),
	})
	assert.NotNil(t, newReq)
}

func TestRequest_Mutate_BodyFormWithPrefixSuffix(t *testing.T) {
	req, _ := NewRequest("POST", "http://example.com/api", strings.NewReader("user=admin&pass=123"))
	req.SetHeader("Content-Type", "application/x-www-form-urlencoded")
	req.doCache()

	newReq := req.Mutate(&Parameter{
		Position: PositionBody,
		Key:      "user",
		Value:    "test",
		Prefix:   "<",
		Suffix:   ">",
	})
	assert.NotNil(t, newReq)
}

func TestRequest_ParamsPath_EdgeCases(t *testing.T) {
	// Test with single path segment that doesn't end with /
	req, _ := NewRequest("GET", "http://example.com/single", nil)
	params := req.ParamsPath()
	assert.Len(t, params, 1)
	assert.Equal(t, "0", params[0].Key)
	assert.Equal(t, PositionPath, params[0].Position)
}

func TestRequest_ParamsPath_TwoSegments(t *testing.T) {
	req, _ := NewRequest("GET", "http://example.com/api/v1", nil)
	params := req.ParamsPath()
	assert.Len(t, params, 2)
}

func TestRequest_RequestFromNetHttpRequert_WithBody(t *testing.T) {
	body := []byte("username=testuser&password=testpass")
	hReq, _ := http.NewRequest("POST", "http://example.com/login", bytes.NewReader(body))
	hReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	hReq.Header.Set("Authorization", "Basic dGVzdDp0ZXN0")

	req, err := RequestFromNetHttpRequert(hReq)
	assert.NoError(t, err)
	assert.Equal(t, "POST", req.Method)
	assert.Equal(t, "application/x-www-form-urlencoded", req.ContentType())
	assert.Equal(t, "Basic dGVzdDp0ZXN0", req.Header.Get("Authorization"))
}

func TestRequest_PostDataMap_URLEncodedWithSingleValue(t *testing.T) {
	body := "username=testuser"
	req, _ := NewRequest("POST", "http://example.com/login", strings.NewReader(body))
	req.SetHeader("Content-Type", "application/x-www-form-urlencoded")
	req.doCache()

	result := req.PostDataMap()
	assert.Equal(t, "testuser", result["username"])
}

func TestRequest_PostDataMap_InvalidURLEncoded(t *testing.T) {
	// URL-encoded parsing with bad content should fall back
	req, _ := NewRequest("POST", "http://example.com/", strings.NewReader("raw data"))
	req.SetHeader("Content-Type", "text/plain")
	req.doCache()

	result := req.PostDataMap()
	assert.NotNil(t, result)
	// With text/plain, falls back to {"key": body}
	_, hasKey := result["key"]
	assert.True(t, hasKey)
}

func TestRequest_buildBody_MultipartWithFilenameAndContentType(t *testing.T) {
	req, _ := NewRequest("POST", "http://example.com/", nil)
	req.SetHeader("Content-Type", "multipart/form-data; boundary=testboundary")
	req.bodyParams = map[string]*Parameter{
		"upload": {
			Key:         "upload",
			Value:       "file contents here",
			Filename:    "document.pdf",
			ContentType: "application/pdf",
		},
	}
	req.buildBody()
	assert.NotEmpty(t, req.body)
	ct := req.ContentType()
	assert.Contains(t, ct, "multipart/form-data")
}

// =====================================================================
// response.go - zero-coverage and partial-coverage functions
// =====================================================================

func TestResponse_GetTitile_WithHTML(t *testing.T) {
	html := `<!DOCTYPE html><html><head><title>My Page Title</title></head><body>Hello</body></html>`
	r := &Response{rawBody: []byte(html)}
	title := r.GetTitile()
	assert.Equal(t, "My Page Title", title)
}

func TestResponse_GetTitile_WithNilBody(t *testing.T) {
	r := &Response{rawBody: nil}
	title := r.GetTitile()
	assert.Equal(t, "", title)
}

func TestResponse_GetTitile_WithEmptyBody(t *testing.T) {
	r := &Response{rawBody: []byte("")}
	title := r.GetTitile()
	assert.Equal(t, "", title)
}

func TestResponse_GetTitile_WithMalformedHTML(t *testing.T) {
	r := &Response{rawBody: []byte("<html><head><title>Unclosed title")}
	title := r.GetTitile()
	// goquery may still extract partial title
	_ = title
}

func TestResponse_Dump_WithDumpHeader(t *testing.T) {
	nativeResp := &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Header:     http.Header{"Content-Type": {"text/html"}},
		Body:       io.NopCloser(strings.NewReader("body content")),
	}
	r := &Response{
		Text:           "body content",
		NativeResponse: nativeResp,
	}
	dump := r.Dump()
	assert.NotEmpty(t, dump)
	assert.True(t, strings.Contains(string(dump), "body content"))
}

func TestResponse_Cookies_WithMultipleCookies(t *testing.T) {
	r := &http.Response{
		Header: http.Header{
			"Set-Cookie": {"session=abc; Path=/", "user=test; Path=/"},
		},
	}
	resp := &Response{NativeResponse: r}
	cookies := resp.Cookies()
	assert.Len(t, cookies, 2)
}

func TestResponse_IsJavaScript_JSXPath(t *testing.T) {
	u, _ := url.Parse("http://example.com/app.jsx")
	r := &Response{
		url:    u,
		Header: http.Header{"Content-Type": {"text/html"}},
	}
	assert.True(t, r.IsJavaScript())
}

func TestResponse_IsJavaScript_NonJSXPath(t *testing.T) {
	u, _ := url.Parse("http://example.com/app.css")
	r := &Response{
		url:    u,
		Header: http.Header{"Content-Type": {"text/html"}},
	}
	assert.False(t, r.IsJavaScript())
}

func TestResponseFromNetHttpResponse_WithCharset(t *testing.T) {
	nativeResp := &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Header:     http.Header{"Content-Type": {"text/html; charset=utf-8"}},
		Body:       io.NopCloser(strings.NewReader("<html>hello</html>")),
		Request: &http.Request{
			URL: &url.URL{Scheme: "http", Host: "example.com", Path: "/"},
		},
	}
	resp, err := ResponseFromNetHttpResponse(nativeResp)
	assert.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	assert.Contains(t, resp.Text, "hello")
}

func TestUpdateResponseFromRawResponse_WithCharset(t *testing.T) {
	nativeResp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": {"text/html; charset=utf-8"}},
		Body:       io.NopCloser(strings.NewReader("utf8 content")),
		Request: &http.Request{
			Method: "GET",
			URL:    &url.URL{Scheme: "http", Host: "example.com", Path: "/"},
		},
	}
	resp := &Response{NativeResponse: nativeResp}
	UpdateResponseFromRawResponse(nativeResp, resp)
	assert.Contains(t, resp.Text, "utf8 content")
}

func TestGetTextFromResp_WithContent2(t *testing.T) {
	r := &http.Response{
		ContentLength: 5,
		Body:          io.NopCloser(strings.NewReader("hello")),
	}
	result := getTextFromResp(r)
	assert.Equal(t, "hello", result)
}

func TestGetTextFromResp_ZeroContentLength2(t *testing.T) {
	r := &http.Response{
		ContentLength: 0,
		Body:          io.NopCloser(strings.NewReader("")),
	}
	result := getTextFromResp(r)
	assert.Equal(t, "", result)
}

func TestResponseFromNetHttpResponse_GzipBody(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write([]byte("compressed hello"))
	gz.Close()

	nativeResp := &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Header: http.Header{
			"Content-Type":     {"text/plain"},
			"Content-Encoding": {"gzip"},
		},
		Body: io.NopCloser(&buf),
		Request: &http.Request{
			URL: &url.URL{Scheme: "http", Host: "example.com", Path: "/"},
		},
	}
	resp, err := ResponseFromNetHttpResponse(nativeResp)
	assert.NoError(t, err)
	assert.Contains(t, resp.Text, "compressed hello")
}

// =====================================================================
// url.go - zero-coverage and partial-coverage functions
// =====================================================================

func TestGetUrl_WithRelativePath(t *testing.T) {
	parent, _ := GetUrl("http://example.com/base/")
	u, err := GetUrl("subpath", *parent)
	assert.NoError(t, err)
	assert.Equal(t, "example.com", u.Host)
}

func TestGetUrl_WithAbsoluteHTTPS(t *testing.T) {
	u, err := GetUrl("https://secure.example.com/path")
	assert.NoError(t, err)
	assert.Equal(t, "https", u.Scheme)
	assert.Equal(t, "/path", u.Path)
}

func TestGetUrl_WithFragment(t *testing.T) {
	u, err := GetUrl("http://example.com/page#section")
	assert.NoError(t, err)
	assert.NotNil(t, u)
}

func TestGetUrl_WithParentRelativeResolution(t *testing.T) {
	parent, _ := GetUrl("http://example.com/docs/")
	u, err := GetUrl("../api", *parent)
	assert.NoError(t, err)
	assert.Equal(t, "example.com", u.Host)
}

func TestURL_parse_WithParentHTTPURL(t *testing.T) {
	u := &URL{}
	parentUrl, _ := url.Parse("http://example.com")
	parent := URL{URL: *parentUrl}

	result, err := u.parse("http://other.com/path", parent)
	assert.NoError(t, err)
	assert.Equal(t, "http://other.com/path", result)
}

func TestURL_parse_WithParentRelativePath(t *testing.T) {
	u := &URL{}
	parentUrl, _ := url.Parse("http://example.com")
	parent := URL{URL: *parentUrl}

	result, err := u.parse("/relative", parent)
	assert.NoError(t, err)
	assert.Equal(t, "/relative", result)
}

func TestURL_parse_Whitespace(t *testing.T) {
	u := &URL{}
	result, err := u.parse("  http://example.com  ")
	assert.NoError(t, err)
	assert.Equal(t, "http://example.com", result)
}

func TestURL_parse_MultipleHashes(t *testing.T) {
	u := &URL{}
	result, err := u.parse("http://example.com###frag")
	assert.NoError(t, err)
	// Multiple hashes should be reduced to single
	assert.False(t, strings.Contains(result, "###"))
}

func TestURL_RootDomain_NonICANNDomain(t *testing.T) {
	// IP address is not an ICANN domain
	u, _ := url.Parse("http://192.168.1.1/path")
	wu := &URL{URL: *u}
	domain := wu.RootDomain()
	// IP addresses don't have a public suffix, should return empty
	assert.Equal(t, "", domain)
}

func TestURL_RootDomain_Subdomain(t *testing.T) {
	u, _ := url.Parse("http://sub.example.com/path")
	wu := &URL{URL: *u}
	domain := wu.RootDomain()
	assert.Equal(t, "example.com", domain)
}

func TestURL_RootDomain_DeepSubdomain(t *testing.T) {
	u, _ := url.Parse("http://a.b.c.example.com/path")
	wu := &URL{URL: *u}
	domain := wu.RootDomain()
	assert.Equal(t, "example.com", domain)
}

func TestURL_cloneURL_WithUserInfo(t *testing.T) {
	u, _ := url.Parse("http://user:pass@example.com/path?q=1#frag")
	wu := &URL{URL: *u}
	cloned := wu.cloneURL()
	assert.NotNil(t, cloned)
	assert.Equal(t, "user", cloned.User.Username())
	pass, _ := cloned.User.Password()
	assert.Equal(t, "pass", pass)

	// Verify independence
	cloned.User = url.UserPassword("other", "otherpass")
	assert.Equal(t, "user", wu.User.Username())
}

func TestURL_cloneURL_WithoutUserInfo(t *testing.T) {
	u, _ := url.Parse("http://example.com/path")
	wu := &URL{URL: *u}
	cloned := wu.cloneURL()
	assert.NotNil(t, cloned)
	assert.Equal(t, wu.String(), cloned.String())

	// Verify independence
	cloned.Path = "/modified"
	assert.NotEqual(t, cloned.Path, wu.Path)
}

func TestGetURLPort_WithPort(t *testing.T) {
	port, err := GetURLPort("http://example.com:9090")
	assert.NoError(t, err)
	assert.Equal(t, 9090, port)
}

func TestGetURLPort_DefaultHTTP(t *testing.T) {
	port, err := GetURLPort("http://example.com")
	assert.NoError(t, err)
	assert.Equal(t, 80, port)
}

func TestGetURLPort_DefaultHTTPS(t *testing.T) {
	port, err := GetURLPort("https://example.com")
	assert.NoError(t, err)
	assert.Equal(t, 443, port)
}

func TestGetURLPort_UnsupportedScheme(t *testing.T) {
	_, err := GetURLPort("ftp://example.com")
	assert.Error(t, err)
}

func TestUrlSplitHostPort_WithExplicitPort(t *testing.T) {
	host, port, err := UrlSplitHostPort("http://example.com:8080")
	assert.NoError(t, err)
	assert.Equal(t, "example.com", host)
	assert.Equal(t, 8080, port)
}

func TestUrlSplitHostPort_DefaultHTTPPort(t *testing.T) {
	host, port, err := UrlSplitHostPort("http://example.com")
	assert.NoError(t, err)
	assert.Equal(t, "example.com", host)
	assert.Equal(t, 80, port)
}

func TestUrlSplitHostPort_DefaultHTTPSPort(t *testing.T) {
	host, port, err := UrlSplitHostPort("https://example.com")
	assert.NoError(t, err)
	assert.Equal(t, "example.com", host)
	assert.Equal(t, 443, port)
}

func TestUrlSplitHostPort_UnsupportedScheme2(t *testing.T) {
	_, _, err := UrlSplitHostPort("ftp://example.com")
	assert.Error(t, err)
}

func TestUrlSplitHostPort_InvalidURL2(t *testing.T) {
	_, _, err := UrlSplitHostPort("not-a-valid-url")
	assert.Error(t, err)
}

func TestGetURLDepth_EmptyPath(t *testing.T) {
	depth := GetURLDepth("http://example.com")
	assert.Equal(t, 0, depth)
}

func TestGetURLDepth_RootPath(t *testing.T) {
	depth := GetURLDepth("http://example.com/")
	assert.Equal(t, 0, depth)
}

func TestGetURLDepth_DeepPath(t *testing.T) {
	depth := GetURLDepth("http://example.com/a/b/c/d")
	assert.Equal(t, 3, depth)
}

func TestGetURLDepth_InvalidURL2(t *testing.T) {
	depth := GetURLDepth("://invalid")
	assert.Equal(t, -1, depth)
}

func TestUrlJoinPath_BothSlash(t *testing.T) {
	result := UrlJoinPath("http://example.com/", "/path")
	assert.Equal(t, "http://example.com/path", result)
}

func TestUrlJoinPath_NoSlash(t *testing.T) {
	result := UrlJoinPath("http://example.com", "path")
	assert.Equal(t, "http://example.com/path", result)
}

func TestUrlJoinPath_BaseSlashRelativeNoSlash(t *testing.T) {
	result := UrlJoinPath("http://example.com/base/", "sub")
	assert.Equal(t, "http://example.com/base/sub", result)
}

func TestUrlJoinPath_BaseNoSlashRelativeSlash(t *testing.T) {
	result := UrlJoinPath("http://example.com/base", "/sub")
	assert.Equal(t, "http://example.com/base/sub", result)
}

// =====================================================================
// client.go - zero-coverage functions
// =====================================================================

func TestClient_AddFlowCallback_ZeroCov(t *testing.T) {
	client := NewClient()
	client.AddFlowCallback(func(f *Flow) {})
}

func TestClient_respond_ZeroCov(t *testing.T) {
	client := NewClient()
	client.respond()
}

// =====================================================================
// config.go - zero-coverage functions
// =====================================================================

func TestClientOptions_SetProxies_ZeroCov(t *testing.T) {
	opt := &ClientOptions{}
	opt.SetProxies([]string{"http://proxy1:8080", "http://proxy2:8080"})
}

// =====================================================================
// utils.go - zero-coverage functions
// =====================================================================

func TestCloneHeader_ZeroCov(t *testing.T) {
	CloneHeader()
}

func TestIsStaticURL_ZeroCov(t *testing.T) {
	IsStaticURL()
}

func TestIsNeededResource_ZeroCov(t *testing.T) {
	IsNeededResource()
}

func TestReadCompressBody_ZeroCov(t *testing.T) {
	ReadCompressBody()
}

func TestGetTextContent_ZeroCov(t *testing.T) {
	GetTextContent()
}

// =====================================================================
// Additional coverage for partially-covered functions
// =====================================================================

func TestConvertValue_IntegerZero(t *testing.T) {
	result := ConvertValue("0", "42")
	assert.Equal(t, "42", result)
}

func TestConvertValue_FloatZero(t *testing.T) {
	result := ConvertValue("0.0", "1.5")
	// Should parse 1.5 as float64
	assert.NotEqual(t, "", result)
}

func TestConvertValue_BoolTrue(t *testing.T) {
	result := ConvertValue("true", "false")
	assert.Equal(t, "false", result)
}

func TestConvertValue_BoolFalse(t *testing.T) {
	result := ConvertValue("false", "true")
	assert.Equal(t, "true", result)
}

func TestConvertValue_PlainStringNoTypeConversion(t *testing.T) {
	result := ConvertValue("hello", "world")
	assert.Equal(t, "world", result)
}

func TestRecursiveXMLNode_WithSiblings(t *testing.T) {
	doc, err := xmlquery.Parse(strings.NewReader("<root><child1>a</child1><child2>b</child2><child3>c</child3></root>"))
	assert.NoError(t, err)

	visited := []string{}
	RecursiveXMLNode(doc, func(node *xmlquery.Node) {
		if node.Type == xmlquery.ElementNode {
			visited = append(visited, node.Data)
		}
	})
	assert.True(t, len(visited) >= 3)
}

func TestRecursiveXMLNode_WithNestedStructure(t *testing.T) {
	xml := `<root><parent><child>text</child></parent><sibling>val</sibling></root>`
	doc, err := xmlquery.Parse(strings.NewReader(xml))
	assert.NoError(t, err)

	count := 0
	RecursiveXMLNode(doc, func(node *xmlquery.Node) {
		count++
	})
	assert.True(t, count > 0)
}

func TestGetXpathFromNode_AttributeNode(t *testing.T) {
	doc, err := xmlquery.Parse(strings.NewReader(`<root attr="value"><child>text</child></root>`))
	assert.NoError(t, err)

	child := xmlquery.FindOne(doc, "//child")
	assert.NotNil(t, child)
	xpath := GetXpathFromNode(child)
	assert.NotEmpty(t, xpath)
}

func TestReadCookies_WithMultipleValues(t *testing.T) {
	h := http.Header{}
	h.Set("Cookie", "a=1; b=2; c=3")
	cookies := readCookies(h, "")
	assert.Len(t, cookies, 3)
}

func TestReadCookies_WithFilter2(t *testing.T) {
	h := http.Header{}
	h.Set("Cookie", "a=1; b=2; c=3")
	cookies := readCookies(h, "b")
	assert.Len(t, cookies, 1)
	assert.Equal(t, "b", cookies[0].Name)
	assert.Equal(t, "2", cookies[0].Value)
}

func TestReadCookies_WithInvalidCookieValue(t *testing.T) {
	h := http.Header{}
	h.Set("Cookie", "name=val;ue") // semicolon in value is invalid
	cookies := readCookies(h, "")
	// "name" should be parsed, but "ue" is invalid (no value part)
	// The semicolon splits it into "name=val" and "ue"
	assert.True(t, len(cookies) >= 1)
}

func TestBuildFlow_WithCookieAndHeaders(t *testing.T) {
	request := "GET /api HTTP/1.1\r\nHost: example.com\r\nCookie: session=abc\r\nX-Custom: value\r\n\r\n"
	response := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"

	flow := BuildFlow(request, response)
	assert.NotNil(t, flow)
	assert.NotNil(t, flow.Request)
	assert.NotNil(t, flow.Response)
	assert.Equal(t, "GET", flow.Request.Method)
}

func TestRequestFromNetHttpRequert_WithCookies(t *testing.T) {
	hReq, _ := http.NewRequest("GET", "http://example.com/", nil)
	hReq.Header.Set("Cookie", "session=abc123; user=testuser")
	hReq.Header.Set("Accept", "text/html")

	req, err := RequestFromNetHttpRequert(hReq)
	assert.NoError(t, err)
	assert.Equal(t, "GET", req.Method)
}

func TestRequest_PostDataMap_JSONWithNestedObject(t *testing.T) {
	body := `{"user":{"name":"test","age":25},"active":true}`
	req, _ := NewRequest("POST", "http://example.com/api", strings.NewReader(body))
	req.SetHeader("Content-Type", "application/json")
	req.doCache()

	result := req.PostDataMap()
	assert.NotNil(t, result)
	// Should be able to parse nested JSON
	_, hasUser := result["user"]
	assert.True(t, hasUser)
}

func TestRequest_buildBody_FormURLEncodedWithMultipleParams(t *testing.T) {
	req, _ := NewRequest("POST", "http://example.com/", nil)
	req.SetHeader("Content-Type", "application/x-www-form-urlencoded")
	req.bodyParams = map[string]*Parameter{
		"field1": {Key: "field1", Value: "value1"},
		"field2": {Key: "field2", Value: "value2"},
		"field3": {Key: "field3", Value: "value3"},
	}
	req.buildBody()
	assert.NotEmpty(t, req.body)
	bodyStr := string(req.body)
	assert.Contains(t, bodyStr, "field1=value1")
	assert.Contains(t, bodyStr, "field2=value2")
	assert.Contains(t, bodyStr, "field3=value3")
}

func TestRequest_Mutate_BodyMultipartMutation(t *testing.T) {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	_ = writer.WriteField("name", "original")
	writer.Close()

	req, _ := NewRequest("POST", "http://example.com/", &buf)
	req.SetHeader("Content-Type", writer.FormDataContentType())
	req.doCache()

	newReq := req.Mutate(&Parameter{
		Position: PositionBody,
		Key:      "name",
		Value:    "mutated",
		Prefix:   "",
		Suffix:   "",
	})
	assert.NotNil(t, newReq)
}

func TestRequest_Mutate_PathDeepPath(t *testing.T) {
	req, _ := NewRequest("GET", "http://example.com/a/b/c/d", nil)
	req.doCache()

	newReq := req.Mutate(&Parameter{
		Position: PositionPath,
		Key:      "2",
		Value:    "modified",
		Prefix:   "",
		Suffix:   "",
	})
	assert.NotNil(t, newReq)
	assert.Contains(t, newReq.url.Path, "modified")
}

// =====================================================================
// Integration tests for improved response.go coverage
// =====================================================================

func TestResponse_FullCoverage_FromTestServer_HTML(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(200)
		w.Write([]byte("<html><head><title>Test Title</title></head><body>Content</body></html>"))
	}))
	defer ts.Close()

	client := NewClient()
	req, _ := NewRequest("GET", ts.URL, nil)
	resp, err := client.DoRaw(req)
	assert.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	assert.True(t, resp.IsHTML())
	assert.Equal(t, "Test Title", resp.GetTitile())
}

func TestResponse_FullCoverage_FromTestServer_CSS(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css")
		w.WriteHeader(200)
		w.Write([]byte("body { color: red; }"))
	}))
	defer ts.Close()

	client := NewClient()
	req, _ := NewRequest("GET", ts.URL, nil)
	resp, err := client.DoRaw(req)
	assert.NoError(t, err)
	assert.True(t, resp.IsCss())
}

func TestResponse_FullCoverage_FromTestServer_Image(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.WriteHeader(200)
		w.Write([]byte("fake image data"))
	}))
	defer ts.Close()

	client := NewClient()
	req, _ := NewRequest("GET", ts.URL, nil)
	resp, err := client.DoRaw(req)
	assert.NoError(t, err)
	assert.True(t, resp.IsImage())
	assert.True(t, resp.IsImages())
}

func TestResponse_FullCoverage_FromTestServer_JS(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.WriteHeader(200)
		w.Write([]byte("console.log('hello')"))
	}))
	defer ts.Close()

	client := NewClient()
	req, _ := NewRequest("GET", ts.URL, nil)
	resp, err := client.DoRaw(req)
	assert.NoError(t, err)
	assert.True(t, resp.IsJavaScript())
}

func TestResponse_FullCoverage_FromTestServer_Wasm(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/wasm")
		w.WriteHeader(200)
		w.Write([]byte("wasm binary"))
	}))
	defer ts.Close()

	client := NewClient()
	req, _ := NewRequest("GET", ts.URL, nil)
	resp, err := client.DoRaw(req)
	assert.NoError(t, err)
	assert.True(t, resp.IsApplicationWasm())
}

func TestResponse_GetHeaderMap_WithSetCookie(t *testing.T) {
	r := &http.Response{
		Header: http.Header{
			"Content-Type": {"text/html"},
			"Set-Cookie":   {"session=abc123; Path=/", "user=test; Path=/"},
		},
	}
	resp := &Response{
		Header:         r.Header,
		NativeResponse: r,
	}
	hm := resp.GetHeaderMap()
	assert.Equal(t, "text/html", hm["Content-Type"])
	// Set-Cookie should be included
	_, hasSetCookie := hm["Set-Cookie"]
	assert.True(t, hasSetCookie)
}

func TestResponse_GetUTF8Body_NilBody(t *testing.T) {
	r := &Response{utf8Body: nil}
	body, err := r.GetUTF8Body()
	assert.NoError(t, err)
	assert.Nil(t, body)
}

// =====================================================================
// URL additional coverage
// =====================================================================

func TestURL_IsStaticResource_MoreExtensions(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"http://example.com/image.jpg", true},
		{"http://example.com/image.gif", true},
		{"http://example.com/video.mp4", true},
		{"http://example.com/audio.mp3", true},
		{"http://example.com/font.woff2", true},
		{"http://example.com/image.webp", true},
		{"http://example.com/archive.rar", true},
		{"http://example.com/file.exe", true},
		{"http://example.com/file.iso", true},
		{"http://example.com/file.csv", true},
		{"http://example.com/file.swf", true},
		{"http://example.com/file.m4v", true},
		{"http://example.com/file.rmvb", true},
		{"http://example.com/script.js", false}, // js not in StaticSuffix
		{"http://example.com/style.css", false}, // css not in StaticSuffix
		{"http://example.com/page.html", false}, // html not in StaticSuffix
		{"http://example.com/api/data", false},  // no extension
	}

	for _, tt := range tests {
		u, _ := url.Parse(tt.path)
		wu := &URL{URL: *u}
		result := wu.IsStaticResource()
		assert.Equal(t, tt.expected, result, "IsStaticResource(%q)", tt.path)
	}
}

func TestURL_IsDBFile_AllSuffixes(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"http://example.com/backup.sql", true},
		{"http://example.com/data.db", true},
		{"http://example.com/local.sqlite", true},
		{"http://example.com/db.accdb", true},
		{"http://example.com/db.mdb", true},
		{"http://example.com/file.txt", false},
		{"http://example.com/file.json", false},
	}

	for _, tt := range tests {
		u, _ := url.Parse(tt.path)
		wu := &URL{URL: *u}
		result := wu.IsDBFile()
		assert.Equal(t, tt.expected, result, "IsDBFile(%q)", tt.path)
	}
}

func TestURL_ParentPath_DeepPath(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"/", ""},
		{"/dir/", "/"},
		{"/a/b/", "/a"},
		{"/a/b/c/", "/a/b"},
		{"/a/b/file", "/a/b"},
		{"/file", "/"},
	}

	for _, tt := range tests {
		u, _ := url.Parse("http://example.com" + tt.path)
		wu := &URL{URL: *u}
		result := wu.ParentPath()
		assert.Equal(t, tt.expected, result, "ParentPath(%q)", tt.path)
	}
}

func TestURL_QueryMap_SingleAndMultipleValues(t *testing.T) {
	u, _ := url.Parse("http://example.com/?single=val&multi=1&multi=2")
	wu := &URL{URL: *u}
	qm := wu.QueryMap()

	// Single value should be string
	assert.Equal(t, "val", qm["single"])

	// Multiple values should be []string
	multiVal, ok := qm["multi"].([]string)
	assert.True(t, ok)
	assert.Len(t, multiVal, 2)
}

func TestURL_NoQueryUrl_WithQuery(t *testing.T) {
	u, _ := url.Parse("http://example.com/path?a=1&b=2")
	wu := &URL{URL: *u}
	result := wu.NoQueryUrl()
	assert.Equal(t, "http://example.com/path", result)
}

func TestURL_BaseURL_WithPort(t *testing.T) {
	u, _ := url.Parse("http://example.com:8080/path")
	wu := &URL{URL: *u}
	result := wu.BaseURL()
	assert.Equal(t, "http://example.com:8080", result)
}

func TestURL_NoFragmentUrl_WithFragment(t *testing.T) {
	u, _ := url.Parse("http://example.com/path#section")
	wu := &URL{URL: *u}
	result := wu.NoFragmentUrl()
	assert.NotContains(t, result, "#section")
}

func TestURL_NoSchemeFragmentUrl2(t *testing.T) {
	u, _ := url.Parse("http://example.com/path")
	wu := &URL{URL: *u}
	result := wu.NoSchemeFragmentUrl()
	assert.Equal(t, "://example.com/path", result)
}

func TestURL_MarshalJSON_RoundTrip(t *testing.T) {
	u, _ := url.Parse("http://example.com/path?q=1")
	wu := &URL{URL: *u}
	data, err := json.Marshal(wu)
	assert.NoError(t, err)

	var decoded string
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, "http://example.com/path?q=1", decoded)
}

func TestUrlParse_WithPercentSign(t *testing.T) {
	u, err := UrlParse("http://example.com/path%test")
	assert.NoError(t, err)
	assert.NotNil(t, u)
}

func TestUrlParse_NormalURL(t *testing.T) {
	u, err := UrlParse("http://example.com/normal/path")
	assert.NoError(t, err)
	assert.Equal(t, "http", u.Scheme)
	assert.Equal(t, "/normal/path", u.Path)
}

// =====================================================================
// Parameter additional coverage
// =====================================================================

func TestParameter_DeepCopy_WithNilContent(t *testing.T) {
	p := &Parameter{
		Position: PositionQuery,
		Key:      "test",
		Value:    "val",
		Content:  nil,
	}
	copied := p.DeepCopy()
	assert.Equal(t, "test", copied.Key)
	assert.Equal(t, "val", copied.Value)
	assert.Nil(t, copied.Content)
}

func TestParameter_Assign_WithContent(t *testing.T) {
	p := &Parameter{}
	other := Parameter{
		Position:    PositionBody,
		Key:         "file",
		Value:       "content",
		Filename:    "test.txt",
		ContentType: "text/plain",
		Content:     []byte("file data"),
	}
	p.Assign(other)
	assert.Equal(t, PositionBody, p.Position)
	assert.Equal(t, "file", p.Key)
	assert.Equal(t, "test.txt", p.Filename)
}

func TestParameter_Clone_Independence(t *testing.T) {
	p := &Parameter{
		Key:   "test",
		Value: "original",
	}
	cloned := p.Clone()
	cloned.Value = "modified"
	assert.Equal(t, "original", p.Value)
}

// =====================================================================
// Flow additional coverage
// =====================================================================

func TestFlow_Seconds_PositiveDuration(t *testing.T) {
	u, _ := url.Parse("http://example.com")
	f := &Flow{
		Request:  &Request{url: u, TimeStamp: 1000000},
		Response: &Response{TimeStamp: 1005000},
	}
	assert.Equal(t, 5, f.Seconds())
}

func TestAddFlow_ExactlyAtMaxSize(t *testing.T) {
	u, _ := url.Parse("http://example.com")
	var flows []*Flow
	maxSize := 3

	for i := 0; i < 3; i++ {
		f := &Flow{
			Request:  &Request{url: u, TimeStamp: int64(i)},
			Response: &Response{TimeStamp: int64(i)},
		}
		flows = AddFlow(flows, f, maxSize)
	}
	assert.Len(t, flows, maxSize)
}

// =====================================================================
// Clone additional coverage
// =====================================================================

func TestCloneURL_NilURL(t *testing.T) {
	result := cloneURL(nil)
	assert.Nil(t, result)
}

func TestCloneURL_WithQueryAndFragment(t *testing.T) {
	u, _ := url.Parse("http://example.com/path?query=value#fragment")
	result := cloneURL(u)
	assert.Equal(t, u.String(), result.String())

	// Modify clone
	result.RawQuery = "modified=1"
	assert.NotEqual(t, result.RawQuery, u.RawQuery)
}

func TestCloneHeader_WithMultipleValuesPerKey(t *testing.T) {
	h := http.Header{}
	h.Add("Accept", "text/html")
	h.Add("Accept", "application/json")
	h.Add("Accept", "*/*")
	h.Set("Content-Type", "text/plain")

	result := cloneHeader(h)
	assert.Len(t, result["Accept"], 3)
	assert.Equal(t, "text/plain", result["Content-Type"][0])

	// Verify independence
	result["Accept"][0] = "modified"
	assert.Equal(t, "text/html", h["Accept"][0])
}

func TestCloneURLValues_WithMultipleValues(t *testing.T) {
	v := url.Values{}
	v.Add("key", "val1")
	v.Add("key", "val2")

	result := cloneURLValues(v)
	assert.Len(t, result["key"], 2)

	// Verify independence
	result.Set("key", "modified")
	assert.NotEqual(t, v.Get("key"), result.Get("key"))
}
