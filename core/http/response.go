/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package http

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/textproto"
	"net/url"
	"regexp"
	"strings"
	"sync"
	logger "wscan/core/utils/log"

	"github.com/PuerkitoBio/goquery"
	"golang.org/x/net/html/charset"
	transformer "golang.org/x/text/transform"
)

const (
	LOCATION = "location"
)

var JavaScriptFilePattern = regexp.MustCompile(`(?i)\.(js|jsx)$`)

type Timing struct {
	DNSStart             int64
	DNSDone              int64
	ConnectStart         int64
	ConnectDone          int64
	TLSHandshakeStart    int64
	TLSHandshakeDone     int64
	WroteRequest         int64
	GotFirstResponseByte int64
}

type Response struct {
	Text           string
	url            *url.URL
	Status         string
	StatusCode     int
	Proto          string
	Header         http.Header
	ContentLength  int64
	Timing         *Timing
	TimeStamp      int64
	NativeResponse *http.Response
	sync.Mutex
	rawBody  []byte
	utf8Body []byte
	encoding string
}

func (r *Response) IsImage() bool {
	contentType := http.Header(r.Header).Get("Content-Type")
	return strings.HasPrefix(strings.ToLower(contentType), "image")
}

func (r *Response) IsText() bool {
	contentType := http.Header(r.Header).Get("Content-Type")
	match, _ := regexp.MatchString(`(?i)^text\/`, contentType)
	return match
}

func (r *Response) Cookies() []*http.Cookie {
	return r.NativeResponse.Cookies()
}

func (r *Request) Hostname() string {
	hostName := r.URL().Hostname()
	if hostName != "" {
		return hostName
	}
	return ""
}

func (r *Response) Dump() []byte {
	return []byte(fmt.Sprintf("%s\n%s", string(r.DumpHeader()), r.Text))
}

func (r *Response) DumpHeader() (ret []byte) {
	if r.NativeResponse == nil {
		return []byte{}
	}
	ret, _ = httputil.DumpResponse(r.NativeResponse, false)
	return
}

func (r *Response) GetEncoding() string {
	return r.encoding
}

func (r *Response) GetContentType() string {
	return http.Header(r.Header).Get("Content-Type")
}

func (r *Response) GetHeader(key string) string {
	return textproto.MIMEHeader(r.Header).Get(key)
}

func (r *Response) GetHeaderMap() (headerMap map[string]string) {
	headerMap = map[string]string{}
	for k := range r.Header {
		if k != "Set-Cookie" {
			headerMap[k] = http.Header(r.Header).Get(k)
		}
	}
	for _, ck := range r.Cookies() {
		headerMap["Set-Cookie"] += ck.String() + ";"
	}
	return
}

func (r *Response) GetRawBody() []byte {
	if r.rawBody != nil {
		return r.rawBody
	}
	return nil
}

func (r *Response) GetServerProcessingTime() int {
	return 0
}

func (r *Response) GetTitile() string {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(r.rawBody))
	if err != nil {
		return ""
	}
	return doc.Find("title").First().Text()
}

func (r *Response) GetUTF8Body() ([]byte, error) {
	return r.utf8Body, nil
}

func (r *Response) ResetBody(body []byte) {
	r.rawBody = body
}

func (r *Response) URL() *url.URL {
	return r.url
}

func (r *Response) IsApplicationWasm() bool {
	return strings.Contains(r.GetContentType(), "application/wasm")
}

func (r *Response) IsJavaScript() bool {
	path := url.PathEscape(r.url.String())
	if path != "" {
		if JavaScriptFilePattern.MatchString(path) {
			return true
		}
	}
	contentType := http.Header(r.Header).Get("Content-Type")
	return strings.Contains(contentType, "application/javascript") || strings.Contains(contentType, "text/javascript")
}

func (res *Response) IsHTML() bool {
	contentType := http.Header(res.Header).Get("Content-Type")
	if contentType == "" {
		return false
	}
	if strings.Contains(contentType, "text/html") || strings.Contains(contentType, "application/xhtml+xml") || strings.Contains(contentType, "application/xhtml") {
		return true
	}
	return false
}

func (r *Response) IsCss() bool {
	return strings.Contains(r.GetContentType(), "css")
}

func (r *Response) IsImages() bool {
	return strings.Contains(r.GetContentType(), "image")
}

func (r *Response) GetURL() *URL {
	return &URL{
		*r.url,
	}
}
func getTextFromResp(r *http.Response) string {
	// TODO: 编码转换
	if r.ContentLength == 0 {
		return ""
	}
	b, err := io.ReadAll(r.Body)
	if err != nil {
		logger.Debug("get response body err ", err)
	}
	_ = r.Body.Close()
	return string(b)
}

func UpdateResponseFromRawResponse(r *http.Response, resp *Response) {
	if r.Header.Get("Content-Encoding") == "gzip" {
		body, err := gzip.NewReader(r.Body)
		if err == nil {
			r.Body = body
		}
	}
	body, err := io.ReadAll(r.Body)
	if err == nil {
		encoding, _, _ := charset.DetermineEncoding(body, r.Header.Get("Content-Type"))
		utf8Reader := transformer.NewReader(bytes.NewReader(body), encoding.NewDecoder())
		body, err = io.ReadAll(utf8Reader)
		if err != nil {
			logger.Warning("解析http body失败", r.Request.URL.String(), err)
		}
	}
	r.Body = io.NopCloser(bytes.NewBuffer(body))
	resp.NativeResponse.Body = io.NopCloser(bytes.NewBuffer(body))

	resp.Text = string(body)
}

func ResponseFromNetHttpResponse(r *http.Response) (*Response, error) {
	if r.Header.Get("Content-Encoding") == "gzip" {
		body, err := gzip.NewReader(r.Body)
		if err == nil {
			r.Body = body
		}
	}
	body, err := io.ReadAll(r.Body)
	if err == nil {
		encoding, _, _ := charset.DetermineEncoding(body, r.Header.Get("Content-Type"))
		utf8Reader := transformer.NewReader(bytes.NewReader(body), encoding.NewDecoder())
		body, err = io.ReadAll(utf8Reader)
		if err != nil {
			logger.Warning("解析http body失败", r.Request.URL.String(), err)
		}
	}
	r.Body = io.NopCloser(bytes.NewBuffer(body))
	resp := &Response{
		Header:         r.Header,
		url:            r.Request.URL,
		StatusCode:     r.StatusCode,
		NativeResponse: r,
		rawBody:        body,
		utf8Body:       body,
		Text:           string(body),
	}
	return resp, nil
}
