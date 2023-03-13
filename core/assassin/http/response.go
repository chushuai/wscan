/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package http

import (
	"io/ioutil"
	"net/http"
	"net/url"
	"sync"
	logger "wscan/core/utils/log"
)

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
	http.Response
	// raw text Response
	Text           string
	url            *url.URL
	Status         string
	StatusCode     int
	Proto          string
	Header         map[string][]string
	ContentLength  int64
	Timing         *Timing
	TimeStamp      int64
	NativeResponse *Response
	sync.Mutex
	rawBody  []byte
	utf8Body []byte
	encoding string
}

func (Response) Cookies() []*Cookie {
	return nil
}
func (Response) Dump() []byte {
	return nil
}
func (Response) DumpHeader() []byte {
	return nil
}
func (Response) GetEncoding() string {
	return ""
}
func (Response) GetRawBody() []byte {
	return nil
}
func (Response) GetServerProcessingTime() int {
	return 0
}
func (Response) GetTitile() string {

	// FindSubmatch
	return ""
}

func (Response) GetUTF8Body() ([]uint8, error) {
	return nil, nil
}

func (Response) ResetBody([]uint8) {

}
func (r *Response) URL() *url.URL {
	return r.url
}

func getTextFromResp(r *http.Response) string {
	// TODO: 编码转换
	if r.ContentLength == 0 {
		return ""
	}
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		logger.Debug("get response body err ", err)
	}
	_ = r.Body.Close()
	return string(b)
}

func NewResponse(r *http.Response) *Response {
	return &Response{
		Response: *r,
		Text:     getTextFromResp(r),
	}
}
