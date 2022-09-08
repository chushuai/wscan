/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package http

import (
	"net/http"
	"net/url"
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

//type Response struct {
//	url            *url.URL
//	Status         string
//	StatusCode     int
//	Proto          string
//	Header         map[string][]string
//	ContentLength  int64
//	Timing         *Timing
//	TimeStamp      int64
//	NativeResponse *Response
//	sync.Mutex
//	rawBody  []uint8
//	utf8Body []uint8
//	encoding string
//}

type Response struct {
	*http.Response
}

//type http.Response struct{
//	Status string
//	StatusCode int
//	Proto string
//	ProtoMajor int
//	ProtoMinor int
//	Header map[string][]string
//	Body io.ReadCloser
//	ContentLength int64
//	TransferEncoding []string
//	Close bool
//	Uncompressed bool
//	Trailer map[string][]string
//	Request *<nil>
//	TLS *tls.ConnectionState
//}

func (Response) Cookies() []*Cookie {
	return nil
}
func (Response) Dump() []uint8 {
	return nil
}
func (Response) DumpHeader() []uint8 {
	return nil
}
func (Response) GetEncoding() string {
	return ""
}
func (Response) GetRawBody() []uint8 {
	return nil
}
func (Response) GetServerProcessingTime() int {
	return 0
}
func (Response) GetTitile() string {
	return ""
}
func (Response) GetUTF8Body() ([]uint8, error) {
	return nil, nil
}
func (Response) Lock() {

}
func (Response) ResetBody([]uint8) {

}
func (Response) URL() *url.URL {
	return nil
}
func (Response) Unlock() {

}
func (Response) lockSlow() {

}
func (Response) unlockSlow(int32) {

}

//File: response.go
//	(*Timing)GetServerProcessingTime Lines: 44 to 53 (9)
//	(*Timing)SetTrace Lines: 53 to 104 (51)
//	(*Timing).SetTracefunc1 Lines: 55 to 58 (3)
//	(*Timing).SetTracefunc2 Lines: 58 to 61 (3)
//	(*Timing).SetTracefunc3 Lines: 61 to 64 (3)
//	(*Timing).SetTracefunc4 Lines: 64 to 67 (3)
//	(*Timing).SetTracefunc5 Lines: 67 to 70 (3)
//	(*Timing).SetTracefunc6 Lines: 70 to 73 (3)
//	(*Timing).SetTracefunc7 Lines: 73 to 76 (3)
//	(*Timing).SetTracefunc8 Lines: 76 to 265 (189)
//	(*Response)GetServerProcessingTime Lines: 104 to 107 (3)
//	(*Response)Cookies Lines: 107 to 114 (7)
//	(*Response)URL Lines: 114 to 120 (6)
//	(*Response)ResetBody Lines: 120 to 126 (6)
//	(*Response)GetEncoding Lines: 126 to 170 (44)
//	(*Response)GetRawBody Lines: 170 to 176 (6)
//	(*Response)GetTitile Lines: 176 to 193 (17)
//	(*Response)GetUTF8Body Lines: 193 to 217 (24)
//	(*Response)DumpHeader Lines: 217 to 224 (7)
//	(*Response)Dump Lines: 224 to 233 (9)
//	readResponseBody Lines: 233 to 260 (27)
//	ResponseFromAncestor Lines: 260 to 293 (33)
//	ResponseFromAncestorfunc1 Lines: 265 to 267 (2)
//	FakeHTTPResponse Lines: 293 to 302 (9)
