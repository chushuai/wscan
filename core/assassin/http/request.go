/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package http

import (
	"io"
	"net/http"
	"net/url"
)

type Request struct {
	*http.Request
	TimeStamp       int64
	FollowRedirects bool
}

//type Request struct {
//	Method          string
//	Proto           string
//	Host            string
//	Header          map[string][]string
//	TimeStamp       int64
//	FollowRedirects bool
//	Close           bool
//	mu              sync.Mutex
//	url             *url.URL
//	originURL       string
//	body            []uint8
//	stats           uint8
//	once            sync.Once
//	bodyParams      map[string]*Parameter
//	queryParams     map[string]*Parameter
//	extra           map[string]interface{}
//	OnParams        func([]Parameter) []Parameter
//}

func (r *Request) AddCookie(*Cookie) {

}

func (*Request) ContentType() string {
	return ""
}

func (*Request) DelParam(*Parameter) (*Request, error) {
	return nil, nil
}

func (*Request) Dump(*Client) ([]uint8, error) {
	return nil, nil
}

func (*Request) DumpHeader(*Client) ([]uint8, error) {
	return nil, nil
}

func (*Request) DumpHeaderWithoutClient() ([]uint8, error) {
	return nil, nil
}

func (*Request) GetBodyReader() (io.Reader, error) {
	return nil, nil
}

func (*Request) GetOriginURL() string {
	return ""
}

func (*Request) GetParam(string, string) []Parameter {
	return nil
}

func (*Request) GetRawBody() ([]uint8, error) {
	return nil, nil
}

func (*Request) GetValue(string) interface{} {
	return nil
}
func (*Request) HasParams([]string) bool {
	return false
}

func (*Request) MustDump(*Client) string {
	return ""
}

func (*Request) Mutate(*Parameter) *Request {
	return nil
}

func (*Request) Origin() string {
	return ""
}

func (*Request) ParamsAll() []Parameter {
	return nil
}

func (*Request) ParamsBody() []Parameter {
	return nil
}

func (*Request) ParamsCookie() []Parameter {
	return nil
}

func (*Request) ParamsCookieFull() []Parameter {
	return nil
}

func (*Request) ParamsHeader([]string) []Parameter {
	return nil
}

func (*Request) ParamsQuery() []Parameter {
	return nil
}

func (*Request) ParamsQueryAndBody() []Parameter {
	return nil
}

func (*Request) Referrer() string {
	return ""
}
func (*Request) SetURL(*url.URL) {

}

func (*Request) SetValue(string, interface{}) {

}

func (*Request) Spawn() (*Request, error) {
	return nil, nil
}

func (*Request) URL() *url.URL {
	return nil
}

func (*Request) WithBody(io.Reader, string) *Request {
	return nil
}

func (*Request) WithFormBody(io.Reader) *Request {
	return nil
}

func (*Request) WithJSONBody(io.Reader) *Request {
	return nil
}

func (*Request) WithMultipartBody(io.Reader, string) *Request {
	return nil
}

func (*Request) WithRawCookie(string) (*Request, error) {
	return nil, nil
}

func (*Request) WithURL(*url.URL) *Request {
	return nil
}

func (*Request) buildBody() ([]uint8, error) {
	return nil, nil
}

func (*Request) buildDataMap() {

}

func (*Request) buildQuery() {

}

func (*Request) buildQueryData() {

}

func (*Request) clone() {

}

func (*Request) doCache() {

}

func (*Request) isBodyValueJSON() bool {
	return false
}

func (*Request) isParsed() bool {
	return false
}

func (*Request) isQueryValueJSON() bool {
	return false
}

func (*Request) paramsCookie() {

}

func (*Request) parseBody() error {
	return nil
}

func (*Request) parseJSON() {

}

func (*Request) parseQuery() {

}

func (*Request) parseQueryData() {

}
