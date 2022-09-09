/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package http

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/martian/log"
	"github.com/thoas/go-funk"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
)

//type transport.BaseRequest struct {
//Cache bool `default:"true" yaml:"cache"`
//}

// type post struct {
// 	Key          string
// 	Value        string
// 	index        int //
// 	Content_type string
// 	// url   string
// }

// type Param []post

// Param describes an individual posted parameter.
type Param struct {
	// Name of the posted parameter.
	Name string `json:"name"`
	// Value of the posted parameter.
	Value string `json:"value,omitempty"`
	// Filename of a posted file.
	Filename string `json:"fileName,omitempty"`
	// ContentType is the content type of a posted file.
	ContentType string `json:"contentType,omitempty"`

	Index int //
}

// QueryString is a query string parameter on a request.
type QueryString struct {
	// Name is the query parameter name.
	Name string `json:"name"`
	// Value is the query parameter value.
	Value string `json:"value"`
}

// Header is an HTTP request or response header.
type Header struct {
	// Name is the header name.
	Name string `json:"name"`
	// Value is the header value.
	Value string `json:"value"`
}

// PostData describes posted data on a request.
type Variations struct {
	// MimeType is the MIME type of the posted data.
	MimeType string `json:"mimeType"`
	// Params is a list of posted parameters (in case of URL encoded parameters).
	Params []Param `json:"params"`
	// Text contains the posted data. Although its type is string, it may contain
	// binary data.
	Text string `json:"text"`
}

//type Cookie struct {
//	// Name is the cookie name.
//	Name string `json:"name"`
//	// Value is the cookie value.
//	Value string `json:"value"`
//	// Path is the path pertaining to the cookie.
//	Path string `json:"path,omitempty"`
//	// Domain is the host of the cookie.
//	Domain string `json:"domain,omitempty"`
//	// Expires contains cookie expiration time.
//	Expires time.Time `json:"-"`
//	// Expires8601 contains cookie expiration time in ISO 8601 format.
//	Expires8601 string `json:"expires,omitempty"`
//	// HTTPOnly is set to true if the cookie is HTTP only, false otherwise.
//	HTTPOnly bool `json:"httpOnly,omitempty"`
//	// Secure is set to true if the cookie was transmitted over SSL, false
//	// otherwise.
//	Secure bool `json:"secure,omitempty"`
//}
//
//// Request holds data about an individual HTTP request.
//type Request struct {
//	// Method is the request method (GET, POST, ...).
//	Method string `json:"method"`
//	// URL is the absolute URL of the request (fragments are not included).
//	URL string `json:"url"`
//	// HTTPVersion is the Request HTTP version (HTTP/1.1).
//	HTTPVersion string `json:"httpVersion"`
//	// Cookies is a list of cookies.
//	Cookies []Cookie `json:"cookies"`
//	// Headers is a list of headers.
//	Headers []Header `json:"headers"`
//	// QueryString is a list of query parameters.
//	QueryString []QueryString `json:"queryString"`
//	// PostData is the posted data information.
//	PostData *Variations `json:"postData,omitempty"`
//	// HeaderSize is the Total number of bytes from the start of the HTTP request
//	// message until (and including) the double CLRF before the body. Set to -1
//	// if the info is not available.
//	HeadersSize int64 `json:"headersSize"`
//	// BodySize is the size of the request body (POST data payload) in bytes. Set
//	// to -1 if the info is not available.
//	BodySize int64 `json:"bodySize"`
//}

// Content describes details about response content.
type Content struct {
	// Size is the length of the returned content in bytes. Should be equal to
	// response.bodySize if there is no compression and bigger when the content
	// has been compressed.
	Size int64 `json:"size"`
	// MimeType is the MIME type of the response text (value of the Content-Type
	// response header).
	MimeType string `json:"mimeType"`
	// Text contains the response body sent from the server or loaded from the
	// browser cache. This field is populated with fully decoded version of the
	// respose body.
	Text []byte `json:"text,omitempty"`
	// The desired encoding to use for the text field when encoding to JSON.
	Encoding string `json:"encoding,omitempty"`
}

//// Response holds data about an individual HTTP response.
//type Response struct {
//	// Status is the response status code.
//	Status int `json:"status"`
//	// StatusText is the response status description.
//	StatusText string `json:"statusText"`
//	// HTTPVersion is the Response HTTP version (HTTP/1.1).
//	HTTPVersion string `json:"httpVersion"`
//	// Cookies is a list of cookies.
//	Cookies string `json:"cookies"`
//	// Headers is a list of headers.
//	Headers []Header `json:"headers"`
//	// Content contains the details of the response body.
//	Content *Content `json:"content"`
//	// RedirectURL is the target URL from the Location response header.
//	RedirectURL string `json:"redirectURL"`
//	// HeadersSize is the total number of bytes from the start of the HTTP
//	// request message until (and including) the double CLRF before the body.
//	// Set to -1 if the info is not available.
//	HeadersSize int64 `json:"headersSize"`
//	// BodySize is the size of the request body (POST data payload) in bytes. Set
//	// to -1 if the info is not available.
//	BodySize int64 `json:"bodySize"`
//}

//Len()
func (p Variations) Len() int {
	return len(p.Params)
}

//Less(): 顺序有低到高排序
func (p Variations) Less(i, j int) bool {
	return p.Params[i].Index < p.Params[j].Index
}

//Swap()
func (p Variations) Swap(i, j int) {
	p.Params[i], p.Params[j] = p.Params[j], p.Params[i]
}

func (p *Variations) Release() string {

	var buf bytes.Buffer
	mjson := make(map[string]interface{})
	if p.MimeType == "application/json" {
		for _, Param := range p.Params {
			mjson[Param.Name] = Param.Value
		}
		jsonary, err := json.Marshal(mjson)
		if err != nil {
			panic(err)
		}
		buf.Write(jsonary)
	} else {
		for i, Param := range p.Params {
			buf.WriteString(Param.Name + "=" + Param.Value)
			if i != p.Len()-1 {
				buf.WriteString("&")
			}
		}
	}

	return buf.String()
}

func (p Variations) Set(key string, value string) error {
	for i, Param := range p.Params {
		if Param.Name == key {
			p.Params[i].Value = value
			return nil
		}
	}
	return fmt.Errorf("not found: %s", key)
}

const MIN_SEND_COUNT = 5

func (p *Variations) SetPayload(uri string, payload string, method string) []string {
	var result []string
	if strings.ToUpper(method) == "POST" {
		for idx, kv := range p.Params {
			//小于5一个链接参数不能超过5
			if idx <= MIN_SEND_COUNT {
				p.Set(kv.Name, payload)
				result = append(result, p.Release())
				p.Set(kv.Name, kv.Value)
			}

		}
	} else if strings.ToUpper(method) == "GET" {
		u, err := url.Parse(uri)
		if err != nil {
			log.Errorf("%s", err.Error())
			return nil
		}
		v := u.Query()
		for idx, kv := range p.Params {
			if idx <= MIN_SEND_COUNT {
				v.Set(kv.Name, payload)
				result = append(result, strings.Split(string(uri), "?")[0]+"?"+v.Encode())
				v.Set(kv.Name, kv.Value)
			}
		}
	}
	return result
}

func (p *Variations) SetPayloadByindex(index int, uri string, payload string, method string) string {
	var result string
	if strings.ToUpper(method) == "POST" {
		for idx, kv := range p.Params {
			//小于5一个链接参数不能超过5
			if idx <= MIN_SEND_COUNT {
				if idx == index {
					p.Set(kv.Name, payload)
					str := p.Release()
					p.Set(kv.Name, kv.Value)
					return str
				}
				// p.Set(kv.Name, payload)
				// result = append(result, p.Release())
				// p.Set(kv.Name, kv.Value)
			}

		}
	} else if strings.ToUpper(method) == "GET" {
		u, err := url.Parse(uri)
		if err != nil {
			log.Errorf("%v", err.Error())
			return ""
		}
		v := u.Query()
		for idx, kv := range p.Params {
			if idx <= MIN_SEND_COUNT {
				if idx == index {
					p.Set(kv.Name, payload)
					stv := p.Release()
					str := strings.Split(string(uri), "?")[0] + "?" + stv
					v.Set(kv.Name, kv.Value)
					return str
				}
			}
		}
	}
	return result
}

func ParseUri(uri string, body []byte, method string, content_type string) (*Variations, error) {
	var (
		err      error
		index    int
		Postinfo Variations
	)

	json_map := make(map[string]interface{})
	if strings.ToUpper(method) == "POST" {
		if len(body) > 0 {
			switch strings.ToLower(content_type) {
			case "application/json":
				err := json.Unmarshal(body, &json_map)
				if err != nil {
					panic(err)
				}
				for k, v := range json_map {
					index++
					Post := Param{Name: k, Value: v.(string), Index: index, ContentType: content_type}
					Postinfo.Params = append(Postinfo.Params, Post)
				}
			case "application/x-www-form-urlencoded":
				strs := strings.Split(string(body), "&")
				for i, kv := range strs {
					key := strings.Split(string(kv), "=")[0]
					value := strings.Split(string(kv), "=")[1]
					Post := Param{Name: key, Value: value, Index: i, ContentType: content_type}
					Postinfo.Params = append(Postinfo.Params, Post)
				}
			}
			sort.Sort(Postinfo)
			return &Postinfo, nil
		} else {
			return nil, fmt.Errorf("post data is empty")
		}

	} else if strings.ToUpper(method) == "GET" {
		if !funk.Contains(string(uri), "?") {
			return nil, fmt.Errorf("GET data is empty")
		}
		urlparams := strings.Split(string(uri), "?")[1]
		strs := strings.Split(string(urlparams), "&")
		//params := Param{}
		for i, kv := range strs {
			key := strings.Split(string(kv), "=")[0]
			value := strings.Split(string(kv), "=")[1]
			Post := Param{Name: key, Value: value, Index: i, ContentType: content_type}
			Postinfo.Params = append(Postinfo.Params, Post)
		}
		sort.Sort(Postinfo)
		return &Postinfo, nil
	} else {
		err = fmt.Errorf("method not supported")
	}
	return nil, err
}

func Decimal(value float64) float64 {
	value, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", value), 64)
	return value
}

type Status int

func RepairUrl(url string) string {
	//strings.Hasprefix(url, "https")
	lowurl := strings.ToLower(url)
	if strings.HasPrefix(lowurl, "http") || strings.HasPrefix(lowurl, "https") {
		return url
	} else {
		url = "http://" + url
	}
	return url
}

// 判断所给路径文件/文件夹是否存在
func Exists(path string) bool {
	_, err := os.Stat(path) //os.Stat获取文件信息
	if err != nil {
		if os.IsExist(err) {
			return true
		}
		return false
	}
	return true
}

func ConvertHeadersinterface(headers interface{}) (map[string]interface{}, error) {
	newheaders := make(map[string]interface{})
	var err error
	if h, ok := headers.([]Header); ok {
		for _, v := range h {
			newheaders[v.Name] = v.Value
		}
	} else {
		err = errors.New("invalid headers")
	}
	return newheaders, err
}
