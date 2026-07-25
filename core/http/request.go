/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httputil"
	"net/textproto"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"wscan/core/utils"
	"wscan/core/utils/jsonpath"
	logger "wscan/core/utils/log"

	"github.com/antchfx/xmlquery"
)

type Filter struct {
	MarkedQueryMap    map[string]any
	QueryKeysId       string
	QueryMapId        string
	MarkedPostDataMap map[string]any
	PostDataId        string
	MarkedPath        string
	PathId            string
	UniqueId          string
}

const (
	RequsetBuild  = 0
	RequsetParsed = 1
)

type Request struct {
	Method          string
	Proto           string
	Host            string
	Header          http.Header
	TimeStamp       int64
	FollowRedirects bool
	Close           bool
	mu              sync.Mutex
	url             *url.URL
	originURL       string
	body            []byte
	stats           uint8
	once            sync.Once
	bodyParams      map[string]*Parameter
	queryParams     map[string]*Parameter
	extra           map[string]any
	OnParams        func([]Parameter) []Parameter
}

func (r *Request) AddCookie(c *http.Cookie) {
	if r.Header == nil {
		r.Header = make(map[string][]string)
	}
	s := c.String()
	if c := textproto.MIMEHeader(r.Header).Get("Cookie"); c != "" {
		textproto.MIMEHeader(r.Header).Set("Cookie", c+"; "+s)
	} else {
		textproto.MIMEHeader(r.Header).Set("Cookie", s)
	}

}

func (r *Request) ContentType() string {
	if contentTypes, ok := r.Header["Content-Type"]; ok {
		return contentTypes[0]
	}
	return ""
}

func (req *Request) Dump() []byte {
	b, err := req.GetBodyReader()
	if err != nil {
		logger.Error(err)
	}
	r, err := http.NewRequest(strings.ToUpper(req.Method), req.url.String(), b)
	if err != nil {
		logger.Error(err)
		return nil
	}
	r.Header = req.Header

	raw, _ := httputil.DumpRequest(r, true)
	return raw
}

func (*Request) DumpHeader(*Client) ([]byte, error) {
	return nil, nil
}

func (r *Request) SetHeader(key string, value string) {
	http.Header(r.Header).Set(key, value)
}

func (r *Request) SetHeaders(headers map[string]string) {
	for key, value := range headers {
		r.SetHeader(key, value)
	}
}

func (r *Request) SetReqHeader(header map[string][]string) {
	r.Header = header
	r.doCache()
}

func (*Request) DumpHeaderWithoutClient() ([]byte, error) {
	return nil, nil
}

func (r *Request) GetBodyReader() (io.Reader, error) {
	return bytes.NewReader(r.body), nil
}

func (r *Request) GetOriginURL() string {
	return r.originURL
}

func (r *Request) GetRawBody() []byte {
	return r.body
}

func (*Request) GetValue(string) any {
	return nil
}

func (r *Request) HasParams(params []string) bool {
	for _, param := range params {
		if _, exists := r.bodyParams[param]; !exists {
			return false
		}
		if _, exists := r.queryParams[param]; !exists {
			return false
		}
	}
	return true
}

func (*Request) MustDump(*Client) string {
	return ""
}

func (r *Request) Origin() string {
	return r.originURL
}

func (s *Request) Referrer() string {
	return textproto.MIMEHeader(s.Header).Get("Referrer")
}

func (r *Request) SetURL(u *url.URL) {
	r.url = u
}

func (*Request) SetValue(string, any) {

}

func (*Request) Spawn() (*Request, error) {

	return nil, nil
}

func (r *Request) URL() *url.URL {
	return r.url
}

func (r *Request) GetURL() *URL {
	return &URL{
		*r.url,
	}
}

func (r *Request) IsJavaScript() bool {
	return strings.HasSuffix(r.url.Path, ".js")
}

func (r *Request) clone() *Request {
	newReq := new(Request)
	*newReq = *r
	newReq.url = cloneURL(r.url)
	if r.Header != nil {
		newReq.Header = cloneHeader(r.Header)
	}
	// TODO 这里需要深拷贝
	newReq.bodyParams = cloneParameters(r.bodyParams)
	newReq.queryParams = cloneParameters(r.queryParams)
	newReq.body = make([]byte, len(r.body))
	copy(newReq.body, r.body)
	r.doCache()
	return newReq
}

func (r *Request) WithBody(reader io.Reader, contentType string) *Request {
	body, err := io.ReadAll(reader)
	if err != nil {
		return nil
	}
	textproto.MIMEHeader(r.Header).Set("Content-Type", contentType)
	r.body = body
	r.doCache()
	return r
}

func (r *Request) WithFormBody(body io.Reader) *Request {
	return r.WithBody(body, "application/x-www-form-urlencoded")
}

func (r *Request) WithJSONBody(body io.Reader) *Request {
	return r.WithBody(body, "application/json")
}

func (r *Request) WithXMLBody(body io.Reader) *Request {
	return r.WithBody(body, "application/xml")
}

func (r *Request) WithMultipartBody(body io.Reader, boundary string) *Request {
	contentType := "multipart/form-data; boundary=" + boundary
	return r.WithBody(body, contentType)

}

func (r *Request) GetHeaderMap() (headerMap map[string]string) {
	headerMap = map[string]string{}
	for k, v := range r.Header {
		if len(v) > 0 {
			headerMap[k] = v[0]
		} else {
			headerMap[k] = ""
		}
	}
	return
}

func (r *Request) WithRawCookie(rawCookie string) (*Request, error) {
	if r.Header == nil {
		r.Header = make(map[string][]string)
	}
	textproto.MIMEHeader(r.Header).Add("Cookie", rawCookie)
	textproto.CanonicalMIMEHeaderKey(rawCookie)
	return nil, nil
}

func (r *Request) WithURL(u *url.URL) *Request {
	r.url = u
	return nil
}

func (*Request) ParseMultipartForm() *Parameter {
	// 将请求体转换为字节数组
	body := bytes.NewReader([]byte(""))

	// 创建一个multipart.Reader
	multipartReader := multipart.NewReader(body, "boundary")

	// 遍历所有multipart部分
	for {
		part, err := multipartReader.NextPart()
		if err != nil {
			break
		}

		// 处理每个部分
		// 在这里，你可以根据Content-Disposition等信息处理字段或文件
		// 这里只是简单打印内容
		buf := new(bytes.Buffer)
		buf.ReadFrom(part)
		fmt.Println("Part Content:", buf.String())
		fmt.Println("FileName-->", part.FileName())
		fmt.Println("FileName-->", part.FormName())
		// 关闭当前部分，准备处理下一个
		part.Close()
	}
	return nil
}

func (req *Request) buildBody() {
	req.buildDataMap()
	req.buildQueryData()
	contentType := textproto.MIMEHeader(req.Header).Get("Content-Type")
	buff := bytes.Buffer{}

	if strings.Contains(contentType, "application/json") {
	} else if strings.Contains(contentType, "application/xml") {
	} else if strings.Contains(contentType, "multipart/form-data") {
		multipartBody := &bytes.Buffer{}
		multipartWriter := multipart.NewWriter(multipartBody)
		for _, p := range req.bodyParams {
			h := make(textproto.MIMEHeader)
			if p.Filename != "" {
				h.Set("Content-Disposition",
					fmt.Sprintf(`form-data; name="%s"; filename="%s"`, utils.EscapeQuotes(p.Key), utils.EscapeQuotes(p.Filename)))
			} else {
				h.Set("Content-Disposition",
					fmt.Sprintf(`form-data; name="%s"`, utils.EscapeQuotes(p.Key)))
			}
			if p.ContentType != "" {
				h.Set("Content-Type", p.ContentType)
			}
			fieldWriter, _ := multipartWriter.CreatePart(h)
			fieldWriter.Write([]byte(p.Value))
		}
		if err := multipartWriter.Close(); err == nil {
			req.body = multipartBody.Bytes()
		} else {
			logger.Error(err)
		}
		ct := multipartWriter.FormDataContentType()
		textproto.MIMEHeader(req.Header).Set("Content-Type", ct)
	} else {
		v := url.Values{}
		for _, p := range req.bodyParams {
			v.Add(p.Key, p.Value)
		}
		buff.WriteString(v.Encode())
		req.body = buff.Bytes()
	}

}

func (*Request) buildDataMap() {

}

func (r *Request) buildQuery() {
	v := url.Values{}
	for _, p := range r.queryParams {
		v.Add(p.Key, p.Value)
	}
	r.url.RawQuery = v.Encode()
}

func (*Request) buildQueryData() {

}

func (req *Request) doCache() {
	req.queryParams = make(map[string]*Parameter)
	req.bodyParams = make(map[string]*Parameter)
	req.parseQuery()
	req.parseQueryData()
}

func (req *Request) DoCache() {
	req.doCache()
}

func (r *Request) isBodyValueJSON() bool {
	//contentType := r.Headers.Get("Content-Type")
	//return strings.Contains(contentType, "application/json")
	return false
}

func (*Request) isParsed() bool {
	return false
}

func (r *Request) isQueryValueJSON() bool {

	return false
}

func (r *Request) GetURLDepth() int {
	path := r.url.Path
	depth := strings.Count(path, "/") - 1
	// 处理根路径的情况（末尾带斜杠）
	if path == "" {
		depth = 0
	}
	return depth
}

func (*Request) paramsCookie() {

}

// 是一个解析的过程
func (*Request) parseBody() error {
	return nil
}

func (req *Request) parseJSON() {
	contentType := req.ContentType()
	if strings.Contains(contentType, "application/json") {
		for _, path := range jsonpath.RecursiveDeepJsonPath(string(req.body)) {
			req.bodyParams[path] = &Parameter{Position: PositionBody,
				Key:         path,
				Value:       "",
				ContentType: "application/json"}
		}
	}
}

func (req *Request) parseXML() {
	contentType := req.ContentType()
	if strings.Contains(contentType, "application/xml") {
		rootNode, err := xmlquery.Parse(bytes.NewReader(req.body))
		if err != nil {
			logger.Error(err)
			return
		}
		RecursiveXMLNode(rootNode, func(node *xmlquery.Node) {
			xpath := GetXpathFromNode(node)
			if node.Type != xmlquery.TextNode {
				req.bodyParams[xpath] = &Parameter{Position: PositionBody,
					Key:         xpath,
					Value:       "",
					ContentType: "application/xml"}
			}
		})
	}
}

func (req *Request) parseQuery() {
	paramList := req.url.Query()
	for key, values := range paramList {
		for _, value := range values {
			req.queryParams[key] = &Parameter{Position: PositionQuery, Key: key, Value: value, ContentType: ""}
		}
	}
}

func (req *Request) parseQueryData() {
	contentType := req.ContentType()
	if contentType == "" {
		if json.Valid([]byte(req.body)) {
			contentType = "application/json"
		} else {
			contentType = "application/x-www-form-urlencoded"
		}
	}
	if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		paramListBody, _ := url.ParseQuery(string(req.body))
		for key, values := range paramListBody {
			for _, value := range values {
				req.bodyParams[key] = &Parameter{Position: PositionBody, Key: key, Value: value, ContentType: ""}
			}
		}
		return
	} else if strings.Contains(contentType, "multipart/form-data") {
		boundary, err := utils.ExtractBoundaryFromContentType(contentType)
		if err != nil {
			logger.Error(err)
			return
		}
		// 将请求体转换为字节数组
		body := bytes.NewReader(req.body)

		// 创建一个multipart.Reader
		multipartReader := multipart.NewReader(body, boundary)
		// 遍历所有multipart部分
		for {
			part, err := multipartReader.NextPart()
			if err != nil {
				break
			}
			// 这里只是简单打印内容
			buf := new(bytes.Buffer)
			buf.ReadFrom(part)
			// 关闭当前部分，准备处理下一个
			part.Close()
			if part.FormName() != "" {
				param := Parameter{Position: PositionBody, Key: part.FormName(),
					Value:       buf.String(),
					Filename:    part.FileName(),
					ContentType: part.Header.Get("Content-Type"),
					Content:     buf.Bytes(),
				}
				req.bodyParams[part.FormName()] = &param
			}
		}
		return
	} else if strings.Contains(contentType, "application/json") {
		req.parseJSON()
	} else if strings.Contains(contentType, "application/xml") {
		req.parseXML()
	}
}

func (*Request) DelParam(*Parameter) (*Request, error) {
	return nil, nil
}

func (r *Request) GetParam(key string, position string) []Parameter {
	switch position {
	case "query":
		return nil
	case "header":
		return nil
	default:
		return nil
	}
}

// sanitizeHeaderValue removes characters invalid in HTTP header field values.
// Per Go's net/http validation, CTL bytes (0x00-0x1F except HTAB 0x09) and DEL (0x7F) are not permitted.
func sanitizeHeaderValue(v string) string {
	for i := 0; i < len(v); i++ {
		b := v[i]
		if (b < 0x20 && b != 0x09) || b == 0x7f {
			buf := make([]byte, 0, len(v))
			for j := 0; j < len(v); j++ {
				c := v[j]
				if (c < 0x20 && c != 0x09) || c == 0x7f {
					continue
				}
				buf = append(buf, c)
			}
			return string(buf)
		}
	}
	return v
}

// 参数变异;突变
func (req *Request) Mutate(p *Parameter) *Request {
	newReq := req.clone()
	if p.Position == PositionQuery {
		for _, qp := range newReq.queryParams {
			if qp.Key == p.Key {
				qp.Value = p.Prefix + p.Value + p.Suffix
			}
		}
		newReq.buildQuery()
	} else if p.Position == PositionBody {
		// 首先需要检查编码格式
		if req.ContentType() == "application/json" {
			raw := jsonpath.ReplaceString(string(req.body), p.Key, p.Prefix+p.Value+p.Suffix)
			newReq.body = []byte(raw)
		} else if req.ContentType() == "application/xml" {
			rootNode, err := xmlquery.Parse(bytes.NewReader(req.body))
			if err == nil {
				func() {
					defer func() { recover() }()
					nodes := xmlquery.Find(rootNode, p.Key)
					for _, node := range nodes {
						value := ConvertValue(node.InnerText(), p.Prefix+p.Value+p.Suffix)
						node.FirstChild = &xmlquery.Node{
							Data: value,
							Type: xmlquery.TextNode,
						}
						raw := rootNode.OutputXML(false)
						newReq.body = []byte(raw)
						break
					}
				}()
			}
		} else {
			for _, qp := range newReq.bodyParams {
				if qp.Key == p.Key {
					qp.Value = p.Prefix + p.Value + p.Suffix
					qp.Filename = p.Filename
					qp.ContentType = p.ContentType
					// 不能直接 copy，当新内容比原始内容长时会被截断
					// 必须重新分配切片以确保完整复制
					qp.Content = make([]byte, len(p.Content))
					copy(qp.Content, p.Content)
				}
			}
		}
		newReq.buildBody()
	} else if p.Position == PositionCookie {
		cookies := readCookies(req.Header, "")
		if len(cookies) == 0 {
			logger.Fatal("len(cookies) == 0")
		}

		delete(newReq.Header, "Cookie")
		for i := range cookies {
			if cookies[i].Name == p.Key {
				cookies[i].Value = url.QueryEscape(p.Prefix + p.Value + p.Suffix)
			}
			newReq.AddCookie(cookies[i])
		}

	} else if p.Position == PositionHeader {
		headerValue := sanitizeHeaderValue(p.Prefix + p.Value + p.Suffix)
		newReq.Header[p.Key] = []string{headerValue}
		logger.Debugf("Header key=%s  value=%s", p.Key, headerValue)
	} else if p.Position == PositionPath {
		cleanedPath := path.Clean(req.url.Path)
		if cleanedPath == "/" {
			return newReq
		}
		if len(strings.Split(cleanedPath, "/")) <= 1 {
			fmt.Println(len(strings.Split(cleanedPath, "/")))
		}
		parts := strings.Split(cleanedPath, "/")[1:] // 去掉前导空字符串
		index, err := strconv.Atoi(p.Key)
		if err != nil {
			logger.Fatal(err)
		}
		if index >= len(parts) {
			logger.Fatal("Index out of range")
		}
		modifiedParts := make([]string, len(parts))
		copy(modifiedParts, parts)
		modifiedParts[index] = p.Prefix + p.Value + p.Suffix
		newReq.url.Path = "/" + strings.Join(modifiedParts, "/")
	}
	return newReq
}

func (r *Request) ParamsAll() (ret []Parameter) {
	// ret = append(r.ParamsQueryAndBody(), r.ParamsCookie()...)
	ret = append(ret, r.ParamsHeader()...)
	ret = append(ret, r.ParamsPath()...)
	return
}

func (r *Request) ParamsBody() (ret []Parameter) {
	for _, p := range r.bodyParams {
		ret = append(ret, *p)
	}
	return
}

func (r *Request) ParamsCookie() []Parameter {
	params := []Parameter{}
	cookies := readCookies(r.Header, "")
	for _, c := range cookies {
		params = append(params, Parameter{Position: PositionCookie, Key: c.Name, Value: c.Value})
	}
	return params
}

func (r *Request) ParamsPath() (ret []Parameter) {
	params := []Parameter{}
	cleanedPath := path.Clean(r.url.Path)
	if cleanedPath == "/" {
		return
	}
	if len(strings.Split(cleanedPath, "/")) <= 1 {
		return
	}
	parts := strings.Split(cleanedPath, "/")[1:] // 去掉前导空字符串
	for i := range parts {
		params = append(params, Parameter{Position: PositionPath, Key: fmt.Sprintf("%d", i), Value: "", ContentType: ""})
	}
	return params
}

func (r *Request) ParamsCookieFull() []Parameter {

	return nil
}

func (r *Request) ParamsHeader() []Parameter {
	params := []Parameter{}
	for k, v := range r.Header {
		if utils.StringIIn(strings.ToLower(k), []string{
			"user-agent",
			"referer",
			"x-forwarded-for",
		}) {
			params = append(params, Parameter{Position: PositionHeader, Key: k, Value: v[0]})

		}
	}
	return params
}

func (r *Request) ParamsQuery() (ret []Parameter) {
	for _, p := range r.queryParams {
		ret = append(ret, *p)
	}
	return
}

func (r *Request) ParamsQueryAndBody() (ret []Parameter) {
	for _, p := range r.bodyParams {
		ret = append(ret, *p)
	}
	for _, p := range r.queryParams {
		ret = append(ret, *p)
	}
	return
}

func BuildRequest() {

}

func NewRequest(method, rawUrl string, body io.Reader) (*Request, error) {
	var err error
	req := new(Request)
	req.Method = method
	req.Header = make(map[string][]string)
	req.url, err = url.Parse(rawUrl)
	if err != nil {
		return nil, err
	}
	req.originURL = rawUrl
	if body != nil {
		req.body, _ = io.ReadAll(body)
	}
	req.doCache()
	return req, nil
}

func RequestFromRawURL(rawUrl string) (*Request, error) {
	u, err := url.Parse(rawUrl)
	if err != nil {
		return nil, err
	}
	req := Request{
		originURL: rawUrl,
	}
	req.SetURL(u)
	req.doCache()
	return &req, nil
}

func RequestFromNetHttpRequert(hReq *http.Request) (*Request, error) {
	body, _ := utils.ReadAndResetRequestBody(hReq)
	rawReq, err := NewRequest(hReq.Method, hReq.URL.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	// 拷贝标准 http.Request 的 Header
	for key, values := range hReq.Header {
		for _, value := range values {
			rawReq.Header.Add(key, value)
		}
	}
	// Re-parse body params now that headers (especially Content-Type) are set
	rawReq.bodyParams = make(map[string]*Parameter)
	rawReq.queryParams = make(map[string]*Parameter)
	rawReq.parseQuery()
	rawReq.parseQueryData()
	return rawReq, nil
}

/*
*
返回POST请求数据解析后的map结构

支持 application/x-www-form-urlencoded 、application/json

如果解析失败，则返回 key: postDataStr 的map结构
*/
func (req *Request) PostDataMap() map[string]any {
	contentType := req.ContentType()
	if contentType == "" {
		return map[string]any{
			"key": req.GetRawBody(),
		}
	}

	if strings.HasPrefix(contentType, JSONContentType) {
		var result map[string]any
		err := json.Unmarshal([]byte(req.GetRawBody()), &result)
		if err != nil {
			return map[string]any{
				"key": req.GetRawBody(),
			}
		} else {
			return result
		}
	} else if strings.HasPrefix(contentType, URLEncoded) {
		var result = map[string]any{}
		r, err := url.ParseQuery(string(req.GetRawBody()))
		if err != nil {
			return map[string]any{
				"key": req.GetRawBody(),
			}
		} else {
			for key, value := range r {
				if len(value) == 1 {
					result[key] = value[0]
				} else {
					result[key] = value
				}
			}
			return result
		}
	} else {
		return map[string]any{
			"key": req.GetRawBody(),
		}
	}
}
