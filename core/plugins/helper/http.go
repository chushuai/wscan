/**
2 * @Author: shaochuyu
3 * @Date: 12/10/23
4 */

package helper

import (
	"net/url"
	"wscan/core/http"
	"wscan/core/model"
)

func ParseUrl(u *url.URL) *model.UrlType {
	urlType := &model.UrlType{}
	urlType.Scheme = u.Scheme
	urlType.Domain = u.Hostname()
	urlType.Host = u.Host
	urlType.Port = u.Port()
	urlType.Path = u.Path
	urlType.Query = u.RawQuery
	urlType.Fragment = u.Fragment

	return urlType
}

func ConvertHttpRequestToModelRequest(oReq *http.Request) (*model.Request, error) {
	req := &model.Request{}

	req.Method = oReq.Method
	req.Url = ParseUrl(oReq.URL())
	headers := make(map[string]string)
	for k, v := range oReq.Header {
		if len(v) == 0 {
			continue
		}
		headers[k] = v[0]
	}
	req.Headers = headers
	req.ContentType = oReq.ContentType()
	//if oReq.Body != nil && oReq.Body != http.NoBody {
	//	data, err := io.ReadAll(oReq.Body)
	//	if err != nil {
	//		wrappedErr := errors.Newf("Get request error: %v", err)
	//		return nil, wrappedErr
	//	}
	//	req.Body = data
	//	oReq.Body = io.NopCloser(bytes.NewBuffer(data))
	//}
	return req, nil
}

func ConvertHttpResponseToModelResponse(oResp *http.Response, milliseconds int64) (*model.Response, error) {
	resp := &model.Response{}
	resp.Raw = oResp.Dump()

	headers := make(map[string]string)
	resp.Status = int32(oResp.StatusCode)
	resp.Url = ParseUrl(oResp.URL())
	for k, v := range oResp.Header {
		if len(v) == 0 {
			continue
		}
		headers[k] = v[0]
	}
	resp.Headers = headers
	resp.ContentType = oResp.GetContentType()
	// 原始请求头
	resp.RawHeader = oResp.DumpHeader()
	// http响应体
	resp.Body = resp.Raw
	resp.BodyString = string(resp.Raw)
	// 响应时间
	resp.Latency = milliseconds

	return resp, nil
}
