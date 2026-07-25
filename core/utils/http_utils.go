/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package utils

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	logger "wscan/core/utils/log"
)

func MapQueryToString() {

}

func DomainToURLFilter() {

}

func ReadAndResetResponseBody(res *http.Response) ([]byte, error) {
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	res.Body = io.NopCloser(bytes.NewBuffer(body))
	return body, nil
}

func ReadAndResetRequestBody(req *http.Request) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	if req.Method == "POST" {
		logger.Infof("%s %s \n\tPostdata:%s\n", req.Method, req.URL.String(), string(body))
	}

	req.Body = io.NopCloser(bytes.NewBuffer(body))
	return body, nil
}

func CloneRequest(req *http.Request) *http.Request {
	newReq := req.Clone(context.TODO())
	if data, err := ReadAndResetRequestBody(req); err == nil {
		newReq.Body = io.NopCloser(bytes.NewReader(data))
	}
	return newReq
}

// 返回POST请求数据解析后的map结构
func RequestPostDataMap(req *http.Request) map[string]any {
	contentType, err := GetRequestContentType(req)
	postData := ""
	if body, err := ReadAndResetRequestBody(req); err == nil {
		postData = string(body)
	}

	if err != nil {
		return map[string]any{
			"key": postData,
		}
	}
	if strings.HasPrefix(contentType, "application/json") {
		var result map[string]any
		err = json.Unmarshal([]byte(postData), &result)
		if err != nil {
			return map[string]any{
				"key": postData,
			}
		} else {
			return result
		}
	} else if strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
		var result = map[string]any{}
		r, err := url.ParseQuery(postData)
		if err != nil {
			return map[string]any{
				"key": postData,
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
			"key": postData,
		}
	}
}

var supportContentType = []string{"application/json", "application/x-www-form-urlencoded"}

func GetRequestContentType(req *http.Request) (string, error) {
	var contentType string
	if contentTypes, ok := req.Header["Content-Type"]; ok {
		contentType = contentTypes[0]
	}
	for _, ct := range supportContentType {
		if strings.HasPrefix(contentType, ct) {
			return contentType, nil
		}
	}
	return "", errors.New("dont support such content-type:" + contentType)
}

func UrlJoinPath(baseUrl, relativePath string) string {
	if strings.HasSuffix(baseUrl, "/") {
		baseUrl = baseUrl[:len(baseUrl)-1]
	}
	if strings.HasPrefix(relativePath, "/") {
		relativePath = relativePath[1:]
	}
	return baseUrl + "/" + relativePath
}

var quoteEscaper = strings.NewReplacer("\\", "\\\\", `"`, "\\\"")

func EscapeQuotes(s string) string {
	return quoteEscaper.Replace(s)
}

func ExtractBoundaryFromContentType(contentType string) (string, error) {
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return "", fmt.Errorf("error parsing Content-Type: %v", err)
	}

	boundary, ok := params["boundary"]
	if !ok {
		return "", fmt.Errorf("boundary not found in Content-Type")
	}

	return boundary, nil
}

// 检查http请求code 是都是重定向(300 &le; status &lt; 400)
func IsRedirection(statusCode int) bool {
	if statusCode >= 300 && statusCode < 400 {
		return true
	}

	return false
}

// 检查http请求是否是客户端错误
func IsClientError(statusCode int) bool {
	if statusCode >= 400 && statusCode < 500 {
		return true
	}

	return false
}

// 检查http请求是否是服务端错误
func IsServerError(statusCode int) bool {
	if statusCode >= 500 {
		return true
	}

	return false
}
