/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package mitmhelper

import (
	"context"
	"github.com/panjf2000/ants/v2"
	"io"
	"net/http"
	vhttp "wscan/core/http"
	"wscan/core/resource"
	"wscan/core/utils/checker"
	logger "wscan/core/utils/log"
)

// HTTPMirrorModifier 是请求修改器，用于记录请求日志
type HTTPMirrorModifier struct {
	ctx          context.Context
	pool         *ants.Pool
	allowChecker *checker.RequestChecker
	httpOpts     *vhttp.ClientOptions
	output       chan resource.Resource
}

// responseModifier 是响应修改器，用于记录响应日志
func (hmm *HTTPMirrorModifier) ModifyRequest(req *http.Request) error {
	logger.Infof("Received request: %s %s", req.Method, req.URL) // 记录请求方法、URL等日志信息
	return nil
}

// ModifyResponse 是响应修改器，用于记录响应日志
func (hmm *HTTPMirrorModifier) ModifyResponse(res *http.Response) error {
	logger.Infof("Response status: %s", res.Status) // 记录响应状态码等日志信息
	req, err := vhttp.NewRequest(res.Request.Method, res.Request.URL.String(), res.Request.Body)
	if err != nil {
		logger.Error(err)
		return nil
	}
	req.Header = res.Request.Header
	resp := &vhttp.Response{
		NativeResponse: res,
	}
	hmm.output <- &vhttp.Flow{
		Request:  req,
		Response: resp,
	}
	return nil
}

func NewHTTPMirrorModifier(pool *ants.Pool, allowChecker *checker.RequestChecker,
	httpOpts *vhttp.ClientOptions, output chan resource.Resource) *HTTPMirrorModifier {
	return &HTTPMirrorModifier{
		pool:         pool,
		allowChecker: allowChecker,
		httpOpts:     httpOpts,
		output:       output,
	}
}

type multiReadCloser struct {
	io.Reader
	closer []io.Closer
}
