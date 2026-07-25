/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package mitmhelper

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"wscan/core/crawler"
	vhttp "wscan/core/http"
	"wscan/core/resource"
	"wscan/core/utils"
	"wscan/core/utils/checker"
	logger "wscan/core/utils/log"

	"github.com/panjf2000/ants/v2"
)

// HTTPMirrorModifier 是请求修改器，用于记录请求日志
type HTTPMirrorModifier struct {
	ctx             context.Context
	pool            *ants.Pool
	allowChecker    *checker.RequestChecker
	httpOpts        *vhttp.ClientOptions
	output          chan resource.Resource
	smartFilter     *crawler.SmartFilter // 过滤对象
	AllowedHostname string
}

// responseModifier 是响应修改器，用于记录响应日志
func (hmm *HTTPMirrorModifier) ModifyRequest(req *http.Request) error {
	logger.Infof("Martian Received request: %s %s", req.Method, req.URL) // 记录请求方法、URL等日志信息

	if req.Method == "CONNECT" {
		return nil
	}
	if !hmm.allowChecker.TargetStr(req.URL.String()).IsAllowed().Bool() {
		logger.Infof("filter not allow url: %s", req.URL.String())
		return nil
	}
	req1, _ := vhttp.RequestFromNetHttpRequert(req)
	if hmm.smartFilter.DoFilter(req1, false) {
		logger.Infof("filter req: %s", req.URL.String())
		return nil
	}

	body, _ := utils.ReadAndResetRequestBody(req)
	newReq, err := vhttp.NewRequest(req.Method, req.URL.String(), bytes.NewReader(body))
	if err != nil {
		logger.Error(err)
		return nil
	}
	newReq.SetReqHeader(req.Header)
	client := vhttp.NewClientWithOptions(hmm.httpOpts)
	hmm.pool.Submit(func() {
		newRes, err := client.DoRaw(newReq)
		if err != nil {
			logger.Error(err)
			return
		}
		hmm.output <- &vhttp.Flow{
			Request:  newReq,
			Response: newRes,
		}
	})

	return nil
}

// ModifyResponse 是响应修改器，用于记录响应日志
func (hmm *HTTPMirrorModifier) ModifyResponse(res *http.Response) error {
	logger.Infof("Response status: %s %s %s", res.Request.Method, res.Request.URL.String(), res.Status) // 记录响应状态码等日志信息
	if hmm.AllowedHostname == "" {
		hmm.AllowedHostname = res.Request.URL.Hostname()
	}
	if !strings.Contains(res.Request.URL.Hostname(), hmm.AllowedHostname) {
		return nil
	}

	return nil
}

func NewHTTPMirrorModifier(pool *ants.Pool, allowChecker *checker.RequestChecker,
	httpOpts *vhttp.ClientOptions, output chan resource.Resource) *HTTPMirrorModifier {
	smartFilter := crawler.SmartFilter{
		SimpleFilter: crawler.SimpleFilter{},
	}
	smartFilter.Init()
	return &HTTPMirrorModifier{
		pool:         pool,
		allowChecker: allowChecker,
		httpOpts:     httpOpts,
		output:       output,
		smartFilter:  &smartFilter,
	}
}

type multiReadCloser struct {
	io.Reader
	closer []io.Closer
}
