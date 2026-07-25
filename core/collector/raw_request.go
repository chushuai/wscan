/**
* @Author: shaochuyu
* @Date: 6/15/2026
 */
package collector

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	stdhttp "net/http"
	"net/url"
	wscanhttp "wscan/core/http"
	"wscan/core/resource"
	"wscan/core/utils/log"

	"github.com/panjf2000/ants/v2"
)

type rawRequestCollector struct {
	client   *wscanhttp.Client
	opts     *wscanhttp.ClientOptions
	fileData []byte
	forceSSL bool
	pool     *ants.Pool
}

// parseRawRequest 将原始 HTTP 请求文本解析为 wscan Request 对象。
//
// 解析流程：
//  1. 使用 net/http.ReadRequest 解析原始 HTTP 文本
//  2. 从 Host 头和请求 URI 重建完整 URL
//  3. 根据 forceSSL 决定 scheme（https 或 http）
//  4. 调用 RequestFromNetHttpRequert 转换为 wscan Request
func (rc *rawRequestCollector) parseRawRequest(data []byte) (*wscanhttp.Request, error) {
	hReq, err := stdhttp.ReadRequest(bufio.NewReader(bytes.NewReader(data)))
	if err != nil {
		return nil, fmt.Errorf("failed to parse raw HTTP request: %w", err)
	}

	// 确定 scheme
	scheme := "http"
	if rc.forceSSL {
		scheme = "https"
	}

	// 从 Host 头和请求 URI 重建完整 URL
	// net/http.ReadRequest 将 hReq.URL 设为仅包含 request-URI（路径部分），
	// 而 hReq.Host 设为 Host 头的值。需要手动重建完整 URL。
	host := hReq.Host
	if host == "" {
		host = "localhost"
		log.Warn("No Host header in raw request, falling back to localhost")
	}

	reqPath := hReq.URL.Path
	if reqPath == "" {
		reqPath = "/"
	}

	u := &url.URL{
		Scheme:   scheme,
		Host:     host,
		Path:     reqPath,
		RawQuery: hReq.URL.RawQuery,
		Fragment: hReq.URL.Fragment,
	}

	// 将重建的完整 URL 设置到 hReq.URL，以便 RequestFromNetHttpRequert 正确解析
	hReq.URL = u

	req, err := wscanhttp.RequestFromNetHttpRequert(hReq)
	if err != nil {
		return nil, fmt.Errorf("failed to convert request: %w", err)
	}

	return req, nil
}

// FitOut 实现 Fitter 接口，解析原始请求、发送请求并输出 Flow 资源。
func (rc *rawRequestCollector) FitOut(ctx context.Context, targets []string) (chan resource.Resource, error) {
	out := make(chan resource.Resource, 100)

	req, err := rc.parseRawRequest(rc.fileData)
	if err != nil {
		log.Errorf("Failed to parse raw request: %v", err)
		close(out)
		return out, err
	}

	go func() {
		defer close(out)

		// 设置自定义 headers（优先使用 Headers，兼容回退 DefaultHeaders）
		for key, values := range rc.opts.Headers {
			if len(values) > 0 {
				req.Header.Set(key, values[0])
			}
		}
		for key, value := range rc.opts.DefaultHeaders {
			if _, exists := req.Header[key]; !exists {
				req.Header.Set(key, value)
			}
		}

		// 发送请求
		resp, err := rc.client.Respond(ctx, req)
		if err != nil {
			log.Error(err)
			return
		}
		out <- &wscanhttp.Flow{Request: req, Response: resp}
	}()

	return out, nil
}

// NewFromRawRequestFile 创建一个 rawRequestCollector，从原始 HTTP 请求文件数据中解析请求。
func NewFromRawRequestFile(fileData []byte, forceSSL bool, opts *wscanhttp.ClientOptions) *rawRequestCollector {
	rc := &rawRequestCollector{}
	rc.client = wscanhttp.NewClientWithOptions(opts)
	rc.pool, _ = ants.NewPool(30)
	rc.opts = opts
	rc.fileData = fileData
	rc.forceSSL = forceSSL
	return rc
}
