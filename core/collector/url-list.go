/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package collector

import (
	"bytes"
	"context"
	"io"
	"time"
	"wscan/core/http"
	"wscan/core/resource"
	"wscan/core/utils/log"

	"github.com/panjf2000/ants/v2"
)

type urlListCollector struct {
	client *http.Client
	opts   *http.ClientOptions
	r      io.ReadCloser
	pool   *ants.Pool
}

func (c *urlListCollector) FitOut(ctx context.Context, targets []string) (chan resource.Resource, error) {
	out := make(chan resource.Resource, 100)
	postData, _ := io.ReadAll(c.r)
	method := "GET"
	if len(postData) > 0 {
		method = "POST"
	}
	// application/x-www-form-urlencoded
	go func() {
		defer func() {
			time.Sleep(10 * time.Second)
			close(out)
		}()
		for _, target := range targets {
			req, err := http.NewRequest(method, target, nil)
			if err != nil {
				log.Error(err)
				continue
			}
			// 将配置中的自定义 headers 设置到请求上
			// 优先使用 Headers（由 WroteBack 从 DefaultHeaders 转换而来），兼容回退 DefaultHeaders
			for key, values := range c.opts.Headers {
				if len(values) > 0 {
					req.Header.Set(key, values[0])
				}
			}
			for key, value := range c.opts.DefaultHeaders {
				if _, exists := req.Header[key]; !exists {
					req.Header.Set(key, value)
				}
			}
			if len(postData) > 0 {
				req = req.WithFormBody(bytes.NewReader(postData))
			}
			resp, err := c.client.Respond(ctx, req)
			if err != nil {
				log.Error(err)
				continue
			}
			out <- &http.Flow{Request: req, Response: resp}
		}
	}()
	return out, nil
}

func NewFromURLListReader(r io.ReadCloser, opts *http.ClientOptions) *urlListCollector {
	ulc := &urlListCollector{}
	ulc.client = http.NewClientWithOptions(opts)
	ulc.pool, _ = ants.NewPool(30)
	ulc.r = r
	ulc.opts = opts
	return ulc
}
