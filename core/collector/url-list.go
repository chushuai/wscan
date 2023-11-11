/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package collector

import (
	"context"
	"github.com/panjf2000/ants/v2"
	"io"
	"wscan/core/http"
	"wscan/core/resource"
	"wscan/core/utils/log"
)

type urlListCollect struct {
	client *http.Client
	r      io.ReadCloser
	pool   *ants.Pool
}

func (c *urlListCollect) FitOut(ctx context.Context, targets []string) (chan resource.Resource, error) {
	out := make(chan resource.Resource, 100)

	go func() {
		for _, target := range targets {
			req, _ := http.RequestFromRawURL(target)
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

func NewBasicCrawlerCollector(opts *http.ClientOptions) *urlListCollect {
	ulc := &urlListCollect{}
	ulc.client = http.NewClientWithOptions(opts)
	ulc.pool, _ = ants.NewPool(30)
	return ulc
}
