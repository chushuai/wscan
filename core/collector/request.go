/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package collector

import (
	"context"
	"wscan/core/http"
	"wscan/core/resource"
	"wscan/core/utils/log"
)

type reqCollect struct {
	client *http.Client
	req    *http.Request
}

func (c *reqCollect) FitOut(ctx context.Context, targets []string) (chan resource.Resource, error) {
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
