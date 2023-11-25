/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package collector

import (
	"bytes"
	"context"
	"github.com/panjf2000/ants/v2"
	"io"
	"io/ioutil"
	"time"
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
	postData, _ := ioutil.ReadAll(c.r)
	method := "GET"
	if len(postData) > 0 {
		method = "POST"
	}
	go func() {
		defer func() {
			time.Sleep(10 * time.Second)
			close(out)
		}()
		for _, target := range targets {
			req, _ := http.NewRequest(method, target, bytes.NewReader(postData))
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

func NewFromURLListReader(r io.ReadCloser, opts *http.ClientOptions) *urlListCollect {
	ulc := &urlListCollect{}
	ulc.client = http.NewClientWithOptions(opts)
	ulc.pool, _ = ants.NewPool(30)
	ulc.r = r
	return ulc
}

// http://testphp.vulnweb.com/listproducts.php/listproducts.php?cat=1%3CscRipt%3EWscan%28WSCAN_ALERT_VALUE%29%3C%2FscRipt%3E
// /listproducts.php?cat=1%3CscRipt%3EWscan%28WSCAN_ALERT_VALUE%29%3C%2FscRipt%3E
