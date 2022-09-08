/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package collector

import (
	"context"
	"github.com/panjf2000/ants/v2"
	"io"
	"wscan/core/assassin/http"
	"wscan/core/assassin/resource"
)

type urlListCollect struct {
	client *http.Client
	r      io.ReadCloser
	pool   *ants.Pool
}

func (*urlListCollect) FitOut(context.Context, []string) (chan resource.Resource, error) {
	return nil, nil
}
