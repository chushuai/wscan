/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package collector

import (
	"context"
	"wscan/core/assassin/http"
	"wscan/core/assassin/resource"
)

type reqCollect struct {
	client *http.Client
	req    *http.Request
}

func (*reqCollect) FitOut(context.Context, []string) (chan resource.Resource, error) {
	return nil, nil
}
