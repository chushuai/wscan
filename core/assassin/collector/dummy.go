/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package collector

import (
	"context"
	"go.opencensus.io/resource"
)

type dummyCollector struct {
	from chan resource.Resource
}

func (*dummyCollector) FitOut(context.Context, []string) (chan resource.Resource, error) {
	return nil, nil
}
