package collector

import (
	"context"
	"wscan/core/resource"
)

type dummyCollector struct {
	from chan resource.Resource
}

func (*dummyCollector) FitOut(context.Context, []string) (chan resource.Resource, error) {
	return nil, nil
}
