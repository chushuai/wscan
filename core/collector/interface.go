/**
2 * @Author: shaochuyu
3 * @Date: 4/6/23
4 */

package collector

import (
	"context"
	"wscan/core/resource"
)

type Fitter interface {
	FitOut(context.Context, []string) (chan resource.Resource, error)
}
