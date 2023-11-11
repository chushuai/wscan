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
)

type burpFlow struct {
	Url      string `xml:"url"`
	Protocol string `xml:"protocol"`
	Host     string `xml:"host"`
	Port     string `xml:"port"`
	Request  []byte `xml:"request"`
	Status   int    `xml:"status"`
}

type burpCollector struct {
	client *http.Client
	r      io.ReadCloser
	pool   *ants.Pool
}

func (*burpCollector) FitOut(context.Context, []string) (chan resource.Resource, error) {
	return nil, nil
}

func NewFromBurpFile(opts *http.ClientOptions) *burpCollector {
	bc := &burpCollector{}
	bc.client = http.NewClientWithOptions(opts)
	bc.pool, _ = ants.NewPool(30)
	return bc
}
