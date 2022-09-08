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

type burpFlow struct {
	Url      string  `xml:"url"`
	Protocol string  `xml:"protocol"`
	Host     string  `xml:"host"`
	Port     string  `xml:"port"`
	Request  []uint8 `xml:"request"`
	Status   int     `xml:"status"`
}

type burpCollector struct {
	client *http.Client
	r      io.ReadCloser
	pool   *ants.Pool
}

func NewFromBurpFile() {

}

func (*burpCollector) FitOut(context.Context, []string) (chan resource.Resource, error) {
	return nil, nil
}
