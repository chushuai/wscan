/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package basiccrawler

import (
	"context"
	"wscan/core/assassin/http"
	"wscan/core/assassin/resource"
	"wscan/ext/crawler"
)

type basicCrawlerCollector struct {
	targets []string
	config  *crawler.Config
	opts    *http.ClientOptions
}

func (*basicCrawlerCollector) FitOut(context.Context, []string) (chan resource.Resource, error) {
	return nil, nil
}
