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

func (b *basicCrawlerCollector) FitOut(ctx context.Context, targets []string) (chan resource.Resource, error) {
	out := make(chan resource.Resource, 100)
	c := crawler.NewCrawler(b.config, nil)
	http.NewClientWithOptions(b.opts)
	c.OnRequestNotVisit(func(request *http.Request, err error) {
	})

	c.OnResponse(func(response *http.Response) bool {
		out <- nil
	})

	http.IsNeededResource()
	c.Run()
	c.Feed()
	c.Wait()
	return out, nil
}

func init() {
}

func NewBasicCrawlerCollector() *basicCrawlerCollector {
	return &basicCrawlerCollector{}
}
