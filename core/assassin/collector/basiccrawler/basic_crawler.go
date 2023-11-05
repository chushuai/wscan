/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package basiccrawler

import (
	"context"
	"net/http"
	vhttp "wscan/core/assassin/http"
	"wscan/core/assassin/resource"
	"wscan/core/utils/checker"
	"wscan/core/utils/checker/filter"
	"wscan/core/utils/log"
	"wscan/ext/crawler"
)

type basicCrawlerCollector struct {
	targets []string
	config  *crawler.Config
	opts    *vhttp.ClientOptions
}

func (b *basicCrawlerCollector) FitOut(ctx context.Context, targets []string) (chan resource.Resource, error) {
	b.targets = targets
	out := make(chan resource.Resource, 100)
	go func() {
		defer close(out)
		requestChecker := checker.NewRequestChecker(b.config.Restrictions, &filter.SyncMapFilter{})
		if requestChecker == nil {
			log.Fatal("requestChecker is nil")
		}
		c := crawler.NewCrawler(b.config, requestChecker.URLChecker)
		c.OnResponse(func(response *http.Response) bool {
			log.Infof(response.Request.URL.String())
			out <- &vhttp.Flow{}
			return true
		})
		for _, target := range targets {
			if r, err := http.NewRequest("GET", target, nil); err == nil {
				c.NewTask(r, 0)
			}
		}
		c.Run()
		c.Wait()
	}()

	return out, nil
}

func NewBasicCrawlerCollector(opts *vhttp.ClientOptions, config *crawler.Config) *basicCrawlerCollector {
	return &basicCrawlerCollector{
		opts:   opts,
		config: config,
	}
}
