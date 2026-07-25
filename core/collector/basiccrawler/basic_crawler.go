/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package basiccrawler

import (
	"context"

	"net/url"
	"time"
	"wscan/core/crawler"
	"wscan/core/http"
	"wscan/core/resource"
	"wscan/core/utils/checker"
	"wscan/core/utils/checker/filter"
	"wscan/core/utils/log"
)

type basicCrawlerCollector struct {
	targets []string
	config  *crawler.Config
	opts    *http.ClientOptions
}

// applyConfigHeaders 将配置中所有自定义 headers 设置到请求上
// 优先使用 Headers（由 WroteBack 从 DefaultHeaders 转换而来），兼容回退 DefaultHeaders
func applyConfigHeaders(req *http.Request, opts *http.ClientOptions) {
	if opts == nil {
		return
	}
	// 优先从 Headers 字段读取（WroteBack 已填充）
	for key, values := range opts.Headers {
		if len(values) > 0 {
			req.Header.Set(key, values[0])
		}
	}
	// 兼容：如果 WroteBack 未调用，从 DefaultHeaders 回退
	for key, value := range opts.DefaultHeaders {
		if _, exists := req.Header[key]; !exists {
			req.Header.Set(key, value)
		}
	}
}

func (b *basicCrawlerCollector) FitOut(ctx context.Context, targets []string) (chan resource.Resource, error) {
	b.targets = targets
	out := make(chan resource.Resource, 100)
	crawlerCount := 0
	go func() {
		defer func() {
			time.Sleep(10 * time.Second)
			if b.config.Browser {
				log.Infof("Browser Crawler %d", crawlerCount)
			} else {
				log.Infof("Basic Crawler %d", crawlerCount)
			}
			close(out)
		}()
		for _, target := range targets {
			if u, err := url.Parse(target); err == nil {
				b.config.Restrictions.HostnameAllowed = append(b.config.Restrictions.HostnameAllowed, u.Hostname())
			} else {
				log.Error(err.Error())
			}
		}
		requestChecker := checker.NewRequestChecker(b.config.Restrictions, &filter.SyncMapFilter{})
		if requestChecker == nil {
			log.Fatal("requestChecker is nil")
		}
		b.config.HTTPClientOptions = b.opts
		c := crawler.NewCrawler(*b.config, requestChecker.URLChecker)
		c.OnFlow(func(flow *http.Flow) bool {
			log.Infof(flow.Request.GetURL().String())
			crawlerCount += 1
			out <- flow
			return true
		})
		for _, target := range targets {
			if r, err := http.NewRequest("GET", target, nil); err == nil {
				applyConfigHeaders(r, b.opts)
				c.NewTask(r, 0)
			}
			baseURL, err := url.Parse(target)
			if err != nil {
				log.Errorf("invalid target URL: %v", err)
				continue
			}
			// 清除原有路径、查询参数、fragment，只保留 scheme 和 host
			baseURL.Path = ""
			baseURL.RawQuery = ""
			baseURL.Fragment = ""
			for _, file := range []string{
				"/robots.txt", "/sitemap.xml",
			} {
				if u := baseURL.JoinPath(file); u != nil {
					log.Infof("add file to crawl %s", u.String())
					if r, err := http.NewRequest("GET", u.String(), nil); err == nil {
						applyConfigHeaders(r, b.opts)
						c.NewTask(r, 0)
					}
				}
			}
		}
		c.Run()
		c.Wait()
	}()

	return out, nil
}

func NewBasicCrawlerCollector(opts *http.ClientOptions, config *crawler.Config) *basicCrawlerCollector {
	return &basicCrawlerCollector{
		opts:   opts,
		config: config,
	}
}
