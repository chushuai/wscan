/**
2 * @Author: shaochuyu
3 * @Date: 3/19/23
4 */

package crawler

import (
	"testing"
)

func TestNewCrawler(t *testing.T) {
	config := &Config{}
	crawler := NewCrawler(config, nil)
	crawler.Run()
	crawler.Wait()
	crawler.Stop()
}
