/**
* @Author: shaochuyu
* @Date: 3/19/23
 */
package crawler

import (
	"testing"
)

// newTestCrawler creates a minimal Crawler for unit tests (no browser, no
// network). Several sibling test files rely on this helper.
func newTestCrawler() *Crawler {
	config := Config{
		MaxConcurrent:  2,
		MaxDepth:       3,
		MaxCountOfURLs: 100,
	}
	corrected, _ := config.Correct()
	return NewCrawler(*corrected, nil)
}

func TestNewCrawler(t *testing.T) {
	config := &Config{}
	corrected, err := config.Correct()
	if err != nil {
		t.Fatalf("Correct failed: %v", err)
	}
	crawler := NewCrawler(*corrected, nil)
	crawler.Run()
	crawler.Wait()
	crawler.Stop()
}
