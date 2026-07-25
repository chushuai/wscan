package checker

import (
	"testing"
	"wscan/core/http"
	"wscan/core/utils/checker/filter"
)

func TestRequestChecker(t *testing.T) {
	sf := filter.NewSyncMapFilter()
	rc := NewRequestChecker(&RequestCheckerConfig{}, sf)
	req, _ := http.NewRequest("GET", "http://www.baidu.com", nil)
	if rc.Target(req).IsAllowed().WithTTL(10).Bool() {

	}

	if rc.TargetStr("xxx").IsAllowed().IsNewWebsitePath().Bool() {

	}
}
