package client

import (
	"fmt"
	"net/http"
)

type ScanEvent struct {
	Request     *http.Request
	Response    *RespMetrics
	PocMatched  string
	RuleMatched string
}

func (s *ScanEvent) String() string {
	return fmt.Sprintf("[%s] scanned %s", s.Request.RemoteAddr, s.PocMatched)
}

type ScanEventHandleFunc func(e *ScanEvent)

// OnRuleMatch will be called if there is a poc rule matched
// for example, if a poc has there rules, OnRuleMatch will be called there times,
// meanwhile OnPocMatch will only be called once.
func (h *RegexpHandler) OnRuleMatch(fn ScanEventHandleFunc) {
	h.onRuleMatches = append(h.onRuleMatches, fn)
}

// OnPocMatch will be called only if the last rule of poc get matched
// see details at OnRuleMatch
func (h *RegexpHandler) OnPocMatch(fn ScanEventHandleFunc) {
	h.onPocMatches = append(h.onPocMatches, fn)
}
