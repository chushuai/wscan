/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package http

import (
	"sync"
	"time"
)

type responseTime struct {
	count int64
	time  int64
}

type Statistics struct {
	sync.Mutex
	foundNumber             int64
	scannedNumber           int64
	requestNumber           int64
	succeededResponseNumber int64
	failedResponseNumber    int64
	responseTimeHistory     map[int64]*responseTime
	averageTimeWindow       int64
	ratioFailedHTTPRequests float32
	averageResponseTime     float32
	lastCommitTime          int64
}

func (s *Statistics) AddResponseTime(time int64) {
	s.Lock()
	defer s.Unlock()

	rt := s.responseTimeHistory[time]
	if rt == nil {
		rt = &responseTime{int64(0), time}
		s.responseTimeHistory[time] = rt
	}
	rt.count++
}

func (s *Statistics) requestSent() {
	s.Lock()
	s.requestNumber++
	s.Unlock()
}

func (s *Statistics) respondFailed() {
	s.Lock()
	s.failedResponseNumber++
	s.Unlock()
}

func (s *Statistics) respondSucceeded() {
	s.Lock()
	s.succeededResponseNumber++
	s.Unlock()
}

func (s *Statistics) TargetFound() {
	s.Lock()
	s.foundNumber++
	s.Unlock()
}

func (s *Statistics) TargetScanned() {
	s.Lock()
	s.scannedNumber++
	s.Unlock()
}

func (s *Statistics) calc() {
	s.Lock()
	defer s.Unlock()

	totalTime := int64(0)
	totalCount := int64(0)
	for _, rt := range s.responseTimeHistory {
		totalTime += rt.time * rt.count
		totalCount += rt.count
	}

	if s.requestNumber > 0 {
		s.ratioFailedHTTPRequests = float32(s.failedResponseNumber) / float32(s.requestNumber)
	}

	if totalCount > 0 {
		s.averageResponseTime = float32(totalTime) / float32(totalCount)
	}

	s.lastCommitTime = time.Now().Unix()
}

func (s *Statistics) AverageResponseTime() int32 {
	s.calc()
	return int32(s.averageResponseTime)
}

func (s *Statistics) Raw() map[string]any {
	s.calc()
	return map[string]any{
		"foundNumber":             s.foundNumber,
		"scannedNumber":           s.scannedNumber,
		"requestNumber":           s.requestNumber,
		"succeededResponseNumber": s.succeededResponseNumber,
		"failedResponseNumber":    s.failedResponseNumber,
		"responseTimeHistory":     s.responseTimeHistory,
		"averageTimeWindow":       s.averageTimeWindow,
		"ratioFailedHTTPRequests": s.ratioFailedHTTPRequests,
		"averageResponseTime":     s.averageResponseTime,
		"lastCommitTime":          s.lastCommitTime,
	}
}

func (s *Statistics) Stat() *StatRepr {
	s.calc()
	return &StatRepr{
		FoundNumber:             s.foundNumber,
		ScannedNumber:           s.scannedNumber,
		RequestNumber:           s.requestNumber,
		RatioFailedHTTPRequests: s.ratioFailedHTTPRequests,
		AverageResponseTime:     s.averageResponseTime,
	}
}
