package http

import (
	"testing"
)

func newTestStatistics() *Statistics {
	return &Statistics{
		responseTimeHistory: make(map[int64]*responseTime),
	}
}

func TestStatistics_AddResponseTime(t *testing.T) {
	s := newTestStatistics()
	s.AddResponseTime(100)
	s.AddResponseTime(200)
	s.AddResponseTime(100) // duplicate

	if len(s.responseTimeHistory) != 2 {
		t.Errorf("expected 2 response time entries, got %d", len(s.responseTimeHistory))
	}

	if s.responseTimeHistory[100].count != 2 {
		t.Errorf("expected count 2 for time 100, got %d", s.responseTimeHistory[100].count)
	}
}

func TestStatistics_requestSent(t *testing.T) {
	s := newTestStatistics()
	s.requestSent()
	s.requestSent()
	s.requestSent()

	if s.requestNumber != 3 {
		t.Errorf("expected requestNumber 3, got %d", s.requestNumber)
	}
}

func TestStatistics_respondFailed(t *testing.T) {
	s := newTestStatistics()
	s.respondFailed()
	s.respondFailed()

	if s.failedResponseNumber != 2 {
		t.Errorf("expected failedResponseNumber 2, got %d", s.failedResponseNumber)
	}
}

func TestStatistics_respondSucceeded(t *testing.T) {
	s := newTestStatistics()
	s.respondSucceeded()
	s.respondSucceeded()
	s.respondSucceeded()

	if s.succeededResponseNumber != 3 {
		t.Errorf("expected succeededResponseNumber 3, got %d", s.succeededResponseNumber)
	}
}

func TestStatistics_TargetFound(t *testing.T) {
	s := newTestStatistics()
	s.TargetFound()
	s.TargetFound()

	if s.foundNumber != 2 {
		t.Errorf("expected foundNumber 2, got %d", s.foundNumber)
	}
}

func TestStatistics_TargetScanned(t *testing.T) {
	s := newTestStatistics()
	s.TargetScanned()
	s.TargetScanned()
	s.TargetScanned()

	if s.scannedNumber != 3 {
		t.Errorf("expected scannedNumber 3, got %d", s.scannedNumber)
	}
}

func TestStatistics_AverageResponseTime(t *testing.T) {
	s := newTestStatistics()
	s.AddResponseTime(100)
	s.AddResponseTime(200)

	avg := s.AverageResponseTime()
	if avg <= 0 {
		t.Errorf("expected positive average response time, got %d", avg)
	}
}

func TestStatistics_AverageResponseTime_NoData(t *testing.T) {
	s := newTestStatistics()
	avg := s.AverageResponseTime()
	if avg != 0 {
		t.Errorf("expected 0 average response time with no data, got %d", avg)
	}
}

func TestStatistics_Raw(t *testing.T) {
	s := newTestStatistics()
	s.requestSent()
	s.respondSucceeded()
	s.respondFailed()
	s.TargetFound()
	s.TargetScanned()
	s.AddResponseTime(50)

	raw := s.Raw()

	if raw["requestNumber"].(int64) != 1 {
		t.Errorf("expected requestNumber 1, got %d", raw["requestNumber"])
	}
	if raw["succeededResponseNumber"].(int64) != 1 {
		t.Errorf("expected succeededResponseNumber 1, got %d", raw["succeededResponseNumber"])
	}
	if raw["failedResponseNumber"].(int64) != 1 {
		t.Errorf("expected failedResponseNumber 1, got %d", raw["failedResponseNumber"])
	}
	if raw["foundNumber"].(int64) != 1 {
		t.Errorf("expected foundNumber 1, got %d", raw["foundNumber"])
	}
	if raw["scannedNumber"].(int64) != 1 {
		t.Errorf("expected scannedNumber 1, got %d", raw["scannedNumber"])
	}
}

func TestStatistics_Stat(t *testing.T) {
	s := newTestStatistics()
	s.requestSent()
	s.respondSucceeded()
	s.respondFailed()
	s.TargetFound()
	s.TargetScanned()
	s.AddResponseTime(100)

	stat := s.Stat()

	if stat.RequestNumber != 1 {
		t.Errorf("expected RequestNumber 1, got %d", stat.RequestNumber)
	}
	if stat.FoundNumber != 1 {
		t.Errorf("expected FoundNumber 1, got %d", stat.FoundNumber)
	}
	if stat.ScannedNumber != 1 {
		t.Errorf("expected ScannedNumber 1, got %d", stat.ScannedNumber)
	}
	// ratioFailedHTTPRequests should be 1/1 = 1.0
	if stat.RatioFailedHTTPRequests != 1.0 {
		t.Errorf("expected RatioFailedHTTPRequests 1.0, got %f", stat.RatioFailedHTTPRequests)
	}
}

func TestStatistics_RatioFailedHTTPRequests(t *testing.T) {
	s := newTestStatistics()
	s.requestSent()
	s.requestSent()
	s.requestSent()
	s.respondFailed()

	stat := s.Stat()
	// 1 failed out of 3 requests = 0.333...
	if stat.RatioFailedHTTPRequests < 0.3 || stat.RatioFailedHTTPRequests > 0.4 {
		t.Errorf("expected RatioFailedHTTPRequests ~0.333, got %f", stat.RatioFailedHTTPRequests)
	}
}

func TestStatistics_Raw_HasAllFields(t *testing.T) {
	s := newTestStatistics()
	raw := s.Raw()

	expectedFields := []string{
		"foundNumber",
		"scannedNumber",
		"requestNumber",
		"succeededResponseNumber",
		"failedResponseNumber",
		"responseTimeHistory",
		"averageTimeWindow",
		"ratioFailedHTTPRequests",
		"averageResponseTime",
		"lastCommitTime",
	}

	for _, field := range expectedFields {
		if _, ok := raw[field]; !ok {
			t.Errorf("Raw() missing field %q", field)
		}
	}
}
