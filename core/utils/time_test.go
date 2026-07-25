package utils

import (
	"testing"
	"time"
)

func TestTimeStampNano(t *testing.T) {
	result := TimeStampNano()
	// Should return a value between 0 and 999999999
	if result < 0 || result > 999999999 {
		t.Errorf("TimeStampNano() = %d, should be between 0 and 999999999", result)
	}
}

func TestTimeStampSecond(t *testing.T) {
	result := TimeStampSecond()
	now := time.Now().Unix()

	// The result should be close to the current time
	diff := now - result
	if diff < -1 || diff > 1 {
		t.Errorf("TimeStampSecond() = %d, current Unix = %d, diff = %d", result, now, diff)
	}
}
