/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package utils

import "time"

func TimeStampNano() int {
	return time.Now().Nanosecond()
}

func TimeStampSecond() int64 {
	// Get the current time in Unix time (seconds since January 1, 1970 UTC)
	now := time.Now().Unix()

	// Return the current time in Unix time
	return now
}

func DatetimePretty() {
	v1 := time.Now()
	v1.Format("------")
}
