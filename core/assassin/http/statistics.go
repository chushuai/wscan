/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package http

import "sync"

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

//func (*Statistics) Lock() {
//
//}
//
//func (*Statistics) Unlock() {
//
//}

func (*Statistics) AddResponseTime(int64) {

}

func (*Statistics) requestSent() {

}

func (*Statistics) respondFailed() {

}

func (*Statistics) respondSucceeded() {

}

func (*Statistics) TargetFound() {

}

func (*Statistics) TargetScanned() {

}
func (*Statistics) calc() {

}

func (*Statistics) AverageResponseTime() int32 {
	return 0
}

func (*Statistics) Raw() map[string]interface{} {
	return nil
}

func (*Statistics) Stat() *StatRepr {
	return nil
}

//func (*Statistics) lockSlow() {
//
//}
//
//func (*Statistics) unlockSlow(int32) {
//
//}
