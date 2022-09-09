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

func (*Statistics) Lock() {

}

func (*Statistics) Unlock() {

}

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

func (*Statistics) lockSlow() {

}

func (*Statistics) unlockSlow(int32) {

}

//func (*http.Statistics) AddResponseTime(int64)
//func (*http.Statistics) AverageResponseTime() int32
//func (*http.Statistics) Lock()
//func (*http.Statistics) Raw() map[string]interface {}
//func (*http.Statistics) Stat() *http.StatRepr
//func (*http.Statistics) TargetFound()
//func (*http.Statistics) TargetScanned()
//func (*http.Statistics) Unlock()
//func (*http.Statistics) calc()
//func (*http.Statistics) lockSlow()
//func (*http.Statistics) requestSent()
//func (*http.Statistics) respondFailed()
//func (*http.Statistics) respondSucceeded()
//func (*http.Statistics) unlockSlow(int32)

//File: statistics.go
//	(*Statistics)AddResponseTime Lines: 44 to 67 (23)
//	(*Statistics)requestSent Lines: 67 to 74 (7)
//	(*Statistics)respondFailed Lines: 74 to 80 (6)
//	(*Statistics)respondSucceeded Lines: 80 to 86 (6)
//	(*Statistics)TargetFound Lines: 86 to 92 (6)
//	(*Statistics)TargetScanned Lines: 92 to 98 (6)
//	(*Statistics)TargetScanned-fm Lines: 92 to 92 (0)
//	(*Statistics)calc Lines: 98 to 124 (26)
//	(*Statistics)AverageResponseTime Lines: 124 to 131 (7)
//	(*Statistics)Raw Lines: 131 to 142 (11)
//	(*Statistics)Stat Lines: 142 to 153 (11)
