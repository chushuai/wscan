/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package http

import "sync"

type compiledProxyRule struct {
	sync.Mutex
	match   glob.Glob
	servers weighted.RRW
}

type flowDispatcher struct {
	callbacks []func(*Flow)
}

//File: resource.go
//	(*Request)Timestamp Lines: 14 to 17 (3)
//	(*Request)DeepClone Lines: 17 to 20 (3)
//	(*Request)String Lines: 20 to 25 (5)
//	(*Flow)Name Lines: 25 to 28 (3)
//	(*Flow)DeepClone Lines: 28 to 36 (8)
//	(*Flow)Type Lines: 36 to 40 (4)
//	(*Flow)Timestamp Lines: 40 to 43 (3)
//	(*Flow)String Lines: 43 to 44 (1)
