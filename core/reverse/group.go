/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package reverse

import (
	"sync"
	"time"
)

type Unit struct {
	sync.Mutex
	reverse  *Reverse
	id       string
	group    *UnitGroup
	Callback func(*Event) error
	Data     interface {
	}
}

type UnitGroup struct {
	id             string
	units          sync.Map
	callbackCalled int32
	expireAt       time.Time
}
