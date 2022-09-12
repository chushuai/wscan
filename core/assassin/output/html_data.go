/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package output

import (
	"sync"
)

type _escFile struct {
	compressed string
	size       int64
	modtime    int64
	local      string
	isDir      bool
	once       sync.Once
	data       []uint8
	name       string
}
