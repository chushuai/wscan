/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package filter

type Filter interface {
	Close() error
	Insert(string, int64)
	IsInserted(string, bool, int64) bool
	Reset() error
}
