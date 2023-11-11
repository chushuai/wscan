/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package utils

import "net/url"

type Reverse interface {
	GetDomain() (string, error)
	GetIP() (string, error)
	GetURL() (*url.URL, error)
	Wait(int64) error
}
