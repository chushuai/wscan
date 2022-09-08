/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package http

import (
	"net/http/cookiejar"
	"sync"
	"time"
)

type Cookie struct {
	Name       string
	Value      string
	Path       string
	Domain     string
	Expires    time.Time
	RawExpires string
	MaxAge     int
	Secure     bool
	HttpOnly   bool
	SameSite   int
	Raw        string
	Unparsed   []string
}

type CookieJar struct {
	sync.Mutex
	presetCookies map[string]string
	*cookiejar.Jar
}

func (CookieJar) cookies() {

}

func (CookieJar) domainAndType() {

}

func (CookieJar) newEntry() {

}

func (CookieJar) setCookies() {

}
