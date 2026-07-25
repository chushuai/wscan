/**
2 * @Author: shaochuyu
3 * @Date: 1/6/23
4 */

package http

import (
	"net/http"
	"net/url"
)

func cloneURLValues(v url.Values) url.Values {
	if v == nil {
		return nil
	}
	return url.Values(http.Header(v).Clone())
}

func cloneURL(u *url.URL) *url.URL {
	if u == nil {
		return nil
	}
	u2 := new(url.URL)
	*u2 = *u
	if u.User != nil {
		u2.User = new(url.Userinfo)
		*u2.User = *u.User
	}
	return u2
}

func cloneHeader(h map[string][]string) map[string][]string {
	nv := 0
	for _, vv := range h {
		nv += len(vv)
	}
	h2 := make(map[string][]string, len(h))
	for k, vv := range h {
		for _, vvv := range vv {
			h2[k] = append(h2[k], vvv)
		}
	}
	return h2
}
