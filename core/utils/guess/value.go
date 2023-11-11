/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package guess

import "net/url"

func IsFullURL(str string) bool {
	u, err := url.Parse(str)
	if err != nil {
		return false
	}
	return u.Scheme != "" && u.Host != ""
}

func IsURLPath(str string) bool {
	u, err := url.Parse(str)
	if err != nil {
		return false
	}
	return u.Scheme == "" && u.Host == "" && u.Path != ""
}
