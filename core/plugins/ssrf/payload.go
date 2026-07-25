/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package ssrf

import "regexp"

type Payload struct {
	description string
	host        string
	regex       *regexp.Regexp
}
