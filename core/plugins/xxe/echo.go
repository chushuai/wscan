/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package xxe

import (
	"regexp"
)

var (
	// etcPasswdRegex matches /etc/passwd content patterns like "root:x:0:0:"
	etcPasswdRegex = regexp.MustCompile(`root:[x*]:\d+:\d+:`)
	// etcShadowRegex matches /etc/shadow content patterns
	etcShadowRegex = regexp.MustCompile(`root:\$6\$|root:\$5\$|root:\$1\$`)
	// linuxUserInfo matches id command output like "uid=0(root) gid=0("
	linuxUserInfo = regexp.MustCompile(`uid=\d+\(.*\) gid=\d+\(`)
	// windowsDirRegex matches Windows dir command output
	windowsDirRegex = regexp.MustCompile(`Volume in drive [A-Za-z]`)
)

// CheckXXEEcho checks if the response body contains XXE echo content
// This is used for in-band XXE detection where the server reflects
// the content of the requested file in the response
func CheckXXEEcho(body string) bool {
	return etcPasswdRegex.MatchString(body) ||
		etcShadowRegex.MatchString(body) ||
		linuxUserInfo.MatchString(body) ||
		windowsDirRegex.MatchString(body)
}
