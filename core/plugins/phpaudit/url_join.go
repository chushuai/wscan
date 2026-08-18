/**
* @Author: shaochuyu
* @Date: 2026-07-28
*
* url_join.go is a thin local wrapper around utils.UrlJoinPath so phpaudit.go
* can call joinBase() without a direct utils import in the main file. Kept in a
* separate file so the example plugin's detection logic stays the focus.
 */
package phpaudit

import "wscan/core/utils"

func urlJoinPath(baseURL, relativePath string) string {
	return utils.UrlJoinPath(baseURL, relativePath)
}
