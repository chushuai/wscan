/**
2 * @Author: shaochuyu
3 * @Date: 4/25/24
4 */

package utils

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
)

func CalcMd5(items ...any) string {
	e := fmt.Sprintf("%v", items)
	md5Raw := md5.Sum([]byte(e))
	return hex.EncodeToString(md5Raw[:])
}

func CalcSha1(items ...any) string {
	s := fmt.Sprintf("%v", items)
	raw := sha1.Sum([]byte(s))
	return hex.EncodeToString(raw[:])
}
