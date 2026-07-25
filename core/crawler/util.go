/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package crawler

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/crypto/pkcs12"
	"golang.org/x/net/idna"
)

// AbsoluteURL returns an absolute URL based on the provided base URL and relative path.
func AbsoluteURL(base *url.URL, path string) *url.URL {
	absoluteURL := &url.URL{}
	*absoluteURL = *base
	absoluteURL.Path = path
	return absoluteURL
}

func ParsePKCS12(p12Data []byte, password string) (tls.Certificate, error) {
	privateKey, cert, err := pkcs12.Decode(p12Data, password)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("pkcs12: failed to decode: %w", err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  privateKey,
		Leaf:        cert,
	}
	return tlsCert, nil
}

// shouldCopyHeaderOnRedirect determines whether the given header should be copied on a redirect.
func shouldCopyHeaderOnRedirect(header string, value []string) bool {
	// The following headers should not be copied on redirects:
	switch header {
	case "Authorization", "Cookie":
		return false
	}
	// By default, all other headers are copied:
	return true
}

// canonicalAddr returns the canonical form of the network address addr.
func canonicalAddr(addr string) string {
	return (&net.TCPAddr{IP: net.ParseIP(addr)}).String()
}

// idnaASCII returns the ASCII form of the given domain name using IDNA (RFC 5891).
func idnaASCII(s string) (string, error) {
	return idna.ToASCII(s)
}

// getParentPaths returns a slice of all parent paths of the given path.
func getParentPaths(path string) []string {
	var result []string
	dir := path
	for {
		dir = filepath.Dir(dir)
		if dir == "/" || dir == "." {
			break
		}
		result = append(result, dir)
	}
	return result
}

// escapePercentSign 把url中的%替换为%25
func escapePercentSign(raw string) string {
	return strings.ReplaceAll(raw, "%", "%25")
}

// UrlParse 调用url.Parse，增加了对%的处理
func UrlParse(sourceUrl string) (*url.URL, error) {
	u, err := url.Parse(sourceUrl)
	if err != nil {
		u, err = url.Parse(escapePercentSign(sourceUrl))
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

func GetUrl(_url string, parentUrls ...url.URL) (*url.URL, error) {
	// 补充解析URL为完整格式
	var u url.URL
	_url, err := parse(_url, parentUrls...)
	if err != nil {
		return nil, err
	}

	if len(parentUrls) == 0 {
		_u, err := UrlParse(_url)
		if err != nil {
			return nil, err
		}
		u = *_u
		if u.Path == "" {
			u.Path = "/"
		}
	} else {
		pUrl := parentUrls[0]
		_u, err := pUrl.Parse(_url)
		if err != nil {
			return nil, err
		}
		u = *_u
		if u.Path == "" {
			u.Path = "/"
		}
		//fmt.Println(_url, pUrl.String(), u.String())
	}

	fixPath := regexp.MustCompile("^/{2,}")

	if fixPath.MatchString(u.Path) {
		u.Path = fixPath.ReplaceAllString(u.Path, "/")
	}

	return &u, nil
}

/*
*
修复不完整的URL
*/
func parse(_url string, parentUrls ...url.URL) (string, error) {
	_url = strings.Trim(_url, " ")

	if len(_url) == 0 {
		return "", errors.New("invalid url, length 0")
	}
	// 替换掉多余的#
	if strings.Count(_url, "#") > 1 {
		_url = regexp.MustCompile(`#+`).ReplaceAllString(_url, "#")
	}

	// 没有父链接，直接退出
	if len(parentUrls) == 0 {
		return _url, nil
	}

	if strings.HasPrefix(_url, "http://") || strings.HasPrefix(_url, "https://") {
		return _url, nil
	} else if strings.HasPrefix(_url, "javascript:") {
		return "", errors.New("invalid url, javascript protocol")
	} else if strings.HasPrefix(_url, "mailto:") {
		return "", errors.New("invalid url, mailto protocol")
	}
	return _url, nil
}

func NavigationUrl(u *url.URL) string {
	return fmt.Sprintf("://%s%s", u.Host, u.Path)
}

/*
*
文件扩展名
*/
func UrlFileName(u *url.URL) string {
	parts := strings.Split(u.Path, `/`)
	lastPart := parts[len(parts)-1]
	if strings.Contains(lastPart, ".") {
		return lastPart
	} else {
		return ""
	}
}

func UrlFileExt(u *url.URL) string {
	fileName := UrlFileName(u)
	if fileName == "" {
		return ""
	}
	parts := strings.Split(fileName, ".")
	return strings.ToLower(parts[len(parts)-1])
}
