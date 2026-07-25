/*
*
2 * @Author: shaochuyu
3 * @Date: 12/7/22
4
*/
package http

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"wscan/core/utils"

	"golang.org/x/net/publicsuffix"
)

type URL struct {
	url.URL
}

func (u *URL) RawUrl() *url.URL {
	return &u.URL
}

func GetUrl(_url string, parentUrls ...URL) (*URL, error) {
	// 补充解析URL为完整格式
	var u URL
	_url, err := u.parse(_url, parentUrls...)
	if err != nil {
		return nil, err
	}

	if len(parentUrls) == 0 {
		_u, err := UrlParse(_url)
		if err != nil {
			return nil, err
		}
		u = URL{*_u}
		if u.Path == "" {
			u.Path = "/"
		}
	} else {
		pUrl := parentUrls[0]
		_u, err := pUrl.Parse(_url)
		if err != nil {
			return nil, err
		}
		u = URL{*_u}
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
func (u *URL) parse(_url string, parentUrls ...URL) (string, error) {
	_url = strings.Trim(_url, " ")

	if len(_url) == 0 {
		return "", errors.New("invalid url, length 0")
	}
	// 替换掉多余的#
	if strings.Count(_url, "#") > 1 {
		_url = regexp.MustCompile(`#+`).ReplaceAllString(_url, "#")
	}

	if strings.HasPrefix(_url, "javascript:") {
		return "", errors.New("invalid url, javascript protocol")
	} else if strings.HasPrefix(_url, "mailto:") {
		return "", errors.New("invalid url, mailto protocol")
	}

	// 没有父链接，直接退出
	if len(parentUrls) == 0 {
		return _url, nil
	}

	if strings.HasPrefix(_url, "http://") || strings.HasPrefix(_url, "https://") {
		return _url, nil
	}
	return _url, nil
}

func (u *URL) QueryMap() map[string]any {
	queryMap := map[string]any{}
	for key, value := range u.Query() {
		if len(value) == 1 {
			queryMap[key] = value[0]
		} else {
			queryMap[key] = value
		}
	}
	return queryMap
}

func (u *URL) QueryMapID(dataMap map[string]any) string {
	var keys []string
	var idStr string
	for key := range dataMap {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		idStr += key
	}
	return utils.MD5(idStr)
}

/*
*
返回去掉请求参数的URL
*/
func (u *URL) NoQueryUrl() string {
	return fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, u.Path)
}

func (u *URL) BaseURL() string {
	return fmt.Sprintf("%s://%s", u.Scheme, u.Host)
}

/*
*
返回不带Fragment的URL
*/
func (u *URL) NoFragmentUrl() string {
	return strings.Replace(u.String(), u.Fragment, "", -1)
}

func (u *URL) NoSchemeFragmentUrl() string {
	return fmt.Sprintf("://%s%s", u.Host, u.Path)
}

func (u *URL) NavigationUrl() string {
	return u.NoSchemeFragmentUrl()
}

/*
*
返回根域名

如 a.b.c.360.cn 返回 360.cn
*/
func (u *URL) RootDomain() string {
	domain := u.Hostname()
	suffix, icann := publicsuffix.PublicSuffix(strings.ToLower(domain))
	// 如果不是 icann 的域名，返回空字符串
	if !icann {
		return ""
	}
	i := len(domain) - len(suffix) - 1
	// 如果域名错误
	if i <= 0 {
		return ""
	}
	if domain[i] != '.' {
		return ""
	}
	return domain[1+strings.LastIndex(domain[:i], "."):]
}

/*
*
文件扩展名
*/
func (u *URL) FileName() string {
	parts := strings.Split(u.Path, `/`)
	lastPart := parts[len(parts)-1]
	if strings.Contains(lastPart, ".") {
		return lastPart
	} else {
		return ""
	}
}

/*
*
文件扩展名
*/
func (u *URL) FileExt() string {
	fileName := u.FileName()
	if fileName == "" {
		return ""
	}
	parts := strings.Split(fileName, ".")
	return strings.ToLower(parts[len(parts)-1])
}

/*
*
回去上一级path, 如果当前就是root path，则返回空字符串
*/
func (u *URL) ParentPath() string {
	if u.Path == "/" {
		return ""
	} else if strings.HasSuffix(u.Path, "/") {
		if strings.Count(u.Path, "/") == 2 {
			return "/"
		}
		parts := strings.Split(u.Path, "/")
		parts = parts[:len(parts)-2]
		return strings.Join(parts, "/")
	} else {
		if strings.Count(u.Path, "/") == 1 {
			return "/"
		}
		parts := strings.Split(u.Path, "/")
		parts = parts[:len(parts)-1]
		return strings.Join(parts, "/")
	}
}

func (u *URL) String() string {
	return u.URL.String()
}

func (u *URL) MarshalJSON() ([]byte, error) {
	return json.Marshal(u.URL.String())
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

func (u *URL) IsWebsiteDir() bool {
	// 如果路径部分为空，则该URL为WebsiteDir
	if u.Path == "" {
		return true
	}

	// 如果路径部分以 "/" 结尾，则该URL为WebsiteDir
	return strings.HasSuffix(u.Path, "/")
}

var StaticSuffix = []string{
	"png", "gif", "jpg", "mp4", "mp3", "mng", "pct", "bmp", "jpeg", "pst", "psp", "ttf",
	"tif", "tiff", "ai", "drw", "wma", "ogg", "wav", "ra", "aac", "mid", "au", "aiff",
	"dxf", "eps", "ps", "svg", "3gp", "asf", "asx", "avi", "mov", "mpg", "qt", "rm",
	"wmv", "m4a", "bin", "xls", "xlsx", "ppt", "pptx", "doc", "docx", "odt", "ods", "odg",
	"odp", "exe", "zip", "rar", "tar", "gz", "iso", "rss", "pdf", "txt", "dll", "ico",
	"gz2", "apk", "crt", "woff", "map", "woff2", "webp", "less", "dmg", "bz2", "otf", "swf",
	"flv", "mpeg", "dat", "xsl", "csv", "cab", "exif", "wps", "m4v", "rmvb",
}

var DBFileSuffix = []string{
	"sql", "db", "sqlite", "accdb", "mdb",
}

func (u *URL) IsStaticResource() bool {
	ext := filepath.Ext(u.URL.Path)
	if len(ext) > 1 {
		for _, suffix := range StaticSuffix {
			if suffix == ext[1:] {
				return true
			}
		}
	}
	return false
}

func (u *URL) IsDBFile() bool {
	ext := filepath.Ext(u.URL.Path)
	if len(ext) > 1 {
		for _, suffix := range DBFileSuffix {
			if suffix == ext[1:] {
				return true
			}
		}
	}
	return false
}

// escapePercentSign 把url中的%替换为%25
func escapePercentSign(raw string) string {
	return strings.ReplaceAll(raw, "%", "%25")
}

func (u *URL) cloneURL() *URL {
	if u == nil {
		return nil
	}
	u2 := new(url.URL)
	*u2 = u.URL
	if u.User != nil {
		u2.User = new(url.Userinfo)
		*u2.User = *u.User
	}
	return &URL{URL: *u2}
}

func GetURLPort(rawurl string) (int, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return 0, err
	}
	if u.Port() != "" {
		port, err := strconv.Atoi(u.Port())
		if err != nil {
			return 0, err
		}
		return port, nil
	}
	switch u.Scheme {
	case "http":
		return 80, nil
	case "https":
		return 443, nil
	default:
		return 0, fmt.Errorf("unsupported URL scheme: %s", u.Scheme)
	}
}

func UrlSplitHostPort(rawurl string) (string, int, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return "", 0, err
	}
	host := u.Hostname()
	port := 0
	if u.Port() != "" {
		port, err = strconv.Atoi(u.Port())
		if err != nil {
			return "", 0, err
		}
	}
	if port == 0 {
		switch u.Scheme {
		case "http":
			port = 80
		case "https":
			port = 443
		default:
			return "", 0, fmt.Errorf("unsupported URL scheme: %s", u.Scheme)
		}
	}
	if host == "" || port == 0 {
		return "", 0, errors.New("host or port = 0")
	}
	return u.Hostname(), port, nil
}

func GetURLDepth(urlStr string) int {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return -1 // 解析失败，返回错误深度
	}
	path := parsedURL.Path
	depth := strings.Count(path, "/") - 1
	// 处理根路径的情况（末尾带斜杠）
	if path == "" {
		depth = 0
	}

	return depth
}

func UrlJoinPath(baseUrl, relativePath string) string {
	if strings.HasSuffix(baseUrl, "/") {
		baseUrl = baseUrl[:len(baseUrl)-1]
	}
	if strings.HasPrefix(relativePath, "/") {
		relativePath = relativePath[1:]
	}
	return baseUrl + "/" + relativePath
}
