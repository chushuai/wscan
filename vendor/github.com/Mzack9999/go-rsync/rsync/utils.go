package rsync

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

func SplitURIS(uri string) (string, int, string, string, error) {
	var host, module, path string
	first := uri
	var second string

	if strings.HasPrefix(uri, "rsync://") {
		/* rsync://host[:port]/module[/path] */
		first = first[8:]
		i := strings.IndexByte(first, '/')
		if i == -1 {
			// No module name
			panic("No module name")
		}
		second = first[i+1:] // ignore '/'
		first = first[:i]
	} else {
		// Only for remote
		/* host::module[/path] */
		panic("No implement yet")
	}

	port := 873 // Default port: 873

	// Parse port
	i := strings.IndexByte(first, ':')
	if i != -1 {
		var err error
		port, err = strconv.Atoi(first[i+1:])
		if err != nil {
			// Wrong port
			panic("Wrong port")
		}
		first = first[:i]
	}
	host = first

	// Parse path
	i = strings.IndexByte(second, '/')
	if i != -1 {
		path = second[i:]
		second = second[:i]
	}
	module = second

	return host, port, module, path, nil
}

// For rsync
func SplitURI(uri string) (string, string, string, error) {
	var address, module, path string
	first := uri
	var second string

	if strings.HasPrefix(uri, "rsync://") {
		/* rsync://host[:port]/module[/path] */
		first = first[8:]
		i := strings.IndexByte(first, '/')
		if i == -1 {
			// No module name
			return "", "", "", errors.New("no module name")
		}
		second = first[i+1:] // ignore '/'
		first = first[:i]
	} else {
		// Only for remote
		/* host::module[/path] */
		return "", "", "", errors.New("format not supported yet")
	}

	address = first
	// Parse port
	i := strings.IndexByte(first, ':')
	if i == -1 {
		address += ":873" // Default port: 873
	}

	// Parse path
	i = strings.IndexByte(second, '/')
	if i != -1 {
		path = second[i:]
		second = second[:i]
	}
	module = second

	return address, module, path, nil
}

// For rsync
func SplitURL(url *url.URL) (string, string, string, error) {
	hostport := url.Host
	// Default port: 873
	if !strings.Contains(hostport, ":") {
		hostport += ":873"
	}

	split := strings.SplitN(url.Path, "/", 3)
	if len(split) < 1 {
		return "", "", "", errors.New("no module name")
	}
	module := split[1]

	path := ""
	if len(split) > 2 {
		path = split[2]
	}

	return hostport, module, path, nil
}

// The path always has a trailing slash appended
func TrimPrepath(prepath string) string {
	// pre-path shouldn't use "/" as prefix, and must have a "/" suffix
	// pre-path can be: "xx", "xx/", "/xx", "/xx/", "", "/"
	ppath := prepath
	if !strings.HasSuffix(ppath, "/") {
		ppath += "/"
	}
	ppath = strings.TrimPrefix(ppath, "/")
	return ppath
}

func longestMatch(left []byte, right []byte) int {
	i := 0
	for ; i < len(left) && i < len(right) && i < 256; i++ {
		if left[i] != right[i] {
			break
		}
	}
	return i
}
