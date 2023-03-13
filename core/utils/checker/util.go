/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package checker

import (
	"fmt"
	"net/url"
	"strconv"
)

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

func GetQueryKeys(rawurl string) ([]string, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}
	queryKeys := make([]string, 0)
	queryValues, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, err
	}
	for key := range queryValues {
		queryKeys = append(queryKeys, key)
	}
	return queryKeys, nil
}
