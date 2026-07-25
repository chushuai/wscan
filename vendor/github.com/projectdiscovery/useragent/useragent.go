package useragent

import (
	"fmt"

	sliceutil "github.com/projectdiscovery/utils/slice"
)

// UserAgents of the package
var UserAgents []*UserAgent

// UserAgent with tags
type UserAgent struct {
	Tags []string
	Raw  string
}

// String returns the user agent raw value
func (userAgent *UserAgent) String() string {
	return userAgent.Raw
}

// Pick n items randomly from the available ones
func Pick(n int) ([]*UserAgent, error) {
	return PickWithFilters(n)
}

// Pick n items randomly for the available ones with optional filtering
func PickWithFilters(n int, filters ...Filter) ([]*UserAgent, error) {
	if n > len(UserAgents) {
		return nil, fmt.Errorf("the database does not contain %d items", n)
	}
	// filters out wanted ones
	var filteredUserAgents []*UserAgent
	if len(filters) > 0 {
		for _, ua := range UserAgents {
			for _, filter := range filters {
				if !filter(ua) {
					continue
				}
				filteredUserAgents = append(filteredUserAgents, ua)
			}
		}
	} else {
		filteredUserAgents = UserAgents
	}

	if n > len(filteredUserAgents) {
		return nil, fmt.Errorf("the filtered database does not contain %d items", n)
	}

	var userAgents []*UserAgent

	// retrieve all user agents
	if n == -1 {
		n = len(filteredUserAgents)
	}

	for i := 0; i < n; i++ {
		userAgent := sliceutil.PickRandom(filteredUserAgents)
		userAgents = append(userAgents, userAgent)
	}
	return userAgents, nil
}

func PickRandom() *UserAgent {
	return sliceutil.PickRandom(UserAgents)
}
