package useragent

import (
	"strings"

	stringsutil "github.com/projectdiscovery/utils/strings"
)

// Filter represent the function signature for a filter
type Filter func(*UserAgent) bool

// FilterMap contains filter and its respective function signature
var FilterMap map[string]Filter

// ContainsTagsAny returns true if the user agent contains any of the provided tags
func ContainsTagsAny(userAgent *UserAgent, tags ...string) bool {
	for _, tag := range userAgent.Tags {
		if stringsutil.ContainsAny(tag, tags...) {
			return true
		}
	}
	return false
}

// ContainsTags returns true if the user agent contains all provided tags
func ContainsTags(userAgent *UserAgent, tags ...string) bool {
	foundTags := make(map[string]struct{})
	for _, tag := range userAgent.Tags {
		for _, wantedTag := range tags {
			if strings.Contains(tag, wantedTag) {
				foundTags[tag] = struct{}{}
			}
		}
	}
	return len(foundTags) == len(tags)
}

// Mobile checks if the user agent has typical mobile tags
func Mobile(userAgent *UserAgent) bool {
	return ContainsTags(userAgent, "mobile")
}

// Legacy checks if the user agent falls under legacy category
func Legacy(userAgent *UserAgent) bool {
	return ContainsTags(userAgent, "Legacy")
}

// Google Checks if the user agent has typical GoogleBot tags
func GoogleBot(userAgent *UserAgent) bool {
	return ContainsTags(userAgent, "Google", "Spiders")
}

// Chrome checks if the user agent has typical chrome tags
func Chrome(userAgent *UserAgent) bool {
	return ContainsTagsAny(userAgent, "Chrome", "Chromium")
}

// Mozilla checks if the user agent has typical mozilla firefox tags
func Mozilla(userAgent *UserAgent) bool {
	return ContainsTagsAny(userAgent, "Mozilla", "Firefox")
}

// Safari checks if the user agent has typical safari tags
func Safari(userAgent *UserAgent) bool {
	return ContainsTags(userAgent, "Safari")
}

// Computer checks if the user agent has typical computer tags
func Computer(userAgent *UserAgent) bool {
	return ContainsTags(userAgent, "computer")
}

// Apple checks if the user agent has typical apple tags
func Apple(userAgent *UserAgent) bool {
	return ContainsTags(userAgent, "Apple Computer, Inc.")
}

// Windows checks if the user agent has typical windows tags
func Windows(userAgent *UserAgent) bool {
	return ContainsTagsAny(userAgent, "Win32", "Windows")
}

// Bot checks if the user agent has typical bot tags
func Bot(userAgent *UserAgent) bool {
	return ContainsTagsAny(userAgent, "Spiders - Search")
}

func init() {
	FilterMap = map[string]Filter{}

	FilterMap["computer"] = Computer
	FilterMap["mobile"] = Mobile
	FilterMap["legacy"] = Legacy
	FilterMap["chrome"] = Chrome
	FilterMap["mozilla"] = Mozilla
	FilterMap["googlebot"] = GoogleBot
	FilterMap["safari"] = Safari
	FilterMap["apple"] = Apple
	FilterMap["windows"] = Windows
	FilterMap["bot"] = Bot
}
