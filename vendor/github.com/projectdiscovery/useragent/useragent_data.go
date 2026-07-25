package useragent

import (
	_ "embed"
	"encoding/json"
)

//go:embed useragent_data.json
var userAgentsData string

// initialize user agents data
func init() {
	if err := json.Unmarshal([]byte(userAgentsData), &UserAgents); err != nil {
		panic(err)
	}
}
