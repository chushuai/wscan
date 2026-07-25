package dsl

import (
	"sync"

	iputil "github.com/projectdiscovery/utils/ip"
)

var (
	publicIP string
	getOnce  sync.Once
)

// GetPublicIp of the host
func GetPublicIP() string {
	getOnce.Do(func() {
		publicIP, _ = iputil.WhatsMyIP()
	})
	return publicIP
}
