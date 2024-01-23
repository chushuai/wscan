/**
2 * @Author: shaochuyu
3 * @Date: 1/7/24
4 */

package reverse

import (
	"fmt"
	"sync"
	"testing"
)

func TestDNSServer(t *testing.T) {
	config := &Config{
		Token: "xxxx",
		HTTPServerConfig: HTTPServerConfig{
			Enabled:    true,
			ListenIP:   "0.0.0.0",
			ListenPort: "8003",
		},
		DNSServerConfig: DNSServerConfig{
			Enabled:  true,
			ListenIP: "0.0.0.0",
			Domain:   "xxx.com",
		},
	}

	reverse := NewReverse(config)

	if reverse == nil {
		return
	}

	reverse.Start()

	wg := sync.WaitGroup{}

	wg.Add(1)
	wg.Wait()

}

func TestGenRandDomain(t *testing.T) {
	config := &Config{
		Token: "xxxx",
		HTTPServerConfig: HTTPServerConfig{
			Enabled:    true,
			ListenIP:   "0.0.0.0",
			ListenPort: "8003",
		},
		DNSServerConfig: DNSServerConfig{
			Enabled:  true,
			ListenIP: "0.0.0.0",
			Domain:   "xxx.com",
		},
	}

	randDomain, err := GenRandDomain(config)

	fmt.Println(randDomain, err)
}
