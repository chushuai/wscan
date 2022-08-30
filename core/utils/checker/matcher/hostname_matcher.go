/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package matcher

import (
	"math/big"
	"net"
)

type HostsMatcher struct {
	origin           []string
	ips              *KeyMatcher
	ipNets           []*net.IPNet
	ipv4Range        [][2]uint32
	ipv6Range        [][2]*big.Int
	ipv4SpecialRange [][4][2]int
	globs            *GlobMatcher
}
