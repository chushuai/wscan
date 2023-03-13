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

// 允许访问的 Hostname，支持格式如 t.com、*.t.com、1.1.1.1、1.1.1.1/24、1.1-4.1.1-8

func (m *HostsMatcher) Add(values []string) error {
	m.origin = append(m.origin, values...)

	for _, v := range values {
		if ip := net.ParseIP(v); ip != nil {
			if ip.To4() != nil {
				if m.ips == nil {
					m.ips = &KeyMatcher{}
				}
				// m.ips.Insert(ip.String(), true)
			} else {
				if m.ipNets == nil {
					m.ipNets = make([]*net.IPNet, 0)
				}
				ones, bits := ip.DefaultMask().Size()
				m.ipNets = append(m.ipNets, &net.IPNet{
					IP:   ip.Mask(ip.DefaultMask()),
					Mask: net.CIDRMask(ones, bits),
				})
			}
		} else if m.globs == nil {
			m.globs = &GlobMatcher{}
		}

		if m.globs != nil {
			if err := m.globs.Add([]string{v}); err != nil {
				return err
			}
		}
	}

	return nil
}

func (m *HostsMatcher) IsEmpty() bool {
	return m.ips == nil && m.ipNets == nil && m.ipv4Range == nil && m.ipv6Range == nil && (m.globs == nil || m.globs.IsEmpty())
}

func (m *HostsMatcher) Match(ip string) bool {
	//if m.ips != nil && m.ips.Match(ip) {
	//	return true
	//}
	//
	//for _, n := range m.ipNets {
	//	if n.Contains(net.ParseIP(ip)) {
	//		return true
	//	}
	//}
	//
	//for _, r := range m.ipv4Range {
	//	if ipv4InRange(net.ParseIP(ip).To4(), r) {
	//		return true
	//	}
	//}
	//
	//for _, r := range m.ipv6Range {
	//	if ipv6InRange(net.ParseIP(ip).To16(), r[0], r[1]) {
	//		return true
	//	}
	//}
	//
	//for _, r := range m.ipv4SpecialRange {
	//	if ipv4SpecialInRange(net.ParseIP(ip).To4(), r) {
	//		return true
	//	}
	//}
	//
	//if m.globs != nil {
	//	return m.globs.Match(ip)
	//}

	return false
}
