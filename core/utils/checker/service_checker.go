/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package checker

import (
	"wscan/core/utils/checker/filter"
	"wscan/core/utils/checker/matcher"
)

type ServiceCheckerConfig struct {
	HostnameAllowed    []string
	HostnameDisallowed []string
	TCPPortAllowed     []string
	TCPPortDisallowed  []string
	UDPPortAllowed     []string
	UDPPortDisallowed  []string
}

type ServiceChecker struct {
	filter.Filter
	config                    *ServiceCheckerConfig
	HostnameAllowedMatcher    *matcher.HostsMatcher
	HostnameDisallowedMatcher *matcher.HostsMatcher
	TCPPortAllowedMatcher     *matcher.PortMatcher
	TCPPortDisallowedMatcher  *matcher.PortMatcher
	UDPPortAllowedMatcher     *matcher.PortMatcher
	UDPPortDisallowedMatcher  *matcher.PortMatcher
	Scope                     string
	AutoInsertDisabled        bool
	TTL                       int64
}

func (*ServiceChecker) AddScope() {}
func (*ServiceChecker) Close() error {
	return nil
}
func (*ServiceChecker) DisableAutoInsert()          {}
func (*ServiceChecker) Insert(string)               {}
func (*ServiceChecker) InsertWithTTL(string, int64) {}
func (*ServiceChecker) IsInserted(string, bool) bool {
	return true
}
func (*ServiceChecker) IsInsertedWithTTL(string, bool, int64) bool {
	return true
}
func (*ServiceChecker) NewSubChecker() {}
func (*ServiceChecker) Reset() error {
	return nil
}
func (*ServiceChecker) Target()  {}
func (*ServiceChecker) WithTTL() {}

type ServicePattern struct {
	err                error
	Checker            *ServiceChecker
	TransportProtocol  uint8
	Hostname           string
	Port               string
	Scope              string
	AutoInsertDisabled bool
	TTL                int64
}

func (*ServicePattern) AddScope() {

}

func (*ServicePattern) Bool() bool {
	return true
}

func (*ServicePattern) DisableAutoInsert() {

}

func (*ServicePattern) Error() error {
	return nil
}

func (*ServicePattern) IsAllowed() {

}

func (*ServicePattern) IsNewService() {

}

func (*ServicePattern) WithTTL() {

}
