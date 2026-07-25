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

func (s *ServiceChecker) AddScope() { _ = s }
func (s *ServiceChecker) Close() error {
	return nil
}
func (s *ServiceChecker) DisableAutoInsert()          { _ = s }
func (s *ServiceChecker) Insert(string)               { _ = s }
func (s *ServiceChecker) InsertWithTTL(string, int64) { _ = s }
func (s *ServiceChecker) IsInserted(string, bool) bool {
	return true
}
func (s *ServiceChecker) IsInsertedWithTTL(string, bool, int64) bool {
	return true
}
func (s *ServiceChecker) NewSubChecker() { _ = s }
func (s *ServiceChecker) Reset() error {
	return nil
}
func (s *ServiceChecker) Target()  { _ = s }
func (s *ServiceChecker) WithTTL() { _ = s }

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

func (sp *ServicePattern) AddScope() { _ = sp }

func (*ServicePattern) Bool() bool {
	return true
}

func (sp *ServicePattern) DisableAutoInsert() { _ = sp }

func (*ServicePattern) Error() error {
	return nil
}

func (sp *ServicePattern) IsAllowed() { _ = 0 }

func (sp *ServicePattern) IsNewService() { _ = 0 }

func (sp *ServicePattern) WithTTL() { _ = 0 }
