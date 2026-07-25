/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package resource

import (
	"sync"
)

type ServiceFingerprint struct {
	ServiceName string   `json:"service_name"`
	Product     string   `json:"product"`
	Version     string   `json:"version_verbose"`
	Info        string   `json:"info"`
	Hostname    string   `json:"hostname"`
	DeviceType  string   `json:"device_type"`
	OS          string   `json:"os"`
	CPE         []string `json:"cpe"`
}

type Resource interface {
	DeepClone() Resource
	Name() string
	String() string
	Timestamp() int64
	Type() int
}

type Service struct {
	once        sync.Once
	fp          string
	Host        string
	Port        int
	TLS         bool
	Protocol    int
	Fingerprint ServiceFingerprint
	Banner      string
	Domain      []string
	TimeStamp   int64
}

func (*Service) Addr(int) string {
	return ""
}
func (*Service) DeepClone() Resource {
	return nil
}
func (*Service) IsEmptyFingerprint() bool {
	return false
}
func (*Service) MatchFingerprint(string) bool {
	return false
}
func (*Service) Name() string {
	return ""
}
func (*Service) SimpleFingerprint() string {
	return ""
}
func (*Service) String() string {
	return ""
}
func (*Service) Timestamp() int64 {
	return 0
}
func (*Service) Type() int {
	return 0
}

func ServiceFromAddr() {

}
