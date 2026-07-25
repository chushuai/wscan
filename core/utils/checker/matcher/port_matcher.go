/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package matcher

import (
	"fmt"
	"strconv"
	"strings"
)

// 使用端口号和端口号范围来匹配端口。
type PortMatcher struct {
	origin     []string
	singlePort []int
	actions    []func(int) bool
}

func NewPortMatcher() *PortMatcher {
	return &PortMatcher{}
}

func (m *PortMatcher) Add(values []string) error {
	m.origin = append(m.origin, values...)

	for _, value := range values {
		if strings.Contains(value, "-") {
			ports := strings.Split(value, "-")
			if len(ports) != 2 {
				return fmt.Errorf("invalid port range: %s", value)
			}

			startPort, err := strconv.Atoi(ports[0])
			if err != nil {
				return fmt.Errorf("invalid port range: %s", value)
			}

			endPort, err := strconv.Atoi(ports[1])
			if err != nil {
				return fmt.Errorf("invalid port range: %s", value)
			}

			if startPort > endPort {
				return fmt.Errorf("invalid port range: %s", value)
			}

			m.actions = append(m.actions, func(port int) bool {
				return port >= startPort && port <= endPort
			})
		} else {
			port, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("invalid port: %s", value)
			}

			m.singlePort = append(m.singlePort, port)

			m.actions = append(m.actions, func(p int) bool {
				return p == port
			})
		}
	}

	return nil
}

func (m *PortMatcher) IsEmpty() bool {
	return len(m.singlePort) == 0 && len(m.actions) == 0
}

func (m *PortMatcher) Match(portStr string) bool {
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return false
	}

	for _, p := range m.singlePort {
		if port == p {
			return true
		}
	}

	for _, action := range m.actions {
		if action(port) {
			return true
		}
	}

	return false
}
