/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package matcher

import (
	"github.com/gobwas/glob"
	"sync"
)

// GlobMatcher 使用通配符来匹配字符串。
type GlobMatcher struct {
	sync.Mutex
	pattern map[string]struct{}
	globs   []glob.Glob
}

func NewGlobMatcher() *GlobMatcher {
	return &GlobMatcher{
		pattern: make(map[string]struct{}),
		globs:   make([]glob.Glob, 0),
	}
}

func (m *GlobMatcher) Add(patterns []string) error {
	m.Lock()
	defer m.Unlock()

	if m.pattern == nil {
		m.pattern = make(map[string]struct{})
	}

	for _, pattern := range patterns {
		if _, ok := m.pattern[pattern]; ok {
			continue
		}

		m.pattern[pattern] = struct{}{}

		g, err := glob.Compile(pattern, '/')
		if err != nil {
			return err
		}

		m.globs = append(m.globs, g)
	}

	return nil
}

func (m *GlobMatcher) IsEmpty() bool {
	m.Lock()
	defer m.Unlock()

	return len(m.globs) == 0
}

func (m *GlobMatcher) Match(value string) bool {
	m.Lock()
	defer m.Unlock()

	for _, g := range m.globs {
		if g.Match(value) {
			return true
		}
	}

	return false
}
