/**
2 * @Author: shaochuyu
3 * @Date: 3/10/23
4 */

package matcher

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestKeyMatcher(t *testing.T) {
	m := NewKeyMatcher()
	err := m.Add([]string{"abc", "def"})
	assert.NoError(t, err)

	assert.True(t, m.Match("abc"))
	assert.True(t, m.Match("def"))
	assert.False(t, m.Match("ghi"))

	err = m.Add([]string{"ghi", "jkl"})
	assert.NoError(t, err)

	assert.True(t, m.Match("abc"))
	assert.True(t, m.Match("def"))
	assert.True(t, m.Match("ghi"))
	assert.True(t, m.Match("jkl"))
	assert.False(t, m.Match("mno"))
}
