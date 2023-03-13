/**
2 * @Author: shaochuyu
3 * @Date: 3/10/23
4 */

package matcher

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestRegexpMatcher(t *testing.T) {
	r := NewRegexpMatcher()
	err := r.Add([]string{"^test[0-9]*$", "^example$"})
	require.NoError(t, err)

	testCases := []struct {
		name   string
		input  string
		expect bool
	}{
		{
			name:   "Matched string",
			input:  "test123",
			expect: true,
		},
		{
			name:   "Matched string with special characters",
			input:  "test_123!@#",
			expect: false,
		},
		{
			name:   "Not matched string",
			input:  "testing",
			expect: false,
		},
		{
			name:   "Matched string with exact match",
			input:  "example",
			expect: true,
		},
		{
			name:   "Not matched empty string",
			input:  "",
			expect: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expect, r.Match(tc.input))
		})
	}
}
