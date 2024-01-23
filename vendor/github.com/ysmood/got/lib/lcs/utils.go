package lcs

import (
	"strings"
)

func min(x, y int) int {
	if x < y {
		return x
	}
	return y
}

func eq(x, y Comparable) bool {
	return x.String() == y.String()
}

// String interface
func (xs Sequence) String() string {
	if len(xs) == 0 {
		return ""
	}

	l := 0
	for _, el := range xs {
		l += len(el.String())
	}
	if l == len(xs) {
		out := ""
		for _, c := range xs {
			out += c.String()
		}
		return out
	}

	out := []string{}
	for _, c := range xs {
		out = append(out, c.String())
	}
	return strings.Join(out, "\n")
}

// StandardLCS implementation for testing purpose only, because it's very inefficient.
// https://en.wikipedia.org/wiki/Longest_common_subsequence_problem#LCS_function_defined.
func StandardLCS(xs, ys Sequence) Sequence {
	last := func(s Sequence) Comparable {
		return s[len(s)-1]
	}
	noLast := func(s Sequence) Sequence {
		return s[:len(s)-1]
	}

	if len(xs)*len(ys) == 0 {
		return Sequence{}
	} else if last(xs).String() == last(ys).String() {
		return append(StandardLCS(noLast(xs), noLast(ys)), last(xs))
	}

	left, right := StandardLCS(xs, noLast(ys)), StandardLCS(noLast(xs), ys)
	if len(left) > len(right) {
		return left
	}
	return right
}
