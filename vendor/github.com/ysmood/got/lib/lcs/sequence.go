package lcs

import (
	"bufio"
	"bytes"
	"regexp"
)

// Sequence list
type Sequence []Comparable

// Sub from p, it will automatically decompress the compressed p.
func (xs Sequence) Sub(idx Indices) Sequence {
	s := make(Sequence, len(idx))
	for i, ix := range idx {
		s[i] = xs[ix]
	}
	return s
}

// IsSubsequenceOf returns true if x is a subsequence of y
func (xs Sequence) IsSubsequenceOf(ys Sequence) bool {
	for i, j := 0, 0; i < len(xs); i++ {
		for {
			if j >= len(ys) {
				return false
			}
			if eq(xs[i], ys[j]) {
				j++
				break
			}
			j++
		}
	}

	return true
}

// Histogram of each Comparable
func (xs Sequence) Histogram() map[string][]int {
	h := map[string][]int{}
	for i := len(xs) - 1; i >= 0; i-- {
		s := xs[i].String()
		h[s] = append(h[s], i)
	}
	return h
}

// Occurrence returns the position of each element of y in x.
func (xs Sequence) Occurrence(y Sequence) [][]int {
	o := make([][]int, len(y))
	h := xs.Histogram()

	for i, c := range y {
		if indexes, has := h[c.String()]; has {
			o[i] = indexes
		}
	}

	return o
}

// Comparable interface
type Comparable interface {
	// String for comparison, such as the hash
	String() string
}

// Element of a line, a word, or a character
type Element string

// String returns the full content
func (e Element) String() string {
	return string(e)
}

// NewChars from string
func NewChars(s string) Sequence {
	cs := Sequence{}
	for _, r := range s {
		cs = append(cs, Element(r))
	}
	return cs
}

// NewWords from string list
func NewWords(words []string) Sequence {
	cs := make(Sequence, len(words))
	for i, word := range words {
		cs[i] = Element(word)
	}
	return cs
}

// NewLines from string. It will split the s via newlines.
func NewLines(s string) Sequence {
	sc := bufio.NewScanner(bytes.NewBufferString(s))
	cs := Sequence{}
	for i := 0; sc.Scan(); i++ {
		cs = append(cs, Element(sc.Text()))
	}

	if len(s) > 0 && s[len(s)-1] == '\n' {
		cs = append(cs, Element(""))
	}

	return cs
}

// RegWord to match a word
var regWord = regexp.MustCompile(`(?s)` + // enable . to match newline
	`[[:alpha:]]{1,12}` + // match alphabets, length limit is 12
	`|[[:digit:]]{1,3}` + // match digits, length limit is 3
	`|.` + // match others as single-char words
	``)

// RegRune to match a rune
var regRune = regexp.MustCompile(`(?s).`)

// SplitKey for context
var SplitKey = struct{}{}

// Split a line into words
func Split(s string) []string {
	var reg *regexp.Regexp
	if len(s) <= 100 {
		reg = regRune
	} else {
		reg = regWord
	}

	return reg.FindAllString(s, -1)
}
