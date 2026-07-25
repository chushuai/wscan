// Package lcs ...
package lcs

import (
	"context"
)

// Indices is the index list of items in xs that forms the LCS between xs and ys.
type Indices []int

// YadLCS returns the x index of each Comparable that are in the YadLCS between x and y.
// The complexity is O(M * log(L)), M is the number of char matches between x and y, L is the length of LCS.
// The worst memory complexity is O(M), but usually it's much less.
//
// The advantage of this algorithm is it's easy to understand and implement. It converts the LCS
// problem into problems that are familiar to us, such as LIS, binary-search, object-recycle, etc., which give us
// more room to do the optimization for each streamline.
func (xs Sequence) YadLCS(ctx context.Context, ys Sequence) Indices {
	o := xs.Occurrence(ys)
	r := result{list: make([]*node, 0, min(len(xs), len(ys)))}
	rest := len(ys)

	for _, xi := range o {
		if ctx.Err() != nil {
			break
		}

		from := len(r.list)
		for _, i := range xi {
			from = r.add(from, i, rest)
		}

		rest--
	}

	return r.lcs()
}

type node struct {
	x int
	p *node

	c int // pointer count for node recycle
}

func (n *node) link(x int, m *node) {
	if m != nil {
		m.c++
	}

	n.p = m
	n.x = x
}

type result struct {
	list []*node

	// reuse node to reduce memory allocation
	recycle []*node
}

func (r *result) new(x int, n *node) *node {
	var m *node

	// reuse node if possible
	l := len(r.recycle)
	if l > 0 {
		m = r.recycle[l-1]
		r.recycle = r.recycle[:l-1]
	} else {
		m = &node{}
	}

	m.link(x, n)

	return m
}

func (r *result) replace(i, x int, n *node) {
	// recycle nodes
	if m := r.list[i]; m.c == 0 {
		for p := m.p; p != nil && p != n; p = p.p {
			p.c--
			if p.c == 0 {
				r.recycle = append(r.recycle, p)
			} else {
				break
			}
		}

		m.link(x, n)
		return
	}

	r.list[i] = r.new(x, n)
}

func (r *result) add(from, x, rest int) int {
	l := len(r.list)

	next, n := r.find(from, x)
	if n != nil {
		if l-next < rest { // only when we have enough rest xs
			if next == l {
				r.list = append(r.list, r.new(x, n))
			} else if x < r.list[next].x {
				r.replace(next, x, n)
			}
			return next
		}
	}

	if l == 0 {
		r.list = append(r.list, r.new(x, n))
		return 1
	}

	if l-1 < rest && x < r.list[0].x {
		r.replace(0, x, nil)
	}

	return 0
}

// binary search to find the largest r.list[i].x that is smaller than x
func (r *result) find(from, x int) (int, *node) {
	var found *node
	for i, j := 0, from; i < j; {
		h := (i + j) >> 1
		n := r.list[h]
		if n.x < x {
			from = h
			found = n
			i = h + 1
		} else {
			j = h
		}
	}
	return from + 1, found
}

func (r *result) lcs() Indices {
	l := len(r.list)

	idx := make(Indices, l)

	if l == 0 {
		return idx
	}

	for p := r.list[l-1]; p != nil; p = p.p {
		l--
		idx[l] = p.x
	}

	return idx
}
