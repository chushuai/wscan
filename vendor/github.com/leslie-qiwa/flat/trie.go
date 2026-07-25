package flat

import (
	"fmt"
	"strconv"
)

type TrieNode struct {
	children   map[string]*TrieNode
	sliceDepth int // record depth of slice in case it is slice of slice
	value      interface{}
}

func (t *TrieNode) Print(delimiter string) {
	t.print("", delimiter)
}

func (t *TrieNode) print(parent, delimiter string) {
	if t.value != nil {
		fmt.Printf("%s: %v\n", parent, t.value)
	}
	for k, child := range t.children {
		if parent != "" {
			child.print(parent+delimiter+k, delimiter)
		} else {
			child.print(k, delimiter)
		}
	}
}

func (t *TrieNode) insert(parts []string, value interface{}) {
	node := t
	for i, part := range parts {
		if node.children == nil {
			node.children = make(map[string]*TrieNode)
		}
		cnode, ok := node.children[part]
		if !ok {
			cnode = &TrieNode{}
			node.children[part] = cnode
		}
		node = cnode
		if i == len(parts)-1 {
			node.value = value
		}
	}
}

// Start from the bottom to handle slice case
// TODO: support slice of slice when flatten support it
func (t *TrieNode) unflatten() map[string]interface{} {
	ret := make(map[string]interface{})
	for k, child := range t.children {
		ret[k] = child.uf()
	}
	return ret
}

func (t *TrieNode) uf() interface{} {
	if t.value != nil || len(t.children) == 0 {
		return t.value
	}
	isSlice := true
	sChildren := make([]*TrieNode, len(t.children))
	for k, v := range t.children {
		idx, err := strconv.Atoi(k)
		if err != nil {
			break
		}
		sChildren[idx] = v
	}
	for _, v := range sChildren {
		if v != nil {
			continue
		}
		isSlice = false
		break
	}

	if isSlice {
		ret := make([]interface{}, len(sChildren))
		for i, child := range sChildren {
			ret[i] = child.uf()
		}
		return ret
	}

	ret := make(map[string]interface{})
	for k, child := range t.children {
		ret[k] = child.uf()
	}
	return ret
}
