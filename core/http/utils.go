/**
2 * @Author: shaochuyu
3 * @Date: 9/4/22
4 */

package http

import (
	"fmt"
	"github.com/antchfx/xmlquery"
	"strconv"
	"strings"
	"wscan/core/utils"
)

func CloneHeader() {

}
func IsStaticURL() {

}
func IsNeededResource() {

}
func ReadCompressBody() {

}

func GetTextContent() {

}

func IsMeaninglessCookieKey() bool {
	return false
}

func RecursiveXMLNode(node *xmlquery.Node, callback func(node *xmlquery.Node)) {
	nodesMap := make(map[*xmlquery.Node]struct{})
	count := 0

	var recursiveXMLNode func(node *xmlquery.Node)

	recursiveXMLNode = func(node *xmlquery.Node) {
		if node == nil {
			return
		}
		typ := node.Type
		lowerData := strings.ToLower(node.Data)
		lowerPrefix := strings.ToLower(node.Prefix)
		if typ == xmlquery.CommentNode || typ == xmlquery.DeclarationNode || typ == xmlquery.CharDataNode {
			return
		}

		if _, ok := nodesMap[node]; ok {
			return
		}

		// 防止死循环
		count++
		if count > 81920 {
			return
		}

		// soap的特殊节点直接返回
		if (lowerPrefix == "soap" || lowerPrefix == "soap-env") && (lowerData != "envelope" && lowerData != "body") {
			return
		}

		nodesMap[node] = struct{}{}
		// RootNode或者soap的特殊节点不需要回调
		if typ != xmlquery.DocumentNode && lowerPrefix != "soap" && lowerPrefix != "soap-env" {
			callback(node)
		}

		// 遍历兄弟节点
		for sibling := node.PrevSibling; sibling != nil; sibling = sibling.PrevSibling {
			recursiveXMLNode(sibling)
		}
		for sibling := node.NextSibling; sibling != nil; sibling = sibling.NextSibling {
			recursiveXMLNode(sibling)
		}

		// 遍历子节点
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			recursiveXMLNode(child)
		}
	}

	recursiveXMLNode(node)
}
func GetXpathFromNode(node *xmlquery.Node) string {
	var getXpathFromNode func(node *xmlquery.Node, depth int, path string) string

	getXpathFromNode = func(node *xmlquery.Node, depth int, path string) string {
		if node == nil {
			return ""
		}
		nodeType := node.Type

		if nodeType == xmlquery.CommentNode || nodeType == xmlquery.DeclarationNode || nodeType == xmlquery.CharDataNode {
			return ""
		}

		data := node.Data
		prefix := ""
		switch nodeType {
		case xmlquery.TextNode:
			path = "text()"
		case xmlquery.DocumentNode:
			prefix = "/"
		case xmlquery.ElementNode:
			prefix = data
		case xmlquery.AttributeNode:
			prefix = "@" + data
		}

		hasIndex := false
		if node.PrevSibling != nil {
			count := 0
			for prev := node.PrevSibling; prev != nil; prev = prev.PrevSibling {
				if prev.Type == node.Type && prev.Data == data {
					count++
				}
			}
			if count > 0 {
				prefix = fmt.Sprintf("%s[%d]", prefix, count+1)
				hasIndex = true
			}
		}

		if !hasIndex && node.NextSibling != nil {
			existed := false
			for next := node.NextSibling; next != nil; next = next.NextSibling {
				if next.Type == node.Type && next.Data == data {
					existed = true
					break
				}
			}
			if existed {
				prefix = fmt.Sprintf("%s[1]", prefix)
			}
		}

		if prefix != "" {
			if !strings.HasSuffix(prefix, "/") {
				prefix += "/"
			}
			path = prefix + path
		}

		if depth < 128 && node.Parent != nil {
			path = getXpathFromNode(node.Parent, depth+1, path)
		}

		return strings.TrimRight(path, "/")
	}

	return getXpathFromNode(node, 0, "")
}

func ConvertValue(oldValue, newValue string) string {
	var returnValue any = newValue

	oldValueVerbose := fmt.Sprintf("%#v", oldValue)
	isInteger := utils.IsValidInteger(oldValueVerbose)
	isFloat := utils.IsValidFloat(oldValueVerbose)
	isBoolean := utils.IsValidBool(oldValueVerbose)
	if isFloat {
		f, err := strconv.ParseFloat(newValue, 64)
		if err == nil {
			returnValue = f
		}
	} else if isInteger {
		i, err := strconv.ParseInt(newValue, 10, 64)
		if err == nil {
			returnValue = i
		}
	} else if isBoolean {
		b, err := strconv.ParseBool(newValue)
		if err == nil {
			returnValue = b
		}
	}

	return fmt.Sprintf("%v", returnValue)
}
