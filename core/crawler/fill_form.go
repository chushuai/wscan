/**
2 * @Author: shaochuyu
3 * @Date: 12/9/22
4 */
package crawler

import (
	"context"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/chromedp"
	"os"
	"strings"
	"time"
	logger "wscan/core/utils/log"
)

type FillForm struct {
	tab *Tab
}

/**
填充所有 input 标签
*/
func (f *FillForm) fillInput() {
	defer f.tab.fillFormWG.Done()
	var nodes []*cdp.Node
	ctx := f.tab.GetExecutor()

	tCtx, cancel := context.WithTimeout(ctx, time.Second*2)
	defer cancel()
	// 首先判断input标签是否存在，减少等待时间 提前退出
	inputNodes, inputErr := f.tab.GetNodeIDs(`input`)
	if inputErr != nil || len(inputNodes) == 0 {
		logger.Debug("fillInput: get form input element err")
		if inputErr != nil {
			logger.Debug(inputErr)
		}
		return
	}
	// 获取所有的input标签
	err := chromedp.Nodes(`input`, &nodes, chromedp.ByQueryAll).Do(tCtx)

	if err != nil {
		logger.Debug("get all input element err")
		logger.Debug(err)
		return
	}

	// 找出 type 为空 或者 type=text
	for _, node := range nodes {
		// 兜底超时
		tCtxN, cancelN := context.WithTimeout(ctx, time.Second*5)
		attrType := node.AttributeValue("type")
		if attrType == "text" || attrType == "" {
			inputName := node.AttributeValue("id") + node.AttributeValue("class") + node.AttributeValue("name")
			value := f.GetMatchInputText(inputName)
			var nodeIds = []cdp.NodeID{node.NodeID}
			// 先使用模拟输入
			_ = chromedp.SendKeys(nodeIds, value, chromedp.ByNodeID).Do(tCtxN)
			// 再直接赋值JS属性
			_ = chromedp.SetAttributeValue(nodeIds, "value", value, chromedp.ByNodeID).Do(tCtxN)
		} else if attrType == "email" || attrType == "password" || attrType == "tel" {
			value := f.GetMatchInputText(attrType)
			var nodeIds = []cdp.NodeID{node.NodeID}
			// 先使用模拟输入
			_ = chromedp.SendKeys(nodeIds, value, chromedp.ByNodeID).Do(tCtxN)
			// 再直接赋值JS属性
			_ = chromedp.SetAttributeValue(nodeIds, "value", value, chromedp.ByNodeID).Do(tCtxN)
		} else if attrType == "radio" || attrType == "checkbox" {
			var nodeIds = []cdp.NodeID{node.NodeID}
			_ = chromedp.SetAttributeValue(nodeIds, "checked", "true", chromedp.ByNodeID).Do(tCtxN)
		} else if attrType == "file" || attrType == "image" {
			var nodeIds = []cdp.NodeID{node.NodeID}
			wd, _ := os.Getwd()
			filePath := wd + "/upload/image.png"
			_ = chromedp.RemoveAttribute(nodeIds, "accept", chromedp.ByNodeID).Do(tCtxN)
			_ = chromedp.RemoveAttribute(nodeIds, "required", chromedp.ByNodeID).Do(tCtxN)
			_ = chromedp.SendKeys(nodeIds, filePath, chromedp.ByNodeID).Do(tCtxN)
		}
		cancelN()
	}
}

func (f *FillForm) fillTextarea() {
	defer f.tab.fillFormWG.Done()
	ctx := f.tab.GetExecutor()
	tCtx, cancel := context.WithTimeout(ctx, time.Second*2)
	defer cancel()
	value := f.GetMatchInputText("other")

	textareaNodes, textareaErr := f.tab.GetNodeIDs(`textarea`)
	if textareaErr != nil || len(textareaNodes) == 0 {
		logger.Debug("fillTextarea: get textarea element err")
		if textareaErr != nil {
			logger.Debug(textareaErr)
		}
		return
	}

	_ = chromedp.SendKeys(textareaNodes, value, chromedp.ByNodeID).Do(tCtx)
}

func (f *FillForm) fillMultiSelect() {
	defer f.tab.fillFormWG.Done()
	ctx := f.tab.GetExecutor()
	tCtx, cancel := context.WithTimeout(ctx, time.Second*2)
	defer cancel()
	optionNodes, optionErr := f.tab.GetNodeIDs(`select option:first-child`)
	if optionErr != nil || len(optionNodes) == 0 {
		logger.Debug("fillMultiSelect: get select option element err")
		if optionErr != nil {
			logger.Debug(optionErr)
		}
		return
	}
	_ = chromedp.SetAttributeValue(optionNodes, "selected", "true", chromedp.ByNodeID).Do(tCtx)
	_ = chromedp.SetJavascriptAttribute(optionNodes, "selected", "true", chromedp.ByNodeID).Do(tCtx)
}

func (f *FillForm) GetMatchInputText(name string) string {
	// 如果自定义了关键词，模糊匹配
	for key, value := range f.tab.config.CustomFormKeywordValues {
		if strings.Contains(name, key) {
			return value
		}
	}

	name = strings.ToLower(name)
	for key, item := range InputTextMap {
		for _, keyword := range item["keyword"].([]string) {
			if strings.Contains(name, keyword) {
				if customValue, ok := f.tab.config.CustomFormValues[key]; ok {
					return customValue
				} else {
					return item["value"].(string)
				}
			}
		}
	}
	return f.tab.config.CustomFormValues["default"]
}
