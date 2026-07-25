/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package crawler

import (
	"go/types"
	"regexp"
	"sort"
	"strings"
	"sync"
	"wscan/core/http"
	"wscan/core/utils"
	logger "wscan/core/utils/log"

	mapset "github.com/deckarep/golang-set"
)

type Filter interface {
	Check(string, bool) bool
	Close()
	Insert(string)
	Reset()
}

type SyncMapFilter struct {
	*sync.Map
}

func (f *SyncMapFilter) Check(key string, addIfMissing bool) bool {
	_, ok := f.Load(key)
	if !ok && addIfMissing {
		f.Store(key, struct{}{})
	}
	return ok
}

func (f *SyncMapFilter) Close() {
	f.Map = &sync.Map{}
}

func (f *SyncMapFilter) Insert(key string) {
	f.Store(key, struct{}{})
}

func (f *SyncMapFilter) Reset() {
	f.Range(func(key, value any) bool {
		f.Map.Delete(key)
		return true
	})
}

type SimpleFilter struct {
	UniqueSet mapset.Set
	HostLimit string
}

/*
*
需要过滤则返回 true
*/
func (s *SimpleFilter) DoFilter(req *http.Request, redirectionFlag bool) bool {
	if s.UniqueSet == nil {
		s.UniqueSet = mapset.NewSet()
	}
	// 首先判断是否需要过滤域名
	if s.HostLimit != "" && s.DomainFilter(req) {
		return true
	}
	// 去重
	if s.UniqueFilter(req, redirectionFlag) {
		return true
	}
	// 过滤静态资源
	if s.StaticFilter(req) {
		return true
	}
	return false
}

/*
*
不加入Header的请求ID
*/
func NoHeaderId(req *http.Request) string {
	postData := req.GetRawBody()
	return utils.MD5(req.Method + req.GetURL().String() + string(postData))
}

func UniqueId(req *http.Request, redirectionFlag bool) string {
	if redirectionFlag {
		return utils.MD5(NoHeaderId(req) + "Redirection")
	} else {
		return NoHeaderId(req)
	}
	return ""
}

/*
*
请求去重
*/
func (s *SimpleFilter) UniqueFilter(req *http.Request, redirectionFlag bool) bool {
	if s.UniqueSet == nil {
		s.UniqueSet = mapset.NewSet()
	}
	if s.UniqueSet.Contains(UniqueId(req, redirectionFlag)) {
		return true
	} else {
		s.UniqueSet.Add(UniqueId(req, redirectionFlag))
		return false
	}
}

/*
*
静态资源过滤
*/
func (s *SimpleFilter) StaticFilter(req *http.Request) bool {
	if s.UniqueSet == nil {
		s.UniqueSet = mapset.NewSet()
	}
	// 首先将slice转换成map
	extMap := map[string]int{}
	ss := append(StaticSuffix, "css", "json")
	for _, suffix := range ss {
		extMap[suffix] = 1
	}

	if req.GetURL().FileExt() == "" {
		return false
	}
	if req.GetURL().FileName() == "robots.txt" {
		return false
	}
	if _, ok := extMap[req.GetURL().FileExt()]; ok {
		return true
	}
	return false
}

/*
*
只保留指定域名的链接
*/
func (s *SimpleFilter) DomainFilter(req *http.Request) bool {
	if s.UniqueSet == nil {
		s.UniqueSet = mapset.NewSet()
	}
	if req.GetURL().Host == s.HostLimit || req.GetURL().Hostname() == s.HostLimit {
		return false
	}
	if strings.HasSuffix(s.HostLimit, ":80") && req.GetURL().Port() == "" && req.GetURL().Scheme == "http" {
		if req.GetURL().Hostname()+":80" == s.HostLimit {
			return false
		}
	}
	if strings.HasSuffix(s.HostLimit, ":443") && req.GetURL().Port() == "" && req.GetURL().Scheme == "https" {
		if req.GetURL().Hostname()+":443" == s.HostLimit {
			return false
		}
	}
	return true
}

type SmartFilter struct {
	StrictMode                 bool
	SimpleFilter               SimpleFilter
	filterLocationSet          mapset.Set // 非逻辑型参数的位置记录 全局统一标记过滤
	filterParamKeyRepeatCount  sync.Map
	filterParamKeySingleValues sync.Map // 所有参数名重复数量统计
	filterPathParamKeySymbol   sync.Map // 某个path下的某个参数的值出现标记次数统计
	filterParamKeyAllValues    sync.Map
	filterPathParamEmptyValues sync.Map
	filterParentPathValues     sync.Map
	uniqueMarkedIds            mapset.Set // 标记后的唯一ID，用于去重
}

const (
	MaxParentPathCount         = 32 // 相对于上一级目录，本级path目录的数量修正最大值
	MaxParamKeySingleCount     = 8  // 某个URL参数名重复修正最大值
	MaxParamKeyAllCount        = 10 // 本轮所有URL中某个参数名的重复修正最大值
	MaxPathParamEmptyCount     = 10 // 某个path下的参数值为空，参数名个数修正最大值
	MaxPathParamKeySymbolCount = 5  // 某个Path下的某个参数的标记数量超过此值，则该参数被全局标记
)

const (
	CustomValueMark    = "{{Scanner}}"
	FixParamRepeatMark = "{{fix_param}}"
	FixPathMark        = "{{fix_path}}"
	TooLongMark        = "{{long}}"
	NumberMark         = "{{number}}"
	ChineseMark        = "{{chinese}}"
	UpperMark          = "{{upper}}"
	LowerMark          = "{{lower}}"
	UrlEncodeMark      = "{{urlencode}}"
	UnicodeMark        = "{{unicode}}"
	BoolMark           = "{{bool}}"
	ListMark           = "{{list}}"
	TimeMark           = "{{time}}"
	MixAlphaNumMark    = "{{mix_alpha_num}}"
	MixSymbolMark      = "{{mix_symbol}}"
	MixNumMark         = "{{mix_num}}"
	NoLowerAlphaMark   = "{{no_lower}}"
	MixStringMark      = "{{mix_str}}"
)

var chineseRegex = regexp.MustCompile("[\u4e00-\u9fa5]+")
var urlencodeRegex = regexp.MustCompile("(?:%[A-Fa-f0-9]{2,6})+")
var unicodeRegex = regexp.MustCompile(`(?:\\u\w{4})+`)
var onlyAlphaRegex = regexp.MustCompile("^[a-zA-Z]+$")
var onlyAlphaUpperRegex = regexp.MustCompile("^[A-Z]+$")
var alphaUpperRegex = regexp.MustCompile("[A-Z]+")
var alphaLowerRegex = regexp.MustCompile("[a-z]+")
var replaceNumRegex = regexp.MustCompile(`[0-9]+\.[0-9]+|\d+`)
var onlyNumberRegex = regexp.MustCompile(`^[0-9]+$`)
var numberRegex = regexp.MustCompile(`[0-9]+`)
var OneNumberRegex = regexp.MustCompile(`[0-9]`)
var numSymbolRegex = regexp.MustCompile(`\.|_|-`)
var timeSymbolRegex = regexp.MustCompile(`-|:|\s`)
var onlyAlphaNumRegex = regexp.MustCompile(`^[0-9a-zA-Z]+$`)
var markedStringRegex = regexp.MustCompile(`^{{.+}}$`)
var htmlReplaceRegex = regexp.MustCompile(`\.shtml|\.html|\.htm`)

func (s *SmartFilter) Init() {
	s.filterLocationSet = mapset.NewSet()
	s.filterParamKeyRepeatCount = sync.Map{}
	s.filterParamKeySingleValues = sync.Map{}
	s.filterPathParamKeySymbol = sync.Map{}
	s.filterParamKeyAllValues = sync.Map{}
	s.filterPathParamEmptyValues = sync.Map{}
	s.filterParentPathValues = sync.Map{}
	s.uniqueMarkedIds = mapset.NewSet()
}

/*
*
智能去重
可选严格模式

需要过滤则返回 true
*/
func (s *SmartFilter) DoFilter(req *http.Request, redirectionFlag bool) bool {
	//fmt.Println("filter req by simplefilter: " + req.Method + ":" + req.URL.RequestURI())
	// 首先过滤掉静态资源、基础的去重、过滤其它的域名
	if s.SimpleFilter.DoFilter(req, redirectionFlag) {
		//logger.Debugf("filter req by simplefilter: " + req.URL.RequestURI())
		return true
	}

	var reqQueryMapId, reqPostDataId, reqPathId, reqUniqueId, reqMarkedPath, reqQueryKeysId string
	var reqMarkedPostDataMap, reqMarkedQueryMap map[string]any

	// 标记
	if req.Method == GET || req.Method == DELETE || req.Method == HEAD || req.Method == OPTIONS {
		// 首先是解码前的预先替换
		todoURL := *(req.GetURL())
		todoURL.RawQuery = s.preQueryMark(todoURL.RawQuery)

		// 依次打标记
		queryMap := todoURL.QueryMap()
		queryMap = s.markParamName(queryMap)
		queryMap = s.markParamValue(queryMap, *req)
		markedPath := s.MarkPath(todoURL.Path)

		// 计算唯一的ID
		var queryKeyID string
		var queryMapID string
		if len(queryMap) != 0 {
			queryKeyID = s.getKeysID(queryMap)
			queryMapID = s.getParamMapID(queryMap)
		} else {
			queryKeyID = ""
			queryMapID = ""
		}
		pathID := s.getPathID(markedPath)
		reqMarkedQueryMap = queryMap
		reqQueryKeysId = queryKeyID
		reqQueryMapId = queryMapID
		reqMarkedPath = markedPath
		reqPathId = pathID
		// 最后计算标记后的唯一请求ID
		reqUniqueId = s.getMarkedUniqueID(req, reqQueryMapId, reqPostDataId, reqPathId, redirectionFlag)

	} else if req.Method == POST || req.Method == PUT {
		req.PostDataMap()
		postDataMap := req.PostDataMap()
		postDataMap = s.markParamName(postDataMap)
		postDataMap = s.markParamValue(postDataMap, *req)
		markedPath := s.MarkPath(req.GetURL().Path)

		// 计算唯一的ID
		var postDataMapID string
		if len(postDataMap) != 0 {
			postDataMapID = s.getParamMapID(postDataMap)
		} else {
			postDataMapID = ""
		}
		pathID := s.getPathID(markedPath)

		reqMarkedPostDataMap = postDataMap
		reqPostDataId = postDataMapID
		reqMarkedPath = markedPath
		reqPathId = pathID

		// 最后计算标记后的唯一请求ID
		reqUniqueId = s.getMarkedUniqueID(req, reqQueryMapId, reqPostDataId, reqPathId, redirectionFlag)
	} else {
		logger.Debug("dont support such method: " + req.Method)
	}

	if req.Method == GET || req.Method == DELETE || req.Method == HEAD || req.Method == OPTIONS {
		// s.repeatCountStatistic(req)
		queryKeyId := reqQueryKeysId
		pathId := reqPathId
		if queryKeyId != "" {
			// 所有参数名重复数量统计
			if v, ok := s.filterParamKeyRepeatCount.Load(queryKeyId); ok {
				s.filterParamKeyRepeatCount.Store(queryKeyId, v.(int)+1)
			} else {
				s.filterParamKeyRepeatCount.Store(queryKeyId, 1)
			}

			for key, value := range reqMarkedQueryMap {
				// 某个URL的所有参数名重复数量统计
				paramQueryKey := queryKeyId + key

				if set, ok := s.filterParamKeySingleValues.Load(paramQueryKey); ok {
					set := set.(mapset.Set)
					set.Add(value)
				} else {
					s.filterParamKeySingleValues.Store(paramQueryKey, mapset.NewSet(value))
				}

				//本轮所有URL中某个参数重复数量统计
				if _, ok := s.filterParamKeyAllValues.Load(key); !ok {
					s.filterParamKeyAllValues.Store(key, mapset.NewSet(value))
				} else {
					if v, ok := s.filterParamKeyAllValues.Load(key); ok {
						set := v.(mapset.Set)
						if !set.Contains(value) {
							set.Add(value)
						}
					}
				}

				// 如果参数值为空，统计该PATH下的空值参数名个数
				if value == "" {
					if _, ok := s.filterPathParamEmptyValues.Load(pathId); !ok {
						s.filterPathParamEmptyValues.Store(pathId, mapset.NewSet(key))
					} else {
						if v, ok := s.filterPathParamEmptyValues.Load(pathId); ok {
							set := v.(mapset.Set)
							if !set.Contains(key) {
								set.Add(key)
							}
						}
					}
				}

				pathIdKey := pathId + key
				// 某path下的参数值去重标记出现次数统计
				if v, ok := s.filterPathParamKeySymbol.Load(pathIdKey); ok {
					if markedStringRegex.MatchString(value.(string)) {
						s.filterPathParamKeySymbol.Store(pathIdKey, v.(int)+1)
					}
				} else {
					s.filterPathParamKeySymbol.Store(pathIdKey, 1)
				}

			}
		}

		// 相对于上一级目录，本级path目录的数量统计，存在文件后缀的情况下，放行常见脚本后缀
		if req.GetURL().ParentPath() == "" || s.inCommonScriptSuffix(req.GetURL().FileExt()) {

		} else {
			parentPathId := utils.MD5(req.GetURL().ParentPath())
			currentPath := strings.Replace(reqMarkedPath, req.GetURL().ParentPath(), "", -1)
			if _, ok := s.filterParentPathValues.Load(parentPathId); !ok {
				s.filterParentPathValues.Store(parentPathId, mapset.NewSet(currentPath))
			} else {
				if v, ok := s.filterParentPathValues.Load(parentPathId); ok {
					set := v.(mapset.Set)
					if !set.Contains(currentPath) {
						set.Add(currentPath)
					}
				}
			}
		}
		//  repeatCountStatistic
	}

	// 对标记后的请求进行去重
	uniqueId := UniqueId(req, redirectionFlag)
	if s.uniqueMarkedIds.Contains(uniqueId) {
		logger.Debugf("filter req by uniqueMarkedIds 1: " + req.GetURL().RequestURI())
		return true
	}

	// 全局数值型参数标记
	name := req.GetURL().Hostname() + req.GetURL().Path + req.Method
	if req.Method == GET || req.Method == DELETE || req.Method == HEAD || req.Method == OPTIONS {
		for key := range reqMarkedQueryMap {
			name += key
			if s.filterLocationSet.Contains(name) {
				reqMarkedQueryMap[key] = CustomValueMark
			}
		}
	} else if req.Method == POST || req.Method == PUT {
		for key := range reqMarkedPostDataMap {
			name += key
			if s.filterLocationSet.Contains(name) {
				reqMarkedPostDataMap[key] = CustomValueMark
			}
		}
	}

	// 接下来对标记的GET请求进行去重
	if req.Method == GET || req.Method == DELETE || req.Method == HEAD || req.Method == OPTIONS {
		// 对超过阈值的GET请求进行标记
		queryKeyId := reqQueryKeysId
		pathId := reqPathId
		// 参数不为空，
		if reqQueryKeysId != "" {
			// 某个URL的所有参数名重复数量超过阈值 且该参数有超过三个不同的值 则打标记
			if v, ok := s.filterParamKeyRepeatCount.Load(queryKeyId); ok && v.(int) > MaxParamKeySingleCount {
				for key := range reqMarkedQueryMap {
					paramQueryKey := queryKeyId + key
					if set, ok := s.filterParamKeySingleValues.Load(paramQueryKey); ok {
						set := set.(mapset.Set)
						if set.Cardinality() > 3 {
							reqMarkedQueryMap[key] = FixParamRepeatMark
						}
					}
				}
			}

			for key := range reqMarkedQueryMap {
				// 所有URL中，某个参数不同的值出现次数超过阈值，打标记去重
				if paramKeySet, ok := s.filterParamKeyAllValues.Load(key); ok {
					paramKeySet := paramKeySet.(mapset.Set)
					if paramKeySet.Cardinality() > MaxParamKeyAllCount {
						reqMarkedQueryMap[key] = FixParamRepeatMark
					}
				}

				pathIdKey := pathId + key
				// 某个PATH的GET参数值去重标记出现次数超过阈值，则对该PATH的该参数进行全局标记
				if v, ok := s.filterPathParamKeySymbol.Load(pathIdKey); ok && v.(int) > MaxPathParamKeySymbolCount {
					reqMarkedQueryMap[key] = FixParamRepeatMark
				}
			}

			// 处理某个path下空参数值的参数个数超过阈值 如伪静态： http://bang.360.cn/?chu_xiu
			if v, ok := s.filterPathParamEmptyValues.Load(pathId); ok {
				set := v.(mapset.Set)
				if set.Cardinality() > MaxPathParamEmptyCount {
					newMarkerQueryMap := map[string]any{}
					for key, value := range reqMarkedQueryMap {
						if value == "" {
							newMarkerQueryMap[FixParamRepeatMark] = ""
						} else {
							newMarkerQueryMap[key] = value
						}
					}
					reqMarkedQueryMap = newMarkerQueryMap
				}
			}
		}

		// 处理本级path的伪静态
		if req.GetURL().ParentPath() == "" || s.inCommonScriptSuffix(req.GetURL().FileExt()) {

		} else {
			parentPathId := utils.MD5(req.GetURL().ParentPath())
			if set, ok := s.filterParentPathValues.Load(parentPathId); ok {
				set := set.(mapset.Set)
				if set.Cardinality() > MaxParentPathCount {
					if strings.HasSuffix(req.GetURL().ParentPath(), "/") {
						reqMarkedPath = req.GetURL().ParentPath() + FixPathMark
					} else {
						reqMarkedPath = req.GetURL().ParentPath() + "/" + FixPathMark
					}
				}
			}
		}

		// 重新计算 QueryMapId
		reqQueryMapId = s.getParamMapID(reqMarkedQueryMap)
		// 重新计算 PathId
		reqPathId = s.getPathID(reqMarkedPath)
	} else {
		// 重新计算 PostDataId
		reqPostDataId = s.getParamMapID(reqMarkedPostDataMap)
	}

	// 重新计算请求唯一ID
	reqUniqueId = s.getMarkedUniqueID(req, reqQueryMapId, reqPostDataId, reqPathId, redirectionFlag)

	// 新的ID再次去重
	newUniqueId := reqUniqueId
	if s.uniqueMarkedIds.Contains(newUniqueId) {
		logger.Debugf("filter req by uniqueMarkedIds 2: " + req.GetURL().RequestURI())
		return true
	}

	// 添加到结果集中
	s.uniqueMarkedIds.Add(newUniqueId)
	return false
}

/*
*
Query的Map对象会自动解码，所以对RawQuery进行预先的标记
*/
func (s *SmartFilter) preQueryMark(rawQuery string) string {
	if chineseRegex.MatchString(rawQuery) {
		return chineseRegex.ReplaceAllString(rawQuery, ChineseMark)
	} else if urlencodeRegex.MatchString(rawQuery) {
		return urlencodeRegex.ReplaceAllString(rawQuery, UrlEncodeMark)
	} else if unicodeRegex.MatchString(rawQuery) {
		return unicodeRegex.ReplaceAllString(rawQuery, UnicodeMark)
	}
	return rawQuery
}

/*
*
标记参数名
*/
func (s *SmartFilter) markParamName(paramMap map[string]any) map[string]any {
	markedParamMap := map[string]any{}
	for key, value := range paramMap {
		// 纯字母不处理
		if onlyAlphaRegex.MatchString(key) {
			markedParamMap[key] = value
			// 参数名过长
		} else if len(key) >= 32 {
			markedParamMap[TooLongMark] = value
			// 替换掉数字
		} else {
			key = replaceNumRegex.ReplaceAllString(key, NumberMark)
			markedParamMap[key] = value
		}
	}
	return markedParamMap
}

/*
*
标记参数值
*/
func (s *SmartFilter) markParamValue(paramMap map[string]any, req http.Request) map[string]any {
	markedParamMap := map[string]any{}
	for key, value := range paramMap {
		markedParamMap[key] = CustomValueMark
		continue
		switch value.(type) {
		case bool:
			markedParamMap[key] = BoolMark
			continue
		case types.Slice:
			markedParamMap[key] = ListMark
			continue
		case float64:
			markedParamMap[key] = NumberMark
			continue
		}
		// 只处理string类型
		valueStr, ok := value.(string)
		if !ok {
			continue
		}
		// Vscan 为特定字符，说明此参数位置为数值型，非逻辑型，记录下此参数，全局过滤
		if strings.Contains(valueStr, "Scanner") {
			name := req.URL().Hostname() + req.URL().Path + req.Method + key
			s.filterLocationSet.Add(name)
			markedParamMap[key] = CustomValueMark
			// 全大写字母
		} else if onlyAlphaUpperRegex.MatchString(valueStr) {
			markedParamMap[key] = UpperMark
			// 参数值长度大于等于16
		} else if len(valueStr) >= 16 {
			markedParamMap[key] = TooLongMark
			// 均为数字和一些符号组成
		} else if onlyNumberRegex.MatchString(valueStr) || onlyNumberRegex.MatchString(numSymbolRegex.ReplaceAllString(valueStr, "")) {
			markedParamMap[key] = NumberMark
			// 存在中文
		} else if chineseRegex.MatchString(valueStr) {
			markedParamMap[key] = ChineseMark
			// urlencode
		} else if urlencodeRegex.MatchString(valueStr) {
			markedParamMap[key] = UrlEncodeMark
			// unicode
		} else if unicodeRegex.MatchString(valueStr) {
			markedParamMap[key] = UnicodeMark
			// 时间
		} else if onlyNumberRegex.MatchString(timeSymbolRegex.ReplaceAllString(valueStr, "")) {
			markedParamMap[key] = TimeMark
			// 字母加数字
		} else if onlyAlphaNumRegex.MatchString(valueStr) && numberRegex.MatchString(valueStr) {
			markedParamMap[key] = MixAlphaNumMark
			// 含有一些特殊符号
		} else if s.hasSpecialSymbol(valueStr) {
			markedParamMap[key] = MixSymbolMark
			// 数字出现的次数超过3，视为数值型参数
		} else if b := OneNumberRegex.ReplaceAllString(valueStr, "0"); strings.Count(b, "0") >= 3 {
			markedParamMap[key] = MixNumMark
			// 严格模式
		} else if s.StrictMode {
			// 无小写字母
			if !alphaLowerRegex.MatchString(valueStr) {
				markedParamMap[key] = NoLowerAlphaMark
				// 常见的值一般为 大写字母、小写字母、数字、下划线的任意组合，组合类型超过三种则视为伪静态
			} else {
				count := 0
				if alphaLowerRegex.MatchString(valueStr) {
					count += 1
				}
				if alphaUpperRegex.MatchString(valueStr) {
					count += 1
				}
				if numberRegex.MatchString(valueStr) {
					count += 1
				}
				if strings.Contains(valueStr, "_") || strings.Contains(valueStr, "-") {
					count += 1
				}
				if count >= 3 {
					markedParamMap[key] = MixStringMark
				}
			}
		} else {
			markedParamMap[key] = value
		}
	}
	return markedParamMap
}

/*
*
标记路径
*/
func (s *SmartFilter) MarkPath(path string) string {
	pathParts := strings.Split(path, "/")
	for index, part := range pathParts {
		// 对含有.的路径段（文件名），按.拆分后分别标记再拼接
		// 避免类似 main.79aa39a81eb94047e946.js 整段被标记为{{mix_num}}导致不同文件产生相同的标记路径
		if strings.Contains(part, ".") && part != "." && part != ".." {
			dotParts := strings.Split(part, ".")
			// Check if this is an html file extension (.html/.htm/.shtml) and strip it
			lastPart := dotParts[len(dotParts)-1]
			if lastPart == "html" || lastPart == "htm" || lastPart == "shtml" {
				dotParts = dotParts[:len(dotParts)-1]
				// Rejoin the remaining parts and apply html-specific marking
				strippedPart := strings.Join(dotParts, ".")
				if numberRegex.MatchString(strippedPart) && alphaUpperRegex.MatchString(strippedPart) && alphaLowerRegex.MatchString(strippedPart) {
					pathParts[index] = MixAlphaNumMark
				} else if b := numSymbolRegex.ReplaceAllString(strippedPart, ""); onlyNumberRegex.MatchString(b) {
					pathParts[index] = NumberMark
				} else {
					pathParts[index] = strippedPart
				}
				continue
			}
			hasMarked := false
			for i, subPart := range dotParts {
				if len(subPart) >= 32 {
					dotParts[i] = TooLongMark
					hasMarked = true
				} else if onlyNumberRegex.MatchString(subPart) {
					dotParts[i] = NumberMark
					hasMarked = true
				} else if onlyAlphaUpperRegex.MatchString(subPart) && len(subPart) > 1 {
					dotParts[i] = UpperMark
					hasMarked = true
				} else if b := OneNumberRegex.ReplaceAllString(subPart, "0"); strings.Count(b, "0") > 3 {
					dotParts[i] = MixNumMark
					hasMarked = true
				}
			}
			if hasMarked {
				pathParts[index] = strings.Join(dotParts, ".")
			}
			continue
		}
		if len(part) >= 32 {
			pathParts[index] = TooLongMark
		} else if onlyNumberRegex.MatchString(numSymbolRegex.ReplaceAllString(part, "")) {
			pathParts[index] = NumberMark
		} else if strings.HasSuffix(part, ".html") || strings.HasSuffix(part, ".htm") || strings.HasSuffix(part, ".shtml") {
			part = htmlReplaceRegex.ReplaceAllString(part, "")
			// 大写、小写、数字混合
			if numberRegex.MatchString(part) && alphaUpperRegex.MatchString(part) && alphaLowerRegex.MatchString(part) {
				pathParts[index] = MixAlphaNumMark
				// 纯数字
			} else if b := numSymbolRegex.ReplaceAllString(part, ""); onlyNumberRegex.MatchString(b) {
				pathParts[index] = NumberMark
			}
			// 含有特殊符号
		} else if s.hasSpecialSymbol(part) {
			pathParts[index] = MixSymbolMark
		} else if chineseRegex.MatchString(part) {
			pathParts[index] = ChineseMark
		} else if unicodeRegex.MatchString(part) {
			pathParts[index] = UnicodeMark
		} else if onlyAlphaUpperRegex.MatchString(part) {
			pathParts[index] = UpperMark
			// 均为数字和一些符号组成
		} else if b := numSymbolRegex.ReplaceAllString(part, ""); onlyNumberRegex.MatchString(b) {
			pathParts[index] = NumberMark
			// 数字出现的次数超过3，视为伪静态path
		} else if b := OneNumberRegex.ReplaceAllString(part, "0"); strings.Count(b, "0") > 3 {
			pathParts[index] = MixNumMark
		}
	}
	newPath := strings.Join(pathParts, "/")
	return newPath
}

/*
*
计算标记后的唯一请求ID
*/
func (s *SmartFilter) getMarkedUniqueID(req *http.Request, reqQueryMapId, reqPostDataId, reqPathId string, redirectionFlag bool) string {

	var paramId string
	if req.Method == GET || req.Method == DELETE || req.Method == HEAD || req.Method == OPTIONS {
		paramId = reqQueryMapId
	} else {
		paramId = reqPostDataId
	}

	uniqueStr := req.Method + paramId + reqPathId + req.GetURL().Host
	if redirectionFlag {
		uniqueStr += "Redirection"
	}
	if req.GetURL().Path == "/" && req.GetURL().RawQuery == "" && req.GetURL().Scheme == "https" {
		uniqueStr += "https"
	}

	if req.GetURL().Fragment != "" && strings.HasPrefix(req.GetURL().Fragment, "/") {
		uniqueStr += req.GetURL().Fragment
	}
	return utils.MD5(uniqueStr)

}

/*
*
计算请求参数的key标记后的唯一ID
*/
func (s *SmartFilter) getKeysID(dataMap map[string]any) string {
	var keys []string
	var idStr string
	for key := range dataMap {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		idStr += key
	}
	return utils.MD5(idStr)
}

/*
*
计算请求参数标记后的唯一ID
*/
func (s *SmartFilter) getParamMapID(dataMap map[string]any) string {
	var keys []string
	var idStr string
	var markReplaceRegex = regexp.MustCompile(`{{.+}}`)
	for key := range dataMap {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value := dataMap[key]
		idStr += key
		if value, ok := value.(string); ok {
			idStr += markReplaceRegex.ReplaceAllString(value, "{{mark}}")
		}
	}
	return utils.MD5(idStr)
}

/*
*
计算PATH标记后的唯一ID
*/
func (s *SmartFilter) getPathID(path string) string {
	return utils.MD5(path)
}

/*
*
判断字符串中是否存在以下特殊符号
*/
func (s *SmartFilter) hasSpecialSymbol(str string) bool {
	symbolList := []string{"{", "}", " ", "|", "#", "@", "$", "*", ",", "<", ">", "/", "?", "\\", "+", "="}
	for _, sym := range symbolList {
		if strings.Contains(str, sym) {
			return true
		}
	}
	return false
}

func (s *SmartFilter) inCommonScriptSuffix(suffix string) bool {
	for _, value := range ScriptSuffix {
		if value == suffix {
			return true
		}
	}
	return false
}
