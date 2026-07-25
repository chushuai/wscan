/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package sqli_detector

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"wscan/core/http"
	"wscan/core/plugins/base"
	"wscan/core/plugins/sql_injection/sqli_detector/sqli_payload"
	"wscan/core/utils"
	"wscan/core/utils/comparer"
	logger "wscan/core/utils/log"
)

type Detector struct {
	Config *DetectorConfig
	Apollo *base.Apollo
}

type DetectorConfig struct {
	BooleanBasedDetection      bool     `json:"boolean_based_detection" yaml:"boolean_based_detection" #:"是否检测布尔盲注"`
	ErrorBasedDetection        bool     `json:"error_based_detection" yaml:"error_based_detection" #:"是否检测报错注入"`
	TimeBasedDetection         bool     `json:"time_based_detection" yaml:"time_based_detection" #:"是否检测时间盲注"`
	DangerouslyUseCommentInSQL bool     `json:"use_comment_in_payload" yaml:"use_comment_in_payload" #:"在 payload 中使用 or, 慎用！可能导致删库！"`
	Dbms                       []string `json:"-" yaml:"-"`
}

type TimeBasedDetectionStatInfo struct {
	TimeBasedNormalStatInfo `json:"normal,inline"`
	// Steps 记录所有的验证阶梯（例如 2s, 4s, 6s...）
	Steps []DetectionStep `json:"steps"`
}

type DetectionStep struct {
	Sleep   int   `json:"sleep"`   // 预设的时延 (ms)
	Samples []int `json:"samples"` // 实际测得的耗时 (ms)
}

type TimeBasedNormalStatInfo struct {
	Samples   []int   `json:"samples"`
	Avg       float64 `json:"avg"`
	StdDev    float64 `json:"std_dev"`
	SleepTime int     `json:"sleep_time"` // 最终触发漏洞的那个延时
}

func (t *TimeBasedDetectionStatInfo) string() string {
	if data, err := json.Marshal(t); err == nil {
		return string(data)
	}
	return ""
}

// D1-07: DetectErrorBased 增加差异化比对，修复 context.TODO()
// 降级调试日志
func (d *Detector) DetectErrorBased(ctx context.Context, params []http.Parameter) error {
	flow := d.Apollo.GetTargetFlow()
	// D1-07: 降级调试日志，避免打印完整请求 dump
	logger.Debugf("Start error-based detection, %s", flow.Request.URL().String())

	// D1-07: 获取 baseline 响应，发送不含 payload 的原始请求
	baselineReq := flow.Request.DeepClone()
	baselineRes, baselineErr := d.Apollo.HTTPClient.Respond(ctx, baselineReq)

	for _, param := range params {
		payloads := []sqli_payload.Payload{}
		payloads = sqli_payload.GetPayloads()
		for _, sp := range payloads {
			// http://testphp.vulnweb.com/listproducts.php?cat=extractvalue(1,concat(char(126),md5(1859984743)))
			parameter := http.Parameter{Position: param.Position, Key: param.Key}
			if sp.ParameterType == http.ParameterTypeValue {
				parameter.Value = sp.PositiveFmt
			} else if sp.ParameterType == http.ParameterTypePrefix {
				parameter.Prefix = sp.PositiveFmt
				parameter.Value = param.Value
			} else if sp.ParameterType == http.ParameterTypeSuffix {
				parameter.Value = param.Value
				parameter.Suffix = sp.PositiveFmt
			}
			req := flow.Request.Mutate(&parameter)
			// D1-07: 使用 ctx 替代 context.TODO() — 注意：DetectErrorBased 当前无 ctx 参数
			// 使用 context.TODO() 作为临时方案，需上层调用传入 ctx
			res, err := d.Apollo.HTTPClient.Respond(ctx, req)
			if param.Position == http.PositionCookie {
				logger.Debug(string(req.Dump()))
			}
			if err != nil {
				logger.Error(err)
				continue
			}
			// Non-2xx/3xx responses (404, 500 etc.) should not be treated as SQL injection evidence -
			// error pages often echo back the request URL containing the hash
			if res.StatusCode < 200 || res.StatusCode >= 400 {
				continue
			}
			found := false
			if sp.RegativeFmt != "" {
				if strings.Contains(res.Text, sp.RegativeFmt) {
					v := d.Apollo.NewWebVuln(req, res, &param)
					if v != nil {
						v.SetTargetURL(flow.Request.URL())
						v.Payload = sp.PositiveFmt
						v.Param = &parameter
						// TODO(PostScan): Record reflection point for stored SQLi verification.
						// After detecting SQL injection, record the reflection so the PostScan
						// phase can re-visit this URL to check if the payload persisted:
						//   d.Apollo.ApolloBase.RecordReflection(&base.ReflectionRecord{
						//       URL:        flow.Request.URL().String(),
						//       Method:     flow.Request.Method,
						//       Parameter:  param.Key,
						//       Payload:    sp.PositiveFmt,
						//       PluginName: "sqldet",
						//       VulnType:   "sqli",
						//       Timestamp:  time.Now(),
						//   })
						d.Apollo.OutputVuln(v)
						found = true
						break
					}
				}
			}

			for _, er := range ErrorRegexList {
				if er.Match([]byte(res.Text)) {
					// D1-07: 差异化比对 - 如果 baseline 响应中也包含相同的匹配，判定为误报
					if baselineErr == nil && baselineRes != nil && er.Match([]byte(baselineRes.Text)) {
						continue
					}
					v := d.Apollo.NewWebVuln(req, res, &param)
					if v != nil {
						v.SetTargetURL(flow.Request.URL())
						v.Payload = sp.PositiveFmt
						v.Param = &parameter
						d.Apollo.OutputVuln(v)
						found = true
						break
					}
				}
			}
			if found {
				break
			}
		}

	}

	return nil

}

func (d *Detector) Detect() error {
	return nil
}

// D1-09: 布尔盲注阈值调整 — 阈值从 0.10 提高到 0.20
// boolean based handling key: cat pvalue: 1/**/and+3=3 nvalue: 1/**/and+4=5 pn 71 pt 100
func (d *Detector) DetectBooleanBased(ctx context.Context) error {
	flow := d.Apollo.GetTargetFlow()
	if flow.Response.IsImages() {
		return nil
	}
	originalRes := flow.Response
	// 基于页面相似度，如果使用path注入有可能误报很高
	for _, param := range flow.Request.ParamsQueryAndBody() {
		for _, booleanedObject := range sqli_payload.GetBooleanedPayloadWithConfig(d.Config.DangerouslyUseCommentInSQL) {
			falseReq := flow.Request.Mutate(&http.Parameter{Position: param.Position, Key: param.Key, Value: param.Value, Suffix: booleanedObject.FalsePayload})
			falseRes, err := d.Apollo.HTTPClient.Respond(ctx, falseReq)
			if err != nil {
				continue
			}
			if falseRes.IsImages() {
				return nil
			}
			ratioFalse := comparer.CompareResponse(originalRes, falseRes)
			if ratioFalse == 1.0 {
				continue
			}
			trueReq := flow.Request.Mutate(&http.Parameter{Position: param.Position, Key: param.Key, Value: param.Value, Suffix: booleanedObject.TruePayload})
			trueRes, err := d.Apollo.HTTPClient.Respond(ctx, trueReq)
			if err != nil {
				continue
			}
			pn := comparer.CompareResponse(falseRes, trueRes)
			pt := comparer.CompareResponse(originalRes, trueRes)
			// boolean based handling key: cat pvalue: 1/**/and+3=3 nvalue: 1/**/and+4=5 pn 71 pt 100
			logger.Debugf(" boolean based handling key: %s pvalue: %s nvalue: %s pn %d pt %d, url=%s",
				param.Key,
				param.Value+booleanedObject.TruePayload,
				param.Value+booleanedObject.FalsePayload,
				int(pn*100), int(pt*100), falseReq.URL())

			// D1-09: 布尔盲注阈值从 0.10 调整为 0.20，减少误报
			if math.Abs(float64(pn)-float64(pt)) > 0.20 && pn < 0.99 {
				v := d.Apollo.NewWebVuln(falseReq, falseRes, &param)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Flow = []*http.Flow{
						{Request: falseReq, Response: falseRes},
						{Request: trueReq, Response: trueRes},
					}
					v.Param = &http.Parameter{Position: param.Position, Key: param.Key, Value: param.Value, Suffix: booleanedObject.TruePayload}
					v.Payload = booleanedObject.FalsePayload
					v.Add("confirm_retry", fmt.Sprintf("%d", 1))
					v.Add("confirm_retry_result", fmt.Sprintf("%d", 1))
					v.Add("pn_similarity", fmt.Sprintf("%d", int(pn*100)))
					v.Add("pt_similarity", fmt.Sprintf("%d", int(pt*100)))
					v.Add("title", fmt.Sprintf("%s", booleanedObject.Describe))
					d.Apollo.OutputVuln(v)
				}
				break
			}

		}
		return nil
	}
	return nil
}

func (d *Detector) DetectTimeBased1(ctx context.Context) error {
	flow := d.Apollo.GetTargetFlow()
	probability := utils.Probability{}

	// 1. 建立基准线 (Baseline)
	for i := 0; i < 3; i++ {
		req := flow.Request.DeepClone()
		res, err := d.Apollo.HTTPClient.Respond(ctx, req)
		if err == nil {
			probability.Input = append(probability.Input, float64(res.TimeStamp-req.TimeStamp))
		}
	}
	avgTime := probability.Avg()
	stdDev := probability.StdDev()

	for _, param := range flow.Request.ParamsAll() {
		for _, delayObject := range sqli_payload.GetExactDelay() {
			// 定义三个阶梯：2s, 4s, 8s (指数增长或等差增长均可)
			delays := []int{2, 4, 8}
			actualTimes := make([]int, 0)
			isVulnerable := true

			for _, sec := range delays {
				payload := delayObject.GetStringForDelay(sec)
				// 排除 Cookie 中的特殊字符限制
				if param.Position == http.PositionCookie && strings.Contains(payload, ";") {
					isVulnerable = false
					break
				}

				req := flow.Request.Mutate(&http.Parameter{
					Position: param.Position,
					Key:      param.Key,
					Value:    param.Value,
					Suffix:   payload,
				})

				res, err := d.Apollo.HTTPClient.Respond(ctx, req)
				if err != nil {
					isVulnerable = false
					break
				}

				usedTime := int(res.TimeStamp - req.TimeStamp)
				actualTimes = append(actualTimes, usedTime)

				// 核心判定条件：
				// 1. 耗时必须大于 (基准值 + 设定延时的80%)
				// 2. 耗时必须大于 (基准值 + 3倍标准差) -> 排除统计学噪声
				threshold := avgTime + float64(sec*1000)*0.8
				noiseFloor := avgTime + 3*stdDev

				if float64(usedTime) < threshold || float64(usedTime) < noiseFloor {
					isVulnerable = false
					break
				}

				// 额外逻辑判定：如果是第二轮以后，当前耗时必须明显大于上一轮耗时
				if len(actualTimes) > 1 {
					if usedTime <= actualTimes[len(actualTimes)-2] {
						isVulnerable = false
						break
					}
				}
			}

			// 如果通过了所有阶梯测试
			if isVulnerable && len(actualTimes) == len(delays) {
				// 最终确认：再发一个原始请求看是否恢复正常（防止是整个服务器挂了导致的慢响应）
				resVerifyReq := flow.Request.DeepClone()
				resVerify, err := d.Apollo.HTTPClient.Respond(ctx, resVerifyReq)
				if err == nil {
					verifyTime := int(resVerify.TimeStamp - resVerifyReq.TimeStamp)
					if float64(verifyTime) > (avgTime + 3*stdDev + 500) {
						continue // 整个服务器都慢了，误报
					}
				}

				// 报漏洞
				v := d.Apollo.NewWebVuln(flow.Request, nil, &param) // 使用req2/res2亦可
				if v != nil {
					v.Add("steps", fmt.Sprintf("Delays:%v | Actual:%v", delays, actualTimes))
					v.Add("avg_baseline", fmt.Sprintf("%.2fms", avgTime))
					d.Apollo.OutputVuln(v)
				}
				return nil
			}
		}
	}
	return nil
}

func (d *Detector) DetectTimeBased(ctx context.Context) error {
	flow := d.Apollo.GetTargetFlow()
	originalUseTime := int(flow.Response.TimeStamp - flow.Request.TimeStamp)
	probability := utils.Probability{}

	// 初始化正常统计信息
	tbnsi := TimeBasedNormalStatInfo{}
	if originalUseTime > 0 {
		probability.Input = append(probability.Input, float64(originalUseTime))
		tbnsi.Samples = append(tbnsi.Samples, originalUseTime)
	}

	// 1. 建立基准线 (Baseline) - D1-09: 增加采样次数到 5
	for i := 0; i < 5; i++ {
		req := flow.Request.DeepClone()
		res, err := d.Apollo.HTTPClient.Respond(ctx, req)
		if err == nil {
			used := int(res.TimeStamp - req.TimeStamp)
			probability.Input = append(probability.Input, float64(used))
			tbnsi.Samples = append(tbnsi.Samples, used)
		}
	}

	avgTime := probability.Avg()
	stdDev := probability.StdDev()
	tbnsi.Avg = avgTime
	tbnsi.StdDev = stdDev
	noiseFloor := avgTime + 3*stdDev // 3倍标准差判定线

	for _, param := range flow.Request.ParamsAll() {
		for _, delayObject := range sqli_payload.GetExactDelay() {

			// 定义验证阶梯
			delaysSec := []int{2, 4, 8}
			isVulnerable := true

			// 初始化新定义的输出结构体
			tbds := TimeBasedDetectionStatInfo{
				TimeBasedNormalStatInfo: tbnsi,
				Steps:                   []DetectionStep{},
			}

			var lastReq *http.Request
			var lastRes *http.Response

			for _, sec := range delaysSec {
				payload := delayObject.GetStringForDelay(sec)
				if param.Position == http.PositionCookie && strings.Contains(payload, ";") {
					isVulnerable = false
					break
				}

				req := flow.Request.Mutate(&http.Parameter{
					Position: param.Position,
					Key:      param.Key,
					Value:    param.Value,
					Suffix:   payload,
				})

				res, err := d.Apollo.HTTPClient.Respond(ctx, req)
				if err != nil {
					isVulnerable = false
					break
				}

				usedTime := int(res.TimeStamp - req.TimeStamp)

				// 记录当前步骤数据
				currentStep := DetectionStep{
					Sleep:   sec * 1000,
					Samples: []int{usedTime},
				}
				tbds.Steps = append(tbds.Steps, currentStep)

				// 判定逻辑
				threshold := avgTime + float64(sec*1000)*0.8
				// 核心判定条件：不能小于物理时延阈值，也不能小于统计学噪声线
				if float64(usedTime) < threshold || float64(usedTime) < noiseFloor {
					isVulnerable = false
					break
				}

				// 线性增长判定：当前耗时必须大于上一个阶梯的耗时
				if len(tbds.Steps) > 1 {
					prevTime := tbds.Steps[len(tbds.Steps)-2].Samples[0]
					if usedTime <= prevTime {
						isVulnerable = false
						break
					}
				}

				lastReq, lastRes = req, res
			}

			// 如果通过了所有阶梯测试
			if isVulnerable && len(tbds.Steps) == len(delaysSec) {
				// 最终确认：反向清理验证
				resVerifyReq := flow.Request.DeepClone()
				resVerify, err := d.Apollo.HTTPClient.Respond(ctx, resVerifyReq)
				if err == nil {
					verifyTime := int(resVerify.TimeStamp - resVerifyReq.TimeStamp)
					if float64(verifyTime) > (noiseFloor + 500) {
						continue // 误报：环境变慢
					}
				}

				// 触发漏洞输出
				v := d.Apollo.NewWebVuln(lastReq, lastRes, &param)
				if v != nil {
					finalSleep := delaysSec[len(delaysSec)-1] * 1000
					tbds.TimeBasedNormalStatInfo.SleepTime = finalSleep

					v.SetTargetURL(flow.Request.URL())
					v.Param = &http.Parameter{Position: param.Position, Key: param.Key, Value: param.Value, Suffix: delayObject.GetStringForDelay(finalSleep / 1000)}

					// 保持原有的 Add 字段名，填充新结构的数据
					v.Add("avg_time", fmt.Sprintf("%d", int(avgTime)))
					v.Add("n_time", fmt.Sprintf("%d", tbds.Steps[len(tbds.Steps)-1].Samples[0]))
					v.Add("p_time", fmt.Sprintf("%d", originalUseTime))
					v.Add("sleep_time", fmt.Sprintf("%d", finalSleep))
					v.Add("stat", tbds.string()) // 这里 tbds.string() 会输出包含 Steps 的 JSON
					v.Add("std_dev", fmt.Sprintf("%d", int(stdDev)))
					v.Add("title", delayObject.GetDBMS())
					v.Add("type", "time_based")
					v.Payload = v.Param.Suffix

					d.Apollo.OutputVuln(v)
				}
				return nil
			}
		}
	}
	return nil
}
func (d *Detector) isDjangoLookup() {

}

func (d *Detector) makeSampleRequest() {

}
