/**
* @Author: shaochuyu
* @Date: 7/26/2026
*
* WebUI 原生 IM 推送通知:wscan 直接调用飞书 / 企业微信 / 钉钉的群机器人
* incoming webhook,把扫描事件(发现漏洞 / 目标达成 / 停止)投递到对应 IM,
* 不依赖任何外部桥接进程。webhook 由用户在各自 IM 群里添加「自定义机器人」
* 获得,可选填加签 secret(飞书/钉钉)做完整性校验。
*
* 三个平台均走标准 HTTPS POST,无第三方 SDK 依赖。
*   - 飞书/Lark: POST <webhook>  body {"msg_type":"text","content":{"text":...}}
*     加签:在 webhook URL 上追加 ?timestamp=<sec>&sign=<base64(hmac_sha256(timestamp+"\n"+secret,""))>
*   - 企业微信: POST <webhook>  body {"msgtype":"markdown","markdown":{"content":...}}
*   - 钉钉:     POST <webhook>  body {"msgtype":"markdown","markdown":{"title":...,"text":...}}
*     加签:在 webhook URL 上追加 &timestamp=<ms>&sign=<urlencode(base64(hmac_sha256(secret,timestamp+"\n"+secret)))>
 */
package web

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// notifyFile 是推送配置的落盘文件名(位于 dataDir)。
const notifyFile = "webui_notify.json"

// 支持的推送平台标识。与前端 select 的 option value 一致。
const (
	platformFeishu  = "feishu"
	platformWecom   = "wecom"
	platformDingtalk = "dingtalk"
)

// NotifyEvents 控制哪些事件会触发推送。默认全部开启。
type NotifyEvents struct {
	Fact    bool `json:"fact"`
	Goal    bool `json:"goal"`
	Stopped bool `json:"stopped"`
}

// NotifyConfig 与前端推送配置表单一一对应。
type NotifyConfig struct {
	Enabled    bool         `json:"enabled"`
	Platform   string       `json:"platform"`   // feishu / wecom / dingtalk
	Webhook    string       `json:"webhook"`    // 群机器人 incoming webhook URL
	Secret     string       `json:"secret"`     // 加签密钥(飞书/钉钉可选,企业微信无)
	AtAll      bool         `json:"atAll"`      // @全体(企业微信/钉钉 markdown 支持)
	Events     NotifyEvents `json:"events"`
}

var (
	notifyMu     sync.Mutex
	notifyCache  *NotifyConfig
	notifyLoaded bool
)

// defaultNotifyConfig 返回关闭、事件全开的默认配置。
func defaultNotifyConfig() *NotifyConfig {
	return &NotifyConfig{
		Enabled:  false,
		Platform: platformFeishu,
		Events: NotifyEvents{
			Fact:    true,
			Goal:    true,
			Stopped: true,
		},
	}
}

// loadNotifyLocked 从磁盘读取推送配置,首次调用时加载。调用方需持有 notifyMu。
func loadNotifyLocked() *NotifyConfig {
	if notifyLoaded {
		return notifyCache
	}
	notifyLoaded = true
	ensureDataDir()
	b, err := os.ReadFile(filepath.Join(dataDir, notifyFile))
	if err == nil {
		var c NotifyConfig
		if json.Unmarshal(b, &c) == nil {
			if c.Platform == "" {
				c.Platform = platformFeishu
			}
			notifyCache = &c
			return notifyCache
		}
	}
	notifyCache = defaultNotifyConfig()
	return notifyCache
}

// getNotifyConfig 返回当前推送配置的拷贝。
func getNotifyConfig() *NotifyConfig {
	notifyMu.Lock()
	defer notifyMu.Unlock()
	c := loadNotifyLocked()
	out := *c
	return &out
}

// saveNotifyConfig 持久化推送配置并更新内存缓存。
func saveNotifyConfig(c *NotifyConfig) error {
	notifyMu.Lock()
	defer notifyMu.Unlock()
	ensureDataDir()
	if c.Platform == "" {
		c.Platform = platformFeishu
	}
	notifyCache = c
	notifyLoaded = true
	return writeJSONFile(filepath.Join(dataDir, notifyFile), c)
}

// notifyResult 是单次推送的结果。
type notifyResult struct {
	OK     bool
	Status int
	Body   string
	Err    error
}

// sendNotify 按配置的平台投递一条消息。message 为纯文本/Markdown 混合,
// 飞书以纯文本发送,企业微信与钉钉以 Markdown 发送。
func sendNotify(ctx context.Context, cfg *NotifyConfig, message string) notifyResult {
	if cfg == nil || !cfg.Enabled {
		return notifyResult{Err: fmt.Errorf("notify disabled")}
	}
	if strings.TrimSpace(cfg.Webhook) == "" {
		return notifyResult{Err: fmt.Errorf("webhook URL is empty")}
	}
	switch cfg.Platform {
	case platformFeishu:
		return sendFeishu(ctx, cfg, message)
	case platformWecom:
		return sendWecom(ctx, cfg, message)
	case platformDingtalk:
		return sendDingtalk(ctx, cfg, message)
	default:
		return notifyResult{Err: fmt.Errorf("unknown platform: %s", cfg.Platform)}
	}
}

// httpPostJSON 发送一次 JSON POST,返回状态码与响应体。
func httpPostJSON(ctx context.Context, target string, body any) notifyResult {
	payload, err := json.Marshal(body)
	if err != nil {
		return notifyResult{Err: fmt.Errorf("encode payload: %w", err)}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(payload))
	if err != nil {
		return notifyResult{Err: fmt.Errorf("build request: %w", err)}
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return notifyResult{Err: fmt.Errorf("HTTP request: %w", err)}
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	return notifyResult{OK: resp.StatusCode == http.StatusOK, Status: resp.StatusCode, Body: strings.TrimSpace(string(respBody))}
}

// feishuSign 计算飞书自定义机器人加签:base64(hmac_sha256(key=timestamp+"\n"+secret, message=""))。
func feishuSign(timestamp int64, secret string) string {
	stringToSign := fmt.Sprintf("%d\n%s", timestamp, secret)
	h := hmac.New(sha256.New, []byte(stringToSign))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func sendFeishu(ctx context.Context, cfg *NotifyConfig, message string) notifyResult {
	target := cfg.Webhook
	if cfg.Secret != "" {
		ts := time.Now().Unix()
		sign := feishuSign(ts, cfg.Secret)
		sep := "?"
		if strings.Contains(target, "?") {
			sep = "&"
		}
		target = fmt.Sprintf("%s%stimestamp=%d&sign=%s", target, sep, ts, url.QueryEscape(sign))
	}
	body := map[string]any{
		"msg_type": "text",
		"content":  map[string]string{"text": message},
	}
	return httpPostJSON(ctx, target, body)
}

// dingtalkSign 计算钉钉自定义机器人加签:urlencode(base64(hmac_sha256(key=secret, message=timestamp+"\n"+secret)))。
func dingtalkSign(timestampMs int64, secret string) string {
	stringToSign := fmt.Sprintf("%d\n%s", timestampMs, secret)
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(stringToSign))
	return url.QueryEscape(base64.StdEncoding.EncodeToString(h.Sum(nil)))
}

func sendDingtalk(ctx context.Context, cfg *NotifyConfig, message string) notifyResult {
	target := cfg.Webhook
	if cfg.Secret != "" {
		ts := time.Now().UnixMilli()
		sign := dingtalkSign(ts, cfg.Secret)
		sep := "?"
		if strings.Contains(target, "?") {
			sep = "&"
		}
		target = fmt.Sprintf("%s%stimestamp=%d&sign=%s", target, sep, ts, sign)
	}
	text := message
	if cfg.AtAll {
		// 钉钉 markdown @全体需要在内容里插入 @全体 标记并配 at 字段;这里简化为内容前缀。
		text = "@全体 " + text
	}
	body := map[string]any{
		"msgtype": "markdown",
		"markdown": map[string]string{
			"title": "wscan",
			"text":  text,
		},
	}
	return httpPostJSON(ctx, target, body)
}

func sendWecom(ctx context.Context, cfg *NotifyConfig, message string) notifyResult {
	// 企业微信群机器人 markdown 不支持 @全体;需要 @全体时用 text 类型 + mentioned_mobile_list=["@all"]。
	if cfg.AtAll {
		body := map[string]any{
			"msgtype": "text",
			"text":    map[string]any{"content": message, "mentioned_list": []string{"@all"}},
		}
		return httpPostJSON(ctx, cfg.Webhook, body)
	}
	body := map[string]any{
		"msgtype": "markdown",
		"markdown": map[string]string{"content": message},
	}
	return httpPostJSON(ctx, cfg.Webhook, body)
}

// notifyEvent 在对应事件开启时投递一条消息。供任务生命周期调用。
func notifyEvent(ctx context.Context, event string, message string) {
	cfg := getNotifyConfig()
	if !cfg.Enabled {
		return
	}
	var on bool
	switch event {
	case "fact":
		on = cfg.Events.Fact
	case "goal":
		on = cfg.Events.Goal
	case "stopped":
		on = cfg.Events.Stopped
	}
	if !on {
		return
	}
	sendNotify(ctx, cfg, message)
}

// platformLabel 返回平台的中文展示名(用于错误消息)。
func platformLabel(p string) string {
	switch p {
	case platformFeishu:
		return "飞书/Lark"
	case platformWecom:
		return "企业微信"
	case platformDingtalk:
		return "钉钉"
	}
	return p
}

