/**
* @Author: shaochuyu
* @Date: 7/26/2026
*
* WebUI 原生 IM 推送通知:wscan 直接调用飞书 / 企业微信 / 钉钉把扫描事件
* (发现漏洞 / 目标达成 / 停止)投递到对应 IM,不依赖任何外部桥接进程。
*
* 两种接入模式并存:
*
*  1. 群机器人 webhook(三个平台都支持):
*     - 飞书/Lark: POST <webhook>  body {"msg_type":"text","content":{"text":...}}
*       加签: 追加 ?timestamp=<sec>&sign=<base64(hmac_sha256(timestamp+"\n"+secret,""))>
*     - 企业微信:   POST <webhook>  body {"msgtype":"markdown","markdown":{"content":...}}
*     - 钉钉:       POST <webhook>  body {"msgtype":"markdown","markdown":{"title":...,"text":...}}
*       加签: 追加 &timestamp=<ms>&sign=<urlencode(base64(hmac_sha256(secret,timestamp+"\n"+secret)))>
*
*  2. 飞书扫码建机器人→1v1 应用消息(仅飞书,复刻 cc-connect `feishu setup` 的
*     device_code 流程):
*     - 用户在 WebUI 点「生成二维码」,wscan 调 accounts.feishu.cn 的 registration
*       接口拿到 verification_uri_complete,后端编码成 QR PNG 返给前端。
*     - 用户用飞书 App 扫码确认后,wscan 轮询拿到 app_id/app_secret + 创建者 open_id。
*     - 之后发消息:用 app_id/app_secret 换 tenant_access_token,调
*       /open-apis/im/v1/messages?receive_id_type=open_id 给创建者发 1v1 文本,
*       无需群、无需公网回调。
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

	"github.com/skip2/go-qrcode"
)

// notifyFile 是推送配置的落盘文件名(位于 dataDir)。
const notifyFile = "webui_notify.json"

// 支持的推送平台标识。与前端 select 的 option value 一致。
const (
	platformFeishu   = "feishu"
	platformLark     = "lark"
	platformWecom    = "wecom"
	platformDingtalk = "dingtalk"
)

// 飞书接入模式。
const (
	feishuModeWebhook = "webhook" // 群机器人 webhook
	feishuModeApp     = "app"     // 扫码建机器人→1v1 应用消息
)

// 飞书扫码建机器人用到的 registration 端点域名。
const (
	feishuAccountsBase = "https://accounts.feishu.cn"
	larkAccountsBase   = "https://accounts.larksuite.com"
	feishuOpenBase     = "https://open.feishu.cn"
	larkOpenBase       = "https://open.larksuite.com"
)

// NotifyEvents 控制哪些事件会触发推送。默认全部开启。
type NotifyEvents struct {
	Fact    bool `json:"fact"`
	Goal    bool `json:"goal"`
	Stopped bool `json:"stopped"`
}

// NotifyConfig 与前端推送配置表单一一对应。
type NotifyConfig struct {
	Enabled  bool   `json:"enabled"`
	Platform string `json:"platform"` // feishu / wecom / dingtalk
	Mode     string `json:"mode"`     // 飞书:webhook / app;其余平台忽略
	// webhook 模式字段
	Webhook string `json:"webhook"` // 群机器人 incoming webhook URL
	Secret  string `json:"secret"`  // 加签密钥(飞书/钉钉可选,企业微信无)
	AtAll   bool   `json:"atAll"`   // @全体(企业微信/钉钉 markdown 支持)
	// 飞书 app 模式字段(扫码建机器人后落盘)
	FeishuAppID     string       `json:"feishuAppId"`
	FeishuAppSecret string       `json:"feishuAppSecret"`
	FeishuOpenID    string       `json:"feishuOpenId"` // 创建者 open_id,1v1 收件人
	FeishuIsLark    bool         `json:"feishuIsLark"` // 是否 Lark 国际版
	Events          NotifyEvents `json:"events"`
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
		Mode:     feishuModeWebhook,
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
			if c.Platform == platformFeishu && c.Mode == "" {
				c.Mode = feishuModeWebhook
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
	if c.Platform == platformFeishu && c.Mode == "" {
		c.Mode = feishuModeWebhook
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
	switch cfg.Platform {
	case platformFeishu, platformLark:
		if cfg.Mode == feishuModeApp {
			return sendFeishuApp(ctx, cfg, message)
		}
		if strings.TrimSpace(cfg.Webhook) == "" {
			return notifyResult{Err: fmt.Errorf("webhook URL is empty")}
		}
		return sendFeishu(ctx, cfg, message)
	case platformWecom:
		if strings.TrimSpace(cfg.Webhook) == "" {
			return notifyResult{Err: fmt.Errorf("webhook URL is empty")}
		}
		return sendWecom(ctx, cfg, message)
	case platformDingtalk:
		if strings.TrimSpace(cfg.Webhook) == "" {
			return notifyResult{Err: fmt.Errorf("webhook URL is empty")}
		}
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
		"msgtype":  "markdown",
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

// platformLabel 返回平台的中文展示名 (用于错误消息)。
func platformLabel(p string) string {
	switch p {
	case platformFeishu:
		return "飞书"
	case platformLark:
		return "Lark"
	case platformWecom:
		return "企业微信"
	case platformDingtalk:
		return "钉钉"
	}
	return p
}

// ===== 飞书扫码建机器人(device_code 流程)=====

// feishuRegSession 是一次扫码流程的内存态。WebUI 单机部署,同一时刻只会有
// 一两个会话,用全局 map + mutex 存即可。
type feishuRegSession struct {
	DeviceCode  string
	URI         string // verification_uri_complete
	Interval    int
	ExpireAt    time.Time
	IsLark      bool
	OwnerOpenID string // 轮询成功后写入
}

var (
	feishuRegMu       sync.Mutex
	feishuRegSessions = map[string]*feishuRegSession{}
)

// feishuRegInit / Begin / Poll 响应结构,字段对齐 cc-connect。
type feishuRegInitResp struct {
	SupportedAuthMethods []string `json:"supported_auth_methods"`
	Error                string   `json:"error"`
	ErrorDescription     string   `json:"error_description"`
}
type feishuRegBeginResp struct {
	DeviceCode              string `json:"device_code"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	Interval                int    `json:"interval"`
	ExpireIn                int    `json:"expire_in"`
	Error                   string `json:"error"`
	ErrorDescription        string `json:"error_description"`
}
type feishuRegPollResp struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	UserInfo     struct {
		OpenID      string `json:"open_id"`
		TenantBrand string `json:"tenant_brand"`
	} `json:"user_info"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// feishuRegCall 调用 accounts.feishu.cn /oauth/v1/app/registration。
// action: init / begin / poll。
func feishuRegCall(ctx context.Context, baseURL, action string, params map[string]string, out any) error {
	form := url.Values{}
	form.Set("action", action)
	for k, v := range params {
		form.Set(k, v)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/oauth/v1/app/registration", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, out)
}

// feishuQRStart 发起一次扫码建机器人流程,返回二维码 PNG(base64)、URL、
// 会话 token(用于后续 poll)、过期秒数。
func feishuQRStart(ctx context.Context) (qrB64 string, uri string, token string, expireIn int, err error) {
	baseURL := feishuAccountsBase
	var initRes feishuRegInitResp
	if err = feishuRegCall(ctx, baseURL, "init", nil, &initRes); err != nil {
		return
	}
	if initRes.Error != "" {
		err = fmt.Errorf("%s: %s", initRes.Error, initRes.ErrorDescription)
		return
	}
	if len(initRes.SupportedAuthMethods) > 0 {
		ok := false
		for _, m := range initRes.SupportedAuthMethods {
			if strings.EqualFold(strings.TrimSpace(m), "client_secret") {
				ok = true
				break
			}
		}
		if !ok {
			err = fmt.Errorf("当前环境不支持 client_secret 授权")
			return
		}
	}
	var beginRes feishuRegBeginResp
	beginParams := map[string]string{
		"archetype":         "PersonalAgent",
		"auth_method":       "client_secret",
		"request_user_info": "open_id",
	}
	if err = feishuRegCall(ctx, baseURL, "begin", beginParams, &beginRes); err != nil {
		return
	}
	if beginRes.Error != "" {
		err = fmt.Errorf("%s: %s", beginRes.Error, beginRes.ErrorDescription)
		return
	}
	if beginRes.DeviceCode == "" || beginRes.VerificationURIComplete == "" {
		err = fmt.Errorf("onboarding 响应不完整")
		return
	}
	png, qerr := qrcode.Encode(beginRes.VerificationURIComplete, qrcode.Medium, 280)
	if qerr != nil {
		err = fmt.Errorf("生成二维码失败: %w", qerr)
		return
	}
	qrB64 = base64.StdEncoding.EncodeToString(png)
	uri = beginRes.VerificationURIComplete
	token = beginRes.DeviceCode
	expireIn = beginRes.ExpireIn
	if expireIn <= 0 {
		expireIn = 600
	}
	interval := beginRes.Interval
	if interval <= 0 {
		interval = 5
	}
	feishuRegMu.Lock()
	feishuRegSessions[token] = &feishuRegSession{
		DeviceCode: beginRes.DeviceCode,
		URI:        uri,
		Interval:   interval,
		ExpireAt:   time.Now().Add(time.Duration(expireIn) * time.Second),
	}
	feishuRegMu.Unlock()
	return
}

// feishuQRPoll 轮询一次扫码状态。成功时把 app_id/app_secret/open_id 写入 cfg
// 并持久化,返回 done=true。pending 返回 done=false + 空错误。
func feishuQRPoll(ctx context.Context, token string, cfg *NotifyConfig) (done bool, err error) {
	feishuRegMu.Lock()
	sess, ok := feishuRegSessions[token]
	feishuRegMu.Unlock()
	if !ok {
		return false, fmt.Errorf("invalid or expired session token")
	}
	if time.Now().After(sess.ExpireAt) {
		feishuRegMu.Lock()
		delete(feishuRegSessions, token)
		feishuRegMu.Unlock()
		return false, fmt.Errorf("扫码会话已过期,请重新生成二维码")
	}
	baseURL := feishuAccountsBase
	if sess.IsLark {
		baseURL = larkAccountsBase
	}
	var pollRes feishuRegPollResp
	if err = feishuRegCall(ctx, baseURL, "poll", map[string]string{"device_code": sess.DeviceCode}, &pollRes); err != nil {
		return false, err
	}
	// 命中 lark 租户品牌时切换域名重试一次。
	if strings.EqualFold(strings.TrimSpace(pollRes.UserInfo.TenantBrand), "lark") && !sess.IsLark {
		sess.IsLark = true
		feishuRegMu.Lock()
		feishuRegSessions[token] = sess
		feishuRegMu.Unlock()
		return feishuQRPoll(ctx, token, cfg)
	}
	switch pollRes.Error {
	case "", "authorization_pending":
		return false, nil
	case "slow_down":
		return false, nil
	case "access_denied":
		return false, fmt.Errorf("用户拒绝了授权")
	case "expired_token":
		feishuRegMu.Lock()
		delete(feishuRegSessions, token)
		feishuRegMu.Unlock()
		return false, fmt.Errorf("扫码会话已过期,请重新生成二维码")
	}
	if pollRes.ClientID == "" || pollRes.ClientSecret == "" {
		if pollRes.Error != "" {
			return false, fmt.Errorf("%s: %s", pollRes.Error, pollRes.ErrorDescription)
		}
		return false, nil
	}
	// 成功:落库。
	cfg.Mode = feishuModeApp
	cfg.FeishuAppID = pollRes.ClientID
	cfg.FeishuAppSecret = pollRes.ClientSecret
	cfg.FeishuOpenID = pollRes.UserInfo.OpenID
	cfg.FeishuIsLark = sess.IsLark
	if err = saveNotifyConfig(cfg); err != nil {
		return false, err
	}
	feishuRegMu.Lock()
	delete(feishuRegSessions, token)
	feishuRegMu.Unlock()
	return true, nil
}

// ===== 飞书应用消息(1v1)=====

type feishuTenantTokenResp struct {
	Code              int    `json:"code"`
	Msg               string `json:"msg"`
	TenantAccessToken string `json:"tenant_access_token"`
	ExpireIn          int    `json:"expire"`
}

// feishuTenantAccessToken 用 app_id/app_secret 换 tenant_access_token。
// 结果带短期缓存(有效期内复用)。
type feishuTokenCacheEntry struct {
	token string
	expAt time.Time
}

var (
	feishuTokenMu    sync.Mutex
	feishuTokenCache feishuTokenCacheEntry
)

func feishuTenantAccessToken(ctx context.Context, cfg *NotifyConfig) (string, error) {
	feishuTokenMu.Lock()
	if feishuTokenCache.token != "" && time.Now().Before(feishuTokenCache.expAt.Add(-60*time.Second)) {
		t := feishuTokenCache.token
		feishuTokenMu.Unlock()
		return t, nil
	}
	feishuTokenMu.Unlock()

	base := feishuOpenBase
	if cfg.FeishuIsLark {
		base = larkOpenBase
	}
	body, _ := json.Marshal(map[string]string{
		"app_id":     cfg.FeishuAppID,
		"app_secret": cfg.FeishuAppSecret,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/open-apis/auth/v3/tenant_access_token/internal", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var tr feishuTenantTokenResp
	if err := json.Unmarshal(respBody, &tr); err != nil {
		return "", fmt.Errorf("decode tenant_access_token: %w", err)
	}
	if tr.Code != 0 {
		return "", fmt.Errorf("tenant_access_token: code=%d msg=%s", tr.Code, tr.Msg)
	}
	expIn := tr.ExpireIn
	if expIn <= 0 {
		expIn = 7200
	}
	feishuTokenMu.Lock()
	feishuTokenCache = feishuTokenCacheEntry{token: tr.TenantAccessToken, expAt: time.Now().Add(time.Duration(expIn) * time.Second)}
	feishuTokenMu.Unlock()
	return tr.TenantAccessToken, nil
}

// sendFeishuApp 用自建应用凭证给创建者发 1v1 文本消息。
func sendFeishuApp(ctx context.Context, cfg *NotifyConfig, message string) notifyResult {
	if cfg.FeishuAppID == "" || cfg.FeishuAppSecret == "" || cfg.FeishuOpenID == "" {
		return notifyResult{Err: fmt.Errorf("飞书应用凭证未配置(请先扫码建机器人)")}
	}
	tok, err := feishuTenantAccessToken(ctx, cfg)
	if err != nil {
		return notifyResult{Err: err}
	}
	base := feishuOpenBase
	if cfg.FeishuIsLark {
		base = larkOpenBase
	}
	target := base + "/open-apis/im/v1/messages?receive_id_type=open_id"
	payload, _ := json.Marshal(map[string]any{
		"receive_id": cfg.FeishuOpenID,
		"msg_type":   "text",
		"content":    fmt.Sprintf(`{"text":%q}`, message),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(payload))
	if err != nil {
		return notifyResult{Err: err}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return notifyResult{Err: fmt.Errorf("HTTP request: %w", err)}
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	bodyStr := strings.TrimSpace(string(respBody))
	// 飞书消息接口 HTTP 恒为 200,业务错误在 body.code 里。
	var biz struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
	}
	ok := resp.StatusCode == http.StatusOK
	if ok {
		_ = json.Unmarshal(respBody, &biz)
		if biz.Code != 0 {
			ok = false
			bodyStr = fmt.Sprintf("code=%d msg=%s", biz.Code, biz.Msg)
		}
	}
	return notifyResult{OK: ok, Status: resp.StatusCode, Body: bodyStr}
}
