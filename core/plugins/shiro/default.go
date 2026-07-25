/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package shiro

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"github.com/golang/groupcache/lru"
	uuid "github.com/satori/go.uuid"
	"math/big"
	"strings"
	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/utils/checker"
	logger "wscan/core/utils/log"
)

//go:embed "shirokeys.txt"
var fileShirokeys string

type defaultKey struct {
	domainFilter *checker.URLChecker
	cache        *lru.Cache
	cookieName   string
}

func Padding(plainText []byte, blockSize int) []byte {
	n := blockSize - len(plainText)%blockSize
	temp := bytes.Repeat([]byte{byte(n)}, n)
	plainText = append(plainText, temp...)
	return plainText
}

// AESCBCEncrypt 使用随机 IV 进行 AES-CBC 加密
func AESCBCEncrypt(key []byte, Content []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	Content = Padding(Content, block.BlockSize())
	iv := uuid.NewV4().Bytes()
	blockMode := cipher.NewCBCEncrypter(block, iv)
	cipherText := make([]byte, len(Content))
	blockMode.CryptBlocks(cipherText, Content)
	return base64.StdEncoding.EncodeToString(append(iv[:], cipherText[:]...)), nil
}

// AESCBCEncryptZeroIV 使用零 IV 进行 AES-CBC 加密（兼容 Java Shiro 默认模式）
// D1-02: 新增零 IV 模式，Java Shiro 默认使用零 IV
func AESCBCEncryptZeroIV(key []byte, Content []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	Content = Padding(Content, block.BlockSize())
	iv := make([]byte, aes.BlockSize) // 零 IV
	blockMode := cipher.NewCBCEncrypter(block, iv)
	cipherText := make([]byte, len(Content))
	blockMode.CryptBlocks(cipherText, Content)
	// 零 IV 模式不附加 IV 前缀（与 Java Shiro 行为一致）
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

// AESGCMEncrypt 使用 AES-GCM 模式加密（Shiro 1.4.2+ 支持）
// D1-02: 新增 GCM 模式，支持 Shiro 1.4.2+ 版本
func AESGCMEncrypt(key []byte, Content []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, 12) // GCM 标准 nonce 长度
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	cipherText := aesgcm.Seal(nil, nonce, Content, nil)
	// GCM 模式：nonce + ciphertext + tag
	return base64.StdEncoding.EncodeToString(append(nonce, cipherText...)), nil
}

func Randcase(len int) string {
	var container string
	var str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
	b := bytes.NewBufferString(str)
	length := b.Len()
	bigInt := big.NewInt(int64(length))
	for i := 0; i < len; i++ {
		randomInt, _ := rand.Int(rand.Reader, bigInt)
		container += string(str[randomInt.Int64()])
	}
	return container
}

var CheckContent = "rO0ABXNyADJvcmcuYXBhY2hlLnNoaXJvLnN1YmplY3QuU2ltcGxlUHJpbmNpcGFsQ29sbGVjdGlvbqh/WCXGowhKAwABTAAPcmVhbG1QcmluY2lwYWxzdAAPTGphdmEvdXRpbC9NYXA7eHBwdwEAeA=="
var ShiroKeys = []string{}

// containsDeleteMeInCookies 检查 Set-Cookie 响应头中是否包含精确的 deleteMe 标记
// D1-03: 使用精确匹配 cookieName+"=deleteMe" 而非 strings.Contains(setCookieAll, "deleteMe")
func containsDeleteMeInCookies(setCookieHeaders []string, cookieName string) bool {
	for _, cookie := range setCookieHeaders {
		// 逐个检查每个 Set-Cookie 头，精确匹配 cookieName=deleteMe
		if strings.Contains(cookie, cookieName+"=deleteMe") {
			return true
		}
	}
	return false
}

func (p *defaultKey) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			cookieName := "rememberMe"
			if p.cookieName != "" {
				cookieName = p.cookieName
			}
			req, _ := http.NewRequest("GET", flow.Request.URL().String(), nil)
			req.SetHeader("Cookie", cookieName+"=1")
			res, err := a.HTTPClient.Respond(ctx, req)
			if err != nil {
				logger.Error(err)
				return nil
			}

			// D1-03: 使用精确匹配检查 deleteMe
			if !containsDeleteMeInCookies(res.Header["Set-Cookie"], cookieName) {
				return nil
			}

			logger.Debugf("发现Shiro框架，开始尝试 defaultKey, %s", flow.Request.URL().String())
			content, _ := base64.StdEncoding.DecodeString(CheckContent)

			for _, shiroKey := range ShiroKeys {
				keyDecrypt, _ := base64.StdEncoding.DecodeString(shiroKey)

				// D1-02: 对每个 key 尝试三种加密模式
				var found bool

				// 模式1: CBC-零IV (Java Shiro 默认模式，最常见)
				RememberMe, err := AESCBCEncryptZeroIV(keyDecrypt, content)
				if err == nil {
					found = checkDefaultKey(ctx, a, flow.Request.URL().String(), cookieName, RememberMe, res.Header["Set-Cookie"])
				}

				// 模式2: CBC-随机IV
				if !found {
					RememberMe, err = AESCBCEncrypt(keyDecrypt, content)
					if err == nil {
						found = checkDefaultKey(ctx, a, flow.Request.URL().String(), cookieName, RememberMe, res.Header["Set-Cookie"])
					}
				}

				// 模式3: GCM (Shiro 1.4.2+)
				if !found {
					RememberMe, err = AESGCMEncrypt(keyDecrypt, content)
					if err == nil {
						found = checkDefaultKey(ctx, a, flow.Request.URL().String(), cookieName, RememberMe, res.Header["Set-Cookie"])
					}
				}

				if found {
					// key 有效，报告漏洞并退出
					return nil
				}
			}
			return nil
		},
		Channel: "web-path",
		Binding: &model.VulnBinding{ID: "shiro/shiro/default-key", Plugin: "shiro/shiro/default-key", Category: "shiro/shiro/default-key", Severity: model.SeverityHigh},
	}
}

// checkDefaultKey 检查默认 key 是否有效
// D1-03: 增加与 baseline 响应的交叉验证，减少对非 Shiro 应用的误判
func checkDefaultKey(ctx context.Context, a *base.Apollo, urlStr, cookieName, rememberMe string, baselineSetCookies []string) bool {
	req, _ := http.NewRequest("GET", urlStr, nil)
	req.SetHeader("Cookie", "JSESSIONID="+Randcase(8)+";"+cookieName+"="+rememberMe)
	res, err := a.HTTPClient.Respond(ctx, req)
	if err != nil {
		logger.Error(err)
		return false
	}

	// D1-03: 使用精确匹配检查 deleteMe
	if containsDeleteMeInCookies(res.Header["Set-Cookie"], cookieName) {
		// 返回了 deleteMe，说明 key 不正确
		return false
	}

	// D1-03: 交叉验证 - 检查响应状态码是否合理
	// 如果 key 有效，Shiro 应该不会返回 deleteMe 且响应正常
	if res.StatusCode >= 500 {
		// 500 错误可能是解密失败导致的异常，不一定是 key 有效
		return false
	}

	// 报告漏洞
	v := a.NewWebVuln(req, res, nil)
	if v != nil {
		v.SetTargetURL(req.URL())
		v.Payload = rememberMe
		a.OutputVuln(v)
	}
	return true
}
