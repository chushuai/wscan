/**
* @Author: shaochuyu
* @Date: 6/16/2026
 */
package cookiekey

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	logger "wscan/core/utils/log"
)

// CookieKey is the plugin struct for Cookie weak key brute-force detection.
type CookieKey struct {
	base.PluginMixinInitConfig
	base.PluginMixinClose
}

// Config holds the plugin configuration.
type Config struct {
	base.PluginBaseConfig `json:",inline" yaml:",inline"`
	CheckDjango           bool `json:"check_django" yaml:"check_django" #:"检测Django Cookie弱密钥"`
	CheckFlask            bool `json:"check_flask" yaml:"check_flask" #:"检测Flask Cookie弱密钥"`
	CheckExpress          bool `json:"check_express" yaml:"check_express" #:"检测Express Cookie弱密钥"`
	CheckJWT              bool `json:"check_jwt" yaml:"check_jwt" #:"检测JWT弱密钥"`
	CheckRack             bool `json:"check_rack" yaml:"check_rack" #:"检测Rack Cookie弱密钥"`
	CheckTornado          bool `json:"check_tornado" yaml:"check_tornado" #:"检测Tornado Cookie弱密钥"`
	CheckWeb2py           bool `json:"check_web2py" yaml:"check_web2py" #:"检测Web2py Cookie弱密钥"`
	CheckYii2             bool `json:"check_yii2" yaml:"check_yii2" #:"检测Yii2 Cookie弱密钥"`
	CheckLaravel          bool `json:"check_laravel" yaml:"check_laravel" #:"检测Laravel Cookie弱密钥"`
	CheckBeaker           bool `json:"check_beaker" yaml:"check_beaker" #:"检测Beaker Cookie弱密钥"`
	CheckBottlePy         bool `json:"check_bottlepy" yaml:"check_bottlepy" #:"检测BottlePy Cookie弱密钥"`
	CheckPyramid          bool `json:"check_pyramid" yaml:"check_pyramid" #:"检测Pyramid Cookie弱密钥"`
}

func (c *Config) BaseConfig() *base.PluginBaseConfig {
	return &c.PluginBaseConfig
}

// Close shuts down the plugin.
func (*CookieKey) Close() error {
	return nil
}

// DefaultConfig returns the default plugin configuration.
func (*CookieKey) DefaultConfig() base.PluginConfigInterface {
	return &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:       "cookiekey",
			Enabled:    false,
			IsAdvanced: true,
		},
		CheckDjango:   true,
		CheckFlask:    true,
		CheckExpress:  true,
		CheckJWT:      true,
		CheckRack:     true,
		CheckTornado:  true,
		CheckWeb2py:   true,
		CheckYii2:     true,
		CheckLaravel:  true,
		CheckBeaker:   true,
		CheckBottlePy: true,
		CheckPyramid:  true,
	}
}

// Fingers returns the detection rules based on the enabled config flags.
func (p *CookieKey) Fingers() []*base.Finger {
	cfg, ok := p.GetConfig().(*Config)
	if !ok || cfg == nil {
		return nil
	}
	fingers := []*base.Finger{}
	if cfg.CheckDjango {
		fingers = append(fingers, (&djangoCookieCheck{}).Finger())
	}
	if cfg.CheckFlask {
		fingers = append(fingers, (&flaskCookieCheck{}).Finger())
	}
	if cfg.CheckExpress {
		fingers = append(fingers, (&expressCookieSessionCheck{}).Finger())
		fingers = append(fingers, (&expressSessionCheck{}).Finger())
	}
	if cfg.CheckJWT {
		fingers = append(fingers, (&jwtCheck{}).Finger())
	}
	if cfg.CheckRack {
		fingers = append(fingers, (&rackCookieCheck{}).Finger())
	}
	if cfg.CheckTornado {
		fingers = append(fingers, (&tornadoCookieCheck{}).Finger())
	}
	if cfg.CheckWeb2py {
		fingers = append(fingers, (&web2pyCookieCheck{}).Finger())
	}
	if cfg.CheckYii2 {
		fingers = append(fingers, (&yii2CookieCheck{}).Finger())
	}
	if cfg.CheckLaravel {
		fingers = append(fingers, (&laravelCookieCheck{}).Finger())
	}
	if cfg.CheckBeaker {
		fingers = append(fingers, (&beakerCookieCheck{}).Finger())
	}
	if cfg.CheckBottlePy {
		fingers = append(fingers, (&bottlePyCookieCheck{}).Finger())
	}
	if cfg.CheckPyramid {
		fingers = append(fingers, (&pyramidCookieCheck{}).Finger())
	}
	return fingers
}

// GetConfig returns the current plugin configuration.
func (p *CookieKey) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

// Init initializes the plugin.
func (p *CookieKey) Init(ctx context.Context, pci base.PluginConfigInterface, ab *base.ApolloBase) error {
	logger.Debug("CookieKey init")
	return p.PluginMixinInitConfig.Init(ctx, pci, ab)
}

// ============================================================================
// Django Cookie Check
// ============================================================================

type djangoCookieCheck struct{}

func (*djangoCookieCheck) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			cookies := flow.Response.Cookies()
			for _, cookie := range cookies {
				if http.IsCookieExpired(cookie) {
					continue
				}
				value := cookie.Value
				if found, key := checkDjangoCookie(value); found {
					v := a.NewWebVuln(flow.Request, flow.Response, nil)
					if v != nil {
						v.SetTargetURL(flow.Request.URL())
						v.Payload = "Django Cookie weak key found: " + key
						v.Add("framework", "django")
						v.Add("cookie_name", cookie.Name)
						v.Add("weak_key", key)
						a.OutputVuln(v)
					}
					return nil
				}
			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{
			ID:       "cookiekey/django/weak-key",
			Plugin:   "cookiekey/django/weak-key",
			Category: "cookiekey/django/weak-key",
			Severity: model.SeverityCritical,
		},
	}
}

// checkDjangoCookie checks if a cookie value matches the Django signed cookie format
// and can be verified with a known weak key.
// Django format: value:timestamp:signature
// Algorithm: HMAC-SHA1 with derived key = SHA1(key + salt)
func checkDjangoCookie(cookieValue string) (bool, string) {
	// Django session cookies use the format: value:timestamp:signature
	parts := strings.Split(cookieValue, ":")
	if len(parts) != 3 {
		return false, ""
	}
	value := parts[0]
	timestamp := parts[1]
	signature := parts[2]

	// Validate that the timestamp and signature are present
	if timestamp == "" || signature == "" {
		return false, ""
	}

	// Try Django session salt first, then the signing salt
	salts := []string{
		"django.contrib.sessions.backends.session",
		"django.core.signing",
	}

	keys := append(CommonWeakKeys, DjangoWeakKeys...)

	for _, key := range keys {
		for _, salt := range salts {
			if verifyDjangoSignature(value, timestamp, signature, key, salt) {
				return true, key
			}
		}
	}
	return false, ""
}

// verifyDjangoSignature verifies a Django signed cookie signature.
// derived_key = SHA1(key + salt)
// expected = HMAC-SHA1(derived_key, value + ":" + timestamp)
func verifyDjangoSignature(value, timestamp, signature, secretKey, salt string) bool {
	// Compute derived key: SHA1(key + salt)
	h := sha1.New()
	h.Write([]byte(secretKey + salt))
	derivedKey := h.Sum(nil)

	// Compute HMAC-SHA1(derivedKey, value + ":" + timestamp)
	mac := hmac.New(sha1.New, derivedKey)
	mac.Write([]byte(value + ":" + timestamp))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(expectedSig), []byte(signature))
}

// ============================================================================
// Flask Cookie Check
// ============================================================================

type flaskCookieCheck struct{}

func (*flaskCookieCheck) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			cookies := flow.Response.Cookies()
			for _, cookie := range cookies {
				if http.IsCookieExpired(cookie) {
					continue
				}
				value := cookie.Value
				if found, key := checkFlaskCookie(value); found {
					v := a.NewWebVuln(flow.Request, flow.Response, nil)
					if v != nil {
						v.SetTargetURL(flow.Request.URL())
						v.Payload = "Flask Cookie weak key found: " + key
						v.Add("framework", "flask")
						v.Add("cookie_name", cookie.Name)
						v.Add("weak_key", key)
						a.OutputVuln(v)
					}
					return nil
				}
			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{
			ID:       "cookiekey/flask/weak-key",
			Plugin:   "cookiekey/flask/weak-key",
			Category: "cookiekey/flask/weak-key",
			Severity: model.SeverityCritical,
		},
	}
}

// checkFlaskCookie checks if a cookie value matches the Flask session cookie format.
// Flask (itsdangerous) format: payload.timestamp.signature
// The payload is base64-encoded JSON, timestamp is base64-encoded integer,
// and signature is HMAC-SHA1 of "payload.timestamp" using the secret key.
func checkFlaskCookie(cookieValue string) (bool, string) {
	// Flask session cookies use the format: payload.timestamp.signature
	// separated by dots
	parts := strings.Split(cookieValue, ".")
	if len(parts) != 3 {
		return false, ""
	}
	payload := parts[0]
	timestamp := parts[1]
	signature := parts[2]

	if payload == "" || timestamp == "" || signature == "" {
		return false, ""
	}

	// Validate that the payload looks like base64-encoded JSON
	decodedPayload, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		// Try standard base64 encoding
		decodedPayload, err = base64.StdEncoding.DecodeString(payload)
		if err != nil {
			return false, ""
		}
	}
	// Check if the decoded payload looks like JSON
	if len(decodedPayload) == 0 || decodedPayload[0] != '{' {
		return false, ""
	}

	keys := append(CommonWeakKeys, FlaskWeakKeys...)

	for _, key := range keys {
		if verifyFlaskSignature(payload, timestamp, signature, key) {
			return true, key
		}
	}
	return false, ""
}

// verifyFlaskSignature verifies a Flask (itsdangerous) signed cookie signature.
// signature = base64url(HMAC-SHA1(key, "payload.timestamp"))
func verifyFlaskSignature(payload, timestamp, signature, secretKey string) bool {
	data := payload + "." + timestamp
	mac := hmac.New(sha1.New, []byte(secretKey))
	mac.Write([]byte(data))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(expectedSig), []byte(signature))
}

// ============================================================================
// Express cookie-session Check
// ============================================================================

type expressCookieSessionCheck struct{}

func (*expressCookieSessionCheck) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			cookies := flow.Response.Cookies()

			// Build a map of cookie names to values for lookup
			cookieMap := make(map[string]string)
			for _, cookie := range cookies {
				if http.IsCookieExpired(cookie) {
					continue
				}
				cookieMap[cookie.Name] = cookie.Value
			}

			// Express cookie-session: value + ".sig" companion cookie
			// The .sig cookie contains HMAC-SHA1(key, value)
			for name, value := range cookieMap {
				sigName := name + ".sig"
				sigValue, hasSig := cookieMap[sigName]
				if !hasSig {
					continue
				}
				if value == "" || sigValue == "" {
					continue
				}
				if found, key := checkExpressCookieSession(value, sigValue); found {
					v := a.NewWebVuln(flow.Request, flow.Response, nil)
					if v != nil {
						v.SetTargetURL(flow.Request.URL())
						v.Payload = "Express cookie-session weak key found: " + key
						v.Add("framework", "express-cookie-session")
						v.Add("cookie_name", name)
						v.Add("sig_cookie_name", sigName)
						v.Add("weak_key", key)
						a.OutputVuln(v)
					}
					return nil
				}
			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{
			ID:       "cookiekey/express-cookie-session/weak-key",
			Plugin:   "cookiekey/express-cookie-session/weak-key",
			Category: "cookiekey/express-cookie-session/weak-key",
			Severity: model.SeverityCritical,
		},
	}
}

// checkExpressCookieSession checks Express cookie-session format.
// The .sig cookie = base64url(HMAC-SHA1(key, value))
func checkExpressCookieSession(value, sigValue string) (bool, string) {
	keys := append(CommonWeakKeys, ExpressWeakKeys...)

	for _, key := range keys {
		if verifyExpressCookieSessionSig(value, sigValue, key) {
			return true, key
		}
	}
	return false, ""
}

// verifyExpressCookieSessionSig verifies an Express cookie-session signature.
// sig = base64url(HMAC-SHA1(key, value))
func verifyExpressCookieSessionSig(value, sigValue, secretKey string) bool {
	mac := hmac.New(sha1.New, []byte(secretKey))
	mac.Write([]byte(value))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(expectedSig), []byte(sigValue))
}

// ============================================================================
// Express express-session Check
// ============================================================================

type expressSessionCheck struct{}

func (*expressSessionCheck) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			cookies := flow.Response.Cookies()

			// Build a map of cookie names to values for lookup
			cookieMap := make(map[string]string)
			for _, cookie := range cookies {
				if http.IsCookieExpired(cookie) {
					continue
				}
				cookieMap[cookie.Name] = cookie.Value
			}

			// Express express-session: cookie value has format "s:value.signature"
			// The signature part is HMAC-SHA256(key, "s:value")
			for name, cookieValue := range cookieMap {
				if !strings.HasPrefix(cookieValue, "s:") {
					continue
				}
				// Remove the "s:" prefix
				inner := cookieValue[2:]
				dotIdx := strings.LastIndex(inner, ".")
				if dotIdx <= 0 {
					continue
				}
				value := inner[:dotIdx]
				signature := inner[dotIdx+1:]
				if value == "" || signature == "" {
					continue
				}
				if found, key := checkExpressSession(value, signature); found {
					v := a.NewWebVuln(flow.Request, flow.Response, nil)
					if v != nil {
						v.SetTargetURL(flow.Request.URL())
						v.Payload = "Express express-session weak key found: " + key
						v.Add("framework", "express-session")
						v.Add("cookie_name", name)
						v.Add("weak_key", key)
						a.OutputVuln(v)
					}
					return nil
				}
			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{
			ID:       "cookiekey/express-session/weak-key",
			Plugin:   "cookiekey/express-session/weak-key",
			Category: "cookiekey/express-session/weak-key",
			Severity: model.SeverityCritical,
		},
	}
}

// checkExpressSession checks Express express-session format.
// signature = base64url(HMAC-SHA256(key, "s:" + value))
func checkExpressSession(value, signature string) (bool, string) {
	keys := append(CommonWeakKeys, ExpressWeakKeys...)

	for _, key := range keys {
		if verifyExpressSessionSig(value, signature, key) {
			return true, key
		}
	}
	return false, ""
}

// verifyExpressSessionSig verifies an Express express-session signature.
// sig = base64url(HMAC-SHA256(key, "s:" + value))
func verifyExpressSessionSig(value, signature, secretKey string) bool {
	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write([]byte("s:" + value))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(expectedSig), []byte(signature))
}

// ============================================================================
// JWT Check
// ============================================================================

type jwtCheck struct{}

func (*jwtCheck) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			cookies := flow.Response.Cookies()
			for _, cookie := range cookies {
				if http.IsCookieExpired(cookie) {
					continue
				}
				value := cookie.Value
				if found, key, alg := checkJWTCookie(value); found {
					v := a.NewWebVuln(flow.Request, flow.Response, nil)
					if v != nil {
						v.SetTargetURL(flow.Request.URL())
						v.Payload = "JWT weak key found (" + alg + "): " + key
						v.Add("framework", "jwt")
						v.Add("cookie_name", cookie.Name)
						v.Add("weak_key", key)
						v.Add("algorithm", alg)
						a.OutputVuln(v)
					}
					return nil
				}
			}
			// Also check Authorization header for JWT Bearer tokens
			authHeader := flow.Request.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				token := strings.TrimPrefix(authHeader, "Bearer ")
				if found, key, alg := checkJWTCookie(token); found {
					v := a.NewWebVuln(flow.Request, flow.Response, nil)
					if v != nil {
						v.SetTargetURL(flow.Request.URL())
						v.Payload = "JWT weak key found (" + alg + "): " + key
						v.Add("framework", "jwt")
						v.Add("source", "authorization_header")
						v.Add("weak_key", key)
						v.Add("algorithm", alg)
						a.OutputVuln(v)
					}
					return nil
				}
			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{
			ID:       "cookiekey/jwt/weak-key",
			Plugin:   "cookiekey/jwt/weak-key",
			Category: "cookiekey/jwt/weak-key",
			Severity: model.SeverityCritical,
		},
	}
}

// checkJWTCookie checks if a value is a JWT and can be verified with a weak key.
// JWT format: header.payload.signature (three base64url-encoded segments)
func checkJWTCookie(token string) (bool, string, string) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false, "", ""
	}

	headerB64 := parts[0]
	payloadB64 := parts[1]
	signatureB64 := parts[2]

	if headerB64 == "" || payloadB64 == "" || signatureB64 == "" {
		return false, "", ""
	}

	// Decode the header to get the algorithm
	headerJSON, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		return false, "", ""
	}

	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return false, "", ""
	}

	// Only check HMAC-based algorithms (HS256, HS384, HS512)
	alg := strings.ToUpper(header.Alg)
	if alg != "HS256" && alg != "HS384" && alg != "HS512" {
		return false, "", ""
	}

	// Decode the signature
	signature, err := base64.RawURLEncoding.DecodeString(signatureB64)
	if err != nil {
		return false, "", ""
	}

	// The signing input is "header.payload"
	signingInput := headerB64 + "." + payloadB64

	keys := append(CommonWeakKeys, JWTWeakKeys...)

	for _, key := range keys {
		if verifyJWTSignature(signingInput, signature, key, alg) {
			return true, key, alg
		}
	}
	return false, "", ""
}

// verifyJWTSignature verifies a JWT HMAC signature.
func verifyJWTSignature(signingInput string, signature []byte, secretKey string, alg string) bool {
	switch alg {
	case "HS256":
		mac := hmac.New(sha256.New, []byte(secretKey))
		mac.Write([]byte(signingInput))
		expectedSig := mac.Sum(nil)
		return hmac.Equal(signature, expectedSig)
	case "HS384":
		mac := hmac.New(sha512.New384, []byte(secretKey))
		mac.Write([]byte(signingInput))
		expectedSig := mac.Sum(nil)
		return hmac.Equal(signature, expectedSig)
	case "HS512":
		mac := hmac.New(sha512.New, []byte(secretKey))
		mac.Write([]byte(signingInput))
		expectedSig := mac.Sum(nil)
		return hmac.Equal(signature, expectedSig)
	default:
		return false
	}
}

// ============================================================================
// Rack/Ruby Cookie Check
// ============================================================================

type rackCookieCheck struct{}

func (*rackCookieCheck) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			cookies := flow.Response.Cookies()
			for _, cookie := range cookies {
				if http.IsCookieExpired(cookie) {
					continue
				}
				value := cookie.Value
				if found, key := checkRackCookie(value); found {
					v := a.NewWebVuln(flow.Request, flow.Response, nil)
					if v != nil {
						v.SetTargetURL(flow.Request.URL())
						v.Payload = "Rack/Rails Cookie weak key found: " + key
						v.Add("framework", "rack")
						v.Add("cookie_name", cookie.Name)
						v.Add("weak_key", key)
						a.OutputVuln(v)
					}
					return nil
				}
			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{
			ID:       "cookiekey/rack/weak-key",
			Plugin:   "cookiekey/rack/weak-key",
			Category: "cookiekey/rack/weak-key",
			Severity: model.SeverityCritical,
		},
	}
}

// checkRackCookie checks if a cookie value matches the Rack/Rails session format.
// Rack format: data--signature
// The data is base64-encoded marshaled Ruby object,
// and signature is HMAC-SHA1(secret_key_base, data)
func checkRackCookie(cookieValue string) (bool, string) {
	// Rack/Rails session cookies use the format: data--signature
	sepIdx := strings.LastIndex(cookieValue, "--")
	if sepIdx <= 0 {
		return false, ""
	}
	data := cookieValue[:sepIdx]
	signature := cookieValue[sepIdx+2:]

	if data == "" || signature == "" {
		return false, ""
	}

	// Validate that the data looks like base64
	if _, err := base64.StdEncoding.DecodeString(data); err != nil {
		if _, err := base64.RawStdEncoding.DecodeString(data); err != nil {
			return false, ""
		}
	}

	keys := append(CommonWeakKeys, RackWeakKeys...)

	for _, key := range keys {
		if verifyRackSignature(data, signature, key) {
			return true, key
		}
	}
	return false, ""
}

// verifyRackSignature verifies a Rack/Rails session cookie signature.
// signature = hex(HMAC-SHA1(secret_key_base, data))
func verifyRackSignature(data, signature, secretKey string) bool {
	mac := hmac.New(sha1.New, []byte(secretKey))
	mac.Write([]byte(data))
	expectedSig := fmt.Sprintf("%x", mac.Sum(nil))

	return hmac.Equal([]byte(expectedSig), []byte(signature))
}

// ============================================================================
// Tornado Cookie Check
// ============================================================================

type tornadoCookieCheck struct{}

func (*tornadoCookieCheck) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			cookies := flow.Response.Cookies()
			for _, cookie := range cookies {
				if http.IsCookieExpired(cookie) {
					continue
				}
				value := cookie.Value
				if found, key := checkTornadoCookie(cookie.Name, value); found {
					v := a.NewWebVuln(flow.Request, flow.Response, nil)
					if v != nil {
						v.SetTargetURL(flow.Request.URL())
						v.Payload = "Tornado Cookie weak key found: " + key
						v.Add("framework", "tornado")
						v.Add("cookie_name", cookie.Name)
						v.Add("weak_key", key)
						a.OutputVuln(v)
					}
					return nil
				}
			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{
			ID:       "cookiekey/tornado/weak-key",
			Plugin:   "cookiekey/tornado/weak-key",
			Category: "cookiekey/tornado/weak-key",
			Severity: model.SeverityCritical,
		},
	}
}

// checkTornadoCookie checks if a cookie value matches the Tornado signed cookie format.
// Tornado v1 format: value|timestamp|signature (3 parts, signature is hex SHA1 HMAC)
// Tornado v2 format: version|fields...|signature (6 parts, signature is hex SHA256 HMAC)
// v1: HMAC-SHA1(secret, cookie_name + value + timestamp)
// v2: HMAC-SHA256(secret, all_parts_before_signature)
func checkTornadoCookie(cookieName, cookieValue string) (bool, string) {
	// Strip surrounding quotes if present
	cleanValue := strings.Trim(cookieValue, "\"")

	if !strings.Contains(cleanValue, "|") {
		return false, ""
	}

	parts := strings.Split(cleanValue, "|")

	// Tornado v1: value|timestamp|signature (3 parts)
	// signature is 40 hex chars (SHA1)
	if len(parts) == 3 {
		signature := parts[2]
		if !isHex(signature) || len(signature) != 40 {
			return false, ""
		}
		value := parts[0]
		timestamp := parts[1]
		// HMAC input for v1: cookie_name + value + timestamp
		hmacInput := cookieName + value + timestamp

		keys := append(CommonWeakKeys, TornadoWeakKeys...)
		for _, key := range keys {
			if verifyTornadoV1Signature(hmacInput, signature, key) {
				return true, key
			}
		}
		return false, ""
	}

	// Tornado v2: version|1:0|10:timestamp|8:name|12:value|signature (6 parts)
	// signature is 64 hex chars (SHA256)
	if len(parts) == 6 {
		signature := parts[5]
		if !isHex(signature) || len(signature) != 64 {
			return false, ""
		}
		// HMAC input for v2: the entire string before the last "|"
		lastPipeIdx := strings.LastIndex(cleanValue, "|")
		if lastPipeIdx <= 0 {
			return false, ""
		}
		hmacInput := cleanValue[:lastPipeIdx]

		keys := append(CommonWeakKeys, TornadoWeakKeys...)
		for _, key := range keys {
			if verifyTornadoV2Signature(hmacInput, signature, key) {
				return true, key
			}
		}
		return false, ""
	}

	return false, ""
}

// verifyTornadoV1Signature verifies a Tornado v1 cookie signature.
// signature = hex(HMAC-SHA1(secret, hmacInput))
func verifyTornadoV1Signature(hmacInput, signature, secretKey string) bool {
	mac := hmac.New(sha1.New, []byte(secretKey))
	mac.Write([]byte(hmacInput))
	expectedSig := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expectedSig), []byte(signature))
}

// verifyTornadoV2Signature verifies a Tornado v2 cookie signature.
// signature = hex(HMAC-SHA256(secret, hmacInput))
func verifyTornadoV2Signature(hmacInput, signature, secretKey string) bool {
	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write([]byte(hmacInput))
	expectedSig := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expectedSig), []byte(signature))
}

// isHex checks if a string is a valid hexadecimal string.
func isHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil
}

// ============================================================================
// Web2py Cookie Check
// ============================================================================

type web2pyCookieCheck struct{}

func (*web2pyCookieCheck) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			cookies := flow.Response.Cookies()
			for _, cookie := range cookies {
				if http.IsCookieExpired(cookie) {
					continue
				}
				value := cookie.Value
				if found, key := checkWeb2pyCookie(value); found {
					v := a.NewWebVuln(flow.Request, flow.Response, nil)
					if v != nil {
						v.SetTargetURL(flow.Request.URL())
						v.Payload = "Web2py Cookie weak key found: " + key
						v.Add("framework", "web2py")
						v.Add("cookie_name", cookie.Name)
						v.Add("weak_key", key)
						a.OutputVuln(v)
					}
					return nil
				}
			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{
			ID:       "cookiekey/web2py/weak-key",
			Plugin:   "cookiekey/web2py/weak-key",
			Category: "cookiekey/web2py/weak-key",
			Severity: model.SeverityCritical,
		},
	}
}

// checkWeb2pyCookie checks if a cookie value matches the Web2py session cookie format.
// Web2py format: md5_hmac:session_data
// The HMAC is computed as: HMAC-MD5(SHA1(secret), session_data)
func checkWeb2pyCookie(cookieValue string) (bool, string) {
	// Strip surrounding quotes if present
	cleanValue := strings.Trim(cookieValue, "\"")

	// Web2py format: <32-hex-char-md5>:<session_data>
	web2pyRe := regexp.MustCompile(`^([0-9a-f]{32}):(.+)$`)
	matches := web2pyRe.FindStringSubmatch(cleanValue)
	if matches == nil || len(matches) != 3 {
		return false, ""
	}

	signature := matches[1]
	data := matches[2]
	if signature == "" || data == "" {
		return false, ""
	}

	keys := append(CommonWeakKeys, Web2pyWeakKeys...)
	for _, key := range keys {
		if verifyWeb2pySignature(data, signature, key) {
			return true, key
		}
	}
	return false, ""
}

// verifyWeb2pySignature verifies a Web2py session cookie signature.
// derived_key = SHA1(secret)
// signature = hex(HMAC-MD5(derived_key, data))
func verifyWeb2pySignature(data, signature, secretKey string) bool {
	// Compute SHA1 of the secret key
	h := sha1.New()
	h.Write([]byte(secretKey))
	sha1Key := h.Sum(nil)

	// Compute HMAC-MD5 using the SHA1 hash as the key
	mac := hmac.New(md5.New, sha1Key)
	mac.Write([]byte(data))
	expectedSig := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expectedSig), []byte(signature))
}

// ============================================================================
// Yii2 Cookie Check
// ============================================================================

type yii2CookieCheck struct{}

// yii2CSRFNameRe matches Yii2 CSRF cookie names
var yii2CSRFNameRe = regexp.MustCompile(`^_csrf`)

func (*yii2CookieCheck) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			cookies := flow.Response.Cookies()
			for _, cookie := range cookies {
				if http.IsCookieExpired(cookie) {
					continue
				}
				// Yii2 typically uses _csrf cookie names
				if !yii2CSRFNameRe.MatchString(cookie.Name) {
					continue
				}
				value := cookie.Value
				if found, key := checkYii2Cookie(value); found {
					v := a.NewWebVuln(flow.Request, flow.Response, nil)
					if v != nil {
						v.SetTargetURL(flow.Request.URL())
						v.Payload = "Yii2 Cookie weak key found: " + key
						v.Add("framework", "yii2")
						v.Add("cookie_name", cookie.Name)
						v.Add("weak_key", key)
						a.OutputVuln(v)
					}
					return nil
				}
			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{
			ID:       "cookiekey/yii2/weak-key",
			Plugin:   "cookiekey/yii2/weak-key",
			Category: "cookiekey/yii2/weak-key",
			Severity: model.SeverityCritical,
		},
	}
}

// checkYii2Cookie checks if a cookie value matches the Yii2 CSRF cookie format.
// Yii2 format: <64-hex-char-sha256-hmac><url-encoded-data>
// The HMAC is computed as: HMAC-SHA256(validationKey, data)
func checkYii2Cookie(cookieValue string) (bool, string) {
	// Yii2 format: <64-hex-signature><url-encoded-value>
	// The signature is the first 64 hex chars, the rest is URL-encoded PHP serialized data
	yii2Re := regexp.MustCompile(`^([0-9a-f]{64})(.+)$`)
	matches := yii2Re.FindStringSubmatch(cookieValue)
	if matches == nil || len(matches) != 3 {
		return false, ""
	}

	signature := matches[1]
	encodedData := matches[2]
	if signature == "" || encodedData == "" {
		return false, ""
	}

	// URL-decode the data part
	data, err := url.QueryUnescape(encodedData)
	if err != nil {
		data = encodedData
	}

	keys := append(CommonWeakKeys, Yii2WeakKeys...)
	for _, key := range keys {
		if verifyYii2Signature(data, signature, key) {
			return true, key
		}
	}
	return false, ""
}

// verifyYii2Signature verifies a Yii2 cookie signature.
// signature = hex(HMAC-SHA256(validationKey, data))
func verifyYii2Signature(data, signature, secretKey string) bool {
	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write([]byte(data))
	expectedSig := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expectedSig), []byte(signature))
}

// ============================================================================
// Laravel Cookie Check
// ============================================================================

type laravelCookieCheck struct{}

func (*laravelCookieCheck) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			cookies := flow.Response.Cookies()
			for _, cookie := range cookies {
				if http.IsCookieExpired(cookie) {
					continue
				}
				value := cookie.Value
				if found, key := checkLaravelCookie(value); found {
					v := a.NewWebVuln(flow.Request, flow.Response, nil)
					if v != nil {
						v.SetTargetURL(flow.Request.URL())
						v.Payload = "Laravel Cookie weak key found: " + key
						v.Add("framework", "laravel")
						v.Add("cookie_name", cookie.Name)
						v.Add("weak_key", key)
						a.OutputVuln(v)
					}
					return nil
				}
			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{
			ID:       "cookiekey/laravel/weak-key",
			Plugin:   "cookiekey/laravel/weak-key",
			Category: "cookiekey/laravel/weak-key",
			Severity: model.SeverityCritical,
		},
	}
}

// checkLaravelCookie checks if a cookie value matches the Laravel encrypted cookie format.
// Laravel format: base64(HMAC-SHA256(key, value))
// The cookie value is base64-encoded, and the MAC is included in the serialized payload.
// Laravel uses base64-encoded APP_KEY (with "base64:" prefix stripped).
func checkLaravelCookie(cookieValue string) (bool, string) {
	// Laravel cookies are base64-encoded JSON containing "iv", "value", and "mac" fields
	decoded, err := base64.StdEncoding.DecodeString(cookieValue)
	if err != nil {
		// Try URL-safe base64
		decoded, err = base64.RawURLEncoding.DecodeString(cookieValue)
		if err != nil {
			return false, ""
		}
	}

	// Check if it looks like JSON
	decodedStr := string(decoded)
	if !strings.HasPrefix(decodedStr, "{") {
		return false, ""
	}

	// Parse the Laravel encrypted cookie structure
	var laravelCookie struct {
		IV    string `json:"iv"`
		Value string `json:"value"`
		Mac   string `json:"mac"`
	}
	if err := json.Unmarshal(decoded, &laravelCookie); err != nil {
		return false, ""
	}

	if laravelCookie.IV == "" || laravelCookie.Value == "" || laravelCookie.Mac == "" {
		return false, ""
	}

	keys := append(CommonWeakKeys, LaravelWeakKeys...)
	for _, key := range keys {
		if verifyLaravelSignature(laravelCookie.IV, laravelCookie.Value, laravelCookie.Mac, key) {
			return true, key
		}
	}
	return false, ""
}

// verifyLaravelSignature verifies a Laravel encrypted cookie MAC.
// MAC = HMAC-SHA256(key, iv + value)
// The key is base64-decoded from the APP_KEY value (after stripping "base64:" prefix).
func verifyLaravelSignature(iv, value, mac, secretKey string) bool {
	// Laravel APP_KEY may be prefixed with "base64:"
	rawKey := secretKey
	if strings.HasPrefix(secretKey, "base64:") {
		rawKey = strings.TrimPrefix(secretKey, "base64:")
	}

	// Try to base64-decode the key (Laravel stores keys as base64)
	keyBytes, err := base64.StdEncoding.DecodeString(rawKey)
	if err != nil {
		// If it's not base64, use the raw key
		keyBytes = []byte(rawKey)
	}

	// MAC = HMAC-SHA256(key, iv + value)
	payload := iv + value
	h := hmac.New(sha256.New, keyBytes)
	h.Write([]byte(payload))
	expectedMac := hex.EncodeToString(h.Sum(nil))

	return hmac.Equal([]byte(expectedMac), []byte(mac))
}

// ============================================================================
// Beaker Cookie Check
// ============================================================================

type beakerCookieCheck struct{}

func (*beakerCookieCheck) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			cookies := flow.Response.Cookies()
			for _, cookie := range cookies {
				if http.IsCookieExpired(cookie) {
					continue
				}
				value := cookie.Value
				if found, key := checkBeakerCookie(value); found {
					v := a.NewWebVuln(flow.Request, flow.Response, nil)
					if v != nil {
						v.SetTargetURL(flow.Request.URL())
						v.Payload = "Beaker Cookie weak key found: " + key
						v.Add("framework", "beaker")
						v.Add("cookie_name", cookie.Name)
						v.Add("weak_key", key)
						a.OutputVuln(v)
					}
					return nil
				}
			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{
			ID:       "cookiekey/beaker/weak-key",
			Plugin:   "cookiekey/beaker/weak-key",
			Category: "cookiekey/beaker/weak-key",
			Severity: model.SeverityCritical,
		},
	}
}

// checkBeakerCookie checks if a cookie value matches the Beaker session cookie format.
// Beaker format: base64_signed_data!signature
// The signature is HMAC-SHA1 of the data before the "!" separator.
func checkBeakerCookie(cookieValue string) (bool, string) {
	// Beaker uses "!" as separator between data and signature
	bangIdx := strings.LastIndex(cookieValue, "!")
	if bangIdx <= 0 {
		return false, ""
	}
	data := cookieValue[:bangIdx]
	signature := cookieValue[bangIdx+1:]

	if data == "" || signature == "" {
		return false, ""
	}

	keys := append(CommonWeakKeys, BeakerWeakKeys...)
	for _, key := range keys {
		if verifyBeakerSignature(data, signature, key) {
			return true, key
		}
	}
	return false, ""
}

// verifyBeakerSignature verifies a Beaker session cookie signature.
// signature = base64(HMAC-SHA1(key, data))
func verifyBeakerSignature(data, signature, secretKey string) bool {
	mac := hmac.New(sha1.New, []byte(secretKey))
	mac.Write([]byte(data))
	expectedSig := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(expectedSig), []byte(signature))
}

// ============================================================================
// BottlePy Cookie Check
// ============================================================================

type bottlePyCookieCheck struct{}

func (*bottlePyCookieCheck) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			cookies := flow.Response.Cookies()
			for _, cookie := range cookies {
				if http.IsCookieExpired(cookie) {
					continue
				}
				value := cookie.Value
				if found, key := checkBottlePyCookie(value); found {
					v := a.NewWebVuln(flow.Request, flow.Response, nil)
					if v != nil {
						v.SetTargetURL(flow.Request.URL())
						v.Payload = "BottlePy Cookie weak key found: " + key
						v.Add("framework", "bottlepy")
						v.Add("cookie_name", cookie.Name)
						v.Add("weak_key", key)
						a.OutputVuln(v)
					}
					return nil
				}
			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{
			ID:       "cookiekey/bottlepy/weak-key",
			Plugin:   "cookiekey/bottlepy/weak-key",
			Category: "cookiekey/bottlepy/weak-key",
			Severity: model.SeverityCritical,
		},
	}
}

// checkBottlePyCookie checks if a cookie value matches the BottlePy signed cookie format.
// BottlePy format: "!base64_signature?value" (cookie value is quoted with surrounding double quotes)
// The signature is HMAC-MD5 of the value using the secret key.
// Reference: AWVS BottlePy_Cookie_Weak_Secret.js
func checkBottlePyCookie(cookieValue string) (bool, string) {
	// BottlePy cookie values are quoted: "!sig?data"
	// Pattern: "!" at position 1 (after opening quote), signature (24 base64 chars), "?", data, closing quote
	bottleRe := regexp.MustCompile(`^"!([\w+/=]{22,24})\?(.+)"$`)
	matches := bottleRe.FindStringSubmatch(cookieValue)
	if matches == nil || len(matches) != 3 {
		return false, ""
	}

	signB64 := matches[1]
	data := matches[2]
	if signB64 == "" || data == "" {
		return false, ""
	}

	// Decode the base64 signature to get hex
	sigBytes, err := base64.StdEncoding.DecodeString(signB64)
	if err != nil {
		return false, ""
	}
	signature := hex.EncodeToString(sigBytes)

	keys := append(CommonWeakKeys, BottlePyWeakKeys...)
	for _, key := range keys {
		if verifyBottlePySignature(data, signature, key) {
			return true, key
		}
	}
	return false, ""
}

// verifyBottlePySignature verifies a BottlePy cookie signature.
// signature = hex(HMAC-MD5(key, data))
func verifyBottlePySignature(data, signature, secretKey string) bool {
	mac := hmac.New(md5.New, []byte(secretKey))
	mac.Write([]byte(data))
	expectedSig := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expectedSig), []byte(signature))
}

// ============================================================================
// Pyramid Cookie Check
// ============================================================================

type pyramidCookieCheck struct{}

func (*pyramidCookieCheck) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			cookies := flow.Response.Cookies()
			for _, cookie := range cookies {
				if http.IsCookieExpired(cookie) {
					continue
				}
				value := cookie.Value
				if found, key := checkPyramidCookie(value); found {
					v := a.NewWebVuln(flow.Request, flow.Response, nil)
					if v != nil {
						v.SetTargetURL(flow.Request.URL())
						v.Payload = "Pyramid Cookie weak key found: " + key
						v.Add("framework", "pyramid")
						v.Add("cookie_name", cookie.Name)
						v.Add("weak_key", key)
						a.OutputVuln(v)
					}
					return nil
				}
			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{
			ID:       "cookiekey/pyramid/weak-key",
			Plugin:   "cookiekey/pyramid/weak-key",
			Category: "cookiekey/pyramid/weak-key",
			Severity: model.SeverityCritical,
		},
	}
}

// checkPyramidCookie checks if a cookie value matches the Pyramid signed cookie format.
// Pyramid uses the `pyramid.session.UnencryptedCookieSessionFactoryConfig` which signs
// cookies with HMAC-SHA1 using the `cookie_secret` setting.
// Format: base64_encoded_data-hex_signature
func checkPyramidCookie(cookieValue string) (bool, string) {
	// Pyramid cookies use "-" as separator between data and signature
	// Similar to Rack but with "-" instead of "--"
	dashIdx := strings.LastIndex(cookieValue, "-")
	if dashIdx <= 0 {
		return false, ""
	}
	data := cookieValue[:dashIdx]
	signature := cookieValue[dashIdx+1:]

	if data == "" || signature == "" {
		return false, ""
	}

	// The signature should be a hex string (SHA1 = 40 hex chars)
	if !isHex(signature) {
		return false, ""
	}

	keys := append(CommonWeakKeys, PyramidWeakKeys...)
	for _, key := range keys {
		if verifyPyramidSignature(data, signature, key) {
			return true, key
		}
	}
	return false, ""
}

// verifyPyramidSignature verifies a Pyramid session cookie signature.
// signature = hex(HMAC-SHA1(cookie_secret, data))
func verifyPyramidSignature(data, signature, secretKey string) bool {
	mac := hmac.New(sha1.New, []byte(secretKey))
	mac.Write([]byte(data))
	expectedSig := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expectedSig), []byte(signature))
}
