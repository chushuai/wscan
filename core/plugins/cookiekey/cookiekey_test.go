/**
* @Author: shaochuyu
* @Date: 6/16/2026
 */
package cookiekey

import (
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
	"strings"
	"testing"
	"wscan/core/plugins/base"
)

// ============================================================================
// Django Cookie Tests
// ============================================================================

// generateDjangoSignedCookie creates a Django-style signed cookie for testing.
func generateDjangoSignedCookie(value, secretKey, salt string) string {
	// derived_key = SHA1(key + salt)
	h := sha1.New()
	h.Write([]byte(secretKey + salt))
	derivedKey := h.Sum(nil)

	// Compute HMAC-SHA1(derivedKey, value + ":" + timestamp)
	timestamp := "1234567890"
	mac := hmac.New(sha1.New, derivedKey)
	mac.Write([]byte(value + ":" + timestamp))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return value + ":" + timestamp + ":" + signature
}

func TestCheckDjangoCookie_Valid(t *testing.T) {
	secretKey := "secret"
	salt := "django.contrib.sessions.backends.session"
	cookieValue := generateDjangoSignedCookie("sessionid", secretKey, salt)

	found, key := checkDjangoCookie(cookieValue)
	if !found {
		t.Errorf("Expected Django cookie to be detected with key %q, but it was not found", secretKey)
	}
	if key != secretKey {
		t.Errorf("Expected key %q, got %q", secretKey, key)
	}
}

func TestCheckDjangoCookie_Invalid(t *testing.T) {
	// Not a Django cookie format
	cookieValue := "notadjangocookie"
	found, _ := checkDjangoCookie(cookieValue)
	if found {
		t.Error("Expected non-Django cookie to not be detected")
	}
}

func TestCheckDjangoCookie_InvalidSignature(t *testing.T) {
	// Create a cookie with an invalid signature
	cookieValue := "sessionid:1234567890:invalidsignature"
	found, _ := checkDjangoCookie(cookieValue)
	if found {
		t.Error("Expected cookie with invalid signature to not be detected")
	}
}

// ============================================================================
// Flask Cookie Tests
// ============================================================================

// generateFlaskSignedCookie creates a Flask-style signed cookie for testing.
func generateFlaskSignedCookie(payload, secretKey string) string {
	// Encode timestamp as base64
	timestamp := base64.RawURLEncoding.EncodeToString([]byte("12345"))

	// signature = base64url(HMAC-SHA1(key, "payload.timestamp"))
	data := payload + "." + timestamp
	mac := hmac.New(sha1.New, []byte(secretKey))
	mac.Write([]byte(data))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return payload + "." + timestamp + "." + signature
}

func TestCheckFlaskCookie_Valid(t *testing.T) {
	secretKey := "secret"
	// Flask payload is base64-encoded JSON
	jsonData := `{"user":"admin"}`
	payload := base64.RawURLEncoding.EncodeToString([]byte(jsonData))
	cookieValue := generateFlaskSignedCookie(payload, secretKey)

	found, key := checkFlaskCookie(cookieValue)
	if !found {
		t.Errorf("Expected Flask cookie to be detected with key %q, but it was not found", secretKey)
	}
	if key != secretKey {
		t.Errorf("Expected key %q, got %q", secretKey, key)
	}
}

func TestCheckFlaskCookie_Invalid(t *testing.T) {
	cookieValue := "notaflaskcookie"
	found, _ := checkFlaskCookie(cookieValue)
	if found {
		t.Error("Expected non-Flask cookie to not be detected")
	}
}

func TestCheckFlaskCookie_NotJson(t *testing.T) {
	// Payload that doesn't decode to JSON
	secretKey := "secret"
	payload := base64.RawURLEncoding.EncodeToString([]byte("notjson"))
	cookieValue := generateFlaskSignedCookie(payload, secretKey)

	found, _ := checkFlaskCookie(cookieValue)
	if found {
		t.Error("Expected non-JSON Flask cookie to not be detected")
	}
}

// ============================================================================
// Express cookie-session Tests
// ============================================================================

func generateExpressCookieSessionSig(value, secretKey string) string {
	mac := hmac.New(sha1.New, []byte(secretKey))
	mac.Write([]byte(value))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func TestCheckExpressCookieSession_Valid(t *testing.T) {
	secretKey := "keyboard cat"
	value := `{"user":"admin"}`
	sigValue := generateExpressCookieSessionSig(value, secretKey)

	found, key := checkExpressCookieSession(value, sigValue)
	if !found {
		t.Errorf("Expected Express cookie-session to be detected with key %q, but it was not found", secretKey)
	}
	if key != secretKey {
		t.Errorf("Expected key %q, got %q", secretKey, key)
	}
}

func TestCheckExpressCookieSession_InvalidSig(t *testing.T) {
	value := `{"user":"admin"}`
	sigValue := "invalidsignature"

	found, _ := checkExpressCookieSession(value, sigValue)
	if found {
		t.Error("Expected Express cookie-session with invalid sig to not be detected")
	}
}

// ============================================================================
// Express express-session Tests
// ============================================================================

func generateExpressSessionSig(value, secretKey string) string {
	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write([]byte("s:" + value))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func TestCheckExpressSession_Valid(t *testing.T) {
	secretKey := "keyboard cat"
	value := `{"user":"admin"}`
	signature := generateExpressSessionSig(value, secretKey)

	found, key := checkExpressSession(value, signature)
	if !found {
		t.Errorf("Expected Express express-session to be detected with key %q, but it was not found", secretKey)
	}
	if key != secretKey {
		t.Errorf("Expected key %q, got %q", secretKey, key)
	}
}

func TestCheckExpressSession_InvalidSig(t *testing.T) {
	value := `{"user":"admin"}`
	signature := "invalidsignature"

	found, _ := checkExpressSession(value, signature)
	if found {
		t.Error("Expected Express express-session with invalid sig to not be detected")
	}
}

// ============================================================================
// JWT Tests
// ============================================================================

func generateJWT(payload map[string]interface{}, secretKey, alg string) string {
	var header map[string]interface{}
	switch alg {
	case "HS256":
		header = map[string]interface{}{"alg": "HS256", "typ": "JWT"}
	case "HS384":
		header = map[string]interface{}{"alg": "HS384", "typ": "JWT"}
	case "HS512":
		header = map[string]interface{}{"alg": "HS512", "typ": "JWT"}
	default:
		return ""
	}

	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signingInput := headerB64 + "." + payloadB64

	var sig []byte
	switch alg {
	case "HS256":
		mac := hmac.New(sha256.New, []byte(secretKey))
		mac.Write([]byte(signingInput))
		sig = mac.Sum(nil)
	case "HS384":
		mac := hmac.New(sha512.New384, []byte(secretKey))
		mac.Write([]byte(signingInput))
		sig = mac.Sum(nil)
	case "HS512":
		mac := hmac.New(sha512.New, []byte(secretKey))
		mac.Write([]byte(signingInput))
		sig = mac.Sum(nil)
	}

	signatureB64 := base64.RawURLEncoding.EncodeToString(sig)

	return headerB64 + "." + payloadB64 + "." + signatureB64
}

func TestCheckJWTCookie_HS256(t *testing.T) {
	secretKey := "secret"
	token := generateJWT(map[string]interface{}{"sub": "1234567890", "name": "John Doe"}, secretKey, "HS256")

	found, key, alg := checkJWTCookie(token)
	if !found {
		t.Errorf("Expected JWT HS256 to be detected with key %q, but it was not found", secretKey)
	}
	if key != secretKey {
		t.Errorf("Expected key %q, got %q", secretKey, key)
	}
	if alg != "HS256" {
		t.Errorf("Expected alg HS256, got %q", alg)
	}
}

func TestCheckJWTCookie_HS384(t *testing.T) {
	secretKey := "secret"
	token := generateJWT(map[string]interface{}{"sub": "1234567890"}, secretKey, "HS384")

	found, key, alg := checkJWTCookie(token)
	if !found {
		t.Errorf("Expected JWT HS384 to be detected with key %q, but it was not found", secretKey)
	}
	if key != secretKey {
		t.Errorf("Expected key %q, got %q", secretKey, key)
	}
	if alg != "HS384" {
		t.Errorf("Expected alg HS384, got %q", alg)
	}
}

func TestCheckJWTCookie_HS512(t *testing.T) {
	secretKey := "secret"
	token := generateJWT(map[string]interface{}{"sub": "1234567890"}, secretKey, "HS512")

	found, key, alg := checkJWTCookie(token)
	if !found {
		t.Errorf("Expected JWT HS512 to be detected with key %q, but it was not found", secretKey)
	}
	if key != secretKey {
		t.Errorf("Expected key %q, got %q", secretKey, key)
	}
	if alg != "HS512" {
		t.Errorf("Expected alg HS512, got %q", alg)
	}
}

func TestCheckJWTCookie_Invalid(t *testing.T) {
	// Not a JWT
	token := "notajwt"
	found, _, _ := checkJWTCookie(token)
	if found {
		t.Error("Expected non-JWT to not be detected")
	}
}

func TestCheckJWTCookie_RS256(t *testing.T) {
	// RS256 should not be checked (non-HMAC algorithm)
	header := map[string]interface{}{"alg": "RS256", "typ": "JWT"}
	payload := map[string]interface{}{"sub": "1234567890"}
	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	token := headerB64 + "." + payloadB64 + ".fakesignature"

	found, _, _ := checkJWTCookie(token)
	if found {
		t.Error("Expected RS256 JWT to not be detected (only HMAC algorithms should be checked)")
	}
}

func TestCheckJWTCookie_InvalidSignature(t *testing.T) {
	// Create a valid-looking JWT but with a non-matching signature
	header := map[string]interface{}{"alg": "HS256", "typ": "JWT"}
	payload := map[string]interface{}{"sub": "1234567890"}
	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	token := headerB64 + "." + payloadB64 + ".invalidsignature"

	found, _, _ := checkJWTCookie(token)
	if found {
		t.Error("Expected JWT with invalid signature to not be detected")
	}
}

// ============================================================================
// Rack Cookie Tests
// ============================================================================

func generateRackSignedCookie(data, secretKey string) string {
	mac := hmac.New(sha1.New, []byte(secretKey))
	mac.Write([]byte(data))
	signature := fmt.Sprintf("%x", mac.Sum(nil))
	return data + "--" + signature
}

func TestCheckRackCookie_Valid(t *testing.T) {
	secretKey := "secret_key_base"
	data := base64.StdEncoding.EncodeToString([]byte(`{"session_id":"12345"}`))
	cookieValue := generateRackSignedCookie(data, secretKey)

	found, key := checkRackCookie(cookieValue)
	if !found {
		t.Errorf("Expected Rack cookie to be detected with key %q, but it was not found", secretKey)
	}
	if key != secretKey {
		t.Errorf("Expected key %q, got %q", secretKey, key)
	}
}

func TestCheckRackCookie_Invalid(t *testing.T) {
	cookieValue := "notarackcookie"
	found, _ := checkRackCookie(cookieValue)
	if found {
		t.Error("Expected non-Rack cookie to not be detected")
	}
}

func TestCheckRackCookie_InvalidSignature(t *testing.T) {
	data := base64.StdEncoding.EncodeToString([]byte(`{"session_id":"12345"}`))
	cookieValue := data + "--" + "invalidsignature"
	found, _ := checkRackCookie(cookieValue)
	if found {
		t.Error("Expected Rack cookie with invalid signature to not be detected")
	}
}

// ============================================================================
// Weak Key Lists Tests
// ============================================================================

func TestAllKeys_Dedup(t *testing.T) {
	keys := AllKeys()
	seen := make(map[string]bool)
	for _, key := range keys {
		if seen[key] {
			t.Errorf("Duplicate key found: %q", key)
		}
		seen[key] = true
	}
}

func TestAllKeys_NotEmpty(t *testing.T) {
	keys := AllKeys()
	if len(keys) == 0 {
		t.Error("Expected AllKeys to return at least one key")
	}
}

func TestCommonWeakKeysContainExpected(t *testing.T) {
	expectedKeys := []string{"secret", "password", "changeme", "keyboard cat", "development"}
	for _, expected := range expectedKeys {
		found := false
		for _, key := range CommonWeakKeys {
			if key == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected CommonWeakKeys to contain %q", expected)
		}
	}
}

// ============================================================================
// Plugin Config Tests
// ============================================================================

func TestCookieKey_DefaultConfig(t *testing.T) {
	plugin := &CookieKey{}
	config := plugin.DefaultConfig().(*Config)
	if config.Name != "cookiekey" {
		t.Errorf("Expected plugin name 'cookiekey', got %q", config.Name)
	}
	if config.IsAdvanced != true {
		t.Error("Expected IsAdvanced to be true")
	}
	if !config.CheckDjango {
		t.Error("Expected CheckDjango to be true by default")
	}
	if !config.CheckFlask {
		t.Error("Expected CheckFlask to be true by default")
	}
	if !config.CheckExpress {
		t.Error("Expected CheckExpress to be true by default")
	}
	if !config.CheckJWT {
		t.Error("Expected CheckJWT to be true by default")
	}
	if !config.CheckRack {
		t.Error("Expected CheckRack to be true by default")
	}
	if !config.CheckTornado {
		t.Error("Expected CheckTornado to be true by default")
	}
	if !config.CheckWeb2py {
		t.Error("Expected CheckWeb2py to be true by default")
	}
	if !config.CheckYii2 {
		t.Error("Expected CheckYii2 to be true by default")
	}
	if !config.CheckLaravel {
		t.Error("Expected CheckLaravel to be true by default")
	}
	if !config.CheckBeaker {
		t.Error("Expected CheckBeaker to be true by default")
	}
	if !config.CheckBottlePy {
		t.Error("Expected CheckBottlePy to be true by default")
	}
	if !config.CheckPyramid {
		t.Error("Expected CheckPyramid to be true by default")
	}
}

func TestConfig_BaseConfig(t *testing.T) {
	config := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:       "cookiekey",
			Enabled:    true,
			IsAdvanced: true,
		},
	}
	bc := config.BaseConfig()
	if bc.Name != "cookiekey" {
		t.Errorf("Expected name 'cookiekey', got %q", bc.Name)
	}
}

// ============================================================================
// Signature Verification Tests
// ============================================================================

func TestVerifyDjangoSignature(t *testing.T) {
	secretKey := "development"
	salt := "django.contrib.sessions.backends.session"
	value := "testsessionid"
	timestamp := "1623456789"

	// Generate expected signature
	h := sha1.New()
	h.Write([]byte(secretKey + salt))
	derivedKey := h.Sum(nil)
	mac := hmac.New(sha1.New, derivedKey)
	mac.Write([]byte(value + ":" + timestamp))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if !verifyDjangoSignature(value, timestamp, expectedSig, secretKey, salt) {
		t.Error("Expected Django signature verification to succeed")
	}

	// Wrong key should fail
	if verifyDjangoSignature(value, timestamp, expectedSig, "wrongkey", salt) {
		t.Error("Expected Django signature verification to fail with wrong key")
	}
}

func TestVerifyFlaskSignature(t *testing.T) {
	secretKey := "development"
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"user":"test"}`))
	timestamp := base64.RawURLEncoding.EncodeToString([]byte("12345"))

	data := payload + "." + timestamp
	mac := hmac.New(sha1.New, []byte(secretKey))
	mac.Write([]byte(data))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if !verifyFlaskSignature(payload, timestamp, signature, secretKey) {
		t.Error("Expected Flask signature verification to succeed")
	}

	if verifyFlaskSignature(payload, timestamp, signature, "wrongkey") {
		t.Error("Expected Flask signature verification to fail with wrong key")
	}
}

func TestVerifyExpressCookieSessionSig(t *testing.T) {
	secretKey := "keyboard cat"
	value := `{"user":"admin"}`

	mac := hmac.New(sha1.New, []byte(secretKey))
	mac.Write([]byte(value))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if !verifyExpressCookieSessionSig(value, sig, secretKey) {
		t.Error("Expected Express cookie-session sig verification to succeed")
	}

	if verifyExpressCookieSessionSig(value, sig, "wrongkey") {
		t.Error("Expected Express cookie-session sig verification to fail with wrong key")
	}
}

func TestVerifyExpressSessionSig(t *testing.T) {
	secretKey := "keyboard cat"
	value := `{"user":"admin"}`

	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write([]byte("s:" + value))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if !verifyExpressSessionSig(value, sig, secretKey) {
		t.Error("Expected Express express-session sig verification to succeed")
	}

	if verifyExpressSessionSig(value, sig, "wrongkey") {
		t.Error("Expected Express express-session sig verification to fail with wrong key")
	}
}

func TestVerifyJWTSignature_HS256(t *testing.T) {
	secretKey := "secret"
	signingInput := "header.payload"

	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write([]byte(signingInput))
	sig := mac.Sum(nil)

	if !verifyJWTSignature(signingInput, sig, secretKey, "HS256") {
		t.Error("Expected JWT HS256 signature verification to succeed")
	}

	if verifyJWTSignature(signingInput, sig, "wrongkey", "HS256") {
		t.Error("Expected JWT HS256 signature verification to fail with wrong key")
	}
}

func TestVerifyJWTSignature_HS384(t *testing.T) {
	secretKey := "secret"
	signingInput := "header.payload"

	mac := hmac.New(sha512.New384, []byte(secretKey))
	mac.Write([]byte(signingInput))
	sig := mac.Sum(nil)

	if !verifyJWTSignature(signingInput, sig, secretKey, "HS384") {
		t.Error("Expected JWT HS384 signature verification to succeed")
	}
}

func TestVerifyJWTSignature_HS512(t *testing.T) {
	secretKey := "secret"
	signingInput := "header.payload"

	mac := hmac.New(sha512.New, []byte(secretKey))
	mac.Write([]byte(signingInput))
	sig := mac.Sum(nil)

	if !verifyJWTSignature(signingInput, sig, secretKey, "HS512") {
		t.Error("Expected JWT HS512 signature verification to succeed")
	}
}

func TestVerifyRackSignature(t *testing.T) {
	secretKey := "secret_key_base"
	data := base64.StdEncoding.EncodeToString([]byte(`{"session_id":"123"}`))

	mac := hmac.New(sha1.New, []byte(secretKey))
	mac.Write([]byte(data))
	sig := fmt.Sprintf("%x", mac.Sum(nil))

	if !verifyRackSignature(data, sig, secretKey) {
		t.Error("Expected Rack signature verification to succeed")
	}

	if verifyRackSignature(data, sig, "wrongkey") {
		t.Error("Expected Rack signature verification to fail with wrong key")
	}
}

// ============================================================================
// Tornado Cookie Tests
// ============================================================================

func generateTornadoV1SignedCookie(cookieName, value, timestamp, secretKey string) string {
	hmacInput := cookieName + value + timestamp
	mac := hmac.New(sha1.New, []byte(secretKey))
	mac.Write([]byte(hmacInput))
	signature := hex.EncodeToString(mac.Sum(nil))
	return value + "|" + timestamp + "|" + signature
}

func generateTornadoV2SignedCookie(cookieName, value, timestamp, secretKey string) string {
	// Tornado v2: version|1:0|10:timestamp|8:name|12:value|signature
	prefix := "2|1:0|10:" + timestamp + "|8:" + cookieName + "|12:" + value
	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write([]byte(prefix))
	signature := hex.EncodeToString(mac.Sum(nil))
	return prefix + "|" + signature
}

func TestCheckTornadoCookie_V1(t *testing.T) {
	secretKey := "secret"
	cookieName := "mycookie"
	cookieValue := generateTornadoV1SignedCookie(cookieName, "bXl2YWx1ZQ==", "1574851482", secretKey)

	found, key := checkTornadoCookie(cookieName, cookieValue)
	if !found {
		t.Errorf("Expected Tornado v1 cookie to be detected with key %q", secretKey)
	}
	if key != secretKey {
		t.Errorf("Expected key %q, got %q", secretKey, key)
	}
}

func TestCheckTornadoCookie_V2(t *testing.T) {
	secretKey := "secret"
	cookieName := "mycookie"
	cookieValue := generateTornadoV2SignedCookie(cookieName, "bXl2YWx1ZQ==", "1574851461", secretKey)

	found, key := checkTornadoCookie(cookieName, cookieValue)
	if !found {
		t.Errorf("Expected Tornado v2 cookie to be detected with key %q", secretKey)
	}
	if key != secretKey {
		t.Errorf("Expected key %q, got %q", secretKey, key)
	}
}

func TestCheckTornadoCookie_Invalid(t *testing.T) {
	cookieName := "mycookie"
	found, _ := checkTornadoCookie(cookieName, "notatornadocookie")
	if found {
		t.Error("Expected non-Tornado cookie to not be detected")
	}
}

func TestCheckTornadoCookie_InvalidSignature(t *testing.T) {
	cookieName := "mycookie"
	cookieValue := "bXl2YWx1ZQ==|1574851482|invalidsignature0000000000000000000"
	found, _ := checkTornadoCookie(cookieName, cookieValue)
	if found {
		t.Error("Expected Tornado cookie with invalid signature to not be detected")
	}
}

func TestVerifyTornadoV1Signature(t *testing.T) {
	secretKey := "cookie_secret"
	hmacInput := "mycookiebXl2YWx1ZQ==1574851482"
	mac := hmac.New(sha1.New, []byte(secretKey))
	mac.Write([]byte(hmacInput))
	sig := hex.EncodeToString(mac.Sum(nil))

	if !verifyTornadoV1Signature(hmacInput, sig, secretKey) {
		t.Error("Expected Tornado v1 signature verification to succeed")
	}
	if verifyTornadoV1Signature(hmacInput, sig, "wrongkey") {
		t.Error("Expected Tornado v1 signature verification to fail with wrong key")
	}
}

func TestVerifyTornadoV2Signature(t *testing.T) {
	secretKey := "cookie_secret"
	hmacInput := "2|1:0|10:1574851461|8:mycookie|12:bXl2YWx1ZQ=="
	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write([]byte(hmacInput))
	sig := hex.EncodeToString(mac.Sum(nil))

	if !verifyTornadoV2Signature(hmacInput, sig, secretKey) {
		t.Error("Expected Tornado v2 signature verification to succeed")
	}
	if verifyTornadoV2Signature(hmacInput, sig, "wrongkey") {
		t.Error("Expected Tornado v2 signature verification to fail with wrong key")
	}
}

// ============================================================================
// Web2py Cookie Tests
// ============================================================================

func generateWeb2pySignedCookie(data, secretKey string) string {
	h := sha1.New()
	h.Write([]byte(secretKey))
	sha1Key := h.Sum(nil)

	mac := hmac.New(md5.New, sha1Key)
	mac.Write([]byte(data))
	signature := hex.EncodeToString(mac.Sum(nil))

	return signature + ":" + data
}

func TestCheckWeb2pyCookie_Valid(t *testing.T) {
	secretKey := "yoursecret"
	data := "2UPUY95IyOA2jY-3N0_FLQtCTZPDlaBEqszVb5jHTc"
	cookieValue := generateWeb2pySignedCookie(data, secretKey)

	found, key := checkWeb2pyCookie(cookieValue)
	if !found {
		t.Errorf("Expected Web2py cookie to be detected with key %q", secretKey)
	}
	if key != secretKey {
		t.Errorf("Expected key %q, got %q", secretKey, key)
	}
}

func TestCheckWeb2pyCookie_Invalid(t *testing.T) {
	found, _ := checkWeb2pyCookie("notaweb2pycookie")
	if found {
		t.Error("Expected non-Web2py cookie to not be detected")
	}
}

func TestCheckWeb2pyCookie_InvalidSignature(t *testing.T) {
	cookieValue := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:somedatahere"
	found, _ := checkWeb2pyCookie(cookieValue)
	if found {
		t.Error("Expected Web2py cookie with invalid signature to not be detected")
	}
}

func TestVerifyWeb2pySignature(t *testing.T) {
	secretKey := "yoursecret"
	data := "testsessiondata"

	h := sha1.New()
	h.Write([]byte(secretKey))
	sha1Key := h.Sum(nil)

	mac := hmac.New(md5.New, sha1Key)
	mac.Write([]byte(data))
	sig := hex.EncodeToString(mac.Sum(nil))

	if !verifyWeb2pySignature(data, sig, secretKey) {
		t.Error("Expected Web2py signature verification to succeed")
	}
	if verifyWeb2pySignature(data, sig, "wrongkey") {
		t.Error("Expected Web2py signature verification to fail with wrong key")
	}
}

// ============================================================================
// Yii2 Cookie Tests
// ============================================================================

func generateYii2SignedCookie(data, secretKey string) string {
	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write([]byte(data))
	signature := hex.EncodeToString(mac.Sum(nil))
	return signature + url.QueryEscape(data)
}

func TestCheckYii2Cookie_Valid(t *testing.T) {
	secretKey := "yii2"
	data := "a:2:{i:0;s:5:\"_csrf\";i:1;s:32:\"UgbHRQ2TZabdvk_OXU1RqwlvdW8ITkFL\";}"
	cookieValue := generateYii2SignedCookie(data, secretKey)

	found, key := checkYii2Cookie(cookieValue)
	if !found {
		t.Errorf("Expected Yii2 cookie to be detected with key %q", secretKey)
	}
	if key != secretKey {
		t.Errorf("Expected key %q, got %q", secretKey, key)
	}
}

func TestCheckYii2Cookie_Invalid(t *testing.T) {
	found, _ := checkYii2Cookie("notayii2cookie")
	if found {
		t.Error("Expected non-Yii2 cookie to not be detected")
	}
}

func TestCheckYii2Cookie_InvalidSignature(t *testing.T) {
	cookieValue := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa%3A2%3A%7Bi%3A0%3Bs%3A5%3A%22_csrf%22%3B%7D"
	found, _ := checkYii2Cookie(cookieValue)
	if found {
		t.Error("Expected Yii2 cookie with invalid signature to not be detected")
	}
}

func TestVerifyYii2Signature(t *testing.T) {
	secretKey := "yii2"
	data := "a:2:{i:0;s:5:\"_csrf\";}"
	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write([]byte(data))
	sig := hex.EncodeToString(mac.Sum(nil))

	if !verifyYii2Signature(data, sig, secretKey) {
		t.Error("Expected Yii2 signature verification to succeed")
	}
	if verifyYii2Signature(data, sig, "wrongkey") {
		t.Error("Expected Yii2 signature verification to fail with wrong key")
	}
}

// ============================================================================
// Laravel Cookie Tests
// ============================================================================

func generateLaravelEncryptedCookie(iv, value, secretKey string) string {
	rawKey := secretKey
	if strings.HasPrefix(secretKey, "base64:") {
		rawKey = strings.TrimPrefix(secretKey, "base64:")
	}

	keyBytes, err := base64.StdEncoding.DecodeString(rawKey)
	if err != nil {
		keyBytes = []byte(rawKey)
	}

	payload := iv + value
	mac := hmac.New(sha256.New, keyBytes)
	mac.Write([]byte(payload))
	macHex := hex.EncodeToString(mac.Sum(nil))

	laravelCookie := map[string]string{
		"iv":    iv,
		"value": value,
		"mac":   macHex,
	}
	jsonData, _ := json.Marshal(laravelCookie)
	return base64.StdEncoding.EncodeToString(jsonData)
}

func TestCheckLaravelCookie_Valid(t *testing.T) {
	secretKey := "base64:dGVzdGluZ2FwcGtleQ=="
	iv := base64.StdEncoding.EncodeToString([]byte("1234567890123456"))
	value := base64.StdEncoding.EncodeToString([]byte("encrypted_data"))

	cookieValue := generateLaravelEncryptedCookie(iv, value, secretKey)

	found, key := checkLaravelCookie(cookieValue)
	if !found {
		t.Errorf("Expected Laravel cookie to be detected with key %q", secretKey)
	}
	if key != secretKey {
		t.Errorf("Expected key %q, got %q", secretKey, key)
	}
}

func TestCheckLaravelCookie_Invalid(t *testing.T) {
	found, _ := checkLaravelCookie("notalaravelcookie")
	if found {
		t.Error("Expected non-Laravel cookie to not be detected")
	}
}

func TestCheckLaravelCookie_InvalidMac(t *testing.T) {
	laravelCookie := map[string]string{
		"iv":    "dGVzdA==",
		"value": "aW52YWxpZA==",
		"mac":   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	jsonData, _ := json.Marshal(laravelCookie)
	cookieValue := base64.StdEncoding.EncodeToString(jsonData)

	found, _ := checkLaravelCookie(cookieValue)
	if found {
		t.Error("Expected Laravel cookie with invalid MAC to not be detected")
	}
}

func TestVerifyLaravelSignature(t *testing.T) {
	secretKey := "base64:dGVzdGluZ2FwcGtleQ=="
	iv := "dGVzdGl2"
	value := "dGVzdHZhbHVl"

	rawKey := strings.TrimPrefix(secretKey, "base64:")
	keyBytes, _ := base64.StdEncoding.DecodeString(rawKey)

	payload := iv + value
	mac := hmac.New(sha256.New, keyBytes)
	mac.Write([]byte(payload))
	macHex := hex.EncodeToString(mac.Sum(nil))

	if !verifyLaravelSignature(iv, value, macHex, secretKey) {
		t.Error("Expected Laravel signature verification to succeed")
	}
	if verifyLaravelSignature(iv, value, macHex, "base64:d3JvbmdrZXk=") {
		t.Error("Expected Laravel signature verification to fail with wrong key")
	}
}

// ============================================================================
// Beaker Cookie Tests
// ============================================================================

func generateBeakerSignedCookie(data, secretKey string) string {
	mac := hmac.New(sha1.New, []byte(secretKey))
	mac.Write([]byte(data))
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return data + "!" + signature
}

func TestCheckBeakerCookie_Valid(t *testing.T) {
	secretKey := "beaker.session.id"
	data := "session_data_here"
	cookieValue := generateBeakerSignedCookie(data, secretKey)

	found, key := checkBeakerCookie(cookieValue)
	if !found {
		t.Errorf("Expected Beaker cookie to be detected with key %q", secretKey)
	}
	if key != secretKey {
		t.Errorf("Expected key %q, got %q", secretKey, key)
	}
}

func TestCheckBeakerCookie_Invalid(t *testing.T) {
	found, _ := checkBeakerCookie("notabeakercookie")
	if found {
		t.Error("Expected non-Beaker cookie to not be detected")
	}
}

func TestCheckBeakerCookie_InvalidSignature(t *testing.T) {
	cookieValue := "somedata!invalidsignature"
	found, _ := checkBeakerCookie(cookieValue)
	if found {
		t.Error("Expected Beaker cookie with invalid signature to not be detected")
	}
}

func TestVerifyBeakerSignature(t *testing.T) {
	secretKey := "beaker.session.id"
	data := "testsessiondata"

	mac := hmac.New(sha1.New, []byte(secretKey))
	mac.Write([]byte(data))
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	if !verifyBeakerSignature(data, sig, secretKey) {
		t.Error("Expected Beaker signature verification to succeed")
	}
	if verifyBeakerSignature(data, sig, "wrongkey") {
		t.Error("Expected Beaker signature verification to fail with wrong key")
	}
}

// ============================================================================
// BottlePy Cookie Tests
// ============================================================================

func generateBottlePySignedCookie(data, secretKey string) string {
	mac := hmac.New(md5.New, []byte(secretKey))
	mac.Write([]byte(data))
	sigBytes := mac.Sum(nil)
	sigB64 := base64.StdEncoding.EncodeToString(sigBytes)
	return "\"!" + sigB64 + "?" + data + "\""
}

func TestCheckBottlePyCookie_Valid(t *testing.T) {
	secretKey := "some-secret-key"
	data := "gASVFwAAAAAAAACMB2FjY291bnSUjAd0ZXN0YWNjlIaULg=="
	cookieValue := generateBottlePySignedCookie(data, secretKey)

	found, key := checkBottlePyCookie(cookieValue)
	if !found {
		t.Errorf("Expected BottlePy cookie to be detected with key %q", secretKey)
	}
	if key != secretKey {
		t.Errorf("Expected key %q, got %q", secretKey, key)
	}
}

func TestCheckBottlePyCookie_Invalid(t *testing.T) {
	found, _ := checkBottlePyCookie("notabottlepycookie")
	if found {
		t.Error("Expected non-BottlePy cookie to not be detected")
	}
}

func TestCheckBottlePyCookie_InvalidSignature(t *testing.T) {
	cookieValue := "\"!aW52YWxpZHNpZ25hdHVy?somevalue\""
	found, _ := checkBottlePyCookie(cookieValue)
	if found {
		t.Error("Expected BottlePy cookie with invalid signature to not be detected")
	}
}

func TestVerifyBottlePySignature(t *testing.T) {
	secretKey := "some-secret-key"
	data := "testsessiondata"

	mac := hmac.New(md5.New, []byte(secretKey))
	mac.Write([]byte(data))
	sig := hex.EncodeToString(mac.Sum(nil))

	if !verifyBottlePySignature(data, sig, secretKey) {
		t.Error("Expected BottlePy signature verification to succeed")
	}
	if verifyBottlePySignature(data, sig, "wrongkey") {
		t.Error("Expected BottlePy signature verification to fail with wrong key")
	}
}

// ============================================================================
// Pyramid Cookie Tests
// // ===========================================================================

func generatePyramidSignedCookie(data, secretKey string) string {
	mac := hmac.New(sha1.New, []byte(secretKey))
	mac.Write([]byte(data))
	signature := hex.EncodeToString(mac.Sum(nil))
	return data + "-" + signature
}

func TestCheckPyramidCookie_Valid(t *testing.T) {
	secretKey := "pyramid"
	data := base64.StdEncoding.EncodeToString([]byte(`{"session_id":"12345"}`))
	cookieValue := generatePyramidSignedCookie(data, secretKey)

	found, key := checkPyramidCookie(cookieValue)
	if !found {
		t.Errorf("Expected Pyramid cookie to be detected with key %q", secretKey)
	}
	if key != secretKey {
		t.Errorf("Expected key %q, got %q", secretKey, key)
	}
}

func TestCheckPyramidCookie_Invalid(t *testing.T) {
	found, _ := checkPyramidCookie("notapyramidcookie")
	if found {
		t.Error("Expected non-Pyramid cookie to not be detected")
	}
}

func TestCheckPyramidCookie_InvalidSignature(t *testing.T) {
	data := base64.StdEncoding.EncodeToString([]byte(`{"session_id":"123"}`))
	cookieValue := data + "-invalidhexsignature"
	found, _ := checkPyramidCookie(cookieValue)
	if found {
		t.Error("Expected Pyramid cookie with invalid signature to not be detected")
	}
}

func TestVerifyPyramidSignature(t *testing.T) {
	secretKey := "pyramid"
	data := "testsessiondata"

	mac := hmac.New(sha1.New, []byte(secretKey))
	mac.Write([]byte(data))
	sig := hex.EncodeToString(mac.Sum(nil))

	if !verifyPyramidSignature(data, sig, secretKey) {
		t.Error("Expected Pyramid signature verification to succeed")
	}
	if verifyPyramidSignature(data, sig, "wrongkey") {
		t.Error("Expected Pyramid signature verification to fail with wrong key")
	}
}
