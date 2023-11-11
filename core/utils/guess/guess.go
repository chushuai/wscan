/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package guess

import (
	"encoding/base64"
	"encoding/xml"
	"regexp"
	"strings"
)

// IsRedirectParam checks if the given parameter name is related to a redirect.
func IsRedirectParam(param string) bool {
	redirectParams := []string{"redirect", "url", "return", "go", "to"}
	for _, redirectParam := range redirectParams {
		if strings.ToLower(param) == redirectParam {
			return true
		}
	}
	return false
}

// IsJsRedirectResponse checks if the response body contains JavaScript that redirects the user.
func IsJsRedirectResponse(body string) bool {
	return strings.Contains(strings.ToLower(body), "window.location") || strings.Contains(strings.ToLower(body), "location.replace")
}

// IsJSONPParam checks if the given parameter name is related to JSONP.
func IsJSONPParam(param string) bool {
	jsonpParams := []string{"callback", "jsonp", "cb"}
	for _, jsonpParam := range jsonpParams {
		if strings.ToLower(param) == jsonpParam {
			return true
		}
	}
	return false
}

func IsSensitiveJSON(body string) bool {
	sensitiveKeys := []string{"password", "secret", "token", "session", "auth", "cookie"}
	for _, sensitiveKey := range sensitiveKeys {
		if strings.Contains(strings.ToLower(body), sensitiveKey) {
			return true
		}
	}
	return false
}

// IsTokenParam checks if the given parameter name is related to a security token.
func IsTokenParam(param string) bool {
	tokenParams := []string{"token", "csrf", "xsrf", "authenticity_token", "nonce"}
	for _, tokenParam := range tokenParams {
		if strings.ToLower(param) == tokenParam {
			return true
		}
	}
	return false
}

// IsXMLString checks if the given string is XML.
func IsXMLString(s string) bool {
	return strings.HasPrefix(strings.TrimSpace(s), "<xml")
}

// IsXMLBytes checks if the given byte slice represents XML.
func IsXMLBytes(b []byte) bool {
	var xmlData struct{}
	err := xml.Unmarshal(b, &xmlData)
	return err == nil
}

// IsXMLParam checks if the given parameter name is related to XML.
func IsXMLParam(param string) bool {
	xmlParams := []string{"xml", "rss", "atom", "rdf"}
	for _, xmlParam := range xmlParams {
		if strings.ToLower(param) == xmlParam {
			return true
		}
	}
	return false
}

// IsXMLRequest checks if the request is an XML request by checking the content type header.
func IsXMLRequest(contentType string) bool {
	return strings.HasPrefix(strings.ToLower(contentType), "application/xml") ||
		strings.HasPrefix(strings.ToLower(contentType), "text/xml")
}

// IsSQLColumnName checks if the given string is a valid SQL column name.
func IsSQLColumnName(s string) bool {
	// Valid column names consist of alphanumeric characters and underscores.
	// They cannot start with a number.
	matched, _ := regexp.MatchString(`^[a-zA-Z_][a-zA-Z0-9_]*$`, s)
	return matched
}

// IsPasswordKey checks if the given string is related to a password.
func IsPasswordKey(s string) bool {
	passwordKeys := []string{"password", "pass", "pwd"}
	for _, passwordKey := range passwordKeys {
		if strings.ToLower(s) == passwordKey {
			return true
		}
	}
	return false
}

// IsUsernameKey checks if the given string is related to a username.
func IsUsernameKey(s string) bool {
	usernameKeys := []string{"username", "user", "login", "email", "mail", "account"}
	for _, usernameKey := range usernameKeys {
		if strings.ToLower(s) == usernameKey {
			return true
		}
	}
	return false
}

// IsSignUpKey checks if the given string is related to a sign-up or registration process.
func IsSignUpKey(s string) bool {
	signUpKeys := []string{"signup", "register", "registration"}
	for _, signUpKey := range signUpKeys {
		if strings.ToLower(s) == signUpKey {
			return true
		}
	}
	return false
}

// IsCaptchaKey checks if the given string is related to a captcha.
func IsCaptchaKey(s string) bool {
	captchaKeys := []string{"captcha", "recaptcha"}
	for _, captchaKey := range captchaKeys {
		if strings.ToLower(s) == captchaKey {
			return true
		}
	}
	return false
}

// IsCSRFKey checks if the given string is related to CSRF protection.
func IsCSRFKey(s string) bool {
	csrfKeys := []string{"csrf", "xsrf", "cross-site request forgery"}
	for _, csrfKey := range csrfKeys {
		if strings.Contains(strings.ToLower(s), csrfKey) {
			return true
		}
	}
	return false
}

// IsBase64 checks if the given string is a valid base64-encoded string.
func IsBase64(s string) bool {
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}

// IsBase64Password checks if the given string is a base64-encoded password.
func IsBase64Password(s string) bool {
	// Passwords should not contain whitespace, so we remove any whitespace
	// characters before checking if the string is a valid base64-encoded string.
	normalized := strings.ReplaceAll(s, " ", "")
	return IsBase64(normalized)
}

// IsMD5Data checks if the given string is a valid MD5 hash.
func IsMD5Data(s string) bool {
	matched, _ := regexp.MatchString(`^[a-f0-9]{32}$`, s)
	return matched
}

// IsSHA256Data checks if the given string is a valid SHA256 hash.
func IsSHA256Data(s string) bool {
	matched, _ := regexp.MatchString(`^[a-f0-9]{64}$`, s)
	return matched
}
