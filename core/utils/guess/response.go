/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package guess

import (
	"bytes"
	"encoding/json"
	"regexp"
	"wscan/core/apollo/http"
)

func isBadCaseNumber(caseNumber string) bool {
	// Check if caseNumber matches the pattern "[A-Z]+\d{2}-\d+"
	pattern := regexp.MustCompile(`^[A-Z]+\d{2}-\d+$`)
	return !pattern.MatchString(caseNumber)
}

func IsSensitiveJSONP(jsonpResponse string) bool {
	// Parse the JSONP response into a map
	var data map[string]interface{}
	err := json.Unmarshal([]byte(jsonpResponse), &data)
	if err != nil {
		return false
	}

	// Check if the map contains a key that indicates sensitive information
	_, sensitive := data["secret_key"]
	return sensitive
}

func IsGenericServerError(response *http.Response) bool {

	// Check if the response status code is in the 5xx range
	return response.StatusCode >= 500 && response.StatusCode < 600
}

func IsHTMLResponse(responseBody []byte) bool {
	// Check if the response starts with the "<!DOCTYPE html>" tag
	return bytes.HasPrefix(responseBody, []byte("<!DOCTYPE html>"))
}

func SearchChinaIDCardNumber(text string) string {
	// Find the first occurrence of a 18-digit Chinese ID card number in the text
	pattern := regexp.MustCompile(`\b\d{6}(19|20)\d{2}(0\d|1[0-2])([0-2]\d|3[01])\d{3}[\dxX]\b`)
	match := pattern.FindString(text)
	return match
}

func SearchChinaPhoneNumber(text string) string {
	// Find the first occurrence of a Chinese phone number in the text
	pattern := regexp.MustCompile(`\b(0\d{2,3}-)?\d{7,8}(-\d{1,4})?\b`)
	match := pattern.FindString(text)
	return match
}

func SearchChinaBankCard(text string) string {
	// Find the first occurrence of a 16-digit or 19-digit Chinese bank card number in the text
	pattern := regexp.MustCompile(`\b\d{16}(\d{3})?\b`)
	match := pattern.FindString(text)
	if match == "" {
		pattern = regexp.MustCompile(`\b\d{19}\b`)
		match = pattern.FindString(text)
	}
	return match
}

func SearchChinaAddress(text string) string {
	// Find the first occurrence of a Chinese address in the text
	pattern := regexp.MustCompile(`\b[\u4e00-\u9fa5]+(?:省|市|自治区)?[\u4e00-\u9fa5]+(?:市|区|县|镇|乡|村)[\u4e00-\u9fa5]*(?:街道)?[\u4e00-\u9fa5]*(?:号|\d+号)?\b`)
	match := pattern.FindString(text)
	return match
}

func SearchEmail(text string) string {
	// Find the first occurrence of an email address in the text
	pattern := regexp.MustCompile(`\b[\w.%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b`)
	match := pattern.FindString(text)
	return match
}

func SearchPrivateIP(text string) string {
	// Find the first occurrence of a private IP address in the text
	pattern := regexp.MustCompile(`\b(10|172\.(1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b`)
	match := pattern.FindString(text)
	return match
}

func SearchHTMLComments(text string) string {
	// Find the first occurrence of an HTML comment in the text
	pattern := regexp.MustCompile(`<!--(.|\n)*?-->`)
	match := pattern.FindString(text)
	return match
}

func SearchSystemPath(text string) string {
	// Find the first occurrence of a system path in the text
	pattern := regexp.MustCompile(`(/[A-Za-z0-9\-_+]+)+/?`)
	match := pattern.FindString(text)
	return match
}
