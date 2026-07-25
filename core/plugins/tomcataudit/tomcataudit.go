/**
* @Author: wscan middleware audit
* @Description: Tomcat Audit Plugin - detects Tomcat fingerprint, default credentials,
* manager interface exposure, example apps, known CVEs, and Ghostcat vulnerability
 */
package tomcataudit

import (
	"context"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/utils"
	logger "wscan/core/utils/log"
)

// tomcatVersionCVEs maps Tomcat version ranges to known CVEs
var tomcatVersionCVEs = []struct {
	minMajor, minMinor, minPatch int
	maxMajor, maxMinor, maxPatch int
	cveID                        string
	description                  string
}{
	{7, 0, 0, 7, 0, 32, "CVE-2011-2526", "Apache Tomcat Manager application HTML injection"},
	{7, 0, 0, 7, 0, 27, "CVE-2011-2204", "Apache Tomcat HTTP Digest authentication weakness"},
	{6, 0, 0, 6, 0, 36, "CVE-2011-3190", "Apache Tomcat HTTP DOS via chunked transfer encoding"},
	{7, 0, 0, 7, 0, 21, "CVE-2011-1184", "Apache Tomcat DIGEST auth plaintext password disclosure"},
	{6, 0, 0, 6, 0, 32, "CVE-2012-0022", "Apache Tomcat HTTP NIO connector Information Disclosure"},
	{7, 0, 0, 7, 0, 23, "CVE-2012-0022", "Apache Tomcat HTTP NIO connector Information Disclosure"},
	{5, 5, 0, 5, 5, 35, "CVE-2012-0022", "Apache Tomcat HTTP NIO connector Information Disclosure"},
	{6, 0, 0, 6, 0, 35, "CVE-2012-3546", "Apache Tomcat HTTP digest authentication bypass"},
	{7, 0, 0, 7, 0, 30, "CVE-2012-3546", "Apache Tomcat HTTP digest authentication bypass"},
	{6, 0, 0, 6, 0, 36, "CVE-2013-1976", "Apache Tomcat CSRF protection bypass"},
	{7, 0, 0, 7, 0, 39, "CVE-2013-1976", "Apache Tomcat CSRF protection bypass"},
	{8, 0, 0, 8, 0, 1, "CVE-2013-4322", "Apache Tomcat denial of service"},
	{7, 0, 0, 7, 0, 40, "CVE-2014-0050", "Apache Tomcat denial of service via multipart upload"},
	{8, 0, 0, 8, 0, 3, "CVE-2014-0050", "Apache Tomcat denial of service via multipart upload"},
	{7, 0, 0, 7, 0, 42, "CVE-2014-0075", "Apache Tomcat Information Disclosure"},
	{8, 0, 0, 8, 0, 5, "CVE-2014-0075", "Apache Tomcat Information Disclosure"},
	{8, 0, 0, 8, 0, 8, "CVE-2014-0119", "Apache Tomcat denial of service"},
	{7, 0, 0, 7, 0, 54, "CVE-2014-0119", "Apache Tomcat denial of service"},
	{8, 0, 0, 8, 0, 9, "CVE-2014-0230", "Apache Tomcat denial of service"},
	{7, 0, 0, 7, 0, 55, "CVE-2014-0230", "Apache Tomcat denial of service"},
	{6, 0, 0, 6, 0, 43, "CVE-2014-0230", "Apache Tomcat denial of service"},
	{8, 0, 0, 8, 0, 12, "CVE-2015-5174", "Apache Tomcat session fixation"},
	{7, 0, 0, 7, 0, 62, "CVE-2015-5174", "Apache Tomcat session fixation"},
	{8, 0, 0, 8, 0, 21, "CVE-2015-5345", "Apache Tomcat session fixation"},
	{7, 0, 0, 7, 0, 67, "CVE-2015-5345", "Apache Tomcat session fixation"},
	{6, 0, 0, 6, 0, 45, "CVE-2015-5345", "Apache Tomcat session fixation"},
	{8, 0, 0, 8, 0, 30, "CVE-2016-0706", "Apache Tomcat security manager bypass"},
	{8, 0, 0, 8, 0, 32, "CVE-2016-0714", "Apache Tomcat Information Disclosure"},
	{8, 0, 0, 8, 0, 33, "CVE-2016-6325", "Apache Tomcat Security Manager bypass"},
	{8, 5, 0, 8, 5, 6, "CVE-2016-6325", "Apache Tomcat Security Manager bypass"},
	{8, 0, 0, 8, 0, 36, "CVE-2016-6816", "Apache Tomcat HTTP/2 denial of service"},
	{8, 5, 0, 8, 5, 12, "CVE-2016-6816", "Apache Tomcat HTTP/2 denial of service"},
	{9, 0, 0, 9, 0, 0, "CVE-2016-6816", "Apache Tomcat HTTP/2 denial of service"},
	{8, 0, 0, 8, 0, 39, "CVE-2017-6056", "Apache Tomcat cross-site scripting"},
	{8, 5, 0, 8, 5, 15, "CVE-2017-6056", "Apache Tomcat cross-site scripting"},
	{9, 0, 0, 9, 0, 0, "CVE-2017-6056", "Apache Tomcat cross-site scripting"},
	{7, 0, 0, 7, 0, 76, "CVE-2017-5647", "Apache Tomcat pipelined request processing"},
	{8, 0, 0, 8, 0, 42, "CVE-2017-5647", "Apache Tomcat pipelined request processing"},
	{8, 5, 0, 8, 5, 19, "CVE-2017-5647", "Apache Tomcat pipelined request processing"},
	{9, 0, 0, 9, 0, 0, "CVE-2017-5647", "Apache Tomcat pipelined request processing"},
	{8, 5, 0, 8, 5, 20, "CVE-2017-12615", "Apache Tomcat PUT RCE (Windows)"},
	{8, 0, 0, 8, 0, 45, "CVE-2017-12615", "Apache Tomcat PUT RCE (Windows)"},
	{7, 0, 0, 7, 0, 79, "CVE-2017-12617", "Apache Tomcat JSP upload RCE"},
	{8, 5, 0, 8, 5, 23, "CVE-2017-12617", "Apache Tomcat JSP upload RCE"},
	{8, 0, 0, 8, 0, 47, "CVE-2017-12617", "Apache Tomcat JSP upload RCE"},
	{9, 0, 0, 9, 0, 0, "CVE-2019-0199", "Apache Tomcat HTTP/2 denial of service"},
	{9, 0, 0, 9, 0, 14, "CVE-2019-0232", "Apache Tomcat CGI RCE (Windows)"},
	{7, 0, 0, 7, 0, 94, "CVE-2019-10072", "Apache Tomcat HTTP/2 denial of service"},
	{8, 5, 0, 8, 5, 42, "CVE-2019-10072", "Apache Tomcat HTTP/2 denial of service"},
	{9, 0, 0, 9, 0, 22, "CVE-2019-10072", "Apache Tomcat HTTP/2 denial of service"},
	{7, 0, 0, 7, 0, 96, "CVE-2020-1938", "Apache Tomcat AJP Ghostcat file read/inclusion"},
	{8, 5, 0, 8, 5, 46, "CVE-2020-1938", "Apache Tomcat AJP Ghostcat file read/inclusion"},
	{9, 0, 0, 9, 0, 30, "CVE-2020-1938", "Apache Tomcat AJP Ghostcat file read/inclusion"},
	{7, 0, 0, 7, 0, 100, "CVE-2020-9484", "Apache Tomcat session persistence deserialization RCE"},
	{8, 5, 0, 8, 5, 55, "CVE-2020-9484", "Apache Tomcat session persistence deserialization RCE"},
	{9, 0, 0, 9, 0, 35, "CVE-2020-9484", "Apache Tomcat session persistence deserialization RCE"},
	{10, 0, 0, 10, 0, 4, "CVE-2020-9484", "Apache Tomcat session persistence deserialization RCE"},
	{10, 0, 0, 10, 0, 2, "CVE-2020-11996", "Apache Tomcat HTTP/2 denial of service"},
	{10, 0, 0, 10, 0, 6, "CVE-2021-25122", "Apache Tomcat Information Disclosure"},
	{10, 0, 0, 10, 0, 6, "CVE-2021-25329", "Apache Tomcat request smuggling"},
	{9, 0, 0, 9, 0, 44, "CVE-2021-25122", "Apache Tomcat Information Disclosure"},
	{9, 0, 0, 9, 0, 45, "CVE-2021-25329", "Apache Tomcat request smuggling"},
	{10, 0, 0, 10, 0, 10, "CVE-2021-2471", "Apache Tomcat Information Disclosure"},
	{9, 0, 0, 9, 0, 48, "CVE-2021-2471", "Apache Tomcat Information Disclosure"},
	{10, 1, 0, 10, 1, 6, "CVE-2022-23181", "Apache Tomcat session persistence deserialization RCE"},
	{10, 0, 0, 10, 0, 16, "CVE-2022-23181", "Apache Tomcat session persistence deserialization RCE"},
	{10, 1, 0, 10, 1, 11, "CVE-2022-29885", "Apache Tomcat denial of service"},
	{10, 0, 0, 10, 0, 21, "CVE-2022-29885", "Apache Tomcat denial of service"},
	{10, 1, 0, 10, 1, 13, "CVE-2023-24998", "Apache Tomcat multipart upload DoS"},
	{10, 0, 0, 10, 0, 23, "CVE-2023-24998", "Apache Tomcat multipart upload DoS"},
	{9, 0, 0, 9, 0, 72, "CVE-2023-24998", "Apache Tomcat multipart upload DoS"},
}

// defaultCredentials contains default Tomcat Manager credential pairs
var defaultCredentials = [][2]string{
	{"admin", "admin"},
	{"admin", "password"},
	{"admin", "tomcat"},
	{"admin", ""},
	{"tomcat", "tomcat"},
	{"tomcat", "changelt"},
	{"tomcat", "s3cret"},
	{"tomcat", "password"},
	{"tomcat", ""},
	{"role1", "role1"},
	{"role1", "tomcat"},
	{"manager", "manager"},
	{"manager", ""},
	{"both", "tomcat"},
	{"both", ""},
	{"manager", "manager"},
	{"ccm", "ccm"},
	{"j2deployer", "j2deployer"},
	{"admin", "adminadmin"},
	{"admin", "j5Brn9"},
	{"admin", "owaspbsp"},
	{"owasp", "owasp"},
	{"x", "x"},
	{"q", "q"},
}

// isTomcatApp checks if the target appears to be a Tomcat application
func isTomcatApp(flow *http.Flow) bool {
	if flow == nil || flow.Response == nil {
		return false
	}
	// Check Server header
	serverHeader := flow.Response.GetHeader("Server")
	if strings.Contains(strings.ToLower(serverHeader), "coyote") ||
		strings.Contains(strings.ToLower(serverHeader), "tomcat") {
		return true
	}
	// Check response body for Tomcat signatures
	body := flow.Response.Text
	if strings.Contains(body, "Apache Tomcat") ||
		strings.Contains(body, "org.apache.catalina") ||
		strings.Contains(body, "org.apache.coyote") ||
		strings.Contains(body, "org.apache.jasper") {
		return true
	}
	// Check error page pattern
	if strings.Contains(body, "type Status report") && strings.Contains(body, "HTTP Status") {
		return true
	}
	return false
}

// extractTomcatVersion attempts to extract Tomcat version from Server header or error page
func extractTomcatVersion(flow *http.Flow) (major, minor, patch int, found bool) {
	re := regexp.MustCompile(`Apache Tomcat/(\d+)\.(\d+)\.(\d+)`)
	// Try Server header
	serverHeader := flow.Response.GetHeader("Server")
	if matches := re.FindStringSubmatch(serverHeader); len(matches) == 4 {
		fmt.Sscanf(matches[1], "%d", &major)
		fmt.Sscanf(matches[2], "%d", &minor)
		fmt.Sscanf(matches[3], "%d", &patch)
		return major, minor, patch, true
	}
	// Try response body
	if matches := re.FindStringSubmatch(flow.Response.Text); len(matches) == 4 {
		fmt.Sscanf(matches[1], "%d", &major)
		fmt.Sscanf(matches[2], "%d", &minor)
		fmt.Sscanf(matches[3], "%d", &patch)
		return major, minor, patch, true
	}
	return 0, 0, 0, false
}

// versionInRange checks if a version falls within a CVE range
func versionInRange(major, minor, patch, minMaj, minMin, minPat, maxMaj, maxMin, maxPat int) bool {
	v := major*10000 + minor*100 + patch
	vMin := minMaj*10000 + minMin*100 + minPat
	vMax := maxMaj*10000 + maxMin*100 + maxPat
	return v >= vMin && v <= vMax
}

// TomcatFingerprint detects Tomcat via Server header and error pages
type TomcatFingerprint struct{}

func (*TomcatFingerprint) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			if flow == nil || flow.Response == nil {
				return nil
			}
			logger.Debugf("TomcatAudit: fingerprint check for %s", flow.Request.URL().String())

			if !isTomcatApp(flow) {
				// Send a request to trigger an error page
				baseURL := flow.Request.URL()
				testURL := http.UrlJoinPath(baseURL.String(), fmt.Sprintf("/%d.jsp", utils.RandInt(100000, 999999)))
				req, err := http.NewRequest("GET", testURL, nil)
				if err != nil {
					return nil
				}
				res, err := a.HTTPClient.Respond(ctx, req)
				if err != nil {
					return nil
				}
				serverHeader := res.GetHeader("Server")
				if !strings.Contains(strings.ToLower(serverHeader), "coyote") &&
					!strings.Contains(strings.ToLower(serverHeader), "tomcat") &&
					!strings.Contains(res.Text, "Apache Tomcat") &&
					!strings.Contains(res.Text, "type Status report") {
					return nil
				}
			}

			// Tomcat detected - extract version and check CVEs
			major, minor, patch, versionFound := extractTomcatVersion(flow)
			v := a.NewWebVuln(flow.Request, flow.Response, nil)
			if v != nil {
				v.SetTargetURL(flow.Request.URL())
				v.Payload = "Tomcat fingerprint detected"
				if versionFound {
					v.Add("version", fmt.Sprintf("%d.%d.%d", major, minor, patch))
					// Check for known CVEs based on version
					var matchedCVEs []string
					for _, cve := range tomcatVersionCVEs {
						if versionInRange(major, minor, patch, cve.minMajor, cve.minMinor, cve.minPatch,
							cve.maxMajor, cve.maxMinor, cve.maxPatch) {
							matchedCVEs = append(matchedCVEs, cve.cveID+": "+cve.description)
						}
					}
					if len(matchedCVEs) > 0 {
						v.AddStringArray("potential_cves", matchedCVEs)
					}
				}
				a.OutputVuln(v)
			}
			return nil
		},
		Channel: "website",
		Binding: &model.VulnBinding{
			ID:       "tomcat-audit/fingerprint",
			Plugin:   "tomcat-audit",
			Category: "tomcat-audit/fingerprint",
			Severity: model.SeverityInfo,
		},
	}
}

// TomcatDefaultCredentials tests default credential pairs on Manager interface
type TomcatDefaultCredentials struct{}

func (*TomcatDefaultCredentials) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			if flow == nil || flow.Response == nil {
				return nil
			}
			logger.Debugf("TomcatAudit: default credentials check for %s", flow.Request.URL().String())

			baseURL := flow.Request.URL()

			// First, find the manager interface
			managerPaths := []string{"/manager/html", "/manager/status", "/host-manager/html"}
			var managerURL string
			for _, path := range managerPaths {
				testURL := http.UrlJoinPath(baseURL.String(), path)
				req, err := http.NewRequest("GET", testURL, nil)
				if err != nil {
					continue
				}
				res, err := a.HTTPClient.Respond(ctx, req)
				if err != nil {
					continue
				}
				// 401 indicates the manager exists and requires auth
				if res.StatusCode == 401 {
					managerURL = testURL
					break
				}
				// 200 means it's accessible without auth (also report)
				if res.StatusCode == 200 && (strings.Contains(res.Text, "Tomcat Web Application Manager") ||
					strings.Contains(res.Text, "Server Status") ||
					strings.Contains(res.Text, "host-manager")) {
					v := a.NewWebVuln(req, res, nil)
					if v != nil {
						v.SetTargetURL(req.URL())
						v.Payload = path + " accessible without authentication"
						v.Add("credential", "none required")
						a.OutputVuln(v)
					}
					return nil
				}
			}

			if managerURL == "" {
				return nil
			}

			// Get baseline response with wrong credentials
			wrongCred := base64.StdEncoding.EncodeToString([]byte("wscan_invalid:wscan_invalid"))
			baselineReq, _ := http.NewRequest("GET", managerURL, nil)
			baselineReq.SetHeader("Authorization", "Basic "+wrongCred)
			baselineRes, err := a.HTTPClient.Respond(ctx, baselineReq)
			if err != nil {
				return nil
			}

			// Test default credentials
			for _, cred := range defaultCredentials {
				cred := cred
				credStr := base64.StdEncoding.EncodeToString([]byte(cred[0] + ":" + cred[1]))
				req, err := http.NewRequest("GET", managerURL, nil)
				if err != nil {
					continue
				}
				req.SetHeader("Authorization", "Basic "+credStr)
				res, err := a.HTTPClient.Respond(ctx, req)
				if err != nil {
					continue
				}
				if res.StatusCode >= 200 && res.StatusCode < 400 {
					// Compare with baseline - if very similar, the credentials likely failed
					if baselineRes != nil {
						baselineLen := len(baselineRes.Text)
						resLen := len(res.Text)
						// If response lengths are very similar and baseline was 401, likely failed
						if baselineRes.StatusCode == 401 && res.StatusCode == 401 {
							continue
						}
						if baselineLen > 0 && resLen > 0 {
							ratio := float64(resLen) / float64(baselineLen)
							if ratio > 0.95 && ratio < 1.05 && baselineRes.StatusCode == res.StatusCode {
								continue
							}
						}
					}
					v := a.NewWebVuln(req, res, nil)
					if v != nil {
						v.SetTargetURL(req.URL())
						v.Payload = fmt.Sprintf("Default credentials: %s:%s", cred[0], cred[1])
						v.Add("username", cred[0])
						v.Add("password", cred[1])
						a.OutputVuln(v)
					}
					return nil
				}
			}
			return nil
		},
		Channel: "website",
		Binding: &model.VulnBinding{
			ID:       "tomcat-audit/default-credentials",
			Plugin:   "tomcat-audit",
			Category: "tomcat-audit/default-credentials",
			Severity: model.SeverityHigh,
		},
	}
}

// TomcatManagerExposure checks for exposed Manager and Host Manager interfaces
type TomcatManagerExposure struct{}

func (*TomcatManagerExposure) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			if flow == nil || flow.Response == nil {
				return nil
			}
			logger.Debugf("TomcatAudit: manager exposure check for %s", flow.Request.URL().String())

			baseURL := flow.Request.URL()
			paths := []struct {
				path        string
				description string
			}{
				{"/manager/html", "Tomcat Web Application Manager"},
				{"/manager/status", "Tomcat Server Status"},
				{"/manager/text/list", "Tomcat Manager Text Interface"},
				{"/host-manager/html", "Tomcat Virtual Host Manager"},
			}

			for _, p := range paths {
				testURL := http.UrlJoinPath(baseURL.String(), p.path)
				req, err := http.NewRequest("GET", testURL, nil)
				if err != nil {
					continue
				}
				res, err := a.HTTPClient.Respond(ctx, req)
				if err != nil {
					continue
				}
				// 200 = accessible; 401 = exists but requires auth (still info disclosure)
				if res.StatusCode == 200 || res.StatusCode == 401 {
					v := a.NewWebVuln(req, res, nil)
					if v != nil {
						v.SetTargetURL(req.URL())
						if res.StatusCode == 401 {
							v.Payload = p.path + " exists (authentication required)"
						} else {
							v.Payload = p.path + " accessible without authentication"
						}
						v.Add("path", p.path)
						v.Add("status_code", fmt.Sprintf("%d", res.StatusCode))
						a.OutputVuln(v)
					}
				}
			}
			return nil
		},
		Channel: "website",
		Binding: &model.VulnBinding{
			ID:       "tomcat-audit/manager-exposure",
			Plugin:   "tomcat-audit",
			Category: "tomcat-audit/manager-exposure",
			Severity: model.SeverityMedium,
		},
	}
}

// TomcatExampleApps checks for default example applications and documentation
type TomcatExampleApps struct{}

func (*TomcatExampleApps) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			if flow == nil || flow.Response == nil {
				return nil
			}
			logger.Debugf("TomcatAudit: example apps check for %s", flow.Request.URL().String())

			baseURL := flow.Request.URL()
			paths := []struct {
				path        string
				description string
			}{
				{"/examples/", "Tomcat Servlet and JSP Examples"},
				{"/examples/servlets/", "Tomcat Servlet Examples"},
				{"/examples/jsp/", "Tomcat JSP Examples"},
				{"/docs/", "Tomcat Documentation"},
				{"/docs/changelog.html", "Tomcat Changelog (version info)"},
				{"/manager/", "Tomcat Manager"},
			}

			for _, p := range paths {
				testURL := http.UrlJoinPath(baseURL.String(), p.path)
				req, err := http.NewRequest("GET", testURL, nil)
				if err != nil {
					continue
				}
				res, err := a.HTTPClient.Respond(ctx, req)
				if err != nil {
					continue
				}
				if res.StatusCode == 200 {
					v := a.NewWebVuln(req, res, nil)
					if v != nil {
						v.SetTargetURL(req.URL())
						v.Payload = p.path + " - " + p.description + " exposed"
						v.Add("path", p.path)
						v.Add("description", p.description)
						a.OutputVuln(v)
					}
				}
			}
			return nil
		},
		Channel: "website",
		Binding: &model.VulnBinding{
			ID:       "tomcat-audit/example-apps",
			Plugin:   "tomcat-audit",
			Category: "tomcat-audit/example-apps",
			Severity: model.SeverityLow,
		},
	}
}

// TomcatGhostcat checks for CVE-2020-1938 (Ghostcat) via AJP connector
type TomcatGhostcat struct{}

func (*TomcatGhostcat) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			if flow == nil || flow.Response == nil {
				return nil
			}
			logger.Debugf("TomcatAudit: Ghostcat (CVE-2020-1938) check for %s", flow.Request.URL().String())

			baseURL := flow.Request.URL()
			// The Ghostcat vulnerability exploits the AJP connector
			// via crafted URL paths that may reveal web.xml contents
			// Check for AJP-related path traversal patterns
			ghostcatPaths := []string{
				"/ajp///WEB-INF/web.xml",
				"/;ajp///WEB-INF/web.xml",
			}

			for _, path := range ghostcatPaths {
				testURL := http.UrlJoinPath(baseURL.String(), path)
				req, err := http.NewRequest("GET", testURL, nil)
				if err != nil {
					continue
				}
				res, err := a.HTTPClient.Respond(ctx, req)
				if err != nil {
					continue
				}
				// Check if web.xml contents are revealed
				if res.StatusCode == 200 &&
					(strings.Contains(res.Text, "<web-app") ||
						strings.Contains(res.Text, "<display-name") ||
						strings.Contains(res.Text, "<servlet>") ||
						strings.Contains(res.Text, "WEB-INF")) {
					v := a.NewWebVuln(req, res, nil)
					if v != nil {
						v.SetTargetURL(req.URL())
						v.Payload = "CVE-2020-1938 Ghostcat: WEB-INF/web.xml readable via AJP connector"
						v.Add("cve", "CVE-2020-1938")
						v.Add("description", "Ghostcat: AJP file read/inclusion vulnerability")
						a.OutputVuln(v)
					}
					return nil
				}
			}
			return nil
		},
		Channel: "website",
		Binding: &model.VulnBinding{
			ID:       "tomcat-audit/ghostcat-cve-2020-1938",
			Plugin:   "tomcat-audit",
			Category: "tomcat-audit/ghostcat-cve-2020-1938",
			Severity: model.SeverityCritical,
		},
	}
}

// TomcatPUTRCE checks for CVE-2017-12615 (PUT method RCE on Windows)
type TomcatPUTRCE struct{}

func (*TomcatPUTRCE) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			if flow == nil || flow.Response == nil {
				return nil
			}
			logger.Debugf("TomcatAudit: CVE-2017-12615 PUT RCE check for %s", flow.Request.URL().String())

			baseURL := flow.Request.URL()
			// Try uploading a test text file via PUT
			testFileName := fmt.Sprintf("wscan_test_%d.txt", utils.RandInt(100000, 999999))
			testURL := http.UrlJoinPath(baseURL.String(), testFileName)
			testContent := fmt.Sprintf("wscan-test-%d", utils.RandInt(100000, 999999))

			req, err := http.NewRequest("PUT", testURL, strings.NewReader(testContent))
			if err != nil {
				return nil
			}
			req.SetHeader("Content-Type", "text/plain")
			res, err := a.HTTPClient.Respond(ctx, req)
			if err != nil {
				return nil
			}

			// If PUT succeeded (201 or 200), try to read the file back
			if res.StatusCode == 201 || res.StatusCode == 200 || res.StatusCode == 204 {
				verifyReq, _ := http.NewRequest("GET", testURL, nil)
				verifyRes, err := a.HTTPClient.Respond(ctx, verifyReq)
				if err == nil && verifyRes.StatusCode == 200 && strings.Contains(verifyRes.Text, testContent) {
					v := a.NewWebVuln(req, res, nil)
					if v != nil {
						v.SetTargetURL(req.URL())
						v.Payload = "CVE-2017-12615: PUT method allows file upload"
						v.Add("cve", "CVE-2017-12615")
						v.Add("description", "Tomcat PUT RCE: arbitrary file upload via PUT method")
						a.OutputVuln(v)
					}
					// Clean up the test file
					delReq, _ := http.NewRequest("DELETE", testURL, nil)
					a.HTTPClient.Respond(ctx, delReq)
				}
			}
			return nil
		},
		Channel: "website",
		Binding: &model.VulnBinding{
			ID:       "tomcat-audit/put-rce-cve-2017-12615",
			Plugin:   "tomcat-audit",
			Category: "tomcat-audit/put-rce-cve-2017-12615",
			Severity: model.SeverityCritical,
		},
	}
}

// Config holds the plugin configuration
type Config struct {
	base.PluginBaseConfig `json:",inline" yaml:",inline"`
}

// BaseConfig returns the base configuration
func (c *Config) BaseConfig() *base.PluginBaseConfig {
	return &c.PluginBaseConfig
}

// TomcatAudit is the main plugin struct
type TomcatAudit struct {
	base.PluginMixinInitConfig
	base.PluginMixinClose
}

// Close shuts down the plugin
func (*TomcatAudit) Close() error {
	return nil
}

// DefaultConfig returns the default configuration
func (*TomcatAudit) DefaultConfig() base.PluginConfigInterface {
	config := &Config{PluginBaseConfig: base.PluginBaseConfig{
		Name:    "tomcat-audit",
		Enabled: true,
	}}
	return config
}

// Fingers returns the detection rules
func (p *TomcatAudit) Fingers() []*base.Finger {
	fingers := []*base.Finger{}
	fingers = append(fingers, (&TomcatFingerprint{}).Finger())
	fingers = append(fingers, (&TomcatDefaultCredentials{}).Finger())
	fingers = append(fingers, (&TomcatManagerExposure{}).Finger())
	fingers = append(fingers, (&TomcatExampleApps{}).Finger())
	fingers = append(fingers, (&TomcatGhostcat{}).Finger())
	fingers = append(fingers, (&TomcatPUTRCE{}).Finger())
	return fingers
}

// GetConfig returns the current configuration
func (p *TomcatAudit) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

// Init initializes the plugin
func (p *TomcatAudit) Init(ctx context.Context, pci base.PluginConfigInterface, ab *base.ApolloBase) error {
	logger.Debug("TomcatAudit Plugin init")
	return p.PluginMixinInitConfig.Init(ctx, pci, ab)
}
