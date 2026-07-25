/**
* @Author: wscan
* @Date: 2026/06/16
* WAF Fingerprint Database - Built-in fingerprints for 50+ WAF products
 */
package waftest

// BlockResponseRule defines how a WAF blocks attack requests
type BlockResponseRule struct {
	StatusCodes    []int             // HTTP status codes returned when blocking
	BodyPatterns   []string          // Regex patterns in blocking response body
	HeaderPatterns map[string]string // Header key->value regex patterns when blocking
}

// WAFFingerprint defines a single WAF product fingerprint
type WAFFingerprint struct {
	Name     string // WAF product name
	Vendor   string // WAF vendor/company
	Category string // Category: "cloud-cn", "cloud-intl", "hardware", "software"
	// Passive detection rules - matched against normal HTTP responses
	Headers      map[string]string // Header name->value regex patterns (case-insensitive header name)
	Cookies      []string          // Cookie name patterns (regex)
	BodyPatterns []string          // Response body regex patterns
	StatusCodes  []int             // Characteristic status codes
	// Active detection rules - matched against WAF block responses
	BlockResponse *BlockResponseRule
	// Bypass suggestions
	BypassTips []string
}

// BuiltInWAFFingerprints returns the built-in WAF fingerprint database
func BuiltInWAFFingerprints() []WAFFingerprint {
	return []WAFFingerprint{

		// ==================== Chinese Cloud WAFs ====================

		{
			Name:     "Aliyun WAF (阿里云WAF)",
			Vendor:   "Alibaba Cloud",
			Category: "cloud-cn",
			Headers: map[string]string{
				"Server": "(?i)Aliyun",
			},
			BodyPatterns: []string{
				`://errors\.aliyun\.com`,
				`阿里云Web应用防火墙`,
				`error\.aliyun\.com`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403, 405},
				BodyPatterns: []string{
					`errors\.aliyun\.com`,
					`阿里云`,
				},
			},
			BypassTips: []string{
				"Try chunked transfer encoding",
				"Use HTTP/1.0 protocol version",
				"Double URL encoding bypass",
				"Try multipart/form-data instead of application/x-www-form-urlencoded",
			},
		},

		{
			Name:     "Tencent Cloud WAF (腾讯云WAF)",
			Vendor:   "Tencent Cloud",
			Category: "cloud-cn",
			BodyPatterns: []string{
				`waf\.tencent-cloud\.com`,
				`腾讯云Web应用防火墙`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`waf\.tencent-cloud\.com`,
					`腾讯云WAF`,
				},
			},
			BypassTips: []string{
				"Try HPP (HTTP Parameter Pollution)",
				"Use JSON content-type with array parameters",
				"Try Unicode/HTML entity encoding",
			},
		},

		{
			Name:     "SafeDog (安全狗)",
			Vendor:   "SafeDog",
			Category: "software",
			Headers: map[string]string{
				"Server": "(?i)safedog",
			},
			Cookies: []string{
				`safedog-flow-item`,
			},
			BodyPatterns: []string{
				`safedogsite/broswer_logo\.jpg`,
				`404\.safedog\.cn/sitedog_stat\.html`,
				`404\.safedog\.cn/images/safedogsite/head\.png`,
				`安全狗`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403, 406},
				BodyPatterns: []string{
					`safedog`,
					`安全狗`,
				},
			},
			BypassTips: []string{
				"Try URL encoding with double encoding",
				"Use inline comments for SQL injection: /*!SELECT*/",
				"Try HTTP/1.0 with chunked encoding",
				"Use multipart request to bypass body inspection",
			},
		},

		{
			Name:     "CloudWAF (知道创宇云防御)",
			Vendor:   "KnownSec (知道创宇)",
			Category: "cloud-cn",
			Headers: map[string]string{
				"X-Powered-By-CloudWAF": "",
				"X-Cache":               "(?i)CloudWAF",
			},
			BodyPatterns: []string{
				`CloudWAF`,
				`知道创宇`,
				`/ks-waf-error\.png`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`CloudWAF`,
					`知道创宇`,
				},
			},
			BypassTips: []string{
				"Try chunked transfer encoding",
				"Use case variation in SQL keywords",
				"Try inline comments /*!*/ for SQLi",
			},
		},

		{
			Name:     "Chuangyu Shield (创宇盾)",
			Vendor:   "Yunaq Chuangyu (知道创宇)",
			Category: "cloud-cn",
			BodyPatterns: []string{
				`help\.365cyd\.com/cyd-error-help\.html\?code=403`,
				`://help\.365cyd\.com`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`365cyd\.com`,
					`创宇盾`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use different content-type for POST requests",
			},
		},

		{
			Name:     "Xuanwudun (玄武盾)",
			Vendor:   "DBAPP Security",
			Category: "cloud-cn",
			BodyPatterns: []string{
				`://admin\.dbappwaf\.cn/`,
				`玄武盾`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`dbappwaf\.cn`,
					`玄武盾`,
				},
			},
			BypassTips: []string{
				"Try chunked encoding",
				"Use double URL encoding",
				"Try path parameter pollution (;/path)",
			},
		},

		{
			Name:     "Yundun (云盾)",
			Vendor:   "Yundun",
			Category: "cloud-cn",
			Headers: map[string]string{
				"Server":  "(?i)YUNDUN",
				"X-Cache": "(?i)YUNDUN",
			},
			BodyPatterns: []string{
				`Blocked by YUNDUN Cloud WAF`,
				`yundun\.com/yd_http_error/`,
				`www\.yundun\.com/static/js/fingerprint2\.js`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`YUNDUN`,
					`yundun\.com`,
				},
			},
			BypassTips: []string{
				"Try HTTP/1.0 protocol",
				"Use chunked transfer encoding",
				"Try different encoding methods",
			},
		},

		{
			Name:     "Yunsuo (云锁)",
			Vendor:   "Yunsuo",
			Category: "software",
			Cookies: []string{
				`yunsuo_session`,
			},
			BodyPatterns: []string{
				`yunsuologo`,
				`云锁`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`yunsuo`,
					`云锁`,
				},
			},
			BypassTips: []string{
				"Try URL double encoding",
				"Use HTTP parameter pollution",
				"Try chunked transfer encoding",
			},
		},

		{
			Name:     "360 WangZhanBao (360网站卫士)",
			Vendor:   "360",
			Category: "cloud-cn",
			Headers: map[string]string{
				"X-Powered-By-360WZB": "",
			},
			BodyPatterns: []string{
				`/wzws-waf-cgi/`,
				`360网站卫士`,
				`360wzb`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`360wzb`,
					`wzws-waf-cgi`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use Unicode encoding bypass",
				"Try multipart form data",
			},
		},

		{
			Name:     "Anquanbao (安全宝)",
			Vendor:   "Anquanbao",
			Category: "cloud-cn",
			Headers: map[string]string{
				"X-Powered-By-Anquanbao": "",
			},
			BodyPatterns: []string{
				`aqb_cc/error/`,
				`安全宝`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`aqb_cc`,
					`安全宝`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use chunked transfer encoding",
			},
		},

		{
			Name:     "Jiasule (加速乐)",
			Vendor:   "Jiasule",
			Category: "cloud-cn",
			Headers: map[string]string{
				"Server": "(?i)Jiasule-WAF",
			},
			Cookies: []string{
				`jsl_tracking`,
				`__jsluid`,
			},
			BodyPatterns: []string{
				`static\.jiasule\.com`,
				`notice-jiasule`,
				`加速乐`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`jiasule`,
					`加速乐`,
				},
			},
			BypassTips: []string{
				"Try HTTP/1.0 protocol",
				"Use double URL encoding",
				"Try inline comments for SQLi",
			},
		},

		{
			Name:     "AnYu (安域)",
			Vendor:   "AnYu Technologies",
			Category: "cloud-cn",
			Headers: map[string]string{
				"WZWS-RAY": "",
			},
			BodyPatterns: []string{
				`Sorry! your access has been intercepted by AnYu`,
				`AnYu- the green channel`,
				`安域`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`AnYu`,
					`安域`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use chunked encoding",
			},
		},

		{
			Name:     "Bluedon (蓝盾)",
			Vendor:   "Bluedon",
			Category: "hardware",
			Headers: map[string]string{
				"Server": "(?i)BDWAF",
			},
			BodyPatterns: []string{
				`Bluedon Web Application Firewall`,
				`蓝盾`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`Bluedon`,
					`蓝盾`,
				},
			},
			BypassTips: []string{
				"Try URL encoding bypass",
				"Use HTTP parameter pollution",
			},
		},

		{
			Name:     "NSFocus WAF (绿盟WAF)",
			Vendor:   "NSFocus",
			Category: "hardware",
			Headers: map[string]string{
				"Server": "(?i)NSFocus",
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
			},
			BypassTips: []string{
				"Try HTTP/1.0 protocol",
				"Use chunked encoding",
				"Double URL encoding bypass",
			},
		},

		{
			Name:     "Baidu Yunjiasu (百度云加速)",
			Vendor:   "Baidu",
			Category: "cloud-cn",
			Headers: map[string]string{
				"Server": "(?i)Yunjiasu",
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use different encoding methods",
			},
		},

		// ==================== International Cloud WAFs ====================

		{
			Name:     "AWS WAF",
			Vendor:   "Amazon",
			Category: "cloud-intl",
			Headers: map[string]string{
				"X-Amz-Cf-Id":      "",
				"X-Amz-Request-Id": "",
			},
			BodyPatterns: []string{
				`Request blocked by AWS WAF`,
				`AWS WAF`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`AWS WAF`,
					`Request blocked`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use JSON array parameters: {\"id\": [\"1' OR '1'='1\"]}",
				"Try chunked transfer encoding",
				"Use Unicode encoding for SQL keywords",
			},
		},

		{
			Name:     "Cloudflare WAF",
			Vendor:   "Cloudflare",
			Category: "cloud-intl",
			Headers: map[string]string{
				"Cf-Ray": "",
				"Server": "(?i)cloudflare",
			},
			Cookies: []string{
				`__cfduid`,
				`cf_clearance`,
			},
			BodyPatterns: []string{
				`Cloudflare Ray ID:`,
				`Attention Required! \| Cloudflare`,
				`cf-browser-verification`,
				`_cfduid`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403, 503},
				BodyPatterns: []string{
					`Cloudflare`,
					`cf-ray`,
					`Ray ID`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution (HPP)",
				"Use JSON content-type with nested parameters",
				"Try URL encoding with %00 null byte",
				"Use Unicode/HTML entity encoding for XSS payloads",
				"Try multipart/form-data upload bypass",
			},
		},

		{
			Name:     "Akamai Kona / WAF",
			Vendor:   "Akamai",
			Category: "cloud-intl",
			Headers: map[string]string{
				"Server":    "(?i)AkamaiGHost",
				"X-Akamai-": "",
				"X-Cache":   "(?i)Akamai",
			},
			BodyPatterns: []string{
				`Access Denied.*Akamai`,
				`AkamaiGHost`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`Akamai`,
					`Reference #`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use chunked transfer encoding",
				"Try Unicode normalization bypass",
				"Use content-type switching",
			},
		},

		{
			Name:     "Azure WAF",
			Vendor:   "Microsoft",
			Category: "cloud-intl",
			Headers: map[string]string{
				"X-Powered-By": `(?i)ASP\.NET`,
				"X-Azure-Ref":  "",
			},
			BodyPatterns: []string{
				`Azure Web App.*Error`,
				`Request blocked by Azure`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`Azure`,
					`iisnode`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use JSON content-type",
				"Try URL encoding bypass",
			},
		},

		{
			Name:     "Imperva / Incapsula WAF",
			Vendor:   "Imperva",
			Category: "cloud-intl",
			Headers: map[string]string{
				"X-CDN":   "(?i)Incapsula",
				"X-Iinfo": "",
			},
			Cookies: []string{
				`visid_incap_`,
				`incap_ses_`,
				`nlbi_`,
			},
			BodyPatterns: []string{
				`Incapsula incident ID`,
				`_Incapsula_Resource`,
				`Incapsula`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`Incapsula`,
					`_Incapsula_Resource`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use JSON content-type with arrays",
				"Try chunked transfer encoding",
				"Use double URL encoding",
				"Try null byte injection (%00)",
			},
		},

		{
			Name:     "Imperva SecureSphere",
			Vendor:   "Imperva",
			Category: "hardware",
			BodyPatterns: []string{
				`The incident ID is:`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`incident ID`,
					`SecureSphere`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use chunked encoding",
				"Try different content-type",
			},
		},

		{
			Name:     "Cloudfront WAF",
			Vendor:   "Amazon",
			Category: "cloud-intl",
			Headers: map[string]string{
				"X-Cache": "(?i)CloudFront",
				"Via":     "(?i)CloudFront",
			},
			BodyPatterns: []string{
				`Generated by cloudfront \(CloudFront\)`,
				`cloudfront\.net`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`CloudFront`,
					`cloudfront`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use JSON content-type",
				"Try URL encoding bypass",
			},
		},

		// ==================== Hardware/Software WAFs ====================

		{
			Name:     "ModSecurity",
			Vendor:   "OWASP / Trustwave",
			Category: "software",
			Headers: map[string]string{
				"Server": "(?i)mod[_ ]?security|NOYB",
			},
			BodyPatterns: []string{
				`This error was generated by Mod_Security`,
				`rules of the mod_security module`,
				`/modsecurity-errorpage/`,
				`Protected by Mod Security`,
				`ModSecurity IIS`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403, 418, 500},
				BodyPatterns: []string{
					`Mod_Security`,
					`mod_security`,
					`ModSecurity`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution (duplicate parameters)",
				"Use inline MySQL comments: /*!50000SELECT*/",
				"Try URL encoding / double URL encoding",
				"Use multipart/form-data to bypass body inspection",
				"Try HTTP/1.0 with chunked encoding",
				"Use null byte injection in SQL queries",
			},
		},

		{
			Name:     "F5 BIG-IP ASM",
			Vendor:   "F5 Networks",
			Category: "hardware",
			Headers: map[string]string{
				"X-WA-Info":  "",
				"X-Cnection": "(?i)close",
			},
			Cookies: []string{
				`TS[a-fA-F0-9]{6}`,
				`TS[a-fA-F0-9]{8}`,
				`BIGipServer`,
				`ASINFO`,
			},
			BodyPatterns: []string{
				`BigIP`,
				`F5`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`BigIP`,
					`Request Rejected`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use chunked transfer encoding",
				"Try different encoding (Unicode, double URL encoding)",
				"Use path parameter pollution (;/path)",
			},
		},

		{
			Name:     "Fortinet FortiWeb",
			Vendor:   "Fortinet",
			Category: "hardware",
			Cookies: []string{
				`FORTIWAFSID`,
			},
			BodyPatterns: []string{
				`FortiWeb`,
				`Fortinet`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`FortiWeb`,
					`Fortinet`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use URL encoding bypass",
				"Try multipart/form-data",
			},
		},

		{
			Name:     "Barracuda WAF",
			Vendor:   "Barracuda Networks",
			Category: "hardware",
			Cookies: []string{
				`barra_counter_session`,
				`BNI__BARRACUDA_LB_COOKIE`,
				`BNI_persistence`,
				`NCI__SessionId`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`Barracuda`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use chunked transfer encoding",
				"Try different encoding methods",
			},
		},

		{
			Name:     "Citrix NetScaler (AppFirewall)",
			Vendor:   "Citrix",
			Category: "hardware",
			Headers: map[string]string{
				"Via":        "(?i)NS-CACHE",
				"Cneonction": "(?i)close",
				"Nncoection": "(?i)close",
			},
			Cookies: []string{
				`ns_af`,
				`citrix_ns_id`,
				`NSC_`,
			},
			BodyPatterns: []string{
				`NS Transaction ID:`,
				`Violation Category: APPFW_`,
				`Citrix\|NetScaler`,
				`AppFW Session ID:`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`NetScaler`,
					`AppFW`,
					`Citrix`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use chunked encoding",
				"Try URL double encoding",
			},
		},

		{
			Name:     "Radware AppWall",
			Vendor:   "Radware",
			Category: "hardware",
			Headers: map[string]string{
				"X-SL-CompState": "",
			},
			BodyPatterns: []string{
				`CloudWebSec@radware\.com`,
				`Radware`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`Radware`,
					`AppWall`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use different encoding methods",
			},
		},

		{
			Name:     "Sophos UTM / XG",
			Vendor:   "Sophos",
			Category: "hardware",
			BodyPatterns: []string{
				`://www\.sophos\.com`,
				`Powered by Sophos`,
				`Powered by UTM Web Protection`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`Sophos`,
					`UTM Web Protection`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use chunked encoding",
				"Try URL encoding bypass",
			},
		},

		{
			Name:     "Sucuri WAF",
			Vendor:   "Sucuri",
			Category: "cloud-intl",
			BodyPatterns: []string{
				`Access Denied - Sucuri Website Firewall`,
				`Sucuri WebSite Firewall`,
				`://sucuri\.net/privacy-policy`,
				`://cdn\.sucuri\.net/sucuri-firewall-block\.css`,
				`cloudproxy@sucuri\.net`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`Sucuri`,
					`sucuri-firewall-block`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use JSON content-type",
				"Try URL encoding bypass",
			},
		},

		{
			Name:     "WebKnight",
			Vendor:   "AQTRONIX",
			Category: "software",
			Headers: map[string]string{
				"Server": "(?i)WebKnight",
			},
			BodyPatterns: []string{
				`WebKnight Application Firewall Alert`,
				`What is WebKnight\?`,
				`AQTRONIX WebKnight is an application firewall`,
				`://www\.aqtronix\.com/WebKnight`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{999, 403},
				BodyPatterns: []string{
					`WebKnight`,
					`AQTRONIX`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use chunked encoding",
			},
		},

		{
			Name:     "Naxsi WAF",
			Vendor:   "NBS System",
			Category: "software",
			Headers: map[string]string{
				"Server":        "(?i)naxsi",
				"X-Data-Origin": "(?i)naxsi",
			},
			BodyPatterns: []string{
				`Blocked By NAXSI`,
				`Naxsi Blocked Information`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{418, 403, 502},
				BodyPatterns: []string{
					`NAXSI`,
					`Blocked By NAXSI`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use Unicode encoding",
				"Try different encoding methods",
			},
		},

		{
			Name:     "dotDefender",
			Vendor:   "Applicure",
			Category: "software",
			Headers: map[string]string{
				"X-dotdefender-denied": "",
			},
			BodyPatterns: []string{
				`dotDefender Blocked Your Request`,
				`Applicure is the leading provider of web application security`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`dotDefender`,
					`Applicure`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use URL encoding bypass",
			},
		},

		{
			Name:     "IBM DataPower",
			Vendor:   "IBM",
			Category: "hardware",
			Headers: map[string]string{
				"X-Backside-Transport": "",
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use chunked encoding",
				"Try different encoding methods",
			},
		},

		{
			Name:     "IBM Proventia",
			Vendor:   "IBM",
			Category: "hardware",
			BodyPatterns: []string{
				`request does not match Proventia rules`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`Proventia`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use encoding bypass",
			},
		},

		{
			Name:     "Airlock WAF",
			Vendor:   "Ergon",
			Category: "hardware",
			Cookies: []string{
				`AL_LB`,
				`AL_SESS`,
			},
			BodyPatterns: []string{
				`Check your request and all parameters`,
				`The server detected a syntax error in your request`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`Airlock`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use chunked encoding",
			},
		},

		{
			Name:     "Teros / Citrix AF",
			Vendor:   "Citrix",
			Category: "hardware",
			Cookies: []string{
				`st8id`,
				`st8_wat`,
				`st8_wlf`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use chunked encoding",
			},
		},

		{
			Name:     "BinarySec WAF",
			Vendor:   "BinarySec",
			Category: "software",
			Headers: map[string]string{
				"Server":              "(?i)BinarySEC",
				"X-Binarysec-Via":     "",
				"X-Binarysec-Nocache": "",
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use chunked encoding",
			},
		},

		{
			Name:     "Profense",
			Vendor:   "Armorlogic",
			Category: "hardware",
			Headers: map[string]string{
				"Server": "(?i)Profense",
			},
			Cookies: []string{
				`PLBSID`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use chunked encoding",
			},
		},

		{
			Name:     "WatchGuard",
			Vendor:   "WatchGuard",
			Category: "hardware",
			Headers: map[string]string{
				"Server": "(?i)WatchGuard",
			},
			BodyPatterns: []string{
				`Request denied by WatchGuard Firewall`,
				`WatchGuard Technologies Inc`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`WatchGuard`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use chunked encoding",
			},
		},

		{
			Name:     "SonicWall",
			Vendor:   "Dell / SonicWall",
			Category: "hardware",
			Headers: map[string]string{
				"Server": "(?i)SonicWALL",
			},
			BodyPatterns: []string{
				`Web Site Blocked.*nsa_banner`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`SonicWALL`,
					`nsa_banner`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use chunked encoding",
			},
		},

		{
			Name:     "Wallarm WAF",
			Vendor:   "Wallarm",
			Category: "software",
			Headers: map[string]string{
				"Server": "(?i)nginx-wallarm",
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use chunked encoding",
			},
		},

		{
			Name:     "GoDaddy Website Protection",
			Vendor:   "GoDaddy",
			Category: "cloud-intl",
			BodyPatterns: []string{
				`GoDaddy Security - Access Denied`,
				`Access Denied - GoDaddy Website Firewall`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`GoDaddy`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use URL encoding bypass",
			},
		},

		{
			Name:     "Wordfence",
			Vendor:   "Defiant",
			Category: "software",
			BodyPatterns: []string{
				`Generated by Wordfence`,
				`A potentially unsafe operation has been detected`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`Wordfence`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use URL encoding bypass",
				"Try different encoding methods",
			},
		},

		{
			Name:     "Imunify360",
			Vendor:   "CloudLinux",
			Category: "software",
			Headers: map[string]string{
				"Server": "(?i)imunify360-webshield",
			},
			BodyPatterns: []string{
				`protected by Imunify360`,
				`Powered by Imunify360`,
				`imunify360 preloader`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`Imunify360`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use chunked encoding",
			},
		},

		{
			Name:     "Distil Networks",
			Vendor:   "Imperva (Distil)",
			Category: "cloud-intl",
			Headers: map[string]string{
				"X-Distil-CS": "",
			},
			BodyPatterns: []string{
				`cdn\.distilnetworks\.com/images/anomaly-detected\.png`,
				`distilCallbackGuard`,
				`distilCaptchaForm`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`distil`,
					`Distil`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use chunked encoding",
			},
		},

		{
			Name:     "DOSarrest",
			Vendor:   "DOSarrest",
			Category: "cloud-intl",
			Headers: map[string]string{
				"Server":           "(?i)DOSarrest",
				"X-DIS-Request-ID": "",
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use chunked encoding",
			},
		},

		{
			Name:     "Edgecast WAF (Verizon)",
			Vendor:   "Verizon",
			Category: "cloud-intl",
			Headers: map[string]string{
				"Server": "(?i)^ECD|ECS",
			},
			BodyPatterns: []string{
				`EdgeCast Web Application Firewall \(Verizon\)`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`EdgeCast`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use URL encoding bypass",
			},
		},

		{
			Name:     "Reblaze",
			Vendor:   "Reblaze",
			Category: "cloud-intl",
			Headers: map[string]string{
				"Server": "(?i)Reblaze Secure Web Gateway",
			},
			Cookies: []string{
				`rbzid`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use chunked encoding",
			},
		},

		{
			Name:     "Zenedge WAF",
			Vendor:   "Zenedge",
			Category: "cloud-intl",
			Headers: map[string]string{
				"Server":     "(?i)ZENEDGE",
				"X-Zen-Fury": "",
			},
			BodyPatterns: []string{
				`/__zenedge/`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`ZENEDGE`,
					`__zenedge`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use chunked encoding",
			},
		},

		{
			Name:     "ZScaler",
			Vendor:   "ZScaler",
			Category: "cloud-intl",
			Headers: map[string]string{
				"Server": "(?i)ZScaler",
			},
			BodyPatterns: []string{
				`Zscaler to protect you from internet threats`,
				`login\.zscloud\.net`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`Zscaler`,
					`ZScaler`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use chunked encoding",
			},
		},

		{
			Name:     "PerimeterX",
			Vendor:   "HUMAN Security",
			Category: "cloud-intl",
			BodyPatterns: []string{
				`://www\.perimeterx\.com/whywasiblocked`,
				`client\.perimeterx\.net`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`perimeterx`,
					`PerimeterX`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use different User-Agent",
				"Try JavaScript challenge bypass",
			},
		},

		{
			Name:     "StackPath WAF",
			Vendor:   "StackPath",
			Category: "cloud-intl",
			BodyPatterns: []string{
				`This website is using a security service to protect itself`,
				`You performed an action that triggered the service and blocked your request`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`StackPath`,
					`security service to protect itself`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use URL encoding bypass",
			},
		},

		{
			Name:     "CrawlProtect",
			Vendor:   "CrawlProtect",
			Category: "software",
			Cookies: []string{
				`crawlprotecttag`,
			},
			BodyPatterns: []string{
				`This site is protected by CrawlProtect`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`CrawlProtect`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use URL encoding bypass",
			},
		},

		{
			Name:     "CacheWall (Varnish)",
			Vendor:   "Varnish",
			Category: "software",
			Headers: map[string]string{
				"X-Cachewall-Reason": "",
				"X-Cachewall-Action": "",
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use chunked encoding",
			},
		},

		{
			Name:     "Comodo cWatch WAF",
			Vendor:   "Comodo",
			Category: "cloud-intl",
			Headers: map[string]string{
				"Server": "(?i)Protected by COMODO WAF",
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`COMODO`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use URL encoding bypass",
			},
		},

		{
			Name:     "Safe3 WAF",
			Vendor:   "Safe3",
			Category: "software",
			Headers: map[string]string{
				"Server":       "(?i)Safe3 Web Firewall",
				"X-Powered-By": "(?i)Safe3WAF",
			},
			BodyPatterns: []string{
				`Safe3waf`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`Safe3`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use URL encoding bypass",
			},
		},

		{
			Name:     "Nexusguard WAF",
			Vendor:   "Nexusguard",
			Category: "cloud-intl",
			BodyPatterns: []string{
				`://speresources\.nexusguard\.com/wafpage/index\.html`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`nexusguard`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use URL encoding bypass",
			},
		},

		{
			Name:     "NinjaFirewall",
			Vendor:   "NinTechNet",
			Category: "software",
			BodyPatterns: []string{
				`NinjaFirewall.*403 Forbidden`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`NinjaFirewall`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use URL encoding bypass",
			},
		},

		{
			Name:     "Astra Protection",
			Vendor:   "Astra",
			Category: "cloud-intl",
			Cookies: []string{
				`cz_astra_csrf_cookie`,
			},
			BodyPatterns: []string{
				`www\.getastra\.com/assets/images/`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`Astra`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use URL encoding bypass",
			},
		},

		{
			Name:     "BitNinja",
			Vendor:   "BitNinja",
			Category: "software",
			BodyPatterns: []string{
				`Security check by BitNinja`,
				`Visitor anti-robot validation`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`BitNinja`,
				},
			},
			BypassTips: []string{
				"Try different User-Agent",
				"Use URL encoding bypass",
			},
		},

		{
			Name:     "WebARX",
			Vendor:   "WebARX",
			Category: "software",
			BodyPatterns: []string{
				`WebARX.*Web Application Firewall`,
				`www\.webarxsecurity\.com`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`WebARX`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use URL encoding bypass",
			},
		},

		{
			Name:     "RSFirewall!",
			Vendor:   "RSJoomla!",
			Category: "software",
			BodyPatterns: []string{
				`COM_RSFIREWALL_403_FORBIDDEN`,
				`COM_RSFIREWALL_EVENT`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`RSFIREWALL`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use URL encoding bypass",
			},
		},

		{
			Name:     "SiteGuard (Sakura)",
			Vendor:   "Sakura Internet",
			Category: "software",
			BodyPatterns: []string{
				`Powered by SiteGuard`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`SiteGuard`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use URL encoding bypass",
			},
		},

		{
			Name:     "Sitelock TrueShield",
			Vendor:   "Sitelock",
			Category: "cloud-intl",
			BodyPatterns: []string{
				`SiteLock will remember you`,
				`sitelock-site-verification`,
				`SiteLock Incident ID`,
				`sitelock_shield_logo`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`SiteLock`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use URL encoding bypass",
			},
		},

		{
			Name:     "MalCare WAF",
			Vendor:   "MalCare",
			Category: "software",
			BodyPatterns: []string{
				`Firewall.*powered by.*MalCare`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`MalCare`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use URL encoding bypass",
			},
		},

		{
			Name:     "HyperGuard",
			Vendor:   "Art of Defend",
			Category: "hardware",
			Cookies: []string{
				`WODSESSION`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use chunked encoding",
			},
		},

		{
			Name:     "NevisProxy",
			Vendor:   "Nevis",
			Category: "hardware",
			Cookies: []string{
				`Navajo`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use chunked encoding",
			},
		},

		{
			Name:     "Greywizard",
			Vendor:   "Grey Wizard",
			Category: "cloud-intl",
			Headers: map[string]string{
				"Server": "(?i)greywizard",
			},
			BodyPatterns: []string{
				`Contact the website owner or Grey Wizard`,
				`Grey Wizard`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`Grey Wizard`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use URL encoding bypass",
			},
		},

		{
			Name:     "Janusec Application Gateway",
			Vendor:   "Janusec",
			Category: "software",
			BodyPatterns: []string{
				`by Janusec Application Gateway`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`Janusec`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use URL encoding bypass",
			},
		},

		{
			Name:     "ASP.NET RequestValidation",
			Vendor:   "Microsoft",
			Category: "software",
			BodyPatterns: []string{
				`Request Validation has detected a potentially dangerous client input`,
				`HttpRequestValidationException`,
				`ASP\.NET has detected data in the request`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{500},
				BodyPatterns: []string{
					`HttpRequestValidationException`,
					`Request Validation`,
				},
			},
			BypassTips: []string{
				"Try HTML entity encoding for XSS",
				"Use JavaScript: protocol variant",
				"Try Unicode encoding for special chars",
			},
		},

		{
			Name:     "Viettel WAF",
			Vendor:   "Viettel",
			Category: "cloud-intl",
			BodyPatterns: []string{
				`Viettel WAF system`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`Viettel WAF`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use URL encoding bypass",
			},
		},

		{
			Name:     "Instart DX",
			Vendor:   "Instart",
			Category: "cloud-intl",
			Headers: map[string]string{
				"X-Instart-Request-ID": "",
				"X-Instart-WL":         "",
				"X-Instart-Cache":      "",
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use chunked encoding",
			},
		},

		{
			Name:     "Cloudbric",
			Vendor:   "Cloudbric",
			Category: "cloud-intl",
			BodyPatterns: []string{
				`Your request was blocked by Cloudbric`,
				`cloudbric\.zendesk\.com`,
				`Cloudbric \| ERROR`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`Cloudbric`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use URL encoding bypass",
			},
		},

		{
			Name:     "Armor Defense",
			Vendor:   "Armor",
			Category: "cloud-intl",
			BodyPatterns: []string{
				`blocked by website protection from Armor`,
				`please create an Armor support ticket`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`Armor`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use URL encoding bypass",
			},
		},

		{
			Name:     "Nemesida WAF",
			Vendor:   "Nemesida",
			Category: "software",
			BodyPatterns: []string{
				`nwaf@`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`nwaf`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use URL encoding bypass",
			},
		},

		{
			Name:     "SEnginx (Neusoft)",
			Vendor:   "Neusoft",
			Category: "software",
			BodyPatterns: []string{
				`SENGINX-ROBOT-MITIGATION`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`SENGINX`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use URL encoding bypass",
			},
		},

		{
			Name:     "WTS-WAF",
			Vendor:   "WTS",
			Category: "software",
			Headers: map[string]string{
				"Server": "(?i)^wts",
			},
			BodyPatterns: []string{
				`WTS-WAF`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`WTS-WAF`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use URL encoding bypass",
			},
		},

		{
			Name:     "Mission Control Application Shield",
			Vendor:   "Mission Control",
			Category: "software",
			Headers: map[string]string{
				"Server": "(?i)Mission Control Application Shield",
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use URL encoding bypass",
			},
		},

		{
			Name:     "XLabs Security",
			Vendor:   "XLabs",
			Category: "cloud-intl",
			Headers: map[string]string{
				"Server":  "(?i)XLabs WAF",
				"X-Cdn":   "(?i)XLabs Security",
				"Secured": "(?i)XLabs",
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use URL encoding bypass",
			},
		},

		{
			Name:     "Alert Logic WAF",
			Vendor:   "Alert Logic",
			Category: "cloud-intl",
			BodyPatterns: []string{
				`Requested URL cannot be found.*The page has either been removed.*Reference ID:`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`Reference ID`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use URL encoding bypass",
			},
		},

		{
			Name:     "aeSecure",
			Vendor:   "aeSecure",
			Category: "software",
			Headers: map[string]string{
				"aeSecure-code": "",
			},
			BodyPatterns: []string{
				`aesecure_denied\.png`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`aeSecure`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use URL encoding bypass",
			},
		},

		{
			Name:     "DynamicWeb Injection Check",
			Vendor:   "DynamicWeb",
			Category: "software",
			Headers: map[string]string{
				"X-403-Status-By": "(?i)dw-inj-check",
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use URL encoding bypass",
			},
		},

		{
			Name:     "Palo Alto Next-Gen Firewall",
			Vendor:   "Palo Alto Networks",
			Category: "hardware",
			BodyPatterns: []string{
				`Palo Alto Next Generation Security Platform`,
				`blocked in accordance with company policy`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`Palo Alto`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use URL encoding bypass",
			},
		},

		{
			Name:     "BlockDoS",
			Vendor:   "BlockDoS",
			Category: "cloud-intl",
			Headers: map[string]string{
				"Server": `(?i)BlockDos\.net`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use URL encoding bypass",
			},
		},

		{
			Name:     "Cisco ACE XML Gateway",
			Vendor:   "Cisco",
			Category: "hardware",
			Headers: map[string]string{
				"Server": "(?i)ACE XML Gateway",
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use URL encoding bypass",
			},
		},

		{
			Name:     "NewDefend",
			Vendor:   "NewDefend",
			Category: "software",
			Headers: map[string]string{
				"Server": "(?i)newdefend",
			},
			BodyPatterns: []string{
				`://www\.newdefend\.com/feedback`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`newdefend`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use URL encoding bypass",
			},
		},

		{
			Name:     "ChinaCache CDN",
			Vendor:   "ChinaCache",
			Category: "cloud-cn",
			Headers: map[string]string{
				"Powered-By-ChinaCache": "",
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use URL encoding bypass",
			},
		},

		{
			Name:     "WebSEAL (IBM)",
			Vendor:   "IBM",
			Category: "hardware",
			Headers: map[string]string{
				"Server": "(?i)WebSEAL",
			},
			BodyPatterns: []string{
				`WebSEAL server received an invalid HTTP request`,
				`This is a WebSEAL error message template file`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`WebSEAL`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use URL encoding bypass",
			},
		},

		{
			Name:     "VirusDie",
			Vendor:   "VirusDie",
			Category: "software",
			BodyPatterns: []string{
				`cdn\.virusdie\.ru/splash/firewallstop\.png`,
				`Virusdie`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`VirusDie`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use URL encoding bypass",
			},
		},

		{
			Name:     "WebTotem",
			Vendor:   "WebTotem",
			Category: "software",
			BodyPatterns: []string{
				`The current request was blocked.*WebTotem`,
			},
			BlockResponse: &BlockResponseRule{
				StatusCodes: []int{403},
				BodyPatterns: []string{
					`WebTotem`,
				},
			},
			BypassTips: []string{
				"Try HTTP parameter pollution",
				"Use URL encoding bypass",
			},
		},
	}
}
