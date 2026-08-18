/**
* @Author: shaochuyu
* @Date: 2026-07-28
*
* TechGate gives vuln-detection plugins a reusable "only run if web technology X is
* present" gate backed by the same wappalyzer static engine that powers the WebUI
* 「技术识别」view (core/fingerprint). It is the plugin-facing counterpart of
* core/web/server.go's analyzePage: from one *http.Flow it builds a PageInput,
* runs the cached engine, and reports whether a named technology was detected.
*
* Why real-time engine (not KDB): the CEL fingerprint plugin (core/plugins/fingerprint)
* accumulates names into KDB *asynchronously* and its rule names ("PHP Detect") differ
* from wappalyzer tech names ("PHP"); a vuln plugin gated on it would race the order of
* execution and need a separate name mapping. Running AnalyzeStatic on the current flow
* is order-independent, self-contained, and shares one cached engine across all gates.
*
* Usage from a CheckAction:
*
*	if !base.HasTech(bi, flow, "PHP") {
*	    return nil // not PHP — skip this plugin's checks
*	}
*	// ...PHP-specific detection...
*
* or, to also read the matched version (e.g. to gate on "PHP < 5.6"):
*
*	if v, ok := base.TechVersion(bi, flow, "PHP"); ok && major(v) < 5 { ... }
*
* The engine is loaded once via fingerprint.DefaultEngine() and shared by all callers;
* nil-engine or nil-response flows degrade to "no match" rather than panicking, so a
* plugin that uses the gate never breaks scans when fingerprinting is unavailable.
 */
package base

import (
	"strings"

	"wscan/core/fingerprint"
	"wscan/core/http"
	logger "wscan/core/utils/log"
)

// techEngine is the process-wide cached wappalyzer engine used by all TechGate
// helpers. Initialized lazily on first use via DefaultEngine(); stays nil (and the
// gates return false) if the embedded DB failed to load — fingerprinting degrades
// gracefully without breaking vuln scanning.
var techEngine *fingerprint.Engine

// ensureEngine loads the cached engine once and returns it (nil on failure).
func ensureEngine() *fingerprint.Engine {
	if techEngine != nil {
		return techEngine
	}
	eng, err := fingerprint.DefaultEngine()
	if err != nil {
		logger.Errorf("tech gate: fingerprint engine unavailable: %v (tech-gated plugins will skip)", err)
		return nil
	}
	techEngine = eng
	return techEngine
}

// pageInputFromFlow mirrors core/web/server.go's analyzePage: it projects an
// *http.Flow's response (headers/body/cookies/script srcs/meta) into the
// fingerprint.PageInput AnalyzeStatic consumes. Returns ok=false when the flow
// has no response to analyze (e.g. scan-only seeds, or a flow that never got a
// reply) — callers should treat that as "no tech detected".
func pageInputFromFlow(flow *http.Flow) (fingerprint.PageInput, bool) {
	if flow == nil || flow.Response == nil || flow.Request == nil {
		return fingerprint.PageInput{}, false
	}
	resp := flow.Response
	urlStr := flow.Request.URL().String()

	htmlBytes := resp.GetRawBody()
	if len(htmlBytes) == 0 {
		if ub, err := resp.GetUTF8Body(); err == nil {
			htmlBytes = ub
		}
	}
	html := string(htmlBytes)

	cookies := map[string]string{}
	// resp.Cookies() and GetHeaderMap's Set-Cookie branch dereference
	// NativeResponse; guard against nil (synthetic flows in tests, or responses
	// built without a native net/http response).
	if resp.NativeResponse != nil {
		for _, c := range resp.Cookies() {
			cookies[c.Name] = c.Value
		}
	}

	// Build the header map directly from Response.Header so we don't depend on
	// NativeResponse (GetHeaderMap merges Set-Cookie via Cookies()).
	headers := map[string]string{}
	for k := range resp.Header {
		if k == "Set-Cookie" {
			continue
		}
		headers[k] = resp.Header.Get(k)
	}

	return fingerprint.PageInput{
		URL:     urlStr,
		Headers: headers,
		HTML:    html,
		Cookies: cookies,
		Scripts: fingerprint.ExtractScriptSrcs(html, urlStr),
		Meta:    fingerprint.ExtractMeta(html),
	}, true
}

// detectTechs runs the engine over one flow and returns the resolved technology
// list. Empty (not nil) when the engine or response is unavailable.
func detectTechs(flow *http.Flow) []fingerprint.Tech {
	eng := ensureEngine()
	if eng == nil {
		return nil
	}
	in, ok := pageInputFromFlow(flow)
	if !ok {
		return nil
	}
	return eng.AnalyzeStatic(in)
}

// techNameMatches compares a detected tech name against the wanted name
// case-insensitively. wappalyzer tech names are mixed-case ("PHP", "Apache",
// "jQuery"); plugins gate on the canonical capitalization, but a case-folded
// compare keeps the gate forgiving for callers who write "php".
func techNameMatches(detected, want string) bool {
	return strings.EqualFold(detected, want)
}

// HasTech reports whether the given web technology is present on the flow's
// response, by running the wappalyzer engine in real time. Safe to call with a
// nil bi or a flow lacking a response: it returns false rather than panicking.
// Plugins use this as a cheap pre-check before running tech-specific detection.
//
// Example: only scan for a PHP-only misconfig when PHP is actually served:
//
//	if !base.HasTech(bi, flow, "PHP") { return nil }
func HasTech(_ *Apollo, flow *http.Flow, tech string) bool {
	if tech == "" {
		return false
	}
	for _, t := range detectTechs(flow) {
		if techNameMatches(t.Name, tech) {
			return true
		}
	}
	return false
}

// TechVersion returns the detected version of the named technology on the flow
// (e.g. "7.4") plus ok=true when the technology is present, regardless of
// whether a version was resolved (version may be "" with ok=true). Plugins that
// need to gate on a specific version range use this instead of HasTech.
func TechVersion(_ *Apollo, flow *http.Flow, tech string) (version string, ok bool) {
	if tech == "" {
		return "", false
	}
	for _, t := range detectTechs(flow) {
		if techNameMatches(t.Name, tech) {
			return t.Version, true
		}
	}
	return "", false
}

// DetectTechs returns every wappalyzer technology detected on the flow's
// response. Plugins that need the full stack (e.g. "gate unless any CMS is
// present") use this instead of naming one tech up front.
func DetectTechs(_ *Apollo, flow *http.Flow) []fingerprint.Tech {
	return detectTechs(flow)
}
