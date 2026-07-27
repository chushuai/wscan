// Package fingerprint is the Go port of awvs-go/internal/fingerprint (the
// wappalyzer static-signal engine). It loads the bundled technologies.json
// signature DB and matches a page's url/headers/html/cookies/scripts/meta
// signals against it, the way wappalyzer's analyzeStatic does.
//
// Only the static path is ported (the browser js/dom/css path needs a real
// headless DOM and is out of scope). Regex patterns are compiled with Go's RE2
// engine; patterns that use JS-only features (backreferences, lookbehinds) fail
// to compile and are skipped — the matchable subset still covers the common
// header/url/html/script detections (PHP, Apache, nginx, IIS, Express, jQuery, …).
//
// This package powers the WebUI's "技术识别" (technologies) view, separate from
// core/plugins/fingerprint (the CEL/YAML rule engine used during vuln scanning).
package fingerprint

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// category is one wappalyzer category (id/name/slug/priority).
type category struct {
	ID       int    `json:"-"`
	Slug     string `json:"-"`
	Name     string `json:"name"`
	Priority int    `json:"priority"`
}

// pattern is one parsed signal pattern: a case-insensitive regex plus the
// confidence/version metadata encoded after `\;` in the wappalyzer string.
type pattern struct {
	value      string
	regex      *regexp.Regexp // nil if it failed to compile (skipped)
	confidence int
	version    string // version template, may contain \N backrefs / \N?A:B ternary
}

// patterns is either a flat list (the "main" key) or a map of subkey→list
// (headers/cookies/meta use {nameLower: [patterns]}).
type patterns struct {
	main  []pattern
	byKey map[string][]pattern
}

// technology is one signature entry, post transform.
type technology struct {
	name       string
	slug       string
	categories []int
	signal     map[string]*patterns // keyed by signal type: url/headers/...
	implies    []impliedTech
	excludes   []string
	icon       string
	website    string
	cpe        string
}

type impliedTech struct {
	name       string
	confidence int
}

// Tech is a compact detected technology (mirrors tech_fingerprint.toCompact).
type Tech struct {
	Name       string         `json:"name"`
	Slug       string         `json:"slug"`
	Version    string         `json:"version"`
	Confidence int            `json:"confidence"`
	Categories []categoryLite `json:"categories"`
	Icon       string         `json:"icon"`
	Website    string         `json:"website"`
	CPE        string         `json:"cpe"`
}

type categoryLite struct {
	ID   int    `json:"id"`
	Slug string `json:"slug"`
	Name string `json:"name"`
}

// AggTech is a per-target aggregated technology (mirrors aggregateTechnologies).
type AggTech struct {
	Name       string         `json:"name"`
	Slug       string         `json:"slug"`
	Version    string         `json:"version"`
	Confidence int            `json:"confidence"`
	Categories []categoryLite `json:"categories"`
	Icon       string         `json:"icon"`
	Website    string         `json:"website"`
	CPE        string         `json:"cpe"`
	Hits       int            `json:"hits"`
	SampleURLs []string       `json:"sampleUrls"`
}

// RestoreTechs rebuilds a []Tech from its persisted JSON array (the same shape
// Tech marshals to). Used by the webui to round-trip a page's per-page
// technology fingerprint across a restart.
func RestoreTechs(arr []any) []Tech {
	out := make([]Tech, 0, len(arr))
	for _, it := range arr {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		t := Tech{
			Name: mapStr(m, "name"), Slug: mapStr(m, "slug"),
			Version: mapStr(m, "version"), Confidence: mapInt(m, "confidence"),
			Icon: mapStr(m, "icon"), Website: mapStr(m, "website"), CPE: mapStr(m, "cpe"),
		}
		if cats, ok := m["categories"].([]any); ok {
			for _, c := range cats {
				if cm, ok := c.(map[string]any); ok {
					t.Categories = append(t.Categories, categoryLite{
						ID: mapInt(cm, "id"), Slug: mapStr(cm, "slug"), Name: mapStr(cm, "name"),
					})
				}
			}
		}
		out = append(out, t)
	}
	return out
}

func mapStr(m map[string]any, k string) string {
	if v, ok := m[k]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func mapInt(m map[string]any, k string) int {
	v, ok := m[k]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case int64:
		return int(n)
	}
	return 0
}

// PageInput is the per-page signal set AnalyzeStatic consumes.
type PageInput struct {
	URL     string              // page URL
	Headers map[string]string   // response headers (name→value; multi values joined)
	HTML    string              // response body (HTML)
	Cookies map[string]string   // cookie name→value (from Set-Cookie or a cookie header)
	Scripts []string            // absolute <script src> URLs
	Meta    map[string][]string // meta name/property(lower)→[content]
}

// Engine is a loaded, parsed signature DB. Safe for concurrent AnalyzeStatic.
type Engine struct {
	technologies []*technology
	techByName   map[string]*technology
	categories   map[int]*category
}

// Load parses the signature DB bytes and returns an Engine. Safe to call
// multiple times; callers usually want DefaultEngine (cached singleton).
func Load(data []byte) (*Engine, error) {
	return parseDB(data)
}

// Count returns the number of loaded technology signatures.
func (e *Engine) Count() int {
	if e == nil {
		return 0
	}
	return len(e.technologies)
}

type rawDB struct {
	Technologies map[string]rawTech `json:"technologies"`
	Categories   map[string]category `json:"categories"`
}

type rawTech struct {
	Cats       []int           `json:"cats"`
	URL        json.RawMessage `json:"url"`
	XHR        json.RawMessage `json:"xhr"`
	HTML       json.RawMessage `json:"html"`
	CSS        json.RawMessage `json:"css"`
	Robots     json.RawMessage `json:"robots"`
	Meta       json.RawMessage `json:"meta"`
	Headers    json.RawMessage `json:"headers"`
	DNS        json.RawMessage `json:"dns"`
	CertIssuer json.RawMessage `json:"certIssuer"`
	Cookies    json.RawMessage `json:"cookies"`
	Scripts    json.RawMessage `json:"scripts"`
	DOM        json.RawMessage `json:"dom"`
	JS         json.RawMessage `json:"js"`
	Implies    json.RawMessage `json:"implies"`
	Excludes   json.RawMessage `json:"excludes"`
	Icon       string          `json:"icon"`
	Website    string          `json:"website"`
	CPE        string          `json:"cpe"`
}

func parseDB(data []byte) (*Engine, error) {
	var raw rawDB
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("fingerprint: parse: %w", err)
	}
	e := &Engine{techByName: map[string]*technology{}, categories: map[int]*category{}}
	for idStr, c := range raw.Categories {
		var id int
		fmt.Sscanf(idStr, "%d", &id)
		cc := c
		cc.ID = id
		cc.Slug = slugify(c.Name)
		e.categories[id] = &cc
	}
	for name, rt := range raw.Technologies {
		t := &technology{
			name:       name,
			slug:       slugify(name),
			categories: rt.Cats,
			icon:       orDefault(rt.Icon, "default.svg"),
			website:    rt.Website,
			cpe:        rt.CPE,
			signal:     map[string]*patterns{},
		}
		// static signals only (v1); js/dom left out
		for _, sig := range []struct{ key, field string }{
			{"url", "URL"}, {"xhr", "XHR"}, {"html", "HTML"}, {"css", "CSS"},
			{"robots", "Robots"}, {"meta", "Meta"}, {"headers", "Headers"},
			{"dns", "DNS"}, {"certIssuer", "CertIssuer"}, {"cookies", "Cookies"},
			{"scripts", "Scripts"},
		} {
			p := transform(getRaw(rt, sig.field), false)
			if p != nil {
				t.signal[sig.key] = p
			}
		}
		t.implies = parseImplies(rt.Implies)
		t.excludes = parseExcludes(rt.Excludes)
		e.technologies = append(e.technologies, t)
		e.techByName[name] = t
	}
	return e, nil
}

func getRaw(rt rawTech, field string) json.RawMessage {
	switch field {
	case "URL":
		return rt.URL
	case "XHR":
		return rt.XHR
	case "HTML":
		return rt.HTML
	case "CSS":
		return rt.CSS
	case "Robots":
		return rt.Robots
	case "Meta":
		return rt.Meta
	case "Headers":
		return rt.Headers
	case "DNS":
		return rt.DNS
	case "CertIssuer":
		return rt.CertIssuer
	case "Cookies":
		return rt.Cookies
	case "Scripts":
		return rt.Scripts
	}
	return nil
}

// transform mirrors wappalyzer_core.transformPatterns. Returns nil for no
// patterns. A string/array pattern becomes the "main" list; an object becomes a
// subkey map (keys lowercased when !caseSensitive).
func transform(raw json.RawMessage, caseSensitive bool) *patterns {
	if len(raw) == 0 {
		return nil
	}
	// try array
	var asArr []json.RawMessage
	if json.Unmarshal(raw, &asArr) == nil && asArr != nil {
		return &patterns{main: parsePatternList(asArr)}
	}
	// try object (map[string]json.RawMessage or string)
	var asObj map[string]json.RawMessage
	if json.Unmarshal(raw, &asObj) == nil {
		// detect "main" key
		if mv, ok := asObj["main"]; ok {
			var lst []json.RawMessage
			if json.Unmarshal(mv, &lst) == nil {
				return &patterns{main: parsePatternList(lst)}
			}
			// single string under main
			var s string
			if json.Unmarshal(mv, &s) == nil {
				return &patterns{main: []pattern{parsePattern(s)}}
			}
		}
		byKey := map[string][]pattern{}
		for k, v := range asObj {
			key := k
			if !caseSensitive {
				key = strings.ToLower(k)
			}
			var lst []json.RawMessage
			if json.Unmarshal(v, &lst) == nil {
				byKey[key] = parsePatternList(lst)
			} else {
				var s string
				if json.Unmarshal(v, &s) == nil {
					byKey[key] = []pattern{parsePattern(s)}
				}
			}
		}
		return &patterns{byKey: byKey}
	}
	// try single string
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return &patterns{main: []pattern{parsePattern(s)}}
	}
	return nil
}

func parsePatternList(lst []json.RawMessage) []pattern {
	out := make([]pattern, 0, len(lst))
	for _, item := range lst {
		// each item may be a string or a nested object (dom sub-patterns)
		var s string
		if json.Unmarshal(item, &s) == nil {
			out = append(out, parsePattern(s))
			continue
		}
		// nested object — not used by static signals; skip
	}
	return out
}

// parsePattern splits "value\;confidence:N\;version:..." into a pattern. The
// value is a JS regex; we escape "/" then compile case-insensitive. Compile
// failures (JS-only features) yield a nil regex (the pattern is skipped at
// match time) so the rest of the DB still works.
func parsePattern(s string) pattern {
	parts := strings.Split(s, "\\;")
	p := pattern{confidence: 100}
	if len(parts) == 0 {
		return p
	}
	p.value = parts[0]
	for _, attr := range parts[1:] {
		kv := strings.SplitN(attr, ":", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "confidence":
			var n int
			fmt.Sscanf(kv[1], "%d", &n)
			if n > 0 {
				p.confidence = n
			}
		case "version":
			p.version = kv[1]
		}
	}
	// JS regex → Go RE2: escape "/", anchor case-insensitive.
	expr := strings.ReplaceAll(p.value, "/", "\\/")
	if re, err := regexp.Compile("(?i)" + expr); err == nil {
		p.regex = re
	}
	return p
}

func parseImplies(raw json.RawMessage) []impliedTech {
	var arr []json.RawMessage
	if json.Unmarshal(raw, &arr) != nil {
		// could be a single string
		var s string
		if json.Unmarshal(raw, &s) == nil && s != "" {
			return []impliedTech{{name: impliedName(s), confidence: impliedConf(s)}}
		}
		return nil
	}
	out := make([]impliedTech, 0, len(arr))
	for _, item := range arr {
		var s string
		if json.Unmarshal(item, &s) == nil && s != "" {
			out = append(out, impliedTech{name: impliedName(s), confidence: impliedConf(s)})
		}
	}
	return out
}

// impliedName/conf parse "Name\;confidence:N" (implies patterns reuse the
// `\;` split; confidence defaults 100).
func impliedName(s string) string {
	if i := strings.Index(s, "\\;"); i >= 0 {
		return s[:i]
	}
	return s
}
func impliedConf(s string) int {
	if i := strings.Index(s, "\\;"); i >= 0 {
		rest := s[i+2:]
		if strings.HasPrefix(rest, "confidence:") {
			var n int
			fmt.Sscanf(rest[len("confidence:"):], "%d", &n)
			if n > 0 {
				return n
			}
		}
	}
	return 100
}

func parseExcludes(raw json.RawMessage) []string {
	var arr []string
	if json.Unmarshal(raw, &arr) == nil {
		out := make([]string, 0, len(arr))
		for _, s := range arr {
			if i := strings.Index(s, "\\;"); i >= 0 {
				s = s[:i]
			}
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	var s string
	if json.Unmarshal(raw, &s) == nil && s != "" {
		if i := strings.Index(s, "\\;"); i >= 0 {
			s = s[:i]
		}
		return []string{s}
	}
	return nil
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

func slugify(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	out := b.String()
	// collapse runs of '-'
	for strings.Contains(out, "--") {
		out = strings.ReplaceAll(out, "--", "-")
	}
	return strings.Trim(out, "-")
}

// ---- analysis (port of wappalyzer_core analyze* + resolve) ----

type detection struct {
	tech    *technology
	pattern pattern
	version string
}

// AnalyzeStatic runs the static-signal matchers over one page and returns the
// resolved, compact technology list. Mirrors tech_fingerprint.analyzeStatic.
func (e *Engine) AnalyzeStatic(in PageInput) []Tech {
	headers := headersToWapp(in.Headers)
	cookies := cookiesToWapp(in.Cookies)
	scripts := in.Scripts
	if scripts == nil {
		scripts = []string{}
	}
	meta := in.Meta
	if meta == nil {
		meta = map[string][]string{}
	}
	html := trimHTML(in.HTML)
	url := in.URL

	var detections []detection
	for _, t := range e.technologies {
		detections = append(detections, e.analyzeOneToOne(t, "url", url)...)
		detections = append(detections, e.analyzeOneToOne(t, "xhr", "")...)
		detections = append(detections, e.analyzeOneToOne(t, "html", html)...)
		detections = append(detections, e.analyzeOneToOne(t, "css", "")...)
		detections = append(detections, e.analyzeOneToOne(t, "robots", "")...)
		detections = append(detections, e.analyzeOneToOne(t, "certIssuer", "")...)
		detections = append(detections, e.analyzeOneToMany(t, "scripts", scripts)...)
		detections = append(detections, e.analyzeManyToMany(t, "cookies", cookies)...)
		detections = append(detections, e.analyzeManyToMany(t, "meta", meta)...)
		detections = append(detections, e.analyzeManyToMany(t, "headers", headers)...)
		detections = append(detections, e.analyzeManyToMany(t, "dns", nil)...)
	}
	return e.resolve(detections)
}

func (e *Engine) analyzeOneToOne(t *technology, typ, value string) []detection {
	p := t.signal[typ]
	if p == nil || value == "" {
		return nil
	}
	var out []detection
	for _, pat := range p.main {
		if pat.regex == nil || !pat.regex.MatchString(value) {
			continue
		}
		out = append(out, detection{tech: t, pattern: pat, version: resolveVersion(pat, value)})
	}
	return out
}

func (e *Engine) analyzeOneToMany(t *technology, typ string, items []string) []detection {
	p := t.signal[typ]
	if p == nil {
		return nil
	}
	var out []detection
	for _, value := range items {
		for _, pat := range p.main {
			if pat.regex == nil || !pat.regex.MatchString(value) {
				continue
			}
			out = append(out, detection{tech: t, pattern: pat, version: resolveVersion(pat, value)})
		}
	}
	return out
}

func (e *Engine) analyzeManyToMany(t *technology, typ string, items map[string][]string) []detection {
	p := t.signal[typ]
	if p == nil || p.byKey == nil {
		return nil
	}
	var out []detection
	for key, pats := range p.byKey {
		values := items[key]
		for _, pat := range pats {
			if pat.regex == nil {
				continue
			}
			for _, value := range values {
				if pat.regex.MatchString(value) {
					out = append(out, detection{tech: t, pattern: pat, version: resolveVersion(pat, value)})
				}
			}
		}
	}
	return out
}

// resolveVersion resolves a version template's \N backrefs and \N?A:B ternary
// against the regex match. Mirrors wappalyzer_core.resolveVersion.
func resolveVersion(p pattern, matchStr string) string {
	if p.version == "" || p.regex == nil {
		return ""
	}
	resolved := p.version
	matches := p.regex.FindStringSubmatch(matchStr)
	if matches == nil {
		return strings.TrimSpace(resolved)
	}
	for index, m := range matches {
		// ternary: \N?A:B
		ternary := regexp.MustCompile(`\\` + regexp.QuoteMeta(fmt.Sprintf("%d", index)) + `\?([^:]+):(.*)$`)
		if tm := ternary.FindStringSubmatch(resolved); tm != nil {
			full := tm[0]
			var rep string
			if m != "" {
				rep = tm[1]
			} else {
				rep = tm[2]
			}
			resolved = strings.Replace(resolved, full, rep, 1)
		}
		// backref \N
		resolved = strings.ReplaceAll(resolved, fmt.Sprintf("\\%d", index), m)
	}
	return strings.TrimSpace(resolved)
}

// resolve collapses detections to one entry per technology (sum confidence cap
// 100, longest version ≤10), applies excludes + implies, sorts by category
// priority, and returns compact techs. Mirrors wappalyzer_core.resolve.
func (e *Engine) resolve(detections []detection) []Tech {
	var list []*resolvedTech
	seen := map[string]*resolvedTech{}
	for _, d := range detections {
		r, ok := seen[d.tech.name]
		if !ok {
			r = &resolvedTech{tech: d.tech}
			seen[d.tech.name] = r
			list = append(list, r)
		}
		r.confidence = min(100, r.confidence+d.pattern.confidence)
		if len(d.version) > len(r.version) && len(d.version) <= 10 {
			r.version = d.version
		}
	}
	e.resolveExcludes(list)
	e.resolveImplies(list)
	sort.SliceStable(list, func(i, j int) bool {
		return e.priority(list[i].tech) < e.priority(list[j].tech)
	})
	out := make([]Tech, 0, len(list))
	for _, r := range list {
		out = append(out, Tech{
			Name:       r.tech.name,
			Slug:       r.tech.slug,
			Version:    r.version,
			Confidence: r.confidence,
			Categories: e.catsOf(r.tech),
			Icon:       r.tech.icon,
			Website:    r.tech.website,
			CPE:        r.tech.cpe,
		})
	}
	return out
}

func (e *Engine) resolveExcludes(list []*resolvedTech) {
	for _, r := range list {
		for _, exName := range r.tech.excludes {
			ex := e.techByName[exName]
			if ex == nil {
				continue
			}
			for i := len(list) - 1; i >= 0; i-- {
				if list[i].tech.name == ex.name {
					list = append(list[:i], list[i+1:]...)
				}
			}
		}
	}
}

func (e *Engine) resolveImplies(list []*resolvedTech) {
	done := false
	for len(list) > 0 && !done {
		done = true
		for _, r := range list {
			for _, imp := range r.tech.implies {
				implied := e.techByName[imp.name]
				if implied == nil {
					continue
				}
				exists := false
				for _, x := range list {
					if x.tech.name == implied.name {
						exists = true
						break
					}
				}
				if !exists {
					list = append(list, &resolvedTech{
						tech:       implied,
						confidence: min(r.confidence, imp.confidence),
					})
					done = false
				}
			}
		}
	}
}

type resolvedTech struct {
	tech       *technology
	confidence int
	version    string
}

func (e *Engine) priority(t *technology) int {
	max := 0
	for _, id := range t.categories {
		if c := e.categories[id]; c != nil && c.Priority > max {
			max = c.Priority
		}
	}
	return max
}

func (e *Engine) catsOf(t *technology) []categoryLite {
	out := make([]categoryLite, 0, len(t.categories))
	for _, id := range t.categories {
		if c := e.categories[id]; c != nil {
			out = append(out, categoryLite{ID: c.ID, Slug: c.Slug, Name: c.Name})
		}
	}
	return out
}

// ---- helpers (port of tech_fingerprint helpers) ----

func headersToWapp(h map[string]string) map[string][]string {
	out := map[string][]string{}
	for k, v := range h {
		out[strings.ToLower(k)] = []string{v}
	}
	return out
}

func cookiesToWapp(c map[string]string) map[string][]string {
	out := map[string][]string{}
	for k, v := range c {
		out[strings.ToLower(k)] = []string{v}
	}
	return out
}

// trimHTML keeps the head + tail of a large body so the html regex pass stays
// cheap (mirrors tech_fingerprint.trimHtml).
func trimHTML(html string) string {
	if html == "" {
		return ""
	}
	const maxCols = 2000
	const maxRows = 3000
	rows := len(html) / maxCols
	if rows == 0 {
		return html
	}
	var b strings.Builder
	for i := 0; i < rows; i++ {
		if i < maxRows/2 || i > rows-maxRows/2 {
			b.WriteString(html[i*maxCols : (i+1)*maxCols])
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// resolveURL resolves a possibly-relative URL against base (mirrors Node's
// `new URL(raw, base)`). Returns "" on parse failure.
func resolveURL(raw, base string) string {
	if raw == "" {
		return ""
	}
	if b, err := url.Parse(base); err == nil {
		if r, err := url.Parse(raw); err == nil {
			return b.ResolveReference(r).String()
		}
	}
	return raw
}

// ExtractScriptSrcs pulls <script src> URLs (absolute) from HTML.
func ExtractScriptSrcs(html, baseURL string) []string {
	if html == "" {
		return nil
	}
	re := regexp.MustCompile(`(?i)<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']`)
	var out []string
	seen := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(html, -1) {
		raw := m[1]
		if raw == "" {
			continue
		}
		abs := resolveURL(raw, baseURL)
		if abs != "" && !seen[abs] {
			seen[abs] = true
			out = append(out, abs)
		}
	}
	return out
}

// metaRE matches <meta name="..." content="..."> / <meta property="..."
// content="..."> (case-insensitive, single/double quotes). The key is the
// name/property attribute (lowercased), value the content attribute.
var metaRE = regexp.MustCompile(`(?is)<meta\b[^>]*\b(?:name|property)\s*=\s*["']([^"']+)["'][^>]*\bcontent\s*=\s*["']([^"']*)["']`)

// metaREAlt matches the reversed attribute order (content before name/property).
var metaREAlt = regexp.MustCompile(`(?is)<meta\b[^>]*\bcontent\s*=\s*["']([^"']*)["'][^>]*\b(?:name|property)\s*=\s*["']([^"']+)["']`)

// ExtractMeta pulls <meta name/property → content> pairs from HTML. The key is
// lowercased; multiple contents for the same key accumulate.
func ExtractMeta(html string) map[string][]string {
	out := map[string][]string{}
	if html == "" {
		return out
	}
	add := func(key, val string) {
		key = strings.ToLower(strings.TrimSpace(key))
		if key == "" {
			return
		}
		out[key] = append(out[key], val)
	}
	for _, m := range metaRE.FindAllStringSubmatch(html, -1) {
		add(m[1], m[2])
	}
	for _, m := range metaREAlt.FindAllStringSubmatch(html, -1) {
		add(m[2], m[1])
	}
	return out
}

// Aggregate merges per-page Tech lists into a per-target stack: same-name techs
// merge (longest version ≤10, max confidence, hit count, up to 3 sample URLs),
// sorted by confidence desc then name. Mirrors aggregateTechnologies.
func Aggregate(pages []AggPage) []AggTech {
	agg := map[string]*AggTech{}
	order := []string{}
	for _, pg := range pages {
		for _, t := range pg.Technologies {
			if t.Name == "" {
				continue
			}
			a, ok := agg[t.Name]
			if !ok {
				a = &AggTech{
					Name: t.Name, Slug: t.Slug, Confidence: t.Confidence,
					Categories: t.Categories, Icon: t.Icon, Website: t.Website, CPE: t.CPE,
					SampleURLs: []string{},
				}
				agg[t.Name] = a
				order = append(order, t.Name)
			}
			v := t.Version
			if v != "" && len(v) <= 10 && len(v) > len(a.Version) {
				a.Version = v
			}
			if t.Confidence > a.Confidence {
				a.Confidence = t.Confidence
			}
			a.Hits++
			if len(a.SampleURLs) < 3 && pg.URL != "" {
				dup := false
				for _, u := range a.SampleURLs {
					if u == pg.URL {
						dup = true
						break
					}
				}
				if !dup {
					a.SampleURLs = append(a.SampleURLs, pg.URL)
				}
			}
		}
	}
	out := make([]*AggTech, 0, len(order))
	for _, name := range order {
		out = append(out, agg[name])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Confidence != out[j].Confidence {
			return out[i].Confidence > out[j].Confidence
		}
		return out[i].Name < out[j].Name
	})
	res := make([]AggTech, len(out))
	for i, t := range out {
		res[i] = *t
	}
	return res
}

// AggPage is a page + its detected technologies, for Aggregate.
type AggPage struct {
	URL          string
	Technologies []Tech
}

// ---- cached default engine (embedded technologies.json) ----

var (
	defOnce sync.Once
	defEng  *Engine
	defErr  error
)
