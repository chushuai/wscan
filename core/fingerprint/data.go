// Embedded wappalyzer technologies.json signature DB + cached default engine.
package fingerprint

import _ "embed"

//go:embed data/technologies.json
var technologiesJSON []byte

// DefaultEngine returns the cached Engine built from the embedded
// technologies.json. Loaded once per process; subsequent calls return the same
// instance. If the embedded DB fails to parse, returns (nil, err) and the
// failure is sticky (callers should degrade gracefully — no fingerprinting).
func DefaultEngine() (*Engine, error) {
	defOnce.Do(func() {
		defEng, defErr = Load(technologiesJSON)
	})
	return defEng, defErr
}
