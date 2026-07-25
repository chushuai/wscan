# core/plugins/vulndb

Embedded vulnerability-description database, one XML file per vuln type
(name/description/impact/recommendation/severity/CVSS/details_template/tags/
references) under `data/`. Embedded into the binary at build time via
`go:embed data/*.xml` in `vulndb.go`.

This package owns the advisory catalog. Scan plugins emit a stable `Binding.ID`;
`idAliases` here maps that id onto a DB entry so callers (the web layer)
retrieve the right advisory via `Lookup(id)`.

The XML files are NOT checked into git (see `.gitignore`) — they are a build
artifact produced from `core/scannable_vuln.json`.

## Regenerate

From the repo root, before building:

```sh
python3 core/plugins/vulndb/gen_vulndb.py
```

This writes one `.xml` per reachable vuln type into `data/`. `go build` then
embeds them.

Only vuln types our scan plugins can surface are emitted. The allowlist
(`allowlist.txt`, one id per line) holds the reachable vulndb ids — a plugin
Binding.ID that either matches a DB id directly or maps to one through
`idAliases` in `vulndb.go`. Regenerate the allowlist by collecting those ids
(alias targets + direct plugin-id stems).

## Mapping plugin IDs to DB entries

`vulndb.go` carries an `idAliases` table that maps wscan's action-scoped
plugin Binding.IDs (e.g. `xss/reflected/default`) onto the DB ids (e.g. `xss`)
so a vuln record picks up the right advisory text without changing plugin ids.
