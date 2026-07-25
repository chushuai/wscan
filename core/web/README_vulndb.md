# core/web/vulndb

Generated vulnerability-description database, one XML file per vuln type
(name/description/impact/recommendation/severity/CVSS/details_template/tags/
references). Embedded into the binary at build time via `go:embed vulndb/*.xml`
in `vulndb.go`.

The XML files are NOT checked into git (see `.gitignore`) — they are a build
artifact produced from `core/scannable_vuln.json`.

## Regenerate

From the repo root, before building:

```sh
python3 core/web/gen_vulndb.py
```

This writes 523 `.xml` files into this directory. `go build` then embeds them.

## Mapping plugin IDs to DB entries

`vulndb.go` carries a `vulnIDAliases` table that maps wscan's action-scoped
plugin Binding.IDs (e.g. `xss/reflected/default`) onto the DB ids (e.g. `xss`)
so a vuln record picks up the right advisory text without changing plugin ids.
