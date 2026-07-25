#!/usr/bin/env python3
"""
Generate per-vulnerability XML files from core/scannable_vuln.json.

Each entry in byAppId becomes one file under core/web/vulndb/, named after the
json key (already an xml filename like "xss.xml"). The file contains all fields:
name, description, impact, recommendation, severity, score, cvss2, cvss3,
cvss4, details_template, tags, references.

Run from repo root:  python3 core/web/gen_vulndb.py
"""
import json
import os
import sys
from xml.sax.saxutils import escape

SRC = "core/scannable_vuln.json"
DST = "core/web/vulndb"


def main():
    with open(SRC, "r", encoding="utf-8") as f:
        data = json.load(f)
    apps = data.get("byAppId", {})
    if not apps:
        print("no byAppId entries found", file=sys.stderr)
        sys.exit(1)

    os.makedirs(DST, exist_ok=True)
    # wipe existing generated xml files so removed entries don't linger
    for name in os.listdir(DST):
        if name.endswith(".xml"):
            os.remove(os.path.join(DST, name))

    count = 0
    for key, v in apps.items():
        fname = key
        if not fname.endswith(".xml"):
            fname = fname + ".xml"
        path = os.path.join(DST, fname)
        with open(path, "w", encoding="utf-8") as out:
            out.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
            out.write("<vuln id=\"%s\">\n" % escape(stem(fname)))
            write_str(out, "name", v.get("name", ""))
            write_str(out, "description", v.get("description", ""))
            write_str(out, "impact", v.get("impact", ""))
            write_str(out, "recommendation", v.get("recommendation", ""))
            write_int(out, "severity", v.get("severity"))
            write_num(out, "score", v.get("score"))
            write_str(out, "cvss2", v.get("cvss2", ""))
            write_str(out, "cvss3", v.get("cvss3", ""))
            write_str(out, "cvss4", v.get("cvss4", ""))
            write_str(out, "details_template", v.get("details_template", ""))
            tags = v.get("tags") or []
            out.write("  <tags>\n")
            for tg in tags:
                out.write("    <tag>%s</tag>\n" % escape(str(tg)))
            out.write("  </tags>\n")
            refs = v.get("references") or []
            out.write("  <references>\n")
            for r in refs:
                if isinstance(r, dict):
                    title = r.get("title", "")
                    url = r.get("url", "")
                    out.write("    <reference>\n")
                    out.write("      <title>%s</title>\n" % escape(title))
                    out.write("      <url>%s</url>\n" % escape(url))
                    out.write("    </reference>\n")
                elif isinstance(r, str):
                    out.write("    <reference>\n      <url>%s</url>\n    </reference>\n" % escape(r))
            out.write("  </references>\n")
            out.write("</vuln>\n")
        count += 1

    print("wrote %d vuln xml files to %s" % (count, DST))


def stem(fname):
    return fname[:-4] if fname.endswith(".xml") else fname


def write_str(out, tag, val):
    if val is None:
        val = ""
    out.write("  <%s>%s</%s>\n" % (tag, escape(str(val)), tag))


def write_int(out, tag, val):
    if val is None:
        return
    out.write("  <%s>%d</%s>\n" % (tag, int(val), tag))


def write_num(out, tag, val):
    if val is None:
        return
    out.write("  <%s>%s</%s>\n" % (tag, escape(str(val)), tag))


if __name__ == "__main__":
    main()
