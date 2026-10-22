#!/usr/bin/env python3
"""Checks a runtime list file against its contract (docs/api/runtime-list-v1.md) before anyone signs it.

    python3 -I scripts/runtime-list/validate.py <runtimes-v1.json> [--previous <published runtimes-v1.json>]

Exit status 0 when the file is valid, 1 with one line per problem otherwise. The publishing job (iKnowMyMac-Lists)
runs a vendored copy of this file: change it here, then run scripts/package-list/sync-lists-repo.sh.
Plain Python, standard library only.
"""
import json
import re
import sys

MAX_BYTES = 512 * 1024
LIMITS = {"lines": 64, "releases": 256, "roots": 64, "fixedPackages": 64, "incidents": 64}
RUNTIMES = {"node": 1, "php": 2, "go": 2}
SEVERITIES = {"critical", "high", "medium", "low"}
BANNED = re.compile(r"\b(safe|secure|security guaranteed|protected)\b", re.I)
HEX64 = re.compile(r"^[0-9a-f]{64}$")
DAY = re.compile(r"^\d{4}-\d{2}-\d{2}$")
STAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
VERSION = re.compile(r"^\d+(\.\d+)*$")
HOMEBREW = re.compile(r"^(\d{4}-\d{2}-\d{2}|\d+(\.\d+)*)(_\d+)?$")


def problems_in(data, raw_size, previous=None):
    out = []

    def need(cond, message):
        if not cond:
            out.append(message)
        return cond

    need(raw_size <= MAX_BYTES, "file is %d bytes, over %d" % (raw_size, MAX_BYTES))
    if not need(isinstance(data, dict), "the file is not a JSON object"):
        return out
    need(data.get("format") == 1, "format must be 1")
    need(data.get("kind") == "runtimes", "kind must be \"runtimes\"")
    need(isinstance(data.get("generated"), str) and STAMP.match(data["generated"]), "generated must be YYYY-MM-DDTHH:MM:SSZ")
    if previous and isinstance(previous.get("generated"), str) and isinstance(data.get("generated"), str):
        need(data["generated"] > previous["generated"], "generated %s is not newer than the published %s"
             % (data["generated"], previous["generated"]))

    def source(row, where):
        need(isinstance(row.get("source"), str) and row["source"].startswith("https://"), "%s: source must be an https URL" % where)

    def text(value, where):
        if need(isinstance(value, str) and value.strip(), "%s must be a sentence" % where):
            need(not BANNED.search(value), "%s uses a banned word (safe/secure/protected): %r" % (where, value))

    ids = {}
    for key in ("runtimes", "releases", "roots", "fixedPackages", "incidents"):
        rows = data.get(key, [])
        if not need(isinstance(rows, list), "%s must be a list" % key):
            data[key] = rows = []
        need(len(rows) <= LIMITS.get(key, 64), "%s has %d rows, over the limit" % (key, len(rows)))
        seen = set()
        for row in rows:
            rid = row.get("id") if isinstance(row, dict) else None
            need(isinstance(rid, str) and rid, "%s: a row has no id" % key)
            need(rid not in seen, "%s: id %r twice" % (key, rid))
            seen.add(rid)
        ids[key] = seen

    lines = {}
    for row in data["runtimes"]:
        where = "runtimes[%s]" % row.get("id")
        if row.get("id") in RUNTIMES:
            need(row.get("lineDepth") == RUNTIMES[row["id"]], "%s: lineDepth must be %d" % (where, RUNTIMES[row["id"]]))
        source(row, where)
        names = []
        for line in row.get("lines", []):
            need(isinstance(line.get("line"), str) and VERSION.match(line["line"]) and line["line"].count(".") + 1 == row.get("lineDepth"),
                 "%s: line %r does not have lineDepth numbers" % (where, line.get("line")))
            need(line.get("status") in ("supported", "endOfLife"), "%s: line %s status must be supported or endOfLife" % (where, line.get("line")))
            if "since" in line:
                need(isinstance(line["since"], str) and DAY.match(line["since"]), "%s: line %s since must be YYYY-MM-DD" % (where, line.get("line")))
            names.append(line.get("line"))
        need(len(names) == len(set(names)), "%s: a line is listed twice" % where)
        need(len(names) <= LIMITS["lines"], "%s: too many lines" % where)
        lines[row.get("id")] = {l.get("line"): l.get("status") for l in row.get("lines", [])}

    for row in data["releases"]:
        where = "releases[%s]" % row.get("id")
        runtime = row.get("runtime")
        need(runtime in lines, "%s: runtime %r is not in runtimes" % (where, runtime))
        need(isinstance(row.get("date"), str) and DAY.match(row["date"]), "%s: date must be YYYY-MM-DD" % where)
        need(row.get("severity") in SEVERITIES, "%s: severity must be one of %s" % (where, sorted(SEVERITIES)))
        text(row.get("title"), where + ".title")
        source(row, where)
        fixed = row.get("fixed")
        if need(isinstance(fixed, dict) and fixed, "%s: fixed must name at least one line" % where):
            for line, version in fixed.items():
                need(lines.get(runtime, {}).get(line) == "supported", "%s: fixed names line %s, which is not a supported line" % (where, line))
                need(isinstance(version, str) and VERSION.match(version) and version.startswith(line + "."),
                     "%s: fixed version %r is not on line %s" % (where, version, line))
        cves = row.get("cves", [])
        need(isinstance(cves, list) and len(cves) <= 6 and all(re.match(r"^CVE-\d{4}-\d{4,}$", c) for c in cves),
             "%s: cves must be at most 6 CVE ids" % where)

    for row in data["roots"]:
        where = "roots[%s]" % row.get("id")
        need(isinstance(row.get("spki"), str) and HEX64.match(row["spki"]), "%s: spki must be 64 lowercase hex" % where)
        if "sha256" in row:
            need(isinstance(row["sha256"], str) and HEX64.match(row["sha256"]), "%s: sha256 must be 64 lowercase hex" % where)
        need(row.get("role") in ("issuer", "crossSigner"), "%s: role must be issuer or crossSigner" % where)
        text(row.get("name"), where + ".name")
        source(row, where)

    for row in data["fixedPackages"]:
        where = "fixedPackages[%s]" % row.get("id")
        kind = row.get("kind")
        need(kind in ("homebrew", "composer"), "%s: kind must be homebrew or composer" % where)
        fixed = row.get("fixed")
        if kind == "homebrew":
            need(isinstance(fixed, str) and HOMEBREW.match(fixed), "%s: fixed must be a Homebrew version" % where)
        elif kind == "composer":
            need(isinstance(fixed, list) and fixed and all(isinstance(v, str) and VERSION.match(v) for v in fixed),
                 "%s: fixed must list versions" % where)
        need(isinstance(row.get("name"), str) and row["name"], "%s: name is missing" % where)
        if "incident" in row:
            need(row["incident"] in ids["incidents"], "%s: incident %r is not in incidents" % (where, row["incident"]))
        source(row, where)

    for row in data["incidents"]:
        where = "incidents[%s]" % row.get("id")
        text(row.get("title"), where + ".title")
        text(row.get("summary"), where + ".summary")
        if "notAffected" in row:
            text(row.get("notAffected"), where + ".notAffected")
        need(isinstance(row.get("date"), str) and DAY.match(row["date"]), "%s: date must be YYYY-MM-DD" % where)
        need(row.get("severity") in SEVERITIES, "%s: severity" % where)
        source(row, where)
        covers = row.get("covers")
        if need(isinstance(covers, dict) and covers, "%s: covers must name something" % where):
            for key, pool in (("releases", "releases"), ("roots", "roots"), ("fixedPackages", "fixedPackages")):
                for ref in covers.get(key, []):
                    need(ref in ids[pool], "%s: covers.%s names %r, which is not in %s" % (where, key, ref, pool))
            for adv in covers.get("packageAdvisories", []):
                need(isinstance(adv, dict) and adv.get("e") in ("npm", "pypi") and adv.get("n") and adv.get("id"),
                     "%s: a packageAdvisory needs e (npm/pypi), n and id" % where)
        if "learnMore" in row:
            need(isinstance(row["learnMore"], str) and row["learnMore"].startswith("https://iknowmymac.com/"),
                 "%s: learnMore must be a page on iknowmymac.com" % where)
    return out


def main(argv):
    if not argv or argv[0].startswith("-"):
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 2
    path = argv[0]
    previous = None
    if "--previous" in argv:
        with open(argv[argv.index("--previous") + 1], "rb") as fh:
            previous = json.loads(fh.read().decode("utf-8"))
    with open(path, "rb") as fh:
        raw = fh.read()
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        print("%s: not UTF-8 JSON: %s" % (path, error))
        return 1
    problems = problems_in(data, len(raw), previous)
    for line in problems:
        print("%s: %s" % (path, line))
    if not problems:
        print("%s: valid (%d releases, %d roots, %d incidents)" % (path, len(data["releases"]), len(data["roots"]), len(data["incidents"])))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
