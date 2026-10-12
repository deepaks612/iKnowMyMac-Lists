#!/usr/bin/env python3
"""Package list v1 builder: turns the public OSV exports for npm and PyPI into the list the app reads.

The contract is docs/api/package-list-v1.md ("Building rows from the public records" and "The same rules,
spelled out"). The app's own fallback importer follows the same rules, and both are run against the vectors in
Tests/CoreTests/PackageWatch/Fixtures/list-vectors/.

Usage:
  python3 -I scripts/package-list/build.py --npm <all.zip or folder of .json> --pypi <all.zip or folder of .json>
          [--out <base.jsonl.gz>] [--base <earlier base.jsonl.gz> --delta-out <delta.jsonl.gz>]
          [--generated 2026-10-11T04:00:00Z] [--as-of 2026-10-04T04:00:00Z] [--stats <stats.json>]
  python3 -I scripts/package-list/build.py --check-vectors <list-vectors folder>
  python3 -I scripts/package-list/build.py --check-delta-vectors <delta-vectors folder>

Build mode writes gzip (mtime 0, no name in the gzip header, level 9) of UTF-8 JSON Lines: the header line, then one
row per line. The same input and the same --generated give the same bytes.
  --out        the whole list (a "base").
  --delta-out  only what was added, changed or withdrawn since --base (a "delta"); its header names that base.
  --as-of      builds the list as it stood at that time, for tests and for measuring (see `as_of_view`).

Check modes: --check-vectors builds every <case>/records/*.json and compares the rows with <case>/expected.jsonl as
JSON values. --check-delta-vectors takes every <case>/base.jsonl and <case>/next.jsonl, and checks that the delta
between them is <case>/delta.jsonl and that applying it to the base gives next.jsonl again. Both exit 0 when every
case matches and print each mismatch otherwise.

This file is owned by the app repository (iKnowMyMac-MacOS, scripts/package-list/build.py). The publishing
repository (iKnowMyMac-Lists) carries a copy under vendor/; scripts/package-list/sync-lists-repo.sh keeps the two
the same.

The exports are untrusted data. Zips are read member by member in memory and never unpacked to disk; nothing in them
is executed. Standard library only. Nothing about this Mac is read.
"""
import argparse
import collections
import functools
import gzip
import hashlib
import io
import json
import os
import re
import sys
import time
import zipfile

SOURCES = [
    {"name": "OpenSSF Malicious Packages", "licence": "Apache-2.0", "url": "https://github.com/ossf/malicious-packages"},
    {"name": "GitHub Advisory Database", "licence": "CC-BY-4.0", "url": "https://github.com/github/advisory-database"},
    {"name": "PyPI Advisory Database", "licence": "CC-BY-4.0", "url": "https://github.com/pypa/advisory-database"},
]

# Severity, lowest to highest. A row is written only for the last two.
SEVERITIES = ["none", "low", "medium", "high", "critical"]
LABELS = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "MEDIUM": 2, "LOW": 1}

# One record in a zip larger than this is skipped and counted (a real record is a few KB; the largest are a few MB).
MAX_RECORD_BYTES = 64 * 1024 * 1024
NO_TIME = "1970-01-01T00:00:00Z"   # currentTo when no record carries a usable `modified`


def dumps(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def as_list(value):
    return value if isinstance(value, list) else []


def pep503(name):
    return re.sub(r"[-_.]+", "-", name).lower()


# ---------------------------------------------------------------------------------------------------------------------
# Severity

def cvss3_base(vector):
    """CVSS v3.0/3.1 base score from a vector string. Returns None when it cannot be computed. (From spike 35.)"""
    try:
        parts = dict(p.split(":") for p in vector.split("/")[1:])
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[parts["AV"]]
        ac = {"L": 0.77, "H": 0.44}[parts["AC"]]
        scope = parts["S"]
        pr = {"N": 0.85, "L": 0.62 if scope == "U" else 0.68, "H": 0.27 if scope == "U" else 0.5}[parts["PR"]]
        ui = {"N": 0.85, "R": 0.62}[parts["UI"]]
        cia = {"H": 0.56, "L": 0.22, "N": 0.0}
        c, i, a = cia[parts["C"]], cia[parts["I"]], cia[parts["A"]]
    except (KeyError, ValueError, AttributeError):
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    imp = 6.42 * iss if scope == "U" else 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    expl = 8.22 * av * ac * pr * ui
    if imp <= 0:
        return 0.0
    raw = min(imp + expl, 10) if scope == "U" else min(1.08 * (imp + expl), 10)
    # CVSS "round up to one decimal"
    n = round(raw * 100000)
    return n / 100000.0 if n % 10000 == 0 else (n // 10000 + 1) / 10.0


def severity_of(rec):
    """Index into SEVERITIES. The record's own label wins; else the highest CVSS 3.x score; else none.
    `affected[].ecosystem_specific.severity` is not read (the spike did; the contract does not)."""
    db = rec.get("database_specific")
    label = db.get("severity") if isinstance(db, dict) else None
    if isinstance(label, str) and label.upper() in LABELS:
        return LABELS[label.upper()]
    best = None
    for s in as_list(rec.get("severity")):
        if isinstance(s, dict) and s.get("type") == "CVSS_V3" and isinstance(s.get("score"), str):
            score = cvss3_base(s["score"])
            if score is not None:
                best = score if best is None else max(best, score)
    if best is None:
        return 0
    return 4 if best >= 9.0 else 3 if best >= 7.0 else 2 if best >= 4.0 else 1 if best > 0 else 0


# ---------------------------------------------------------------------------------------------------------------------
# Ranges, times, text

def intervals(rng):
    """OSV events of one range -> list of (introduced, kind, end, real_fix).
    kind "f": fixed, exclusive. "l": last_affected, inclusive. "": no end. A `limit` is written as "f" but is not a
    real fix, so it never makes a vuln row eligible and never gives `fx`."""
    out = []
    intro = None
    for ev in as_list(rng.get("events")):
        if not isinstance(ev, dict):
            continue
        if isinstance(ev.get("introduced"), str):
            if intro is not None:
                out.append((intro, "", "", False))
            intro = ev["introduced"]
        elif isinstance(ev.get("fixed"), str):
            out.append((intro if intro is not None else "0", "f", ev["fixed"], True))
            intro = None
        elif isinstance(ev.get("last_affected"), str):
            out.append((intro if intro is not None else "0", "l", ev["last_affected"], False))
            intro = None
        elif isinstance(ev.get("limit"), str):
            out.append((intro if intro is not None else "0", "f", ev["limit"], False))
            intro = None
    if intro is not None:
        out.append((intro, "", "", False))
    return out


TIME_RE = re.compile(r"([0-9]{4}-[0-9]{2}-[0-9]{2})T([0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.[0-9]+)?Z")
DATE_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")


def norm_time(value):
    """`YYYY-MM-DDTHH:MM:SS[.fraction]Z` cut to seconds, or a date alone as midnight UTC. Anything else: None.
    The result compares correctly as a plain string."""
    if not isinstance(value, str):
        return None
    m = TIME_RE.fullmatch(value)
    if m:
        return m.group(1) + "T" + m.group(2) + "Z"
    if DATE_RE.fullmatch(value):
        return value + "T00:00:00Z"
    return None


WHITE_SPACE_RE = re.compile(r"[ \t\n\r\x0b\x0c]+")


def clean_text(value):
    """Every run of ASCII white space becomes one space; trimmed; cut to 120 code points."""
    if not isinstance(value, str):
        return ""
    return WHITE_SPACE_RE.sub(" ", value).strip(" ")[:120]


# ---------------------------------------------------------------------------------------------------------------------
# Version ordering, ported from Spikes/1.4/35-package-inventory/Versions.swift. Used only to pick `fx`.

SWIFT_INT_RE = re.compile(r"([+-]?)([0-9]+)")


def swift_uint(text):
    """What Swift's UInt64(String) gives: ASCII digits with an optional sign, None when it is not a number."""
    m = SWIFT_INT_RE.fullmatch(text)
    if not m:
        return None
    n = int(m.group(2))
    if n > 0xFFFFFFFFFFFFFFFF or (m.group(1) == "-" and n != 0):
        return None
    return n


def swift_int(text):
    m = SWIFT_INT_RE.fullmatch(text)
    if not m:
        return None
    n = -int(m.group(2)) if m.group(1) == "-" else int(m.group(2))
    return n if -(1 << 63) <= n < (1 << 63) else None


def semver_parse(raw):
    """SemVer 2.0, tolerant: a leading "v" or "=", a missing minor or patch read as 0, build metadata dropped.
    Returns (numbers, pre-release identifiers) or None when it is not a version."""
    s = raw.lstrip("v= ")
    plus = s.find("+")
    if plus >= 0:
        s = s[:plus]
    dash = s.find("-")
    core, pre = (s, "") if dash < 0 else (s[:dash], s[dash + 1:])
    parts = core.split(".")
    if len(parts) > 3:
        return None
    nums = []
    for p in parts:
        n = swift_uint(p)
        if n is None:
            return None
        nums.append(n)
    nums += [0] * (3 - len(nums))
    return nums, (pre.split(".") if pre else [])


def semver_less(a, b):
    if a[0] != b[0]:
        return a[0] < b[0]
    ap, bp = a[1], b[1]
    if not ap or not bp:
        return bool(ap) and not bp          # a pre-release sorts before its release
    for x, y in zip(ap, bp):
        if x == y:
            continue
        p, q = swift_uint(x), swift_uint(y)
        if p is not None and q is not None:
            return p < q
        if p is not None:
            return True                     # numeric identifiers sort before alphanumeric ones
        if q is not None:
            return False
        return x < y
    return len(ap) < len(bp)


# What Swift's CharacterSet.whitespaces holds: the space separators and the tab.
SWIFT_WHITESPACES = "\t                　"


def pep440_parse(raw):
    """PEP 440, reduced to what ordering needs. Returns a dict or None when it is not a version."""
    s = raw.strip(SWIFT_WHITESPACES).lower()
    n = len(s)
    pos = [0]

    def digit(i):
        return i < n and "0" <= s[i] <= "9"

    def number():
        start = pos[0]
        while digit(pos[0]):
            pos[0] += 1
        return int(s[start:pos[0]]) if pos[0] > start else None

    def sep():
        if pos[0] < n and s[pos[0]] in ".-_":
            pos[0] += 1

    def word(*words):
        for w in words:
            if s.startswith(w, pos[0]):
                pos[0] += len(w)
                return True
        return False

    def number_or_zero():
        v = number()
        return 0 if v is None else v

    if pos[0] < n and s[0] == "v":
        pos[0] = 1
    first = number()
    if first is None:
        return None
    epoch = 0
    if pos[0] < n and s[pos[0]] == "!":
        epoch = first
        pos[0] += 1
        first = number()
        if first is None:
            return None
    release = [first]
    while pos[0] + 1 < n and s[pos[0]] == "." and digit(pos[0] + 1):
        pos[0] += 1
        release.append(number())
    # pre-release: a, b, rc (and their long spellings)
    pre = None
    save = pos[0]
    sep()
    kind = 0 if word("alpha", "a") else 1 if word("beta", "b") else 2 if word("rc", "preview", "pre", "c") else None
    if kind is not None:
        sep()
        pre = (kind, number_or_zero())
    else:
        pos[0] = save
    # post-release: ".postN", "-N", "revN", "rN"
    post = None
    save = pos[0]
    if pos[0] < n and s[pos[0]] == "-" and digit(pos[0] + 1):
        pos[0] += 1
        post = number()
    else:
        sep()
        if word("post", "rev", "r"):
            sep()
            post = number_or_zero()
        else:
            pos[0] = save
    # dev release
    dev = None
    save = pos[0]
    sep()
    if word("dev"):
        sep()
        dev = number_or_zero()
    else:
        pos[0] = save
    local = []
    if pos[0] < n and s[pos[0]] == "+":
        local = [seg for seg in re.split(r"[.\-_]", s[pos[0] + 1:]) if seg]
        pos[0] = n
    if pos[0] != n:
        return None
    while len(release) > 1 and release[-1] == 0:      # 1.0 and 1.0.0 are the same release
        release.pop()
    return {"epoch": epoch, "release": release, "pre": pre, "post": post, "dev": dev, "local": local}


def pep440_less(a, b):
    if a["epoch"] != b["epoch"]:
        return a["epoch"] < b["epoch"]
    ra, rb = a["release"], b["release"]
    for i in range(max(len(ra), len(rb))):
        x = ra[i] if i < len(ra) else 0
        y = rb[i] if i < len(rb) else 0
        if x != y:
            return x < y

    # a bare dev release sorts before any pre-release; no pre-release sorts after all of them
    def pre_key(v):
        if v["pre"] is not None:
            return (0, v["pre"][0], v["pre"][1])
        if v["post"] is None and v["dev"] is not None:
            return (-1, 0, 0)
        return (1, 0, 0)

    pa, pb = pre_key(a), pre_key(b)
    if pa != pb:
        return pa < pb
    poa = -1 if a["post"] is None else a["post"]
    pob = -1 if b["post"] is None else b["post"]
    if poa != pob:
        return poa < pob
    da = float("inf") if a["dev"] is None else a["dev"]
    db = float("inf") if b["dev"] is None else b["dev"]
    if da != db:
        return da < db
    # local: absent sorts first; numeric segments sort after alphanumeric ones
    la, lb = a["local"], b["local"]
    if not la or not lb:
        return not la and bool(lb)
    for x, y in zip(la, lb):
        if x == y:
            continue
        p, q = swift_int(x), swift_int(y)
        if p is not None and q is not None:
            return p < q
        if p is not None:
            return False
        if q is not None:
            return True
        return x < y
    return len(la) < len(lb)


def greatest_fixed(eco, fixes):
    """The greatest version by the ecosystem's ordering. Versions that cannot be parsed sort lowest; plain string
    order settles what is left (two unparseable versions, or two spellings of the same version)."""
    parse, less = (pep440_parse, pep440_less) if eco == "pypi" else (semver_parse, semver_less)
    parsed = {v: parse(v) for v in fixes}

    def compare(x, y):
        px, py = parsed[x], parsed[y]
        if px is not None and py is not None:
            if less(px, py):
                return -1
            if less(py, px):
                return 1
        elif px is not None or py is not None:
            return -1 if px is None else 1
        return (x > y) - (x < y)

    return max(sorted(fixes), key=functools.cmp_to_key(compare))


# ---------------------------------------------------------------------------------------------------------------------
# Reading

def read_source(path, counts):
    """Yields the raw bytes of every record in a zip (read in memory, member by member) or in a folder of .json."""
    if os.path.isdir(path):
        for fn in sorted(os.listdir(path)):
            if fn.endswith(".json"):
                with open(os.path.join(path, fn), "rb") as fh:
                    yield fh.read()
        return
    with zipfile.ZipFile(path) as z:
        for info in z.infolist():
            if info.is_dir() or not info.filename.endswith(".json"):
                continue
            if info.file_size > MAX_RECORD_BYTES:
                counts["too_large"] += 1
                continue
            try:
                yield z.read(info)
            except (zipfile.BadZipFile, OSError, ValueError, RuntimeError, EOFError):
                counts["unparseable"] += 1


class Record:
    __slots__ = ("id", "aliases", "severity", "published", "modified", "summary", "details", "entries")


class NotYet(Exception):
    """With --as-of: the record did not exist, or not in this form, at that time."""


def as_of_view(obj, as_of):
    """The record as it stood at `as_of`, as far as the export can say. Raises NotYet when it is left out.

    The exports hold only the newest text of each record, so this is an approximation, used for tests and for
    measuring a delta, never for a published list:
    - a record changed after `as_of` is left out (its earlier text is not in the export), whether it was new or only
      edited. Either way a delta from this base to today carries the row once, so the delta's size is the real one;
    - a record withdrawn after `as_of` that was published before it is put back, as it reads now, so that a delta to
      today marks its row as gone.
    Returns (obj, counts_for_current_to)."""
    withdrawn = norm_time(obj.get("withdrawn")) if obj.get("withdrawn") else None
    modified = norm_time(obj.get("modified"))
    if withdrawn is not None and withdrawn > as_of:
        published = norm_time(obj.get("published"))
        if published is not None and published > as_of:
            raise NotYet()
        obj = dict(obj)
        del obj["withdrawn"]
        return obj, False
    if modified is not None and modified > as_of:
        raise NotYet()
    return obj, True


def parse_record(raw, as_of=None):
    """Raw bytes -> (Record or None when withdrawn, modified time). Raises ValueError when it is not a usable record,
    NotYet when --as-of leaves it out."""
    try:
        obj = json.loads(raw)
    except RecursionError:
        raise ValueError("nested too deeply")
    if not isinstance(obj, dict) or not isinstance(obj.get("id"), str) or not obj["id"]:
        raise ValueError("no id")
    counts = True
    if as_of is not None:
        obj, counts = as_of_view(obj, as_of)
    modified = norm_time(obj.get("modified")) if counts else None
    if obj.get("withdrawn"):
        return None, modified
    rec = Record()
    rec.id = obj["id"]
    rec.aliases = tuple(a for a in as_list(obj.get("aliases")) if isinstance(a, str))
    rec.severity = severity_of(obj)
    rec.published = norm_time(obj.get("published"))
    rec.modified = modified
    rec.summary = clean_text(obj.get("summary"))
    # `details` is read only when every record of a group lacks a summary, so it is kept only then.
    rec.details = "" if rec.summary else clean_text(obj.get("details"))
    rec.entries = {}
    for a in as_list(obj.get("affected")):
        pkg = a.get("package") if isinstance(a, dict) else None
        if not isinstance(pkg, dict):
            continue
        eco, name = pkg.get("ecosystem"), pkg.get("name")
        if not isinstance(eco, str) or not isinstance(name, str) or not name:
            continue
        base = eco.split(":", 1)[0].lower()
        if base == "npm":
            key = ("npm", name)
        elif base == "pypi":
            key = ("pypi", pep503(name))
        else:
            continue
        # Entries of one record that name the same package are one entry.
        versions, ivs = rec.entries.setdefault(key, ([], []))
        versions.extend(v for v in as_list(a.get("versions")) if isinstance(v, str))
        for rng in as_list(a.get("ranges")):
            if isinstance(rng, dict) and rng.get("type") in ("SEMVER", "ECOSYSTEM"):
                ivs.extend(intervals(rng))
    return rec, modified


# ---------------------------------------------------------------------------------------------------------------------
# Building

def split_groups(members):
    """Records of one package, joined when one's id is in the other's aliases, and so on along the chain."""
    if len(members) == 1:
        return [members]
    index = {m.id: n for n, m in enumerate(members)}
    parent = list(range(len(members)))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for n, m in enumerate(members):
        for alias in m.aliases:
            other = index.get(alias)
            if other is not None and other != n:
                parent[find(other)] = find(n)
    groups = collections.defaultdict(list)
    for n, m in enumerate(members):
        groups[find(n)].append(m)
    return list(groups.values())


def make_row(key, group, st):
    """One group of one package -> its row, or None when the group is left out."""
    eco, name = key
    members = sorted(group, key=lambda m: m.id)
    ids = [m.id for m in members]
    mal = [i for i in ids if i.startswith("MAL-")]
    ghsa = [i for i in ids if i.startswith("GHSA-")]
    kind = "mal" if mal else "vuln"
    chosen = mal[0] if mal else ghsa[0] if ghsa else ids[0]

    versions = set()
    ranges = {}                                  # (i, kind, end) -> does a real `fixed` end it
    for m in members:
        vs, ivs = m.entries[key]
        versions.update(vs)
        for i, k, end, real in ivs:
            ranges[(i, k, end)] = ranges.get((i, k, end), False) or real
    fixes = {end for (_, _, end), real in ranges.items() if real}
    severity = max(m.severity for m in members)

    if len(members) > 1:
        st["groups_merged_" + eco] += 1
    if kind == "vuln":
        if severity == 0:
            st["vuln_groups_no_severity_" + eco] += 1
            if fixes:
                st["vuln_groups_no_severity_with_fix_" + eco] += 1
        if severity == 2 and fixes:
            st["vuln_groups_medium_with_fix_" + eco] += 1
        if severity < 3 or not fixes:
            st["vuln_groups_left_out_" + eco] += 1
            return None

    # Rule 4: "from the first version, no end" with no exact versions is the whole package (`all`). With exact
    # versions the row keeps both: the range still covers every version, and the versions say which were seen.
    whole = False
    if ("0", "", "") in ranges:
        if versions:
            st["rows_versions_and_open_range"] += 1
        else:
            whole = True

    row = {"e": eco, "n": name, "k": kind, "id": chosen}
    al = sorted((set(ids) | {a for m in members for a in m.aliases}) - {chosen})
    if al:
        row["al"] = al
    if not whole:
        if versions:
            row["v"] = sorted(versions)
        if ranges:
            order = {"f": 0, "l": 1, "": 2}
            row["r"] = [{"i": i, k: end} if k else {"i": i}
                        for i, k, end in sorted(ranges, key=lambda r: (r[0], order[r[1]], r[2]))]
        elif not versions:
            st["rows_matching_nothing"] += 1
    row["all"] = whole
    if kind == "vuln":
        row["s"] = SEVERITIES[severity]
    if fixes:
        row["fx"] = greatest_fixed(eco, fixes)
    published = [m.published for m in members if m.published]
    modified = [m.modified for m in members if m.modified]
    if published:
        row["p"] = min(published)
    if modified:
        row["m"] = max(modified)
    # The chosen record's summary, else the first member's in id order; else the same search over details.
    order = [m for m in members if m.id == chosen] + [m for m in members if m.id != chosen]
    text = next((m.summary for m in order if m.summary), "") or next((m.details for m in order if m.details), "")
    if text:
        row["t"] = text
    return row


def build(sources, as_of=None):
    """sources: list of (label, path). Returns (rows in output order, currentTo, counts).
    `as_of` (YYYY-MM-DDTHH:MM:SSZ) builds the list as it stood then: see `as_of_view`."""
    st = collections.Counter()
    records = {}
    current_to = None
    for label, path in sources:
        counts = collections.Counter()
        for raw in read_source(path, counts):
            try:
                rec, modified = parse_record(raw, as_of)
            except ValueError:               # not JSON, not UTF-8, or no id: counted and skipped
                counts["unparseable"] += 1
                continue
            except NotYet:
                counts["after_as_of"] += 1
                continue
            counts["read"] += 1
            if modified and (current_to is None or modified > current_to):
                current_to = modified
            if rec is None:
                counts["withdrawn"] += 1
                continue
            if not rec.entries:
                counts["no_npm_or_pypi_package"] += 1
            if rec.id.startswith("MAL-"):
                counts["mal"] += 1
            else:
                counts["vuln"] += 1
                counts["vuln_" + SEVERITIES[rec.severity]] += 1
            # A record that affects both ecosystems is in both exports. The later `modified` wins; the first on a tie.
            old = records.get(rec.id)
            if old is not None:
                counts["same_id_again"] += 1
                if (rec.modified or "") <= (old.modified or ""):
                    continue
            records[rec.id] = rec
        for k in ("read", "unparseable", "withdrawn", "too_large", "same_id_again", "no_npm_or_pypi_package", "mal",
                  "vuln", "vuln_critical", "vuln_high", "vuln_medium", "vuln_low", "vuln_none", "after_as_of"):
            st["records_%s_%s" % (k, label)] += counts[k]

    by_package = collections.defaultdict(list)
    for rec in records.values():
        for key in rec.entries:
            by_package[key].append(rec)
    rows = []
    for key, members in by_package.items():
        for group in split_groups(members):
            row = make_row(key, group, st)
            if row is not None:
                rows.append(row)
    rows.sort(key=lambda r: (r["e"], r["n"], r["id"]))
    return rows, current_to or NO_TIME, st


def pack(lines):
    """Lines of text -> (the UTF-8 bytes, their gzip). Deterministic: mtime 0, no name, level 9."""
    text = "\n".join(lines) + "\n"
    try:
        plain = text.encode("utf-8")
    except UnicodeEncodeError:               # half of a surrogate pair in a record: written as U+FFFD
        plain = text.encode("utf-16", "surrogatepass").decode("utf-16", "replace").encode("utf-8")
    buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", compresslevel=9, fileobj=buf, mtime=0) as gz:
        gz.write(plain)
    return plain, buf.getvalue()


def encode_list(rows, generated, current_to):
    """A base: the whole list."""
    header = {"format": 1, "generated": generated, "currentTo": current_to, "rows": len(rows),
              "sources": SOURCES, "notes": []}
    return pack([dumps(header)] + [dumps(r) for r in rows])


# ---------------------------------------------------------------------------------------------------------------------
# Base and delta (the contract's "Base and delta")

def row_key(row):
    return (row["e"], row["n"], row["id"])


def read_list(path):
    """A list file (.jsonl.gz, base or delta) -> (header, rows as parsed JSON, in file order)."""
    with gzip.open(path, "rb") as fh:
        lines = fh.read().decode("utf-8").split("\n")
    header = json.loads(lines[0])
    if not isinstance(header, dict) or not isinstance(header.get("format"), int):
        raise ValueError("%s: no header" % path)
    return header, [json.loads(line) for line in lines[1:] if line]


def rows_as_written(plain):
    """The rows of a list, read back from its uncompressed bytes (what a reader of the file gets)."""
    return [json.loads(line) for line in plain.decode("utf-8").split("\n")[1:] if line]


def make_delta(base_rows, next_rows):
    """What turns `base_rows` into `next_rows`, as delta lines in output order (`e`, `n`, `id`).
    A row that is new, or differs in any value, is carried whole. A row that is no longer there is carried as
    {"e","n","id","gone":true}. Rows are compared as JSON values."""
    old = {row_key(r): r for r in base_rows}
    new = {row_key(r): r for r in next_rows}
    out = [r for k, r in new.items() if old.get(k) != r]
    out += [{"e": k[0], "n": k[1], "id": k[2], "gone": True} for k in old if k not in new]
    out.sort(key=row_key)
    return out


def apply_delta(base_rows, delta_rows):
    """The app's merge rule: base rows whose (`e`, `n`, `id`) the delta does not name, plus the delta's rows that
    are not `gone`, in output order."""
    named = {row_key(r) for r in delta_rows}
    out = [r for r in base_rows if row_key(r) not in named]
    out += [r for r in delta_rows if r.get("gone") is not True]
    out.sort(key=row_key)
    return out


def encode_delta(delta_rows, generated, current_to, base, rows):
    """A delta. `base`: {"generated", "sha256", "rows"} of the base file it applies to (sha256 of the .gz bytes).
    `rows`: how many rows the list has once the delta is applied."""
    gone = sum(1 for r in delta_rows if r.get("gone") is True)
    header = {"format": 1, "kind": "delta", "generated": generated, "currentTo": current_to,
              "base": {"generated": base["generated"], "sha256": base["sha256"], "rows": base["rows"]},
              "rows": rows, "changed": len(delta_rows) - gone, "gone": gone, "sources": SOURCES, "notes": []}
    return pack([dumps(header)] + [dumps(r) for r in delta_rows])


def base_info(path):
    """What a delta's header says about the base at `path`."""
    with open(path, "rb") as fh:
        packed = fh.read()
    header, rows = read_list(path)
    if header.get("kind", "base") != "base":
        raise ValueError("%s is not a base" % path)
    return {"generated": header["generated"], "sha256": hashlib.sha256(packed).hexdigest(), "rows": len(rows)}, rows


def stats_of(rows, st, generated, current_to, plain, packed, seconds):
    def per(prefix, labels):
        return {label: st[prefix + label] for label in labels}

    by_e = collections.Counter(r["e"] for r in rows)
    by_k = collections.Counter(r["k"] for r in rows)
    by_s = collections.Counter(r.get("s", "none (mal rows)") for r in rows)
    by_e_k = collections.Counter("%s %s" % (r["e"], r["k"]) for r in rows)
    record_keys = ("read", "unparseable", "withdrawn", "too_large", "same_id_again", "no_npm_or_pypi_package", "mal",
                   "vuln", "vuln_critical", "vuln_high", "vuln_medium", "vuln_low", "vuln_none")
    return {
        "generated": generated,
        "currentTo": current_to,
        "records_by_export": {label: {k: st["records_%s_%s" % (k, label)] for k in record_keys}
                              for label in ("npm", "pypi")},
        "rows": {
            "total": len(rows),
            "by_e": dict(sorted(by_e.items())),
            "by_k": dict(sorted(by_k.items())),
            "by_s": dict(sorted(by_s.items())),
            "by_e_and_k": dict(sorted(by_e_k.items())),
            "all_true": sum(1 for r in rows if r["all"]),
            "versions_and_open_range": st["rows_versions_and_open_range"],
            "with_fx": sum(1 for r in rows if "fx" in r),
            "mal_with_fx": sum(1 for r in rows if "fx" in r and r["k"] == "mal"),
            "with_al": sum(1 for r in rows if "al" in r),
            "matching_nothing": st["rows_matching_nothing"],
        },
        "groups": {
            "merged_more_than_one_record": per("groups_merged_", ("npm", "pypi")),
            "vuln_left_out": per("vuln_groups_left_out_", ("npm", "pypi")),
            "vuln_medium_with_fix": per("vuln_groups_medium_with_fix_", ("npm", "pypi")),
            "vuln_no_usable_severity": per("vuln_groups_no_severity_", ("npm", "pypi")),
            "vuln_no_usable_severity_with_fix": per("vuln_groups_no_severity_with_fix_", ("npm", "pypi")),
        },
        "output": {"compressed_bytes": len(packed), "uncompressed_bytes": len(plain),
                   "sha256": hashlib.sha256(packed).hexdigest()},
        "seconds": round(seconds, 1),
    }


# ---------------------------------------------------------------------------------------------------------------------
# Vectors

def check_vectors(folder):
    cases = sorted(d for d in os.listdir(folder) if os.path.isdir(os.path.join(folder, d, "records")))
    failed = 0
    for case in cases:
        rows, _, _ = build([("vectors", os.path.join(folder, case, "records"))])
        got = [json.loads(dumps(r)) for r in rows]
        with open(os.path.join(folder, case, "expected.jsonl"), encoding="utf-8") as fh:
            want = [json.loads(line) for line in fh if line.strip()]
        if got == want:
            continue
        failed += 1
        print("FAIL %s" % case)
        for n in range(max(len(got), len(want))):
            g = got[n] if n < len(got) else None
            w = want[n] if n < len(want) else None
            if g == w:
                continue
            print("  row %d" % (n + 1))
            print("    expected: %s" % ("(no row)" if w is None else dumps(w)))
            print("    built:    %s" % ("(no row)" if g is None else dumps(g)))
            if g is not None and w is not None:
                for k in sorted(set(g) | set(w)):
                    if g.get(k) != w.get(k):
                        print("    %-3s expected %s, built %s" % (k, dumps(w[k]) if k in w else "(absent)",
                                                                dumps(g[k]) if k in g else "(absent)"))
    print("%d cases, %d passed, %d failed" % (len(cases), len(cases) - failed, failed))
    return 0 if cases and not failed else 1


def check_delta_vectors(folder):
    def rows_of(path):
        with open(path, encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]

    cases = sorted(d for d in os.listdir(folder) if os.path.isfile(os.path.join(folder, d, "delta.jsonl")))
    failed = 0
    for case in cases:
        base = rows_of(os.path.join(folder, case, "base.jsonl"))
        nxt = rows_of(os.path.join(folder, case, "next.jsonl"))
        want = rows_of(os.path.join(folder, case, "delta.jsonl"))
        got = [json.loads(dumps(r)) for r in make_delta(base, nxt)]
        problems = []
        if got != want:
            problems.append("delta\n    expected: %s\n    built:    %s" % (dumps(want), dumps(got)))
        merged = apply_delta(base, want)
        if merged != sorted(nxt, key=row_key):
            problems.append("applying delta.jsonl to base.jsonl\n    expected: %s\n    merged:   %s"
                            % (dumps(sorted(nxt, key=row_key)), dumps(merged)))
        # What is written must read back the same (through the real file format).
        plain, _ = encode_delta(make_delta(base, nxt), "2026-10-11T04:00:00Z", "2026-10-11T03:00:00Z",
                                {"generated": "2026-10-04T04:00:00Z", "sha256": "0" * 64, "rows": len(base)}, len(nxt))
        back = [json.loads(line) for line in plain.decode("utf-8").split("\n")[1:] if line]
        if back != want:
            problems.append("the written delta does not read back as delta.jsonl")
        if problems:
            failed += 1
            print("FAIL %s" % case)
            for p in problems:
                print("  " + p)
    print("%d delta cases, %d passed, %d failed" % (len(cases), len(cases) - failed, failed))
    return 0 if cases and not failed else 1


TIME_ARG_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")


def write_atomically(path, data):
    tmp = path + ".tmp"
    with open(tmp, "wb") as fh:
        fh.write(data)
    os.replace(tmp, path)


def main():
    ap = argparse.ArgumentParser(description="Build the package list (docs/api/package-list-v1.md).")
    ap.add_argument("--npm", help="OSV npm export: all.zip or a folder of .json records")
    ap.add_argument("--pypi", help="OSV PyPI export: all.zip or a folder of .json records")
    ap.add_argument("--out", help="the whole list (a base) to write (.jsonl.gz)")
    ap.add_argument("--base", help="an earlier base (.jsonl.gz) to write a delta against")
    ap.add_argument("--delta-out", help="the delta against --base to write (.jsonl.gz)")
    ap.add_argument("--generated", help="build time for the header, YYYY-MM-DDTHH:MM:SSZ (default: now)")
    ap.add_argument("--as-of", help="build the list as it stood at this time (tests and measuring only)")
    ap.add_argument("--stats", help="write counts for the report to this .json")
    ap.add_argument("--check-vectors", metavar="FOLDER", help="run the shared vectors instead of building")
    ap.add_argument("--check-delta-vectors", metavar="FOLDER", help="run the shared delta vectors instead of building")
    args = ap.parse_args()

    if args.check_vectors or args.check_delta_vectors:
        codes = []
        if args.check_vectors:
            codes.append(check_vectors(args.check_vectors))
        if args.check_delta_vectors:
            codes.append(check_delta_vectors(args.check_delta_vectors))
        return max(codes)
    if not (args.npm and args.pypi and (args.out or args.delta_out)):
        ap.error("--npm, --pypi and --out or --delta-out are needed (or --check-vectors)")
    if bool(args.base) != bool(args.delta_out):
        ap.error("--base and --delta-out go together")
    generated = args.generated or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    if not TIME_ARG_RE.fullmatch(generated):
        ap.error("--generated must look like 2026-10-11T04:00:00Z")
    if args.as_of and not TIME_ARG_RE.fullmatch(args.as_of):
        ap.error("--as-of must look like 2026-10-04T04:00:00Z")

    started = time.monotonic()
    rows, current_to, st = build([("npm", args.npm), ("pypi", args.pypi)], as_of=args.as_of)
    plain, packed = encode_list(rows, generated, current_to)
    if args.out:
        write_atomically(args.out, packed)
    stats = stats_of(rows, st, generated, current_to, plain, packed, time.monotonic() - started)
    if args.as_of:
        stats["asOf"] = args.as_of
        stats["records_after_as_of"] = {label: st["records_after_as_of_" + label] for label in ("npm", "pypi")}
    if args.delta_out:
        base, base_rows = base_info(args.base)
        if generated < base["generated"]:
            ap.error("--generated is earlier than the base's")
        # Compared as the file reads back, so a row is never carried only because of how it was written.
        delta_rows = make_delta(base_rows, rows_as_written(plain))
        delta_plain, delta_packed = encode_delta(delta_rows, generated, current_to, base, len(rows))
        write_atomically(args.delta_out, delta_packed)
        gone = sum(1 for r in delta_rows if r.get("gone") is True)
        stats["delta"] = {"base": base, "changed": len(delta_rows) - gone, "gone": gone,
                          "compressed_bytes": len(delta_packed), "uncompressed_bytes": len(delta_plain),
                          "sha256": hashlib.sha256(delta_packed).hexdigest()}
    if args.stats:
        with open(args.stats, "w", encoding="utf-8") as fh:
            json.dump(stats, fh, indent=1)
            fh.write("\n")
    print(json.dumps(stats, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
