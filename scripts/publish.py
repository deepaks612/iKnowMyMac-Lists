#!/usr/bin/env python3
"""Builds, signs, checks and lays out the iKnowMyMac package list for publishing.

The one script the scheduled workflow calls; it runs the same way on a Mac or any machine with Python 3 and OpenSSL 3.
The format it writes is the contract in the app repository, docs/api/package-list-v1.md ("Base and delta").

  python3 -I scripts/publish.py run    --site _site [--previous <folder or https URL>] [--work <folder>]
  python3 -I scripts/publish.py verify --site <folder or https URL>

`run` downloads the two public OSV exports (conditional requests: an unchanged export costs one "not modified"),
builds the list with vendor/build.py, and writes into --site:
  packages-v1.jsonl.gz        (+ .sig)   the base: the whole list, rebuilt about weekly
  packages-v1.delta.jsonl.gz  (+ .sig)   the delta: what changed since that base, rebuilt whenever a source changed
  status.json, NOTICE.txt, LICENSE-APACHE-2.0.txt, index.html
It writes nothing, and says so, when there is nothing new. It exits non-zero, having written nothing a deploy step
would pick up, when any check fails: the previous publication then simply stays in place.

`verify` checks a publication (a folder, or the live site) against the public key committed in keys/.

The signing key is read from the environment variable PACKAGE_LIST_SIGNING_KEY (a PEM private key) or from
--key-file. It is handed to OpenSSL on standard input and is never written to disk, printed or logged.

Standard library only. The exports are untrusted data: they are read in memory by vendor/build.py, never unpacked
to disk and never executed.
"""
import argparse
import base64
import calendar
import datetime
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zlib

sys.dont_write_bytecode = True      # vendor/ must stay exactly what its manifest lists
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

BASE = "packages-v1.jsonl.gz"
DELTA = "packages-v1.delta.jsonl.gz"
STATUS = "status.json"
# PRD_v1.5.1 P97: the hand-checked runtime list (the app repository's docs/api/runtime-list-v1.md). It is edited in
# runtimes/, checked by vendor/runtime-validate.py, signed with the same key and published beside the package list.
RUNTIMES = "runtimes-v1.json"
RUNTIMES_SOURCE = os.path.join(ROOT, "runtimes", RUNTIMES)
PUBLIC_KEY_FILE = os.path.join(ROOT, "keys", "package-list-public-key.txt")

SOURCES = [
    ("npm", "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip"),
    ("pypi", "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"),
]

LICENCE_LINE = ("Built from OpenSSF Malicious Packages (Apache-2.0), the GitHub Advisory Database (CC-BY-4.0) and the "
                "PyPI Advisory Database (CC-BY-4.0), as exported by OSV.dev. Changed: reduced to one row per advisory "
                "and package, malicious releases and critical or high vulnerabilities with a fix only. This list is "
                "offered under CC-BY-4.0; see NOTICE.txt.")


def setting(name, default, kind=float):
    value = os.environ.get(name)
    return kind(value) if value not in (None, "") else default


class Refused(Exception):
    """A check failed: nothing is published and the previous publication stays."""


def log(message):
    print(message, flush=True)


# ---------------------------------------------------------------------------------------------------------------------
# Time

TIME_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")


def stamp(seconds):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(seconds))


def seconds_of(text):
    if not isinstance(text, str) or not TIME_RE.fullmatch(text):
        raise Refused("not a time: %r" % (text,))
    return calendar.timegm(time.strptime(text, "%Y-%m-%dT%H:%M:%SZ"))


# ---------------------------------------------------------------------------------------------------------------------
# Ed25519 verification in plain Python (RFC 8032, section 6, verification only). A second, independent check beside
# OpenSSL's: nothing is published unless both accept the signature. No secret passes through this code.

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P


def _recover_x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * pow(2, (_P - 1) // 4, _P) % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_GY = 4 * pow(5, _P - 2, _P) % _P
_GX = _recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)


def _add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(s, p):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _add(q, p)
        p = _add(p, p)
        s >>= 1
    return q


def _decompress(data):
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


def ed25519_verify(public, message, signature):
    if len(public) != 32 or len(signature) != 64:
        return False
    a = _decompress(public)
    r = _decompress(signature[:32])
    s = int.from_bytes(signature[32:], "little")
    if a is None or r is None or s >= _L:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % _L
    left = _mul(s, _G)
    right = _add(r, _mul(h, a))
    return (left[0] * right[2] - right[0] * left[2]) % _P == 0 and (left[1] * right[2] - right[1] * left[2]) % _P == 0


# ---------------------------------------------------------------------------------------------------------------------
# OpenSSL (version 3: Ed25519 one-shot signing with `pkeyutl -rawin`)

def find_openssl():
    names = [os.environ.get("OPENSSL") or "openssl", "/opt/homebrew/opt/openssl@3/bin/openssl",
             "/usr/local/opt/openssl@3/bin/openssl"]
    for name in names:
        path = shutil.which(name)
        if not path:
            continue
        try:
            version = subprocess.run([path, "version"], capture_output=True, text=True, timeout=30).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        if version.startswith("OpenSSL 3") or version.startswith("OpenSSL 4"):
            return path
    raise Refused("OpenSSL 3 was not found (set OPENSSL to its path; on a Mac: brew install openssl@3)")


SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")     # the fixed start of an Ed25519 public key in DER


def public_pem(raw):
    body = base64.encodebytes(SPKI_PREFIX + raw).decode("ascii")
    return "-----BEGIN PUBLIC KEY-----\n%s-----END PUBLIC KEY-----\n" % body


def read_public_key(path):
    """The committed public key: base64 of the 32 raw bytes, as the app holds it in PackageListKeys.production."""
    try:
        with open(path, encoding="utf-8") as fh:
            lines = [line.strip() for line in fh if line.strip() and not line.startswith("#")]
    except OSError:
        raise Refused("no public key file at %s" % path)
    if len(lines) != 1:
        raise Refused("%s must hold exactly one line: the public key scripts/make-key.sh printed" % path)
    try:
        raw = base64.b64decode(lines[0], validate=True)
    except ValueError:
        raw = b""
    if len(raw) != 32:
        raise Refused("%s does not hold a public key yet (base64 of 32 bytes). Run scripts/make-key.sh and paste "
                      "the line it prints." % path)
    return lines[0], raw


def sign(openssl, private_pem, path):
    """The 64-byte Ed25519 signature over the exact bytes of `path`. The key goes to OpenSSL on standard input."""
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "sig")
        done = subprocess.run([openssl, "pkeyutl", "-sign", "-inkey", "/dev/stdin", "-rawin", "-in", path, "-out", out],
                              input=private_pem, capture_output=True, timeout=120)
        if done.returncode != 0 or not os.path.exists(out):
            # OpenSSL's own message can never hold the key; it is shown to explain the failure.
            raise Refused("signing failed: %s" % done.stderr.decode("utf-8", "replace").strip()[:300])
        with open(out, "rb") as fh:
            signature = fh.read()
    if len(signature) != 64:
        raise Refused("signing gave %d bytes, not 64: is the key an Ed25519 key?" % len(signature))
    return signature


def verify_both(openssl, public_raw, path, signature):
    """True only when OpenSSL and the plain-Python check both accept `signature` over the bytes of `path`."""
    with open(path, "rb") as fh:
        data = fh.read()
    if not ed25519_verify(public_raw, data, signature):
        return False
    with tempfile.TemporaryDirectory() as tmp:
        key, sig = os.path.join(tmp, "public.pem"), os.path.join(tmp, "sig")
        with open(key, "w", encoding="ascii") as fh:
            fh.write(public_pem(public_raw))
        with open(sig, "wb") as fh:
            fh.write(signature)
        done = subprocess.run([openssl, "pkeyutl", "-verify", "-pubin", "-inkey", key, "-rawin", "-in", path,
                               "-sigfile", sig], capture_output=True, timeout=120)
    return done.returncode == 0


def read_signature(path):
    """A .sig file: base64 of the 64 bytes. None when it is anything else."""
    try:
        with open(path, "rb") as fh:
            text = fh.read(4096).decode("ascii", "replace").strip()
        raw = base64.b64decode(text, validate=True)
    except (OSError, ValueError):
        return None
    return raw if len(raw) == 64 else None


# ---------------------------------------------------------------------------------------------------------------------
# Downloads

def user_agent():
    repo = os.environ.get("GITHUB_REPOSITORY")
    contact = "https://github.com/%s" % repo if repo else "https://iknowmymac.com"
    return "iKnowMyMac-Lists/1 (package list builder; +%s)" % contact


def decoded(data, encoding):
    """What a client that accepts gzip ends up with: the body, taken out of its transfer coding when it has one."""
    if (encoding or "").strip().lower() in ("gzip", "x-gzip"):
        return zlib.decompress(data, 16 + zlib.MAX_WBITS)
    return data


def fetch(url, dest, etag=None, attempts=3, limit=2 << 30, as_app=False):
    """GET `url` into `dest` (atomically). Returns (status, etag, last-modified, bytes). 304 when `etag` still holds.
    `as_app`: ask the way the app does (it accepts gzip, and macOS undoes it), so the bytes kept are the bytes the
    app would be given. A host that labels the stored .gz itself as a transfer coding then shows up here as a
    signature that does not verify, not later on every Mac."""
    last = None
    for attempt in range(attempts):
        if attempt:
            time.sleep(5 * attempt)
        request = urllib.request.Request(url, headers={"User-Agent": user_agent()})
        if etag:
            request.add_header("If-None-Match", etag)
        if as_app:
            request.add_header("Accept-Encoding", "gzip")
        tmp = dest + ".part"
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                expected = response.headers.get("Content-Length")
                size = 0
                with open(tmp, "wb") as fh:
                    while True:
                        chunk = response.read(1 << 20)
                        if not chunk:
                            break
                        size += len(chunk)
                        if size > limit:
                            raise Refused("%s is larger than %d bytes" % (url, limit))
                        fh.write(chunk)
                if expected is not None and int(expected) != size:
                    raise OSError("%s: got %d of %s bytes" % (url, size, expected))
                if as_app and response.headers.get("Content-Encoding"):
                    with open(tmp, "rb") as fh:
                        body = decoded(fh.read(), response.headers.get("Content-Encoding"))
                    with open(tmp, "wb") as fh:
                        fh.write(body)
                    size = len(body)
                os.replace(tmp, dest)
                return 200, response.headers.get("ETag"), response.headers.get("Last-Modified"), size
        except urllib.error.HTTPError as error:
            if error.code == 304:
                return 304, etag, None, 0
            if error.code == 404:
                return 404, None, None, 0
            last = error
        except (urllib.error.URLError, OSError, ValueError, zlib.error) as error:
            last = error
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)
    raise Refused("could not download %s: %s" % (url, last))


def get_file(location, name, dest):
    """One file of a publication (a folder or an https URL) into `dest`. False when it is not there."""
    if location.startswith("https://") or location.startswith("http://"):
        status, _, _, _ = fetch(location.rstrip("/") + "/" + name, dest, limit=128 << 20, as_app=True)
        return status == 200
    source = os.path.join(location, name)
    if not os.path.isfile(source):
        return False
    shutil.copyfile(source, dest)
    return True


# ---------------------------------------------------------------------------------------------------------------------
# The builder (vendor/build.py, owned by the app repository)

def load_runtimes(path, old):
    """The runtime list to publish: its bytes, checked by the vendored validator, and its status record. Refused
    when it is not valid or would go backwards against what is published."""
    spec = importlib.util.spec_from_file_location("runtime_validate", os.path.join(ROOT, "vendor", "runtime-validate.py"))
    validate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(validate)
    with open(path, "rb") as fh:
        raw = fh.read()
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise Refused("%s is not UTF-8 JSON: %s" % (RUNTIMES, error))
    published = (old or {}).get("runtimes") or {}
    problems = validate.problems_in(data, len(raw), {"generated": published["generated"]}
                                    if published.get("sha256") not in (None, hashlib.sha256(raw).hexdigest()) else None)
    if problems:
        raise Refused("%s: %s" % (RUNTIMES, "; ".join(problems)))
    return raw, {"file": RUNTIMES, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
                 "generated": data["generated"]}


def load_builder():
    path = os.path.join(ROOT, "vendor", "build.py")
    spec = importlib.util.spec_from_file_location("package_list_build", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with open(path, "rb") as fh:
        return module, hashlib.sha256(fh.read()).hexdigest()


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_bytes(path, data):
    tmp = path + ".tmp"
    with open(tmp, "wb") as fh:
        fh.write(data)
    os.replace(tmp, path)


def write_signature(path, signature):
    write_bytes(path, base64.b64encode(signature) + b"\n")


# ---------------------------------------------------------------------------------------------------------------------
# The previous publication

class Previous:
    """What is published now: status.json and, fetched when needed, the base with its signature."""

    def __init__(self, location, folder):
        self.location = location
        self.folder = folder
        self.status = None
        if location:
            path = os.path.join(folder, STATUS)
            if get_file(location, STATUS, path):
                with open(path, encoding="utf-8") as fh:
                    self.status = json.load(fh)
                if not isinstance(self.status, dict) or self.status.get("format") != 1:
                    raise Refused("the previous status.json is not one this script wrote")

    def base(self, openssl, public_raw):
        """The previous base file, checked: the size and hash status.json gives, and a signature that verifies."""
        info = self.status["base"]
        path = os.path.join(self.folder, BASE)
        for name in (BASE, BASE + ".sig"):
            if not get_file(self.location, name, os.path.join(self.folder, name)):
                raise Refused("the previous publication has no %s" % name)
        if sha256_of(path) != info["sha256"]:
            raise Refused("the previous base is not the file status.json names")
        signature = read_signature(path + ".sig")
        if signature is None or not verify_both(openssl, public_raw, path, signature):
            raise Refused("the previous base's signature does not verify against the committed public key")
        return path


# ---------------------------------------------------------------------------------------------------------------------
# run

def obtain_sources(work, previous, need_bytes, as_of):
    """The two exports, with conditional requests. Returns ({label: path or None}, {label: source record}, changed)."""
    os.makedirs(work, exist_ok=True)
    known = {s["name"]: s for s in (previous.status or {}).get("sources", [])} if previous.status else {}
    paths, records, changed = {}, {}, False
    for label, url in SOURCES:
        dest = os.path.join(work, "%s-all.zip" % label)
        note = dest + ".etag"
        local = None
        if os.path.isfile(dest) and os.path.isfile(note):
            with open(note, encoding="utf-8") as fh:
                local = json.load(fh)
        published = known.get(label, {})
        # Ask with the validator of the copy on disk when there is one, else of the copy the last publication used.
        etag = (local or published).get("etag")
        status, new_etag, modified, size = fetch(url, dest, etag=etag)
        if status == 200:
            local = {"etag": new_etag, "lastModified": modified, "bytes": size}
            with open(note, "w", encoding="utf-8") as fh:
                json.dump(local, fh)
            paths[label] = dest
            log("%s: downloaded %d bytes (%s)" % (label, size, modified))
        elif status == 304:
            paths[label] = dest if local else None
            log("%s: not modified" % label)
        else:
            raise Refused("%s answered %d" % (url, status))
        current = local or published
        if current.get("etag") != published.get("etag") or not published:
            changed = True
        records[label] = {"name": label, "url": url, "etag": current.get("etag"),
                          "lastModified": current.get("lastModified"), "bytes": current.get("bytes")}
    if need_bytes or changed:
        for label, url in SOURCES:
            if paths[label] is None:        # unchanged since the last publication, but both are needed to build
                dest = os.path.join(work, "%s-all.zip" % label)
                status, new_etag, modified, size = fetch(url, dest)
                if status != 200:
                    raise Refused("%s answered %d" % (url, status))
                records[label].update({"etag": new_etag, "lastModified": modified, "bytes": size})
                with open(dest + ".etag", "w", encoding="utf-8") as fh:
                    json.dump({"etag": new_etag, "lastModified": modified, "bytes": size}, fh)
                paths[label] = dest
                log("%s: downloaded %d bytes (needed to build)" % (label, size))
    if as_of:
        # A list "as of" an earlier time is not what these exports are now: the next run must not take them as seen.
        for record in records.values():
            record["etag"] = None
    return paths, records, changed


def run(args):
    openssl = find_openssl()
    public_text, public_raw = read_public_key(args.public_key_file)
    private_pem = None
    if args.key_file:
        with open(args.key_file, "rb") as fh:
            private_pem = fh.read()
    elif os.environ.get("PACKAGE_LIST_SIGNING_KEY"):
        private_pem = os.environ["PACKAGE_LIST_SIGNING_KEY"].encode("utf-8")
    if not private_pem or b"PRIVATE KEY" not in private_pem:
        raise Refused("no signing key: set the repository secret PACKAGE_LIST_SIGNING_KEY (scripts/make-key.sh)")
    if not private_pem.endswith(b"\n"):
        private_pem += b"\n"

    base_max_age = setting("BASE_MAX_AGE_DAYS", 7.0) * 86400
    delta_max_bytes = setting("DELTA_MAX_BYTES", 256 * 1024, int)
    min_rows = setting("MIN_ROWS_FRACTION", 0.9)
    min_base_bytes = setting("MIN_BASE_BYTES_FRACTION", 0.8)
    stale_after = setting("STALE_SOURCE_HOURS", 48.0) * 3600

    build, builder_sha = load_builder()
    vectors = os.path.join(ROOT, "vendor")
    if build.check_vectors(os.path.join(vectors, "list-vectors")) or build.check_delta_vectors(os.path.join(vectors, "delta-vectors")):
        raise Refused("the builder does not pass the contract's vectors")

    now = seconds_of(args.as_of) if args.as_of else (seconds_of(args.now) if args.now else int(time.time()))
    generated = stamp(now)
    work = args.work or tempfile.mkdtemp(prefix="package-list-")
    state = os.path.join(work, "previous")
    os.makedirs(state, exist_ok=True)
    previous = Previous(args.previous, state)
    old = previous.status

    rules_changed = bool(old) and old.get("builder", {}).get("sha256") != builder_sha
    key_changed = bool(old) and old.get("publicKey") != public_text
    force_base = args.force_base or rules_changed or key_changed or not old
    runtimes_raw, runtimes_record = load_runtimes(args.runtimes or RUNTIMES_SOURCE, old)
    runtimes_changed = bool(old) and (old.get("runtimes") or {}).get("sha256") != runtimes_record["sha256"]
    if args.source_dir:
        paths = {label: os.path.join(args.source_dir, "%s-all.zip" % label) for label, _ in SOURCES}
        records = {label: {"name": label, "url": url, "etag": '"%s"' % sha256_of(paths[label])[:32], "lastModified": None,
                           "bytes": os.path.getsize(paths[label])} for label, url in SOURCES}
        known = {s["name"]: s.get("etag") for s in old.get("sources", [])} if old else {}
        changed = any(records[label]["etag"] != known.get(label) for label, _ in SOURCES)
    else:
        paths, records, changed = obtain_sources(work, previous, force_base or runtimes_changed, args.as_of)

    changed_at = generated if changed or not old else old.get("sourcesChangedAt", old["generated"])
    if not changed and not force_base and not runtimes_changed:
        idle = now - seconds_of(changed_at)
        if idle > stale_after:
            raise Refused("neither public export has changed for %.0f hours (they usually change most hours): the "
                          "published list is going stale. Look at https://osv.dev and at this job's requests."
                          % (idle / 3600))
        log("Nothing new: neither export changed since the list of %s. Nothing is published." % old["generated"])
        return {"publish": False, "kind": "none"}

    # Build today's list.
    rows, current_to, st = build.build([(label, paths[label]) for label, _ in SOURCES], as_of=args.as_of)
    plain, packed = build.encode_list(rows, generated, current_to)
    rows = build.rows_as_written(plain)
    for label, _ in SOURCES:
        records[label]["records"] = st["records_read_" + label]
    log("built %d rows, current to %s (%d npm and %d PyPI records read)"
        % (len(rows), current_to, records["npm"]["records"], records["pypi"]["records"]))

    # Safety rails against the previous publication.
    if old:
        if generated <= old["generated"]:
            raise Refused("`generated` would go backwards or stand still: %s after %s" % (generated, old["generated"]))
        if current_to < old["currentTo"]:
            raise Refused("`currentTo` would go backwards: %s after %s (an older export?)" % (current_to, old["currentTo"]))
        if len(rows) < min_rows * old["rows"] and not args.allow_shrink:
            raise Refused("the list would shrink from %d rows to %d (less than %.0f%%): a broken download must not "
                          "wipe the list. If the public data really shrank, run once with allow_shrink."
                          % (old["rows"], len(rows), min_rows * 100))
        for label, _ in SOURCES:
            before = next((s.get("records") for s in old.get("sources", []) if s["name"] == label), None)
            if before and records[label]["records"] < min_rows * before and not args.allow_shrink:
                raise Refused("the %s export holds %d records, down from %d" % (label, records[label]["records"], before))
    if not rows:
        raise Refused("the list would be empty")

    site = args.site
    staging = site.rstrip("/") + ".staging"
    shutil.rmtree(staging, ignore_errors=True)
    os.makedirs(staging)
    base_path, delta_path = os.path.join(staging, BASE), os.path.join(staging, DELTA)

    # Base or delta?
    reason = None
    if not old:
        reason = "the first publication"
    elif args.force_base:
        reason = "asked for"
    elif rules_changed:
        reason = "the builder changed"
    elif key_changed:
        reason = "the public key changed"
    elif now - seconds_of(old["base"]["generated"]) >= base_max_age:
        reason = "the base is %.1f days old" % ((now - seconds_of(old["base"]["generated"])) / 86400)
    delta_rows = None
    if reason is None:
        old_base = previous.base(openssl, public_raw)
        info, base_rows = build.base_info(old_base)
        delta_rows = build.make_delta(base_rows, rows)
        if build.apply_delta(base_rows, delta_rows) != sorted(rows, key=build.row_key):
            raise Refused("the delta does not turn the base into today's list")
        delta_plain, delta_packed = build.encode_delta(delta_rows, generated, current_to, info, len(rows))
        if len(delta_packed) > delta_max_bytes:
            reason = "the delta has grown to %d bytes" % len(delta_packed)
            delta_rows = None
        else:
            shutil.copyfile(old_base, base_path)
            shutil.copyfile(old_base + ".sig", base_path + ".sig")
    if delta_rows is None:
        if old and len(packed) < min_base_bytes * old["base"]["bytes"] and not args.allow_shrink:
            raise Refused("the base would shrink from %d to %d bytes" % (old["base"]["bytes"], len(packed)))
        write_bytes(base_path, packed)
        write_signature(base_path + ".sig", sign(openssl, private_pem, base_path))
        info, base_rows = build.base_info(base_path)
        if base_rows != rows:
            raise Refused("the base does not read back as the rows that were built")
        delta_rows = []
        delta_plain, delta_packed = build.encode_delta(delta_rows, generated, current_to, info, len(rows))
        log("a new base (%s): %d bytes" % (reason, len(packed)))
    write_bytes(delta_path, delta_packed)
    write_signature(delta_path + ".sig", sign(openssl, private_pem, delta_path))
    write_bytes(os.path.join(staging, RUNTIMES), runtimes_raw)
    write_signature(os.path.join(staging, RUNTIMES + ".sig"), sign(openssl, private_pem, os.path.join(staging, RUNTIMES)))
    if runtimes_changed:
        log("the runtime list changed: %s (%d bytes)" % (runtimes_record["generated"], runtimes_record["bytes"]))
    del private_pem

    gone = sum(1 for r in delta_rows if r.get("gone") is True)
    status = {
        "format": 1,
        "generated": generated,
        "currentTo": current_to,
        "rows": len(rows),
        "base": {"file": BASE, "generated": info["generated"], "sha256": info["sha256"],
                 "bytes": os.path.getsize(base_path), "rows": info["rows"]},
        "delta": {"file": DELTA, "sha256": sha256_of(delta_path), "bytes": os.path.getsize(delta_path),
                  "changed": len(delta_rows) - gone, "gone": gone},
        "runtimes": runtimes_record,
        "publicKey": public_text,
        "builder": {"sha256": builder_sha},
        "sources": [records[label] for label, _ in SOURCES],
        "sourcesChangedAt": changed_at,
        "licence": LICENCE_LINE,
        "credits": build.SOURCES,
    }
    with open(os.path.join(staging, STATUS), "w", encoding="utf-8") as fh:
        json.dump(status, fh, indent=1)
        fh.write("\n")
    shutil.copyfile(os.path.join(ROOT, "NOTICE.md"), os.path.join(staging, "NOTICE.txt"))
    shutil.copyfile(os.path.join(ROOT, "LICENSE-APACHE-2.0.txt"), os.path.join(staging, "LICENSE-APACHE-2.0.txt"))
    with open(os.path.join(staging, "index.html"), "w", encoding="utf-8") as fh:
        fh.write(INDEX_HTML % {"generated": generated, "currentTo": current_to, "rows": len(rows)})

    # Nothing is handed over unsigned or unverified: the staged folder is checked as a reader would check it.
    problems = verify_folder(staging, openssl, public_text, public_raw, build)
    if problems:
        raise Refused("the staged publication does not verify: " + "; ".join(problems))
    # The same content gets the same file times, so an unchanged file looks unchanged to whatever serves it.
    for name, when in ((BASE, info["generated"]), (BASE + ".sig", info["generated"]), (DELTA, generated),
                       (DELTA + ".sig", generated), (STATUS, generated), ("index.html", generated),
                       (RUNTIMES, runtimes_record["generated"]), (RUNTIMES + ".sig", runtimes_record["generated"])):
        os.utime(os.path.join(staging, name), (seconds_of(when), seconds_of(when)))
    shutil.rmtree(site, ignore_errors=True)
    os.replace(staging, site)
    kind = "base" if not delta_rows and status["base"]["generated"] == generated else "delta"
    log("published to %s: %s; base %d bytes (%s), delta %d bytes (%d changed, %d gone), %d rows, current to %s"
        % (site, kind, status["base"]["bytes"], status["base"]["generated"], status["delta"]["bytes"],
           status["delta"]["changed"], gone, len(rows), current_to))
    return {"publish": True, "kind": kind, "status": status}


INDEX_HTML = """<!doctype html>
<meta charset="utf-8">
<title>iKnowMyMac package list</title>
<p>The list of known-bad npm and PyPI package versions that <a href="https://iknowmymac.com">iKnowMyMac</a> matches on
the Mac. Built %(generated)s, current to %(currentTo)s, %(rows)d rows.
<a href="status.json">status.json</a> · <a href="NOTICE.txt">sources and licences</a> ·
<a href="LICENSE-APACHE-2.0.txt">Apache License 2.0</a></p>
<p>Data: OpenSSF Malicious Packages (Apache-2.0), GitHub Advisory Database (CC-BY-4.0), PyPI Advisory Database
(CC-BY-4.0), via OSV.dev.</p>
"""


# ---------------------------------------------------------------------------------------------------------------------
# verify

def verify_folder(folder, openssl, public_text, public_raw, build):
    """Every check a reader makes, and the ones only the publisher can. Returns the problems found (none: good)."""
    problems = []
    try:
        with open(os.path.join(folder, STATUS), encoding="utf-8") as fh:
            status = json.load(fh)
    except (OSError, ValueError) as error:
        return ["status.json: %s" % error]
    if status.get("publicKey") != public_text:
        problems.append("status.json names another public key than keys/package-list-public-key.txt")
    for name in (BASE, DELTA):
        path = os.path.join(folder, name)
        if not os.path.isfile(path):
            problems.append("%s is missing" % name)
            continue
        signature = read_signature(path + ".sig")
        if signature is None:
            problems.append("%s.sig is missing or not base64 of 64 bytes" % name)
        elif not verify_both(openssl, public_raw, path, signature):
            problems.append("%s: the signature does not verify against the committed public key" % name)
    runtimes = status.get("runtimes")
    if runtimes:
        path = os.path.join(folder, RUNTIMES)
        signature = read_signature(path + ".sig")
        if not os.path.isfile(path):
            problems.append("%s is missing" % RUNTIMES)
        elif signature is None or not verify_both(openssl, public_raw, path, signature):
            problems.append("%s: the signature does not verify against the committed public key" % RUNTIMES)
        elif sha256_of(path) != runtimes.get("sha256") or os.path.getsize(path) != runtimes.get("bytes"):
            problems.append("status.json runtimes does not describe %s" % RUNTIMES)
    if problems:
        return problems
    try:
        info, base_rows = build.base_info(os.path.join(folder, BASE))
        header, delta_rows = build.read_list(os.path.join(folder, DELTA))
    except (OSError, ValueError, KeyError) as error:
        return ["the files do not read as a base and a delta: %s" % error]
    if header.get("kind") != "delta" or header.get("base") != info:
        problems.append("the delta does not name this base (sha256 %s)" % info["sha256"][:12])
    if header.get("generated", "") < info["generated"]:
        problems.append("the delta is older than its base")
    keys = [build.row_key(r) for r in delta_rows]
    if keys != sorted(keys) or len(set(keys)) != len(keys):
        problems.append("the delta's rows are not in order, or name a row twice")
    merged = build.apply_delta(base_rows, delta_rows)
    if len(merged) != header.get("rows"):
        problems.append("base and delta give %d rows; the delta's header says %s" % (len(merged), header.get("rows")))
    expected = {
        "generated": header.get("generated"), "currentTo": header.get("currentTo"), "rows": header.get("rows"),
        "base.sha256": info["sha256"], "base.bytes": os.path.getsize(os.path.join(folder, BASE)),
        "delta.sha256": sha256_of(os.path.join(folder, DELTA)), "delta.bytes": os.path.getsize(os.path.join(folder, DELTA)),
    }
    for key, value in expected.items():
        found = status
        for part in key.split("."):
            found = found.get(part) if isinstance(found, dict) else None
        if found != value:
            problems.append("status.json %s is %r, the files say %r" % (key, found, value))
    return problems


def verify(args):
    openssl = find_openssl()
    public_text, public_raw = read_public_key(args.public_key_file)
    build, _ = load_builder()
    folder = args.site
    with tempfile.TemporaryDirectory() as tmp:
        if folder.startswith("https://") or folder.startswith("http://"):
            for name in (STATUS, BASE, BASE + ".sig", DELTA, DELTA + ".sig"):
                if not get_file(folder, name, os.path.join(tmp, name)):
                    raise Refused("%s/%s is not there" % (folder.rstrip("/"), name))
            with open(os.path.join(tmp, STATUS), encoding="utf-8") as fh:
                if json.load(fh).get("runtimes"):
                    for name in (RUNTIMES, RUNTIMES + ".sig"):
                        if not get_file(folder, name, os.path.join(tmp, name)):
                            raise Refused("%s/%s is not there" % (folder.rstrip("/"), name))
            folder = tmp
        problems = verify_folder(folder, openssl, public_text, public_raw, build)
        if problems:
            raise Refused("; ".join(problems))
        with open(os.path.join(folder, STATUS), encoding="utf-8") as fh:
            status = json.load(fh)
    if args.expect_generated and status["generated"] != args.expect_generated:
        raise Refused("the site serves the list of %s, not the one just built (%s)" % (status["generated"], args.expect_generated))
    age = (time.time() - seconds_of(status["currentTo"])) / 3600
    log("verified: %d rows, built %s, current to %s (%.1f hours ago), base %d bytes, delta %d bytes"
        % (status["rows"], status["generated"], status["currentTo"], age, status["base"]["bytes"], status["delta"]["bytes"]))
    return {"publish": False, "kind": "verified", "status": status}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Build, sign, check and lay out the iKnowMyMac package list.")
    sub = ap.add_subparsers(dest="command", required=True)
    r = sub.add_parser("run", help="build and sign a publication into --site")
    r.add_argument("--site", required=True, help="the folder to write (replaced whole, only on success)")
    r.add_argument("--previous", help="what is published now: a folder or the site's https URL (none: a first run)")
    r.add_argument("--work", help="where downloads are kept between steps (default: a temporary folder)")
    r.add_argument("--key-file", help="the PEM private key (default: the PACKAGE_LIST_SIGNING_KEY environment variable)")
    r.add_argument("--public-key-file", default=PUBLIC_KEY_FILE, help="the public key to verify against (default: keys/)")
    r.add_argument("--force-base", action="store_true", help="rebuild the whole list now")
    r.add_argument("--allow-shrink", action="store_true", help="accept, this once, a list much smaller than the last")
    r.add_argument("--source-dir", help="use npm-all.zip and pypi-all.zip from this folder instead of downloading (tests)")
    r.add_argument("--now", help="the build time, YYYY-MM-DDTHH:MM:SSZ (tests)")
    r.add_argument("--runtimes", help="the runtime list to publish (default: runtimes/runtimes-v1.json)")
    r.add_argument("--as-of", help="build the list as it stood at this time (trial runs and measuring only)")
    v = sub.add_parser("verify", help="check a publication against the committed public key")
    v.add_argument("--site", required=True, help="a folder, or the site's https URL")
    v.add_argument("--public-key-file", default=PUBLIC_KEY_FILE)
    v.add_argument("--expect-generated", help="fail unless the publication is the one built at this time")
    args = ap.parse_args(argv)
    try:
        result = run(args) if args.command == "run" else verify(args)
    except Refused as error:
        print("REFUSED: %s" % error, file=sys.stderr, flush=True)
        return 1
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as fh:
            fh.write("publish=%s\nkind=%s\n" % ("true" if result["publish"] else "false", result["kind"]))
            if result.get("status"):
                fh.write("generated=%s\n" % result["status"]["generated"])
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary and result.get("status"):
        s = result["status"]
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write("**%s** · %d rows · built %s · current to %s · base %d bytes (%s) · delta %d bytes (%d changed, %d gone)\n"
                     % (result["kind"], s["rows"], s["generated"], s["currentTo"], s["base"]["bytes"], s["base"]["generated"],
                        s["delta"]["bytes"], s["delta"]["changed"], s["delta"]["gone"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
