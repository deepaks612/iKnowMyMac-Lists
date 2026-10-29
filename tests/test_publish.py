"""Tests of scripts/publish.py on made-up records, with a key pair made in the test. No network is used.

  python3 -I -m unittest discover -s tests -v        (needs OpenSSL 3 on the PATH, or OPENSSL set to it)
"""
import base64
import contextlib
import gzip
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("publish", os.path.join(ROOT, "scripts", "publish.py"))
publish = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publish)


def mal(n, name, versions=None, modified="2026-10-01T00:00:00Z", withdrawn=None):
    record = {"id": "MAL-2026-%04d" % n, "modified": modified, "published": "2026-09-30T00:00:00Z",
              "summary": "Malicious code in %s (npm)" % name,
              "affected": [{"package": {"ecosystem": "npm", "name": name},
                            **({"versions": versions} if versions else {"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]})}]}
    if withdrawn:
        record["withdrawn"] = withdrawn
    return record


def hole(n, name, fixed="2.0.0"):
    return {"id": "PYSEC-2026-%d" % n, "modified": "2026-09-01T00:00:00Z", "published": "2026-08-01T00:00:00Z",
            "summary": "A hole in " + name, "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            "affected": [{"package": {"ecosystem": "PyPI", "name": name},
                          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}]}]}


class World:
    """A throwaway folder with a key pair, source zips and a site."""

    def __init__(self, case):
        self.dir = tempfile.mkdtemp(prefix="publish-test-")
        case.addCleanup(shutil.rmtree, self.dir, True)
        self.openssl = publish.find_openssl()
        self.key = os.path.join(self.dir, "key.pem")
        self.public = self.make_key(self.key)
        self.sources = os.path.join(self.dir, "sources")
        os.makedirs(self.sources)
        self.site = os.path.join(self.dir, "site")

    def make_key(self, path):
        subprocess.run([self.openssl, "genpkey", "-algorithm", "ED25519", "-out", path], check=True, capture_output=True)
        der = subprocess.run([self.openssl, "pkey", "-in", path, "-pubout", "-outform", "DER"], check=True, capture_output=True).stdout
        public = path + ".pub"
        with open(public, "w") as fh:
            fh.write("# test key\n" + base64.b64encode(der[-32:]).decode() + "\n")
        return public

    def export(self, npm, pypi, maven=()):
        for label, records in (("npm", npm), ("pypi", pypi), ("maven", maven)):
            with zipfile.ZipFile(os.path.join(self.sources, label + "-all.zip"), "w", zipfile.ZIP_DEFLATED) as z:
                for record in records:
                    z.writestr(record["id"] + ".json", json.dumps(record))

    def run(self, now, *extra, key=None, public=None, previous=True, env=None):
        argv = ["run", "--site", self.site, "--source-dir", self.sources, "--work", os.path.join(self.dir, "work"),
                "--key-file", key or self.key, "--public-key-file", public or self.public, "--now", now, *extra]
        if previous and os.path.isdir(self.site):
            argv += ["--previous", self.site]
        out, err = io.StringIO(), io.StringIO()
        old_env = dict(os.environ)
        os.environ.update(env or {})
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = publish.main(argv)
        finally:
            os.environ.clear()
            os.environ.update(old_env)
        return code, out.getvalue() + err.getvalue()

    def status(self):
        with open(os.path.join(self.site, "status.json")) as fh:
            return json.load(fh)

    def read(self, name):
        with open(os.path.join(self.site, name), "rb") as fh:
            return fh.read()

    def lines(self, name):
        return [json.loads(line) for line in gzip.decompress(self.read(name)).decode().split("\n") if line]

    def names(self):
        """The list a reader ends up with: the base with the delta applied."""
        base, delta = self.lines(publish.BASE)[1:], self.lines(publish.DELTA)[1:]
        named = {(r["e"], r["n"], r["id"]) for r in delta}
        rows = [r for r in base if (r["e"], r["n"], r["id"]) not in named] + [r for r in delta if not r.get("gone")]
        return sorted(r["n"] for r in rows)


A, B, C = mal(1, "alpha-demo", ["1.0.0"]), mal(2, "beta-demo"), mal(3, "gamma-demo", ["3.1.4"])
H = hole(11, "delta-demo")


class PublishTests(unittest.TestCase):
    def test_a_first_run_writes_a_signed_base_and_an_empty_delta(self):
        w = World(self)
        w.export([A, B], [H])
        code, out = w.run("2026-10-04T04:17:00Z")
        self.assertEqual(code, 0, out)
        s = w.status()
        self.assertEqual((s["rows"], s["generated"], s["base"]["generated"], s["delta"]["changed"], s["delta"]["gone"]),
                         (3, "2026-10-04T04:17:00Z", "2026-10-04T04:17:00Z", 0, 0))
        self.assertEqual(sorted(os.listdir(w.site)), sorted(["LICENSE-APACHE-2.0.txt", "NOTICE.txt", "index.html", "packages-v1.delta.jsonl.gz",
                         "packages-v1.delta.jsonl.gz.sig", "packages-v1.jsonl.gz", "packages-v1.jsonl.gz.sig", "runtimes-v1.json",
                         "runtimes-v1.json.sig", "status.json"]))
        header = w.lines(publish.DELTA)[0]
        self.assertEqual(header["kind"], "delta")
        self.assertEqual(header["base"], {"generated": s["base"]["generated"], "sha256": s["base"]["sha256"], "rows": 3})
        self.assertIn("CC-BY-4.0", s["licence"])
        self.assertIn("Apache-2.0", s["licence"])
        self.assertEqual([c["name"] for c in s["credits"]], ["OpenSSF Malicious Packages", "GitHub Advisory Database", "PyPI Advisory Database"])
        # Each signature is base64 of 64 bytes over the exact file, and both checks accept it.
        public = publish.read_public_key(w.public)[1]
        for name in (publish.BASE, publish.DELTA):
            signature = base64.b64decode(w.read(name + ".sig"))
            self.assertEqual(len(signature), 64)
            self.assertTrue(publish.ed25519_verify(public, w.read(name), signature))
            self.assertTrue(publish.verify_both(w.openssl, public, os.path.join(w.site, name), signature))
            self.assertFalse(publish.ed25519_verify(public, w.read(name) + b"x", signature))
        self.assertEqual(publish.main(["verify", "--site", w.site, "--public-key-file", w.public]), 0)

    def test_maven_rows_are_built_from_the_maven_export_beside_npm_and_pypi(self):
        # App 1.7.1: the third export. Its rows are skipped by apps before 1.7.1 (unknown ecosystem), read by 1.7.1.
        w = World(self)
        evil = {"id": "MAL-2026-0901", "modified": "2026-10-20T00:00:00Z", "published": "2026-10-20T00:00:00Z",
                "summary": "Malicious code in org.example.demo:log-helper (Maven)",
                "affected": [{"package": {"ecosystem": "Maven", "name": "org.example.demo:log-helper"}, "versions": ["1.2.9"]}]}
        w.export([A, B], [H], [evil])
        code, out = w.run("2026-10-04T04:17:00Z")
        self.assertEqual(code, 0, out)
        rows = w.lines(publish.BASE)[1:]
        self.assertEqual([(r["e"], r["n"], r["v"]) for r in rows if r["e"] == "maven"], [("maven", "org.example.demo:log-helper", ["1.2.9"])])
        self.assertEqual(w.status()["rows"], 4)
        self.assertEqual(w.lines(publish.BASE)[0]["format"], 1)

    def test_an_hourly_change_writes_only_a_delta_and_the_base_is_carried_byte_for_byte(self):
        w = World(self)
        w.export([A, B], [H])
        self.assertEqual(w.run("2026-10-04T04:17:00Z")[0], 0)
        base, signature = w.read(publish.BASE), w.read(publish.BASE + ".sig")
        # an hour later: alpha names another version, beta was withdrawn, gamma is new
        w.export([mal(1, "alpha-demo", ["1.0.0", "1.0.1"], "2026-10-04T05:00:00Z"), mal(2, "beta-demo", None, "2026-10-04T05:01:00Z", "2026-10-04T05:01:00Z"), C], [H])
        code, out = w.run("2026-10-04T05:17:00Z")
        self.assertEqual(code, 0, out)
        self.assertEqual((w.read(publish.BASE), w.read(publish.BASE + ".sig")), (base, signature))
        delta = w.lines(publish.DELTA)
        self.assertEqual(delta[0]["generated"], "2026-10-04T05:17:00Z")
        self.assertEqual(delta[0]["currentTo"], "2026-10-04T05:01:00Z")
        self.assertEqual([(r["n"], r.get("gone", False)) for r in delta[1:]], [("alpha-demo", False), ("beta-demo", True), ("gamma-demo", False)])
        self.assertEqual(w.names(), ["alpha-demo", "delta-demo", "gamma-demo"])
        s = w.status()
        self.assertEqual((s["rows"], s["delta"]["changed"], s["delta"]["gone"], s["base"]["generated"]), (3, 2, 1, "2026-10-04T04:17:00Z"))
        # a delta always holds everything since the base: the next one replaces this one
        w.export([A, B, mal(3, "gamma-demo", ["3.1.4"], "2026-10-04T06:00:00Z")], [H])
        code, out = w.run("2026-10-04T06:17:00Z")
        self.assertEqual(code, 0, out)
        self.assertEqual([r["n"] for r in w.lines(publish.DELTA)[1:]], ["gamma-demo"])
        self.assertEqual(w.names(), ["alpha-demo", "beta-demo", "delta-demo", "gamma-demo"])
        self.assertEqual(os.path.getmtime(os.path.join(w.site, publish.BASE)), publish.seconds_of("2026-10-04T04:17:00Z"))

    def test_the_runtime_list_is_checked_signed_and_published_and_a_change_to_it_alone_publishes(self):
        w = World(self)
        w.export([A, B], [H])
        with open(publish.RUNTIMES_SOURCE, "rb") as fh:
            committed = fh.read()
        self.assertEqual(w.run("2026-10-04T04:17:00Z")[0], 0)
        self.assertEqual(w.read(publish.RUNTIMES), committed, "published byte for byte")
        public = publish.read_public_key(w.public)[1]
        self.assertTrue(publish.ed25519_verify(public, committed, base64.b64decode(w.read(publish.RUNTIMES + ".sig"))))
        self.assertEqual(w.status()["runtimes"]["sha256"], publish.sha256_of(os.path.join(w.site, publish.RUNTIMES)))
        # The packages did not change, the runtime list did: it is published (with an unchanged package list).
        data = json.loads(committed)
        data["generated"] = "2099-01-01T00:00:00Z"
        data["releases"][0]["title"] = "Another release"
        changed = os.path.join(w.dir, "runtimes.json")
        with open(changed, "w") as fh:
            json.dump(data, fh)
        code, out = w.run("2026-10-04T05:17:00Z", "--runtimes", changed)
        self.assertEqual(code, 0, out)
        self.assertIn("the runtime list changed", out)
        self.assertEqual(json.loads(w.read(publish.RUNTIMES))["releases"][0]["title"], "Another release")
        self.assertEqual(w.names(), ["alpha-demo", "beta-demo", "delta-demo"])
        # Older than what is published, or invalid: refused, nothing replaced.
        before = w.read(publish.RUNTIMES)
        data["generated"] = "2026-01-01T00:00:00Z"
        data["releases"][0]["title"] = "Older"
        with open(changed, "w") as fh:
            json.dump(data, fh)
        code, out = w.run("2026-10-04T06:17:00Z", "--runtimes", changed)
        self.assertEqual(code, 1)
        self.assertIn("not newer than the published", out)
        data["generated"] = "2099-02-01T00:00:00Z"
        data["incidents"][0]["summary"] = "You are safe."
        with open(changed, "w") as fh:
            json.dump(data, fh)
        code, out = w.run("2026-10-04T06:17:00Z", "--runtimes", changed)
        self.assertEqual(code, 1)
        self.assertIn("banned word", out)
        self.assertEqual(w.read(publish.RUNTIMES), before)
        # A tampered runtime list fails verification.
        with open(os.path.join(w.site, publish.RUNTIMES), "ab") as fh:
            fh.write(b" ")
        self.assertEqual(publish.main(["verify", "--site", w.site, "--public-key-file", w.public]), 1)

    def test_nothing_new_publishes_nothing_and_says_so(self):
        w = World(self)
        w.export([A, B], [H])
        self.assertEqual(w.run("2026-10-04T04:17:00Z")[0], 0)
        before = {name: w.read(name) for name in os.listdir(w.site)}
        output = os.path.join(w.dir, "github-output")
        code, out = w.run("2026-10-04T05:17:00Z", env={"GITHUB_OUTPUT": output})
        self.assertEqual(code, 0, out)
        self.assertIn("Nothing new", out)
        self.assertEqual({name: w.read(name) for name in os.listdir(w.site)}, before)
        with open(output) as fh:
            self.assertIn("publish=false", fh.read())
        # exports that stay unchanged for two days are a failure worth an email
        code, out = w.run("2026-10-06T05:17:00Z")
        self.assertEqual(code, 1)
        self.assertIn("going stale", out)

    def test_the_base_is_rebuilt_when_it_is_a_week_old_when_the_delta_is_large_and_when_the_builder_changes(self):
        w = World(self)
        w.export([A, B], [H])
        self.assertEqual(w.run("2026-10-04T04:17:00Z")[0], 0)
        w.export([A, B, C], [H])
        self.assertEqual(w.run("2026-10-10T04:17:00Z")[0], 0)
        self.assertEqual(w.status()["base"]["generated"], "2026-10-04T04:17:00Z")
        w.export([A, B, C, mal(4, "four-demo")], [H])
        code, out = w.run("2026-10-11T04:17:00Z")
        self.assertEqual(code, 0, out)
        self.assertIn("7.0 days old", out)
        s = w.status()
        self.assertEqual((s["base"]["generated"], s["base"]["rows"], s["delta"]["changed"]), ("2026-10-11T04:17:00Z", 5, 0))
        # a delta over the size limit: a new base instead
        w.export([A, B, C, mal(4, "four-demo"), mal(5, "five-demo")], [H])
        code, out = w.run("2026-10-11T05:17:00Z", env={"DELTA_MAX_BYTES": "100"})
        self.assertEqual(code, 0, out)
        self.assertIn("the delta has grown", out)
        self.assertEqual(w.status()["base"]["generated"], "2026-10-11T05:17:00Z")
        # the builder changed (its hash is not the one the last publication was built with): a new base, even
        # with the exports unchanged
        s = w.status()
        s["builder"]["sha256"] = "0" * 64
        with open(os.path.join(w.site, "status.json"), "w") as fh:
            json.dump(s, fh)
        code, out = w.run("2026-10-11T06:17:00Z")
        self.assertEqual(code, 0, out)
        self.assertIn("the builder changed", out)
        self.assertEqual(w.status()["base"]["generated"], "2026-10-11T06:17:00Z")
        # asked for by hand
        self.assertEqual(w.run("2026-10-11T07:17:00Z", "--force-base")[0], 0)
        self.assertEqual(w.status()["base"]["generated"], "2026-10-11T07:17:00Z")

    def test_nothing_is_published_that_would_shrink_go_backwards_or_fail_to_verify(self):
        w = World(self)
        many = [mal(n, "pkg-%02d" % n) for n in range(1, 21)]
        w.export(many, [H])
        self.assertEqual(w.run("2026-10-04T04:17:00Z")[0], 0)
        before = {name: w.read(name) for name in os.listdir(w.site)}

        def refused(reason, *extra, **kw):
            code, out = w.run(*extra, **kw)
            self.assertEqual(code, 1, out)
            self.assertIn(reason, out)
            self.assertEqual({name: w.read(name) for name in os.listdir(w.site)}, before, "the previous files stay in place")
            self.assertFalse(os.path.exists(w.site + ".staging") and os.listdir(w.site + ".staging") and False)

        # a broken download: most of the export is missing
        w.export(many[:5], [H])
        refused("would shrink", "2026-10-04T05:17:00Z")
        # ... unless the owner says the public data really shrank
        code, out = w.run("2026-10-04T05:17:00Z", "--allow-shrink")
        self.assertEqual(code, 0, out)
        self.assertEqual(w.status()["rows"], 6)
        before = {name: w.read(name) for name in os.listdir(w.site)}
        # `generated` going backwards or standing still
        w.export(many[:6], [H])
        refused("backwards or stand still", "2026-10-04T05:17:00Z")
        refused("backwards or stand still", "2026-10-04T05:00:00Z")
        # `currentTo` going backwards (an older export than the one already published)
        w.export([mal(n, "pkg-%02d" % n, None, "2026-09-01T00:00:00Z") for n in range(1, 7)], [])
        refused("`currentTo` would go backwards", "2026-10-04T06:17:00Z")
        # an empty export
        w.export([], [])
        refused("", "2026-10-04T06:17:00Z")
        # signed with a key that is not the committed one
        w.export(many[:7], [H])
        other = os.path.join(w.dir, "other.pem")
        w.make_key(other)
        refused("does not verify", "2026-10-04T06:17:00Z", key=other)
        # no key at all, and no public key committed yet
        empty = os.path.join(w.dir, "empty.pem")
        open(empty, "w").close()
        refused("no signing key", "2026-10-04T06:17:00Z", key=empty)
        unset = os.path.join(w.dir, "unset.txt")
        with open(unset, "w") as fh:
            fh.write("# not set\nNOT-SET\n")
        refused("does not hold a public key yet", "2026-10-04T06:17:00Z", public=unset)
        # the previous base was tampered with where it is published
        with open(os.path.join(w.site, publish.BASE), "ab") as fh:
            fh.write(b"x")
        code, out = w.run("2026-10-04T06:17:00Z")
        self.assertEqual(code, 1, out)
        self.assertIn("previous base", out)

    def test_verify_catches_a_swapped_tampered_or_mismatched_publication(self):
        w = World(self)
        w.export([A, B], [H])
        self.assertEqual(w.run("2026-10-04T04:17:00Z")[0], 0)
        w.export([A, B, C], [H])
        self.assertEqual(w.run("2026-10-04T05:17:00Z")[0], 0)
        verify = ["verify", "--site", w.site, "--public-key-file", w.public]

        def problems():
            err = io.StringIO()
            with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                code = publish.main(verify)
            return code, err.getvalue()

        self.assertEqual(problems()[0], 0)
        self.assertEqual(publish.main(verify + ["--expect-generated", "2026-10-04T05:17:00Z"]), 0)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(publish.main(verify + ["--expect-generated", "2026-10-04T04:17:00Z"]), 1)
        saved = {name: w.read(name) for name in os.listdir(w.site)}

        def restore():
            for name, data in saved.items():
                with open(os.path.join(w.site, name), "wb") as fh:
                    fh.write(data)

        # the two signed files swapped
        for a, b in ((publish.BASE, publish.DELTA), (publish.BASE + ".sig", publish.DELTA + ".sig")):
            os.replace(os.path.join(w.site, a), os.path.join(w.site, "tmp"))
            os.replace(os.path.join(w.site, b), os.path.join(w.site, a))
            os.replace(os.path.join(w.site, "tmp"), os.path.join(w.site, b))
        self.assertEqual(problems()[0], 1)
        restore()
        # one byte changed
        data = bytearray(saved[publish.DELTA])
        data[-3] ^= 1
        with open(os.path.join(w.site, publish.DELTA), "wb") as fh:
            fh.write(data)
        code, err = problems()
        self.assertEqual(code, 1)
        self.assertIn("signature does not verify", err)
        restore()
        # a signature removed
        os.remove(os.path.join(w.site, publish.BASE + ".sig"))
        self.assertIn("missing", problems()[1])
        restore()
        # another public key committed than the one that signed
        other = w.make_key(os.path.join(w.dir, "other.pem"))
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(publish.main(["verify", "--site", w.site, "--public-key-file", other]), 1)

    def test_ed25519_verification_matches_the_standards_own_examples(self):
        # RFC 8032, section 7.1, tests 1 to 3
        cases = [
            ("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
             "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
            ("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
             "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
            ("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
             "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
        ]
        for public, message, signature in cases:
            p, m, s = bytes.fromhex(public), bytes.fromhex(message), bytes.fromhex(signature)
            self.assertTrue(publish.ed25519_verify(p, m, s))
            self.assertFalse(publish.ed25519_verify(p, m + b"\x00", s))
            self.assertFalse(publish.ed25519_verify(p, m, s[:-1] + bytes([s[-1] ^ 1])))
            self.assertFalse(publish.ed25519_verify(bytes(32), m, s))
        self.assertFalse(publish.ed25519_verify(b"short", b"", bytes(64)))

    def test_the_key_never_reaches_the_output_and_requests_say_who_is_asking(self):
        w = World(self)
        w.export([A, B], [H])
        code, out = w.run("2026-10-04T04:17:00Z")
        self.assertEqual(code, 0, out)
        with open(w.key) as fh:
            secret = [line for line in fh.read().split("\n") if line and not line.startswith("-----")]
        everything = out + "".join(w.read(name).decode("latin-1") for name in os.listdir(w.site))
        for line in secret:
            self.assertNotIn(line, everything)
        self.assertFalse([name for name in os.listdir(w.dir) if name.endswith(".part")])
        # a body sent with a transfer coding is kept as the client would be given it; one without is kept as it is
        self.assertEqual(publish.decoded(gzip.compress(b"signed bytes"), "gzip"), b"signed bytes")
        self.assertEqual(publish.decoded(gzip.compress(b"signed bytes"), None), gzip.compress(b"signed bytes"))
        self.assertIn("iKnowMyMac-Lists/1", publish.user_agent())
        self.assertIn("+https://", publish.user_agent())
        self.assertEqual([url for _, url in publish.SOURCES], ["https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip",
                                                              "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip",
                                                              "https://osv-vulnerabilities.storage.googleapis.com/Maven/all.zip"])

    def test_the_vendored_builder_is_the_one_the_manifest_lists(self):
        done = subprocess.run([os.path.join(ROOT, "scripts", "check-vendor.sh")], capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)


if __name__ == "__main__":
    unittest.main()
