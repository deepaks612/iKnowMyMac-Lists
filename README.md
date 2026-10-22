# iKnowMyMac package list

This repository builds and publishes the list that [iKnowMyMac](https://iknowmymac.com)'s Package Watch matches on
the Mac: every npm and PyPI package version that public sources report as malicious, or as carrying a critical or
high vulnerability that has a fixed version. The app downloads the list whole and matches it locally; it never
sends anything about what is installed.

Everything here runs on free services: a scheduled GitHub Actions workflow builds the list, and GitHub Pages
serves it. There are no API keys and no paid data.

| | |
|---|---|
| Published files | `packages-v1.jsonl.gz` (the **base**: the whole list, about 5.4 MB, rebuilt about weekly) · `packages-v1.delta.jsonl.gz` (the **delta**: what changed since that base, rebuilt whenever a source changed; a week of changes is about 38 KB) · a `.sig` beside each · `status.json` · `NOTICE.txt` |
| Format | The app repository's contract, `docs/api/package-list-v1.md` ("Base and delta") |
| Sources | The public OSV exports for npm and PyPI, which carry the OpenSSF Malicious Packages records and the GitHub and PyPI advisory databases. Credits and licences: [NOTICE.md](NOTICE.md) |
| Signing | Ed25519. The private key exists only as the repository secret `PACKAGE_LIST_SIGNING_KEY` and in the owner's offline copy. The public key is in `keys/package-list-public-key.txt` and in the app |

## The runtime list (`runtimes/runtimes-v1.json`)
A second, small file published beside the package list (iKnowMyMac 1.5.1): which Node.js, PHP and Go release lines
still get security fixes, which version fixes each security release, which root certificates an incident makes
untrustworthy, and the incident cards the app shows. Its format is the app repository's
`docs/api/runtime-list-v1.md`. **It is written by hand**, every value from the primary source named in its row.

To change it: edit `runtimes/runtimes-v1.json`, raise `generated`, run
`python3 -I vendor/runtime-validate.py runtimes/runtimes-v1.json`, commit and push. The next hourly run (or "Run
workflow") checks, signs and publishes it as `runtimes-v1.json` + `.sig`, even when the package list has not changed.
A file that is invalid, uses a banned word, or is not newer than the published one is refused and nothing changes.

## What is in here
- `scripts/publish.py`: the one script. Downloads the two exports with conditional requests, builds a base or a
  delta, signs, verifies, and lays out the folder to publish. The workflow calls it; it runs the same way on a Mac.
- `scripts/make-key.sh`: makes the signing key, once.
- `scripts/check-vendor.sh`: refuses to go on when `vendor/` is not what its manifest lists.
- `vendor/`: a copy of the list builder (`build.py`) and the contract's test vectors. **The app repository owns
  them** (`iKnowMyMac-MacOS`, `scripts/package-list/build.py`). Never edit them here: change them there and run
  its `scripts/package-list/sync-lists-repo.sh <this folder>`, then commit in both places. A changed builder makes
  the next run rebuild the whole list.
- `tests/`: tests of `publish.py` on made-up records with a key pair made in the test. No network.
- `.github/workflows/publish.yml`: hourly. Build, sign and check → publish → check the live site → once per new
  base, one line in `ledger/bases.jsonl`.

## Switching it on
In this order. Nothing is published until step 5.

**1. Create the public repository from this folder.**
```sh
cd iKnowMyMac-Lists
gh repo create iKnowMyMac-Lists --public --source . --remote origin --push
```
The site's address will be `https://<your GitHub name>.github.io/iKnowMyMac-Lists/`.

**2. Turn on Pages with "GitHub Actions" as the source.**
```sh
gh api -X POST "repos/{owner}/{repo}/pages" -f build_type=workflow
```
Or in the browser: Settings → Pages → Build and deployment → Source: **GitHub Actions**.

**3. Make the signing key.**
```sh
scripts/make-key.sh
```
It makes the key on this Mac, sends the private half straight into the repository secret
`PACKAGE_LIST_SIGNING_KEY`, keeps an offline copy at `~/.iknowmymac/package-list-signing-key.pem` (mode 600), and
prints one line: the **public** key. Back the offline copy up somewhere that is not this Mac.

**4. Paste that one line into two places.**
- **This repository:** `keys/package-list-public-key.txt`. Replace the line `NOT-SET` with it, then
  ```sh
  git add keys/package-list-public-key.txt && git commit -m "chore: the list's public key" && git push
  ```
- **The app:** `Sources/Core/PackageWatch/PackageList.swift`, in `PackageListKeys`:
  ```swift
  public static let production: String? = "the line make-key.sh printed"
  ```
  That one line is the whole app-side change. Ship it in the next build, after step 7.

**5. Run the workflow once by hand.**
```sh
gh workflow run publish.yml
gh run watch
```
The first run builds a base, signs it, publishes it, and then checks the live site. From then on it runs by
itself at 17 minutes past every hour.

**6. Check the published files.**
```sh
python3 -I scripts/publish.py verify --site "https://<your GitHub name>.github.io/iKnowMyMac-Lists"
curl -sI "https://<your GitHub name>.github.io/iKnowMyMac-Lists/packages-v1.delta.jsonl.gz" | grep -i -E "^(HTTP|etag|content-type|content-encoding|cache-control)"
```
`verify` must print `verified: … rows`. It asks the way the app does, so it checks the bytes a Mac would be
given (the signature is over the gzip file itself). The second command should show an `etag` and no
`content-encoding`. The workflow's own last job runs the same `verify` after every publication.

**7. Point the website at it.** The app asks `https://iknowmymac.com/lists/<file>`; the website answers with a
redirect to this site. In the website's `next.config.ts`, in `redirects()`:
```ts
{ source: "/lists/:file", destination: "https://<your GitHub name>.github.io/iKnowMyMac-Lists/:file", permanent: false },
```
Then check, after the website is deployed:
```sh
curl -sIL "https://iknowmymac.com/lists/packages-v1.delta.jsonl.gz.sig" | grep -i -E "^(HTTP|location)"
```
It must show a 307 to this site and then a 200. The website's privacy list (`src/lib/networkRequests.ts`) needs
the Package Watch row at the same time; the wording is in the app repository's
`docs/review/v1.4/package-list-publishing.md`.

**8. Release the app with the key in it** (step 4). Until then, installed apps keep using the list bundled with
them and never ask for these files.

## Day to day
Nothing to do. Each hour the job asks the two exports whether they changed (an unchanged export costs one "not
modified" reply). If neither did, it publishes nothing. Otherwise it builds today's list and publishes either a
new delta against the base already published, or a new base when:
- the base is 7 days old (`BASE_MAX_AGE_DAYS`),
- the delta would pass 256 KB (`DELTA_MAX_BYTES`): from there a day of deltas costs a Mac more than one base,
- the builder changed, or the public key changed,
- you asked: `gh workflow run publish.yml -f rebase=true`.

**It refuses to publish, and the previous files stay in place, when:**
| Message | What it means | What to do |
|---|---|---|
| `the list would shrink from … rows to …` | Today's list has under 90 % of the rows (or an export under 90 % of the records) of the last one. Almost always a broken download | Nothing; the next hour tries again. If the public data really shrank: `gh workflow run publish.yml -f allow_shrink=true` |
| `` `generated` would go backwards `` / `` `currentTo` would go backwards `` | A clock or an older export | Nothing; look if it repeats |
| `signing failed` / `no signing key` | The secret is missing or is not an Ed25519 key | `scripts/make-key.sh --reuse` puts the offline copy back |
| `does not verify` / `names another public key` | The committed public key is not the one that pairs with the secret | Fix `keys/package-list-public-key.txt` (step 4) |
| `the previous base … does not verify` / `is not the file status.json names` | What is live is not what this job published | Look at the site and the last runs; then `-f rebase=true` |
| `neither public export has changed for … hours` | The sources have been still for two days, which is not normal | Look at osv.dev; nothing is wrong with the list itself |
| `vendor/… is not the file the manifest lists` | Someone edited `vendor/` here | Run the app repository's `sync-lists-repo.sh` |

A failed run emails you (GitHub's default for the person who last changed the schedule: Settings →
Notifications → Actions, "Send notifications for failed workflows only"). The app shows how current its list is
on screen, so a stalled job is also visible there.

**Two things GitHub does that you should know about:**
- In a public repository, scheduled workflows are switched off after 60 days with no repository activity. The
  workflow's `record` job commits one line per new base (about weekly), which is activity. If GitHub ever emails
  that the workflow will be disabled, open the Actions tab and press the button to keep it.
- Scheduled runs can start late or be skipped when GitHub is busy. A skipped hour costs nothing: the next run
  publishes everything since the base.

**The key.** Never commit it, paste it or print it. To put the same key back into the secret (a new repository, a
deleted secret): `scripts/make-key.sh --reuse`. Replacing it with a new key means every released app stops
accepting the list until it is updated with the new public key; `make-key.sh` refuses unless you move the old
file away first.

## Trying it on a Mac, without GitHub
With a throwaway key (never the real one). The same script, the same checks; the folder `_site` is what Pages
would serve.
```sh
mkdir -p work && openssl genpkey -algorithm ED25519 -out work/throwaway.pem
openssl pkey -in work/throwaway.pem -pubout -outform DER | tail -c 32 | base64 > work/public.txt
python3 -I scripts/publish.py run --site _site --work work --key-file work/throwaway.pem --public-key-file work/public.txt
python3 -I scripts/publish.py run --site _site --work work --key-file work/throwaway.pem --public-key-file work/public.txt --previous _site
python3 -I scripts/publish.py verify --site _site --public-key-file work/public.txt
rm -rf work _site
```
The first run downloads both exports (254 MB) and writes a base; the second finds nothing new, or writes a delta.
`--as-of 2026-10-04T18:17:00Z` on the first run builds the base as it stood then, so the second run has a week of
changes to carry. To see the app accept the files, in the app repository:
```sh
TEST_RUNNER_IKMM_LISTS_DIR="$PWD/_site" TEST_RUNNER_IKMM_LISTS_KEY="$(cat work/public.txt)" \
  xcodebuild -project iKnowMyMac.xcodeproj -scheme iKnowMyMacCoreTests -derivedDataPath build test \
  -only-testing:iKnowMyMacCoreTests/PackageListClientTests
```
The tests: `python3 -I -m unittest discover -s tests` (OpenSSL 3 on the PATH; on a Mac `brew install openssl@3`).

## Limits this stays inside
Measured sizes, GitHub's published limits and the head-room at 100, 1,000 and 10,000 users are in the app
repository's `docs/review/v1.4/package-list-publishing.md`. In short: GitHub Actions is free for public
repositories on standard runners; Pages has a soft limit of 100 GB of bandwidth a month, which this design
reaches at roughly 2,700 Macs checking every hour. Before that, move the files behind `lists.iknowmymac.com`
(the app already accepts that name) on a host with no bandwidth limit; nothing in the app changes.

## Licence
The list: CC BY 4.0, with the sources' own licences and notices in [NOTICE.md](NOTICE.md) and
[LICENSE-APACHE-2.0.txt](LICENSE-APACHE-2.0.txt). The scripts: MIT. See [LICENSE](LICENSE).
