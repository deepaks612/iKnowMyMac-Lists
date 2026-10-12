#!/bin/sh
# Creates the list's signing key, once.
#
#   scripts/make-key.sh [owner/repository]            make a new key
#   scripts/make-key.sh --reuse [owner/repository]    put the offline copy back into the repository secret
#
# What it does, in order:
#   1. makes an Ed25519 key pair on this Mac, with OpenSSL 3;
#   2. keeps the private half at ~/.iknowmymac/package-list-signing-key.pem (mode 600): the offline copy. Back it
#      up somewhere that is not this Mac. Whoever holds it can sign a list every installed app will accept;
#   3. sends the private half straight from that file into the repository secret PACKAGE_LIST_SIGNING_KEY
#      (`gh secret set` reads it from standard input, so it is never on screen, in an argument or in shell history);
#   4. prints the PUBLIC half, and nothing else, on standard output: one line, base64 of the 32 raw bytes.
#
# Paste that one line into two places (README.md, "Switching it on"):
#   - this repository:  keys/package-list-public-key.txt   (in place of the line NOT-SET)
#   - the app:          Sources/Core/PackageWatch/PackageList.swift, `PackageListKeys.production`
#
# It refuses to replace an existing key: every app build already released holds the old public half and would stop
# accepting the list.
set -eu
umask 077
reuse=0
if [ "${1:-}" = "--reuse" ]; then reuse=1; shift; fi

say() { printf '%s\n' "$*" >&2; }

openssl_bin=""
for candidate in "${OPENSSL:-openssl}" /opt/homebrew/opt/openssl@3/bin/openssl /usr/local/opt/openssl@3/bin/openssl; do
  if command -v "$candidate" > /dev/null 2>&1 && "$candidate" version 2> /dev/null | grep -Eq '^OpenSSL [34]\.'; then
    openssl_bin=$candidate
    break
  fi
done
[ -n "$openssl_bin" ] || { say "OpenSSL 3 is needed (the one macOS ships is LibreSSL). Install it: brew install openssl@3"; exit 1; }
command -v gh > /dev/null 2>&1 || { say "The GitHub command-line tool is needed: brew install gh, then gh auth login"; exit 1; }

repo=${1:-$(gh repo view --json nameWithOwner --jq .nameWithOwner)}
[ -n "$repo" ] || { say "Which repository? Run this inside the iKnowMyMac-Lists checkout, or pass owner/repository."; exit 1; }

dir="$HOME/.iknowmymac"
key="$dir/package-list-signing-key.pem"
mkdir -p "$dir"
chmod 700 "$dir"

if [ $reuse -eq 1 ]; then
  [ -f "$key" ] || { say "There is no offline copy at $key to reuse."; exit 1; }
elif [ -e "$key" ]; then
  say "A key already exists at $key."
  say "To put that same key back into the repository secret: scripts/make-key.sh --reuse"
  say "To really replace it (every released app would stop accepting the list until it is updated), move that file away first."
  exit 1
else
  "$openssl_bin" genpkey -algorithm ED25519 -out "$key" 2> /dev/null
fi
chmod 600 "$key"

# The private half goes from the file into the secret without passing through this script's output or arguments.
gh secret set PACKAGE_LIST_SIGNING_KEY --repo "$repo" < "$key" > /dev/null
say "The private key is in the secret PACKAGE_LIST_SIGNING_KEY of $repo, and offline at $key (mode 600)."
say "Back that file up off this Mac. The line below is the PUBLIC key: paste it into the two places README.md names."

# The public half: the last 32 bytes of the DER form are the raw key.
"$openssl_bin" pkey -in "$key" -pubout -outform DER | tail -c 32 | base64
