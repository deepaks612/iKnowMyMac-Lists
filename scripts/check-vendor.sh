#!/bin/sh
# Refuses to go on when a file under vendor/ is not the one vendor/MANIFEST.sha256 lists.
# vendor/ is a copy of the list builder and the contract's vectors from the app repository (iKnowMyMac-MacOS,
# scripts/package-list/build.py). Never edit it here: change it there and run its
# scripts/package-list/sync-lists-repo.sh, which rewrites this folder and the manifest together.
set -eu
cd "$(dirname "$0")/../vendor"
if command -v sha256sum > /dev/null 2>&1; then sum="sha256sum"; else sum="shasum -a 256"; fi
listed=$(cut -c67- MANIFEST.sha256 | LC_ALL=C sort)
present=$(find . -type f ! -name MANIFEST.sha256 ! -name .DS_Store | sed 's|^\./||' | LC_ALL=C sort)
if [ "$listed" != "$present" ]; then
  echo "vendor/ holds other files than MANIFEST.sha256 lists" >&2
  exit 1
fi
while read -r want file; do
  have=$($sum "$file" | cut -d' ' -f1)
  if [ "$have" != "$want" ]; then
    echo "vendor/$file is not the file the manifest lists (edited here? run the app repository's sync-lists-repo.sh)" >&2
    exit 1
  fi
done < MANIFEST.sha256
echo "vendor/ matches its manifest ($(grep -c . MANIFEST.sha256) files)"
