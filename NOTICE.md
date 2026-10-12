iKnowMyMac package list: sources, licences and notices
=======================================================

The files published by this repository (`packages-v1.jsonl.gz`, `packages-v1.delta.jsonl.gz` and their
signatures) are a list of npm and PyPI package versions that public sources report as malicious, or as carrying a
critical or high vulnerability that has a fixed version. The list is built by machine, with no hand editing, from
the public records below, as exported by OSV.dev (https://osv.dev, https://google.github.io/osv.dev/data/).

Sources
-------

1. OpenSSF Malicious Packages
   https://github.com/ossf/malicious-packages
   Copyright the OpenSSF Malicious Packages authors. Licensed under the Apache License, Version 2.0
   (https://www.apache.org/licenses/LICENSE-2.0). A copy of the licence is in LICENSE-APACHE-2.0.txt.

2. GitHub Advisory Database
   https://github.com/github/advisory-database
   Copyright GitHub, Inc. and contributors. Licensed under Creative Commons Attribution 4.0 International
   (CC BY 4.0, https://creativecommons.org/licenses/by/4.0/).

3. PyPI Advisory Database (Python Packaging Advisory Database)
   https://github.com/pypa/advisory-database
   Copyright the Python Packaging Authority and contributors. Licensed under Creative Commons Attribution 4.0
   International (CC BY 4.0, https://creativecommons.org/licenses/by/4.0/).

What was changed
----------------

The records were not reproduced whole. For each advisory and each package it affects, the list keeps one row: the
ecosystem, the package name, the record's ID and aliases, the affected versions and version ranges, the severity,
the fixed version, the published and modified times, and the first 120 characters of the summary. Records that are
aliases of each other and affect the same package are joined into one row. Withdrawn records, records for other
ecosystems, and vulnerabilities that are not critical or high or have no fixed version are left out. The exact
rules are in the app's list contract (docs/api/package-list-v1.md) and in vendor/build.py.

No warranty
-----------

The sources and this list are provided "as is", without warranty of any kind. The list can be hours behind a new
incident and can be wrong or incomplete; the sources' authors do not endorse this list or iKnowMyMac.

The list itself
---------------

This compiled list is offered under Creative Commons Attribution 4.0 International (CC BY 4.0). If you reuse it,
credit the three sources above as their licences require, and say that you changed it if you did.
