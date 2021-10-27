Trivy my Debian
===============

Trivy loves CVE, Debian loves patching CVE.

Usage
-----

Fetch a fresh Debian CVE dump.

```bash
curl -o debian_cve.json https://security-tracker.debian.org/tracker/data/json
```

Use Trivy for an analyse, without garbage in STDOUT, in json format.

```bash
trivy --quiet image --no-progress  --format json debian:11
```

One fat command, inside a virtualenv

```bash
trivy --quiet image --no-progress  --format json debian:11 | DB=/tmp/debian_cve.json python debian.py
```

