Trivy my Debian
===============

Trivy loves CVE, Debian loves patching CVE.

Usage
-----

Fetch a fresh Debian CVE dump.

```bash
curl -o debian_cve.json https://security-tracker.debian.org/tracker/data/json
```

Get a fresh Trivy database

```bash
trivy image --download-db-only
```

Use Trivy for an analyse, without garbage in STDOUT, in json format.

```bash
trivy --quiet image --no-progress  --format json debian:11
```

Launch the webserver

```bash
make web
```

Analyze your trivy report, through `curl` (and `jq`)

```bash
trivy --quiet image --no-progress  --format json bearstech/node:16  | curl --silent -H "Content-Type: application/json" -X POST --data-binary @- http://localhost:8000/trivy/debian | jq .
```

