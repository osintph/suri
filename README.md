# Suri

Web application security scanner for authorized VAPT engagements.

[![CI](https://github.com/osintph/suri/actions/workflows/ci.yml/badge.svg)](https://github.com/osintph/suri/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

---

## What Suri is

Suri is a single static binary that crawls a web application, runs a suite of checks against the discovered surface, and writes findings to a SQLite database. It targets web applications, admin panels, REST APIs, and cloud storage. Every outbound request is validated against an engagement scope file before it is sent: if the host is not in scope, the request is blocked and logged. Findings are written in HTML and JSON formats suitable for client deliverables. A diff engine compares consecutive scans to show what changed between assessments.

## What Suri is NOT

Suri does not exploit vulnerabilities. Detection only: it reports that a parameter appears injectable but does not extract data or escalate access. It does not support authenticated sessions in v1 (no cookie injection, no CSRF token handling). It does not execute JavaScript and does not use a headless browser. All checks are safe to run against production systems during an authorized engagement window.

---

## Installation

### Download a release binary

Download the archive for your platform from the [releases page](https://github.com/osintph/suri/releases), extract it, and move the `suri` binary onto your `PATH`.

```bash
# Example for Linux amd64
tar -xzf suri_0.1.0_linux_amd64.tar.gz
sudo mv suri /usr/local/bin/
suri --version
```

### Install with go install

```bash
go install github.com/osintph/suri/cmd/suri@latest
```

### Build from source

```bash
git clone git@github.com:osintph/suri.git
cd suri
go build -o suri ./cmd/suri
./suri --version
```

Requires Go 1.25 or later. No CGO dependencies.

---

## Quickstart

**Step 1: write a scope file.**

```toml
# engagement.toml
engagement_name = "target-corp-2026-q3"
notes           = "Authorized VAPT. Contact: security@target.example.com"

hostnames = [
  "target.example.com",
  "*.target.example.com",
]
```

**Step 2: run a scan.**

```bash
./suri scan --scope engagement.toml https://target.example.com
```

Output at the end of the scan:

```
Scan complete
  URLs discovered:      47
  Forms found:          3
  Unique parameters:    12
  JS artifacts:         8
  Findings:             2 (info: 14 suppressed)
  DB: /tmp/suri-out/a3f2c1d0-....db
```

**Step 3: generate a report.**

Copy the scan ID from the `DB:` line (the UUID portion of the filename).

```bash
./suri report --scan a3f2c1d0-... --format html --out report.html
```

Open `report.html` in a browser. For a machine-readable output:

```bash
./suri report --scan a3f2c1d0-... --format json --out report.json
```

---

## Scope file format

Each engagement gets its own scope file. The scope file is not a config file: it defines the legal boundary for the scan. Keep it outside version control alongside your findings.

```toml
# Required. Short identifier used in log output and report headings.
engagement_name = "acme-vapt-2026-q1"

# Optional free-form notes.
notes = "Authorized VAPT for Acme Corp Q1 2026."

# Hostnames in scope. Supports leftmost-label wildcard only:
# *.example.com matches api.example.com but not example.com itself
# and not sub.api.example.com.
hostnames = [
  "example.com",
  "*.example.com",
]

# Individual IPs in scope.
ips = ["203.0.113.10"]

# CIDR ranges in scope. Every IP within the range is allowed.
cidrs = ["10.10.0.0/24"]

# Port restriction. Empty list means all ports are in scope.
# Port is derived from the URL scheme (80 for http, 443 for https)
# unless an explicit port is present in the URL.
ports = [80, 443, 8080, 8443]

# Cloud storage check authorization. Cloud checks refuse to run
# unless the target bucket host matches an entry here.
# Supports the same wildcard syntax as hostnames, plus * spanning
# multiple labels (e.g. *.s3.*.amazonaws.com).
cloud_buckets = [
  "*.s3.amazonaws.com",
  "*.blob.core.windows.net",
  "*.storage.googleapis.com",
]

# Optional: custom endpoint for S3-compatible storage (Minio, Backblaze, etc).
# The CLI --s3-endpoint flag takes precedence over this value.
s3_endpoint    = ""
azure_endpoint = ""
gcs_endpoint   = ""
```

---

## What Suri checks

**Cloud storage**
- S3 bucket exposure: anonymous list and read via virtual-hosted and path-style addressing
- Azure Blob container anonymous access
- Google Cloud Storage bucket anonymous access
- Bucket name permutation from the target domain

**Admin panel and sensitive path discovery**
- Interesting paths (`.git/HEAD`, `.env`, `.htpasswd`, `wp-config.php`, etc.): content-verified against known patterns; soft-200 SPA responses are not flagged
- Common admin paths: wordlist-based, results reported as info/tentative unless access is denied (401, 403)

**API discovery**
- Swagger and OpenAPI spec discovery; parses found specs and inventories endpoints
- GraphQL introspection: flags open introspection as a finding

**Web injection**
- Reflected XSS: canary-based payload with context detection (HTML, attribute, JS, URL contexts)
- SQL injection: error-based (DB error string detection) and time-based (sleep payload with baseline comparison)
- Server-side template injection: canary expression evaluation for Jinja2, Twig, Freemarker, ERB
- Command injection: time-based sleep payloads only
- Open redirect: canary URL injection

**Security headers**
- CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy

**Backup and source exposure**
- `.git/HEAD`, `.env`, swap files, `.DS_Store`, source maps, common backup extensions
- Content-verified; SPA catch-all responses are filtered by body hash deduplication

---

## Output formats

By default the scan summary shows findings at medium severity or above. Info-severity findings are written to the database but suppressed from the summary line.

```bash
# Show info findings in the summary
suri scan --scope engagement.toml --include-info https://target.example.com
```

Generate reports from any past scan using its ID:

```bash
suri report --scan <id> --format html --out report.html
suri report --scan <id> --format json --out report.json
```

The `--db` flag overrides the default database lookup (most recent `.db` in the current directory):

```bash
suri report --scan <id> --db /path/to/scans.db --format html --out report.html
```

HTML reports are self-contained single files with inline CSS. No external resources. A Content-Security-Policy meta tag prevents execution of any script content found in evidence.

JSON reports include base64-encoded request and response evidence and are suitable for ingestion by other tooling.

---

## Diff engine

Run a second scan after remediations and compare:

```bash
# First scan
suri scan --scope engagement.toml https://target.example.com
# Note scan ID printed at end: abc123...

# Re-scan after remediation
suri scan --scope engagement.toml https://target.example.com
# Note new scan ID: def456...

# Diff report
suri diff --baseline abc123... --current def456... --format html --out diff.html
```

The diff report groups findings into:
- **New**: appeared in the current scan but not in the baseline
- **Persistent**: present in both scans (not yet remediated)
- **Resolved**: present in the baseline but absent from the current scan

---

## Polite scanning principles

Suri is designed for authorized assessments against production systems.

**Rate limiting.** The default is 10 requests per second per host. Override with `--rate`.

**Scan timeout.** The default is 15 minutes. The scan stops cleanly at the limit and writes all findings collected up to that point. Override with `--scan-timeout`. Exit status 124 indicates a timeout.

**Serialised timing probes.** SQL injection and command injection timing checks use sleep-based payloads. Only one sleep payload is in-flight against any single host at a time, so the checks cannot exhaust backend thread pools. Probes against different hosts run in parallel.

**Content verification.** Admin path discovery and backup file checks verify response body content before emitting findings, filtering out SPA catch-all 200 responses.

---

## Legal disclaimer

**Suri is for authorized use only.**

Running Suri against systems you do not own or do not have explicit written permission to test is illegal in most jurisdictions and is a violation of the AGPL license under which Suri is distributed. Every scan requires a scope file that declares the engagement. The scope file is a record that you have identified the legal boundary of your assessment. If you are unsure whether you have authorization, do not run Suri.

---

## Contributing

Bug reports and feature requests: [github.com/osintph/suri/issues](https://github.com/osintph/suri/issues).

Suri is licensed under the AGPL-3.0. Contributions must be made under the same license. By submitting a pull request you agree that your contribution is licensed to the project under AGPL-3.0.

See [WORDLISTS.md](WORDLISTS.md) for wordlist attribution and licensing.

---

## License

Suri is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License as published by the Free Software Foundation, version 3. See [LICENSE](LICENSE) for the full text.
