# Suri

Suri is a web application security scanner for authorized VAPT (Vulnerability Assessment and Penetration Testing) engagements. It targets web applications, admin panels, APIs, and exposed cloud storage. All scans are scope-enforced: every request passes through a scope checker that refuses traffic to hosts not listed in the engagement scope file.

**Status: v0.1.0 in development**

Suri is part of the OSINT-PH brand suite alongside FalconEye and Salakay.

## Build

Requires Go 1.23 or later.

```bash
git clone git@github.com:osintph/suri.git
cd suri
go build -o suri ./cmd/suri
```

Cross-compilation targets:

```bash
GOOS=linux   GOARCH=amd64 go build -o suri-linux-amd64   ./cmd/suri
GOOS=linux   GOARCH=arm64 go build -o suri-linux-arm64   ./cmd/suri
GOOS=darwin  GOARCH=arm64 go build -o suri-darwin-arm64  ./cmd/suri
GOOS=windows GOARCH=amd64 go build -o suri-windows-amd64.exe ./cmd/suri
```

## Usage

```bash
# Scan a target (scope file is required)
suri scan --scope examples/scope.toml https://target.example.com

# View other subcommands
suri --help
```

See `examples/scope.toml` for scope file format and `examples/config.toml` for operator config.

## Testing against S3-compatible storage (Minio, Backblaze, etc)

Cloud checks support any S3-compatible endpoint via `--s3-endpoint`. The endpoint
host must appear in the scope file's `cloud_buckets` list to satisfy the
authorisation gate.

Example using a local Minio server (`examples/scope-minio-local.toml` pre-configures
`localhost` and `127.0.0.1` in `cloud_buckets`):

```bash
./suri scan \
  --scope examples/scope-minio-local.toml \
  --s3-endpoint http://localhost:9000 \
  --domain osintph-suri-test \
  http://localhost:3000
```

The `--s3-endpoint` flag overrides the `s3_endpoint` field in the scope file.
Equivalent flags exist for Azure Blob-compatible storage (`--azure-endpoint`) and
GCS-compatible storage (`--gcs-endpoint`).

## Admin path discovery

The admin check probes two tiers.

**Interesting paths** (`internal/checks/admin/interesting-paths.toml`) is a structured TOML catalogue of ~50 hand-curated entries: `.git/HEAD`, `.env`, `.htpasswd`, `wp-config.php`, `id_rsa`, and similar. Each entry carries content patterns for response body verification. A 200 response is only flagged when the body matches at least one pattern, which eliminates false positives from SPA catch-all routing. A 401, 403, or 5xx response emits a finding without content verification (the path exists but access is restricted). 404 is always skipped.

**Common admin paths** (`admin-common.txt`) is the general discovery wordlist. Responses are emitted as `info/tentative` (200) or `info/firm` (401, 403, 5xx). These are suppressed from the default summary.

Use `--include-info` to show all findings including the info tier:

```bash
# Default: shows medium-or-higher findings only; info count reported separately
suri scan --scope scope.toml https://target.example.com

# Show all findings including info/tentative from the common wordlist
suri scan --scope scope.toml --include-info https://target.example.com
```

## Scanning behaviour

Suri is designed to be polite by default and to avoid disrupting production systems during authorized assessments.

### Scan-wide timeout

Every scan has a hard wall-clock limit controlled by `--scan-timeout` (default: 15 minutes). When the timeout fires:

- In-flight HTTP requests complete or expire per the per-request timeout (10 seconds).
- No new check probes start.
- All findings discovered before the timeout are written to the database.
- The scan exits with status 124 and prints `scan stopped after timeout, partial results in <db>`.

Adjust the timeout for large targets:

```bash
suri scan --scope scope.toml --scan-timeout 60m https://target.example.com
```

### Backup file check throttling

The backup file check (`web.backup.file`) derives probe URLs from the crawler inventory. On large SPAs the inventory can hold thousands of URLs; probing each with four backup extensions would generate tens of thousands of requests.

Three mitigations are applied automatically:

1. **Status filter.** Only URLs that the crawler fetched with HTTP status 200, 401, or 403 are probed. 404s and 5xx responses indicate the path does not exist as a real route, so probing backup variants would be wasteful.

2. **SPA shell deduplication.** The crawler records the SHA-256 of the first 32 KB of each response body. If many URLs on the same host share the same body hash (the Angular/React/Vue shell HTML), that hash is identified as the SPA catch-all and those URLs are excluded from backup probing.

3. **Total probe cap.** The backup check makes at most 200 HTTP probes per scan by default. When the cap is reached a warning is logged. Override with `--max-backup-probes`:

```bash
suri scan --scope scope.toml --max-backup-probes 50 https://target.example.com
```

### Timing-based check serialisation

The SQL injection and command injection checks use sleep-based timing payloads to detect blind vulnerabilities. To avoid stacking multiple concurrent sleep requests against the same host (which can exhaust server thread pools), timing probes are serialised per host: only one sleep payload is in-flight on any single host at a time. Probes against different hosts run in parallel as normal.

## Wordlists

See [WORDLISTS.md](WORDLISTS.md) for attribution and licensing of embedded wordlists.

## License

Suri is free software: you can redistribute it and/or modify it under the terms of the
GNU Affero General Public License as published by the Free Software Foundation, version 3.
See [LICENSE](LICENSE) for the full text.
