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

The admin check probes two wordlists with different severity tiers.

**Interesting paths** (`wordlists/embedded/interesting-paths.txt`) contains ~50 hand-curated paths that are inherently security-relevant when present: `.git/HEAD`, `.env`, `Dockerfile`, `.htpasswd`, `wp-config.php`, and similar. Any response other than 404 (including 401, 403, redirects, and 5xx) emits a `medium/firm` finding. This list is always loaded from the vendored copy and cannot be overridden by the cache or `-w` flag.

**Common admin paths** (`admin-common.txt`) is the general discovery wordlist. Responses are emitted as `info/tentative` (200) or `info/firm` (401, 403, 5xx). Apps that return their SPA shell for every unknown path will produce thousands of `info/tentative` findings, one per wordlist entry. These are suppressed from the default summary.

Use `--include-info` to show all findings including the info tier:

```bash
# Default: shows medium-or-higher findings only; info count reported separately
suri scan --scope scope.toml https://target.example.com

# Show all findings including info/tentative from the common wordlist
suri scan --scope scope.toml --include-info https://target.example.com
```

Suri does not attempt automatic soft-200 detection. Apps that return their SPA shell for every unknown path will produce `info/tentative` findings for every admin-wordlist probe. These are suppressed from default output. Use `--include-info` if you want to review them, typically only useful for engagement audit purposes or for spotting paths that genuinely differ from the SPA template.

## Wordlists

See [WORDLISTS.md](WORDLISTS.md) for attribution and licensing of embedded wordlists.

## License

Suri is free software: you can redistribute it and/or modify it under the terms of the
GNU Affero General Public License as published by the Free Software Foundation, version 3.
See [LICENSE](LICENSE) for the full text.
