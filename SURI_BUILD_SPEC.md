# Suri Build Specification

This is the canonical build plan for Suri. Sessions execute in order. Each session has a goal, files to create, dependencies, and acceptance criteria. Read `CLAUDE.md` for standing rules that apply across all sessions.

## Project summary

Suri is a web application security scanner for authorized VAPT engagements. Target classes: web applications, admin panels, APIs, exposed cloud storage. Single static Go binary. CLI in v1, UI deferred to a later version. Cross-platform: Linux amd64 and arm64, macOS arm64, Windows amd64.

Module path: `github.com/osintph/suri`
License: AGPL-3.0
Binary name: `suri`

## Conventions reference

### AGPL header

Every Go file starts with this block:

```go
// Suri, a web application security scanner for authorized VAPT engagements.
// Copyright (C) 2026 OSINT-PH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
```

### Directory layout (final state)

```
suri/
  cmd/suri/                 main.go and subcommand wiring
  internal/config/          TOML config and engagement profile loader
  internal/scope/           scope parser and request enforcement
  internal/http/            HTTP client wrapper with scope hook
  internal/crawler/         crawler, JS miner, URL queue
  internal/checks/          check interface and registry
  internal/checks/web/      reflected XSS, SQLi, SSTI, command injection, open redirect
  internal/checks/admin/    admin panel discovery
  internal/checks/api/      Swagger, OpenAPI, GraphQL
  internal/checks/cloud/    S3, Azure Blob, GCS probing
  internal/store/           SQLite findings store
  internal/report/          HTML and JSON report generators
  internal/wordlists/       embedded and on-disk wordlist loader
  wordlists/embedded/       vendored wordlist files (go:embed source)
  testdata/                 test fixtures
  examples/                 example scope files, example config
  .github/workflows/        CI
  CLAUDE.md
  SURI_BUILD_SPEC.md
  README.md
  WORDLISTS.md
  LICENSE
  .gitignore
  go.mod
  go.sum
```

### Logging convention

```go
slog.Info("scope check passed", "host", host, "path", path)
slog.Warn("out of scope request blocked", "host", host, "scope_file", scopeFile)
slog.Error("crawler failed", "url", u, "err", err)
```

JSON handler to a log file, text handler to stderr. Configured once in `cmd/suri/main.go`.

### Configuration model

TOML config file. Default path resolved via `os.UserConfigDir()` plus `suri/config.toml`. Overridable via `--config` flag.

Scope file is separate from config. Scope is per-engagement, config is per-operator. Scope path is required on every scan via `--scope` flag.

---

# Session 1: Repo scaffold, scope module, HTTP wrapper

## Goal

Produce a buildable Go project that loads a scope file from TOML, exposes a `suri scan` command that sends test requests through an HTTP wrapper, and refuses any request to a host or CIDR not in scope. End-to-end proof that scope enforcement works at the wire level.

## Pre-flight

The repo `github.com/osintph/suri` does not exist yet. Create it as the first step.

```bash
gh repo create osintph/suri --public \
  --description "Web application security scanner for authorized VAPT engagements" \
  --license AGPL-3.0
cd ~/code
git clone git@github.com:osintph/suri.git
cd suri
```

Move `CLAUDE.md` and `SURI_BUILD_SPEC.md` into the cloned repo if they are not already there.

## Files to create

### Top level

- `go.mod` with module `github.com/osintph/suri` and Go 1.23 directive
- `.gitignore` covering Go build artifacts, IDE files, `.env`, `*.key`, `*.pem`, `secrets/`, `dist/`, local SQLite files (`*.db`, `*.db-journal`), and any `suri` binary at the repo root
- `README.md` with project name, one-paragraph description, status banner (v0.1.0 in development), build instructions, AGPL notice, link to WORDLISTS.md
- `WORDLISTS.md` with SecLists attribution (link to https://github.com/danielmiessler/SecLists, MIT license note). Session 1 has no embedded lists yet, but the attribution file goes in now so it is never forgotten.

### cmd/suri

- `cmd/suri/main.go`: entry point. Wires cobra root command and four subcommands: `scan`, `report`, `diff`, `wordlists`. Only `scan` is implemented in this session; the other three print "not yet implemented" and exit 0. Configures `slog` with text handler to stderr.

### internal/config

- `internal/config/config.go`: defines `Config` struct with fields for output directory, log file path, default thread count, default rate limit. Function `Load(path string) (*Config, error)` parses TOML. Function `DefaultPath() string` returns `os.UserConfigDir()` joined with `suri/config.toml`. Function `Default() *Config` returns sensible defaults so the tool runs without a config file.
- `internal/config/config_test.go`: tests for default values, TOML parsing happy path, TOML parsing error path (malformed file), missing file path returns defaults.

### internal/scope

This is the legal-critical module. Get the tests right.

- `internal/scope/scope.go`: defines `Scope` struct with fields `Hostnames []string`, `IPs []string`, `CIDRs []*net.IPNet`, `Ports []int` (empty means all ports), `EngagementName string`, `Notes string`. Function `Load(path string) (*Scope, error)` parses a TOML scope file. Function `(*Scope).Allows(host string, port int) (bool, string)` returns whether a host plus port is in scope and a reason string for logging. Wildcards in hostnames supported via `*.example.com` style match (left-most label only). IP literals matched directly. CIDRs matched via `net.IPNet.Contains`. If `Ports` is empty, all ports allowed; otherwise port must match. Hostname resolution to IP is not done in this module; that happens in the HTTP wrapper at request time.
- `internal/scope/scope_test.go`: table-driven tests covering exact hostname match, wildcard match (`*.example.com` allows `api.example.com` but not `example.com`), IP literal match, CIDR boundary (`/24` contains first and last usable, excludes the next network), port restriction, port wildcard (empty list allows all), case-insensitive hostname match, trailing dot tolerance on hostnames, IPv6 CIDR match, malformed scope file rejected with clear error.

### internal/http

- `internal/http/client.go`: defines `Client` struct wrapping `*retryablehttp.Client`. Constructor `New(scope *scope.Scope, opts ...Option) *Client`. Method `Do(ctx context.Context, req *http.Request) (*http.Response, error)` checks scope before sending. If scope check fails, returns an error of type `*ErrOutOfScope` with the host, port, and reason fields populated, and never makes the network call. Logs every blocked request with `slog.Warn`. Resolves hostname to IP only after scope check, then re-validates IP against scope CIDRs to prevent DNS rebinding past the hostname check. Defaults: 10 second timeout, 3 retries with exponential backoff, follows up to 10 redirects but re-checks scope on every redirect target.
- `internal/http/client_test.go`: tests using `httptest.NewServer` for in-scope success, and a fake handler plus scope mismatch for out-of-scope rejection without network call. Verifies the `ErrOutOfScope` error type.

### internal/crawler (stub)

- `internal/crawler/crawler.go`: empty package with a `// Package crawler will implement the crawler and JS miner in Session 2.` doc comment and a placeholder type so the package compiles.

### internal/checks (stub)

- `internal/checks/checks.go`: empty package with doc comment and `Check` interface skeleton (ID, Name, Severity, Run signatures defined but no implementations).

### internal/store (stub)

- `internal/store/store.go`: empty package with doc comment.

### examples/

- `examples/scope.toml`: a sample scope file with comments explaining every field. Targets a deliberately fictional engagement, e.g. `acme-vapt-2026-q1` with `*.acme-test.local` and `10.10.0.0/24`.
- `examples/scope-public-test.toml`: scope file allowing only `example.com`, used in the acceptance demo. Comment at the top of the file explains it is for the smoke test only and must not be used as a template for real engagements.
- `examples/config.toml`: a sample operator config with comments.

### Scan command behaviour (Session 1 minimum)

`suri scan --scope <file> <url>` must:

1. Load the scope file. Exit 2 with a clear error if missing or malformed.
2. Construct an HTTP client wrapping the scope.
3. Send a GET to the provided URL.
4. If the URL is in scope, print the response status code, the request URL, and exit 0.
5. If the URL is out of scope, print the block reason to stderr, log it via slog, exit 3.
6. If any other error occurs (network, timeout), print the error to stderr, exit 1.

This is the smallest end-to-end demonstration that scope enforcement works. Real crawling and checks come in Session 2 onward.

## Dependencies

Add to `go.mod`:

```
github.com/spf13/cobra
github.com/pelletier/go-toml/v2
github.com/projectdiscovery/retryablehttp-go
```

Pin to current latest stable. Verify exact versions via `go list -m -versions <module>` and pick the highest stable tag. Note the chosen versions in the commit message.

## Acceptance criteria

After Session 1, these commands must all succeed exactly as shown.

```bash
# 1. Builds cleanly on the current platform.
go build ./...

# 2. Cross-compiles to all four targets.
GOOS=linux GOARCH=amd64 go build -o /tmp/suri-linux-amd64 ./cmd/suri
GOOS=linux GOARCH=arm64 go build -o /tmp/suri-linux-arm64 ./cmd/suri
GOOS=darwin GOARCH=arm64 go build -o /tmp/suri-darwin-arm64 ./cmd/suri
GOOS=windows GOARCH=amd64 go build -o /tmp/suri-windows-amd64.exe ./cmd/suri

# 3. Tests pass with race detector and verbose output.
go test -race -v ./...

# 4. Vet passes.
go vet ./...

# 5. In-scope request succeeds.
go build -o ./suri ./cmd/suri
./suri scan --scope examples/scope-public-test.toml https://example.com
# Expected: prints status 200, exits 0.

# 6. Out-of-scope request is blocked at the wrapper.
./suri scan --scope examples/scope-public-test.toml https://google.com
# Expected: prints block reason to stderr, exits 3, makes no network call.
```

## Out of scope for Session 1

- Crawler logic. Only a single GET to the URL provided on the command line in this session.
- Any check modules. The check interface is stubbed only.
- SQLite store. No findings persistence yet.
- Report generation. No `report` subcommand logic beyond the stub.
- Wordlist embedding. Comes in a later session.
- GoReleaser config. Comes in the packaging session.
- AI features. Deferred to v2.

## Commit and push

```bash
git add .
git commit -m "session 1: repo scaffold, scope module, http wrapper

- cobra subcommand wiring for scan, report, diff, wordlists
- scope parser supporting hostnames (with leftmost wildcard),
  IP literals, CIDRs, optional port restriction
- http client wrapper enforcing scope before every request,
  re-validating after dns resolution to block rebinding
- table-driven tests for all scope edge cases
- example scope and config files
- agpl-3.0 headers on all go files
- wordlists attribution file with seclists credit
"
git push -u origin main
```

After push, verify on GitHub that the repo is public, the description is set, the LICENSE file is AGPL-3.0, and CLAUDE.md plus SURI_BUILD_SPEC.md are visible at the root.

---

# Session 2: Crawler and JavaScript miner

## Goal

Implement the crawler that discovers URLs from a seed, extracts forms and parameters, and mines linked JavaScript bundles for additional URLs, API endpoints, and cloud storage references. Output: a queue of discovered URLs plus a structured inventory of parameters, forms, and JS-extracted artifacts ready for check modules to consume in later sessions.

## Files to create or modify

- `internal/crawler/crawler.go`: replace the stub. Define `Crawler` struct with config (max depth, max URLs, concurrency, allowed content types). Method `Crawl(ctx, seedURLs []string) (*Inventory, error)`. Respects scope via the existing HTTP wrapper. Discovers links from HTML href, src, action attributes; from sitemap.xml; from robots.txt; from JS string extraction.
- `internal/crawler/inventory.go`: defines `Inventory` struct with `URLs`, `Forms`, `Parameters`, `JSArtifacts`. Forms include action, method, fields. Parameters include URL, name, source (query, form, header).
- `internal/crawler/jsminer.go`: pulls every script the crawler sees. Runs a curated regex library extracting URL paths, API endpoints, S3 bucket references, Azure Blob references, GCS references, hardcoded auth headers, role and permission strings. Results feed back into the URL queue and into JSArtifacts.
- `internal/crawler/sitemap.go`: parses sitemap.xml and sitemap index.
- `internal/crawler/robots.go`: parses robots.txt, extracts Disallow paths as discovery hints (paths the operator wanted to hide are paths worth checking).
- Tests for each file. Use `httptest.NewServer` for crawler tests with a fixed handler that serves a small HTML and JS corpus from `testdata/crawler/`.

### testdata/crawler/

Sample HTML pages with links, a minified JS bundle with embedded API paths and an S3 reference, a sitemap.xml, a robots.txt.

### Scan command wiring

`suri scan --scope <file> <seed-url>` now invokes the crawler instead of a single GET. Prints a summary at the end: URLs discovered, forms found, parameters found, JS artifacts extracted. Still no checks running yet; this session ends at "crawler produces an inventory and prints a summary".

Add flags: `--max-depth` (default 3), `--max-urls` (default 500), `--threads` (default 10), `--rate` (default 10 requests per second per host).

## Acceptance criteria

```bash
go test -race -v ./...
go vet ./...
go build ./...

# Crawls the test target, scope-permitting. Use a deliberately small public
# test target like https://example.com or a local docker container running
# a known vulnerable app such as juice-shop. Operator chooses.
./suri scan --scope examples/scope-public-test.toml --max-depth 2 --max-urls 20 https://example.com
# Expected: prints summary with at least 1 URL, 0 forms (example.com is flat), 
# exits 0.
```

## Out of scope for Session 2

- Headless browser. HTTP only.
- JS execution. Static regex extraction only.
- Form submission. Forms are inventoried, not submitted.
- Any check modules.

---

# Session 3: Findings store, schema, and basic persistence

## Goal

Stand up the SQLite findings store using `modernc.org/sqlite`. Schema covers findings, scans, scope snapshots, evidence (request and response pairs). Crawler output begins flowing into the store as a baseline of "URLs and parameters discovered". Foundation for the diff engine in a later session.

## Files

- `internal/store/store.go`: defines `Store` struct with `Open(path string) (*Store, error)`, `Close()`, and methods for inserting scans, findings, evidence, and scope snapshots. Use `database/sql` with `modernc.org/sqlite` driver.
- `internal/store/schema.sql`: embedded via go:embed. Tables: `scans`, `findings`, `evidence`, `scope_snapshots`, `urls_discovered`, `forms_discovered`, `parameters_discovered`, `js_artifacts`. Indexes on common query columns.
- `internal/store/migrations.go`: simple version-stamped migrations table, applies schema.sql if database is fresh.
- Tests for store open, schema apply, basic insert and read for each table.

### Scan command wiring

Each invocation of `suri scan` creates a new scan row in the database, snapshots the scope, and writes crawler discoveries to the appropriate tables. Default DB path: output directory from config plus `<scan-id>.db`. Override via `--db` flag.

Print the DB path at the end of the scan.

## Acceptance criteria

```bash
go test -race -v ./...

./suri scan --scope examples/scope-public-test.toml https://example.com
# Expected: prints DB path. The file exists and is a valid SQLite database.

sqlite3 <db-path> "SELECT count(*) FROM urls_discovered;"
# Expected: at least 1.

sqlite3 <db-path> ".schema scans"
# Expected: schema printed.
```

## Out of scope

Check modules still not running. Diff engine still not implemented.

---

# Session 4: Cloud storage check module

## Goal

First real check module. Probes for exposed cloud storage given the crawler inventory plus target metadata. Two angles: passive extraction from JS artifacts (already in inventory) and active permutation probing using the target domain.

## Files

- `internal/checks/cloud/s3.go`: probes AWS S3 anonymous list and read. Detects regional and accelerated endpoints.
- `internal/checks/cloud/azure.go`: probes Azure Blob containers for anonymous access.
- `internal/checks/cloud/gcs.go`: probes Google Cloud Storage buckets for anonymous access.
- `internal/checks/cloud/permute.go`: takes a target domain and company name, generates plausible bucket names: `{name}`, `{name}-prod`, `{name}-dev`, `{name}-backup`, `{name}-assets`, `{name}-static`, `{name}-data`, `{name}-uploads`, `{name}-tf-state`, `{name}-logs`, `prod-{name}`, `dev-{name}`. Configurable variant list in code.
- `internal/checks/cloud/cloud_test.go`: tests using httptest servers that imitate S3, Azure, and GCS responses.

### Check interface

Solidify `internal/checks/checks.go`:

```go
type Check interface {
    ID() string
    Name() string
    Severity() Severity
    Category() Category
    Run(ctx context.Context, target *Target) ([]*Finding, error)
}

type Target struct {
    Inventory *crawler.Inventory
    Scope     *scope.Scope
    HTTP      *internalhttp.Client
    Domain    string
    Notes     map[string]string
}

type Finding struct {
    CheckID     string
    Severity    Severity
    Title       string
    Description string
    URL         string
    Parameter   string
    Evidence    *Evidence
    CWE         string
    OWASP       string
    Confidence  Confidence
}
```

Findings flow into the store immediately as they are produced.

### Scan command wiring

`suri scan` now runs registered checks after crawl. Cloud checks are the only registered ones in this session. Print finding count at the end.

## Acceptance criteria

```bash
go test -race -v ./...
./suri scan --scope examples/scope-public-test.toml --domain example.com https://example.com
# Expected: completes without error, prints finding count (probably 0 against example.com).
```

Manual verification against a deliberately misconfigured test bucket the operator controls. Document the test target in `testdata/cloud/README.md`.

---

# Session 5: Admin panel and API discovery

## Goal

Implement admin path probing and Swagger/OpenAPI/GraphQL discovery. Uses vendored wordlists for path probing.

## Files

- `internal/wordlists/wordlists.go`: loader supporting vendored (go:embed), cached (`~/.cache/suri/wordlists/`), and user-supplied (`-w` flag) tiers. Records source per entry for finding metadata.
- `wordlists/embedded/admin-common.txt`: ~500 entries, curated. Source attribution in WORDLISTS.md.
- `wordlists/embedded/api-paths.txt`: ~2000 entries.
- `wordlists/embedded/swagger-paths.txt`: known Swagger and OpenAPI discovery paths.
- `internal/checks/admin/admin.go`: runs admin path wordlist against target. Filters responses by status code and content length deltas to reduce false positives.
- `internal/checks/api/swagger.go`: discovers Swagger and OpenAPI specs. If found, parses and inventories every endpoint.
- `internal/checks/api/graphql.go`: probes common GraphQL paths. If introspection is open, dumps schema and flags as a finding.
- `wordlists update` subcommand: fetches SecLists subset from upstream to the cache directory. Pin commit hash in code, document version in WORDLISTS.md.

## Acceptance criteria

```bash
go test -race -v ./...
./suri wordlists update
# Expected: downloads to ~/.cache/suri/wordlists/, prints success.

# Against a local juice-shop or similar known target:
./suri scan --scope examples/scope-local-juiceshop.toml http://localhost:3000
# Expected: discovers /api, /api-docs, etc; produces findings.
```

---

# Session 6: Web injection checks

## Goal

The OWASP-style check engine: reflected XSS, SQLi (error-based and time-based), SSTI, command injection, open redirect, server-side request forgery basics, security header audit.

This is the largest single session by content but it sits cleanly on the inventory plus check interface from earlier sessions.

## Files

- `internal/checks/web/xss.go`: reflected XSS via canary payloads, reflection detection in response body, context awareness (HTML, attribute, JS, URL).
- `internal/checks/web/sqli.go`: error-based via DB error string detection, time-based via timing comparison. No data extraction.
- `internal/checks/web/ssti.go`: template injection via expression evaluation canaries for common engines (Jinja2, Twig, Freemarker, ERB).
- `internal/checks/web/cmdi.go`: command injection via timing-based payloads only (sleep). No exploitation.
- `internal/checks/web/redirect.go`: open redirect via canary URL injection.
- `internal/checks/web/headers.go`: security header audit (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy).
- `internal/checks/web/backups.go`: backup file and source control exposure (.git/HEAD, .env, .DS_Store, swap files, source maps, common backup extensions).

Each check has its own test file with httptest servers simulating vulnerable and non-vulnerable responses.

## Acceptance criteria

Tests pass. Manual run against a known vulnerable test target (DVWA, juice-shop, or operator's lab) produces expected findings.

---

# Session 7: Diff engine and report generation

## Goal

Two features that turn Suri from "scanner" into "engagement tool". Diff engine compares scans against the same scope and produces new, persistent, resolved findings. Report generator outputs an HTML client deliverable.

## Files

- `internal/store/diff.go`: diff query producing categorised findings (new, persistent, resolved) across two scan IDs.
- `internal/report/html.go`: HTML report generator. Template under `internal/report/templates/`. Includes scan metadata, scope snapshot, finding list grouped by severity, evidence (request and response excerpts), reproduction curl commands, CWE and OWASP mapping, footer with Suri version and engagement notes.
- `internal/report/json.go`: full JSON dump of the findings store for that scan, suitable for tooling.
- `report` subcommand: `suri report --scan <id> --format html --out report.html` and `suri report --scan <id> --format json --out report.json`.
- `diff` subcommand: `suri diff --baseline <id> --current <id> --format html --out diff.html`.

## Acceptance criteria

```bash
./suri scan --scope examples/scope-local.toml http://localhost:3000
# Note scan ID printed.
./suri report --scan <id> --format html --out /tmp/r.html
# Expected: file exists, opens in browser, lists findings.

./suri scan --scope examples/scope-local.toml http://localhost:3000
# Second scan, different ID.
./suri diff --baseline <id1> --current <id2> --format html --out /tmp/d.html
# Expected: diff report shows what changed.
```

---

# Session 8: GoReleaser, CI, and v0.1.0 release

## Goal

Ship the binary. Cross-compiled artifacts, checksums, signed release, README polish, Kali submission prep.

## Files

- `.goreleaser.yaml`: builds for linux amd64/arm64, darwin arm64, windows amd64. Archive format `tar.gz` for unix and `zip` for windows. Checksums. SBOM generation optional.
- `.github/workflows/ci.yml`: on push to main and on pull request, runs `go test -race ./...` and `go vet ./...` on Ubuntu, macOS, and Windows runners.
- `.github/workflows/release.yml`: on tag push matching `v*.*.*`, runs GoReleaser, publishes GitHub release.
- `README.md`: full polish. Installation instructions for `go install`, `brew tap` (if Tap repo set up), direct binary download, and Debian package. Quickstart with example scope and command. Feature list. Disclaimer about authorized use only. Link to WORDLISTS.md.
- `debian/`: directory with control file, postinst, postrm, etc., for Debian packaging suitable for Kali submission.

## Acceptance criteria

```bash
# Local dry run of GoReleaser.
goreleaser release --snapshot --clean
# Expected: dist/ contains binaries and archives for all four targets.

# CI passes on a test branch push.
# Tag and release:
git tag v0.1.0
git push --tags
# Expected: release.yml triggers, GitHub release appears with assets.
```

---

# Future sessions (not specified yet, listed for context)

- Session 9: LLM-assisted bucket name permutation and JS analysis (v2 feature start)
- Session 10: Web UI (server-rendered, Caddy plus Cloudflare Access pattern)
- Session 11: Plugin and custom check loader

These are deferred. Do not start them until v0.1.0 is shipped and stable.

---

# Notes for the operator

- Hand Claude Code this file plus CLAUDE.md and say "execute Session 1".
- Review the diff before committing. Trust but verify.
- If a session brief is ambiguous, ask. Do not let Claude Code guess.
- After every session, run the acceptance commands yourself, not just rely on Claude Code's report.
- Keep sessions small. If a session is taking more than one Claude Code conversation to complete, split it.
