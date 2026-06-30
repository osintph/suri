# Improvements log

A running list of refinements, gaps, and observations surfaced during development
and real engagement use.

Each entry records what was observed, when, in which session or engagement, and
the suggested fix. Items marked **RESOLVED** ship in a tagged release; others
remain open for future work.

---

## Cloud check module

### S3 bucket name permutation list is too narrow

**Observed:** Session 4 acceptance testing against a local Minio target with two
test buckets, `osintph-suri-test-public` and `osintph-suri-test-private`, found
zero of them. The 12-entry default permutation list does not include `-public`
or `-private` as suffixes, both of which are common in real-engagement
observations.

**Fix:** Expand the permutation list in `internal/checks/cloud/permute.go`.
Candidates to add based on common real-world naming conventions:

- `-public`, `-private`, `-internal`, `-external`
- `-staging`, `-stg`, `-test`, `-qa`, `-uat`
- `-images`, `-files`, `-media`, `-cdn`
- `-archive`, `-archives`, `-old`, `-legacy`
- `-tmp`, `-temp`, `-scratch`
- `-config`, `-configs`, `-secrets`
- `-reports`, `-exports`
- `-tf-state-backup`, `-terraform-state`
- `-{year}`, `-{year}-backup` for the current and previous two years
- Cross-region permutations for AWS: `-us-east-1`, `-eu-west-1`, `-ap-southeast-1`

**Caveat:** The current list of 12 was deliberate to keep noise low. A larger
list means more probes per scan. Add a tier system: a
`--cloud-permutation-depth` flag with values `small` (current 12), `medium`
(50ish entries), `large` (200ish), so the operator can choose intensity per
engagement. Default stays `small`.

---

### S3 module does not probe path-style listing variants

**Observed:** Session 4.6 added path-style URL support for non-AWS endpoints.
The module probes `{endpoint}/{bucket}/?list-type=2`. Some S3-compatible
servers and some AWS misconfigurations also expose listings via
`{endpoint}/{bucket}` (no trailing slash) or via the legacy `?list-type=1`
parameter.

**Fix:** In `internal/checks/cloud/s3.go`, if the primary list-type=2 probe
returns a non-success status, fall back to a `?list-type=1` probe before
declaring the bucket non-listable. Keep the count of requests per bucket
bounded.

---

### Real-AWS validation before v0.2.0 tag

**Observed:** Session 4 was validated against Minio, a local S3-compatible
server. Real AWS has wire-level quirks (regional redirects, request-payer
headers, the virtual-hosted-vs-path-style duality) that Minio does not
exercise.

**Fix:** Before tagging v0.2.0, set up two real AWS S3 test buckets (one
public-list, one private), run Suri against them, confirm the expected
single finding, delete the buckets. 20 minutes one time. Document the
procedure in a release checklist.

---

## HTTP wrapper

### Out-of-scope log summarisation lacks unique-host detail

**Observed:** Session 4.5 fixed the log spam from cloud permutation by logging
only the first block per unique host plus a summary at scan end. The summary
gives count and unique_hosts but does not list the hosts.

**Fix:** Write the deduplicated host list to the scan log file (the JSON
slog handler, not stderr) at scan end. Stderr stays clean, the audit trail
keeps the full list.

---

## Findings store

### No CASCADE on foreign keys

**Observed:** Session 3 schema review. Deleting a scan does not delete its
findings or evidence rows. Worth checking that `PRAGMA foreign_keys = ON`
is actually set at connection time, otherwise SQLite does not enforce FKs
at all.

**Fix:** Add `PRAGMA foreign_keys = ON` to `internal/store/store.go` Open.
Add `ON DELETE CASCADE` to the findings and evidence foreign key declarations.

---

## Wordlist module

### Vendored wordlist size and SecLists pin freshness

**Observed:** Session 5 vendored curated subsets of SecLists via go:embed.
The pinned commit needs to be refreshed periodically. Stale lists mean
Suri misses paths that other tools find.

**Fix:** Add a quarterly task to refresh the pin, regenerate the curated
subsets, bump the Suri patch version. Document the procedure in
`WORDLISTS.md`.

---

### Catalogue expansion for interesting-paths based on real engagement findings

**Observed:** Session 5.9 hand-curated 51 interesting-path entries with
content verification patterns. Real engagements will turn up file shapes
not in the initial catalogue: language-specific env file formats, CI
config files, IaC state files, framework-specific secret stores.

**Fix:** Grow `internal/checks/admin/interesting-paths.toml` based on
findings from real engagements. Each new entry needs path, description,
and a content pattern that distinguishes the file from soft-200 responses.

---

## Web injection module

### web.sqli.timing has no SQLite sleep payload

**Observed:** Session 6 includes time-based SQLi payloads for MySQL (SLEEP),
Postgres (pg_sleep), and MSSQL (WAITFOR DELAY). SQLite has no native sleep
function, so no payload in the catalogue will trigger a measurable delay
on SQLite-backed applications.

**Fix:** Add a SQLite-specific payload that abuses RANDOMBLOB or a CTE-based
busy loop. Payload candidate:
`' AND (SELECT randomblob(100000000) FROM users LIMIT 1)='a`
Verify against the vulntest target before adding to the payload catalogue.

---

### Backup check 4x suffix duplication

**Observed:** Session 6.2 content-verification dramatically reduced backup
file false positives. Remaining findings against juice-shop's intentional
FTP exposure still show 4x duplication per file (.bak, .old, .orig, .swp
variants all matching the same original content). For 10 distinct exposed
files the operator sees 40 findings.

**Fix:** In `internal/checks/web/backups.go`, deduplicate findings where
the same `(original_url, content_hash)` produces multiple suffix variants.
Emit ONE finding per distinct backup file, with matching suffixes recorded
in the evidence (e.g. `suffixes=[".bak", ".old", ".orig", ".swp"]`).

---

### Injection engine cannot test CSRF-protected forms or authenticated paths

**Observed:** Session 6 injection engine tests parameters from the crawler
inventory. Modern web apps gate most vulnerable functionality behind
authentication, and forms include CSRF tokens that change per request.

**Fix:** Add `--cookie` flag to inject session cookies from the operator's
authenticated browser session. Detect CSRF token fields by name
(csrf_token, _csrf, authenticity_token, user_token) and re-fetch the token
before each form-based injection probe. Significant design change.

---

### Backup check Jaccard threshold tuning

**Observed:** Session 6.2 set the Jaccard similarity threshold for "similar
backup content" at 0.5. This was a starting point based on intuition, not
real-target data.

**Fix:** Collect Jaccard scores from real-engagement findings over the
first few months of v0.1.x use. Re-evaluate the threshold against the
dataset.

---

### Path parameter injection

**Observed:** FalconEye scan (2026-06-29) revealed that the injection
engine cannot test OpenAPI path parameters. FalconEye exposes 5 GET
endpoints with path-style parameters: `/api/crypto/lookup/{address}`,
`/api/domain/lookup/{domain}`, `/api/telegram/lookup/{channel}`,
`/api/ip/lookup/{ip}`, `/api/news/{category}`. Suri's swagger module
correctly extracts these parameters but the injection engine only
substitutes query strings, not path segments.

**Fix:** When the swagger discovery module finds OpenAPI path params,
the injection engine should substitute those segments with payloads.
Build the injection URL by replacing `{paramname}` in the URL template
with each payload, encoded for path-segment safety. Real APIs use
path params more than query strings; this unlocks meaningful injection
testing against modern REST surfaces.

**Origin:** Session 6 + FalconEye 2026-06-29.

---

### JSON body injection from OpenAPI schemas

**Observed:** FalconEye exposes 5 POST endpoints with documented JSON body
schemas (`/api/scanner/scan`, `/api/email-header/analyze`,
`/api/email-header/upload`, `/api/dork-generator/generate`,
`/api/script-decoder/decode`). Suri's injection engine builds GET requests
with query-string payloads only. Modern REST APIs accept JSON bodies for
nearly all non-GET operations.

**Fix:** For POST endpoints discovered via OpenAPI, the injection engine
should generate JSON request bodies from the documented schema and inject
payloads into each schema field. Each field (string properties in the
request body) becomes an injection point. Findings should record which
JSON path field was injected (e.g. `parameter=body.raw_header`).

This is the larger of the two OpenAPI gaps. Probably 3 sessions: schema-
aware payload builder, request execution, finding attribution.

**Origin:** Session 6 + FalconEye 2026-06-29.

---

## WAF detection (RESOLVED in v0.1.2)

### Cloudflare WAF block page false positives

**Observed:** First FalconEye scan (2026-06-29) produced 8 false-positive
`web.backup.file` findings on `wp-config.php` and its `.bak/.old/.orig/.swp`
variants, plus 2 false-positive `admin.path.interesting-exposed` findings.
FalconEye is a FastAPI app, not WordPress.

**Root cause:** Cloudflare WAF returns the block page with status 200 or
403 (depending on rule action), making content verification meaningless
because every probe captures the same block-page shell.

**Resolved:** v0.1.2 (Session 9 + 9.1) adds WAF signature detection for
Cloudflare, Akamai, Imperva, and AWS WAF in both the backup check (200
and 403 paths) and the interesting-paths check. Per-scan WAFTracker emits
`scan.waf.detected` info finding when N >= 10 blocks observed on a host.

---

## OpenAPI exposure (RESOLVED externally)

### FastAPI default exposes complete attack surface

**Observed:** FalconEye scan (2026-06-29) reported
`api.openapi.spec-exposed` medium/confirmed at
`/openapi.json`. FastAPI serves `/openapi.json`, `/docs`, and `/redoc` by
default. This gives attackers a complete attack map.

**Resolved:** FalconEye patched to gate the three endpoints behind a
`FALCONEYE_PUBLIC_DOCS` env var, default off in production. Not a Suri
code change. Pattern documented for future engagement reports as a common
quick win for FastAPI-backed targets.

---

## Reporting

### Multiple output formats from one scan

**Observed:** Session 7 ships HTML and JSON. Real engagements often need
Markdown for issue tracker ingestion, plain text for email attachments,
CSV for triage spreadsheets.

**Fix:** Evaluate which formats are worth the maintenance burden based
on operator feedback. Markdown first if any.

---

### Info findings inclusion in reports

**Observed:** Session 7 HTML reports show info findings by default in the
finding count and severity table, even when the scan was run without
`--include-info`. This conflicts with the scan output's "info: N
suppressed" message.

**Fix:** When scan was run without `--include-info`, report should also
exclude info findings unless explicitly requested via a report-level flag.
Reports should respect the scan's filtering choice.

---

### Scan management subcommands

**Observed:** No way to list or delete past scan DBs. Operators accumulate
`.db` files in `pwd` over time.

**Fix:** Add `suri list-scans` and `suri delete-scan <id>` subcommands.
Goes hand-in-hand with the FK CASCADE work above.

---

## Packaging and release

### macOS Gatekeeper friction

**Observed:** v0.1.1 Homebrew install requires `brew trust osintph/tap`
plus `sudo xattr -d com.apple.quarantine $(which suri)` for the binary
to run because it is not signed with an Apple Developer ID.

**Fix:** Apply for Apple Developer account ($99/year), sign and notarize
the macOS binary via GoReleaser's `signs:` block, eliminate the trust
and xattr friction.

---

### Homebrew formula vs cask

**Observed:** GoReleaser v2 published Suri as a cask (`Casks/suri.rb`)
rather than a formula. Casks require `brew trust` from third-party taps;
formulas do not.

**Fix:** Investigate whether the GoReleaser config can be adjusted to
publish as a formula instead. May require changes to how the artifact
metadata is declared in `.goreleaser.yaml`.

---

### Debian package for Kali submission

**Observed:** Most OSINT and security practitioners live on Kali. A
`suri` apt package gets it in front of the audience that never visits
GitHub release pages.

**Fix:** Add `debian/` directory and packaging files, integrate with the
release pipeline, submit to Kali's repo (separate review process,
unknown wait time).

---

## General

### `--quiet` flag

**Observed:** Current output mixes INFO lines (cloud check skips) with
the scan summary. Operators running scans inside tmux during a real
engagement would benefit from a quiet mode.

**Fix:** Add `--quiet` flag. Maps to slog level WARN. The `--debug` flag
from Session 6.6 already covers the verbose side.

---

### `NO_COLOR` env var support

**Observed:** CLAUDE.md mentions `NO_COLOR` env var respect as a future
addition.

**Fix:** Implement alongside `--quiet`. Suri does not currently use
colour output so this is preventive.

---

### Validate against multiple target classes before declaring a check done

**Observed:** Sessions 5.5 through 5.9 (admin discovery) and 6.0 through
6.6 (injection engine) repeatedly shipped check modules that passed unit
tests but had bugs surfacing only on real targets.

**Fix:** Process change. Before declaring any check session done, run the
integration test against juice-shop (SPA), DVWA (server-rendered PHP),
vulntest (controlled vulnerable Node), AND at least one real target
fronted by a CDN/WAF. The WAF detection bug from FalconEye is a good
example of what slips through pure-localhost validation.
