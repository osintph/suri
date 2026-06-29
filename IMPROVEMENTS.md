# Improvements log

A running list of refinements, gaps, and observations surfaced during development.
Not a roadmap. Not a feature backlog. A scratch pad for things that came up,
were not worth interrupting current work for, and should be revisited later.

Each entry should record what was observed, when, in which session, and the
suggested fix. Cross-reference to a GitHub issue if one gets opened.

---

## Cloud check module

### S3 bucket name permutation list is too narrow

**Observed:** Session 4 acceptance testing against a local Minio target with two
test buckets, `osintph-suri-test-public` and `osintph-suri-test-private`, found
zero of them. The 12-entry default permutation list does not include `-public`
or `-private` as suffixes, both of which are common in real-engagement
observations.

**Fix:** Expand the permutation list in
`internal/checks/cloud/permute.go`. Candidates to add based on common real-world
naming conventions:

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
list means more probes per scan and more requests against AWS endpoints, which
matters for rate limits and for being a polite client. Add a tier system:
a `--cloud-permutation-depth` flag with values `small` (current 12), `medium`
(50ish entries), `large` (200ish), so the operator can choose intensity per
engagement. Default stays `small`.

**Origin:** Session 4 acceptance log, 2026-06-29. Minio test with public bucket
that did not match permutations.

---

### S3 module does not probe path-style listing variants

**Observed:** Session 4.6 added path-style URL support for non-AWS endpoints
(Minio, Backblaze, etc). The module probes `{endpoint}/{bucket}/?list-type=2`.
Some S3-compatible servers and some AWS misconfigurations also expose listings
via `{endpoint}/{bucket}` (no trailing slash) or via the legacy
`?list-type=1` parameter. Worth probing both variants when the primary returns
404 or 403.

**Fix:** In `internal/checks/cloud/s3.go`, if the primary list-type=2 probe
returns a non-success status, fall back to a `?list-type=1` probe before
declaring the bucket non-listable. Keep the count of requests per bucket
bounded (no more than 2 probes per bucket).

**Origin:** Session 4 design discussion, 2026-06-29. Not yet observed in the
field; preventive.

---

## HTTP wrapper

### Out-of-scope log summarisation is good but lacks unique-host detail

**Observed:** Session 4.5 fixed the log spam from cloud permutation by logging
only the first block per unique host plus a summary at scan end. The summary
gives count and unique_hosts but does not list the hosts. For engagement audit
purposes, the full list should be written somewhere the operator can review.

**Fix:** Write the deduplicated host list to the scan log file (the JSON
slog handler, not stderr) at scan end. The log file already exists per
Session 1 design. Stderr stays clean, the audit trail keeps the full list.

**Origin:** Session 4.5 implementation review, 2026-06-29. Cosmetic, not
blocking.

---

## Findings store

### No CASCADE on foreign keys

**Observed:** Session 3 schema review. Deleting a scan does not delete its
findings or evidence rows. Currently there is no `suri delete-scan` command
so this is theoretical, but a future operator-facing cleanup command will
need to handle this. Also worth checking that `PRAGMA foreign_keys = ON`
is actually set at connection time, otherwise SQLite does not enforce FKs
at all even without CASCADE.

**Fix:** Add `PRAGMA foreign_keys = ON` to `internal/store/store.go` Open.
Add `ON DELETE CASCADE` to the findings and evidence foreign key declarations
in `internal/store/schema.sql`. If a schema migration is needed for existing
databases, add a migration step.

**Origin:** Session 3 schema review, 2026-06-28.

---

## Wordlist module

### Vendored wordlist size and SecLists pin freshness

**Observed:** Session 5 vendored curated subsets of SecLists via go:embed.
The pinned SecLists commit needs to be refreshed periodically as the upstream
list gets new entries from real-world breaches. Stale vendored lists mean
Suri misses paths that other tools find.

**Fix:** Add a calendar reminder or a quarterly task to refresh the pinned
commit, regenerate the curated subsets, and bump the Suri patch version.
Document the refresh procedure in `WORDLISTS.md`.

**Origin:** Session 5 planning, 2026-06-29. Preventive.

---

### Catalogue expansion for interesting-paths based on real engagement findings

**Observed:** Session 5.9 hand-curated 51 interesting-path entries with content
verification patterns. Real engagements will turn up file shapes not in the
initial catalogue: language-specific env file formats, CI config files, IaC
state files, framework-specific secret stores, etc.

**Fix:** Grow `internal/checks/admin/interesting-paths.toml` based on findings
from real engagements. Each new entry needs path, description, and a content
pattern that distinguishes the file from soft-200 responses. Defer until v0.2.0
when real-target data is available.

**Origin:** Session 5.9 design, 2026-06-29.

---

## Web injection module

### web.sqli.timing has no SQLite sleep payload

**Observed:** Session 6 includes time-based SQLi payloads for MySQL (SLEEP),
Postgres (pg_sleep), and MSSQL (WAITFOR DELAY). SQLite has no native sleep
function in its SQL dialect, so no time-based SQLi payload in the catalogue
will trigger a measurable delay on SQLite-backed applications. The
vulntest target's `/search-time?q=` endpoint backed by SQLite is detectable
via error-based but not via time-based SQLi.

**Fix:** Add a SQLite-specific timing payload that abuses RANDOMBLOB or a
CTE-based busy loop to burn CPU. RANDOMBLOB(N) allocates N bytes; with
N=100000000 the response takes several seconds. Payload would be something
like `' AND (SELECT randomblob(100000000) FROM users LIMIT 1)='a` for a
500 MB allocation. Verify against the vulntest target before adding to
the payload catalogue.

**Origin:** Session 6.6 vulntest integration. SQLite coverage gap.

---

### Backup check 4x suffix duplication

**Observed:** Session 6.2 content-verification dramatically reduced backup
file false positives. Remaining findings against juice-shop's intentional
FTP exposure still show 4x duplication per file (.bak, .old, .orig, .swp
variants all matching the same original content). For 10 distinct exposed
files the operator sees 40 findings, which is technically correct but
report-noisy.

**Fix:** In `internal/checks/web/backups.go`, deduplicate findings where
the same `(original_url, content_hash)` produces multiple suffix variants.
Emit ONE finding per distinct backup file, with the matching suffixes
recorded in the evidence (e.g. `suffixes=[".bak", ".old", ".orig", ".swp"]`).
This collapses the 40-finding case to 10 without losing information.

**Origin:** Session 6.2 vulntest integration, 2026-06-29.

---

### Injection engine cannot test CSRF-protected forms or authenticated paths

**Observed:** Session 6 injection engine tests parameters from the crawler
inventory. Modern web apps gate most vulnerable functionality behind
authentication, and forms include CSRF tokens that change per request.
Suri's v0.1.0 has no authentication support and does not handle CSRF
tokens, so realistic targets like DVWA and juice-shop only expose their
unauthenticated surface to the injection engine.

**Fix (v0.2.0):** Add `--cookie` flag to inject session cookies from the
operator's authenticated browser session. Detect CSRF token fields by
name (csrf_token, _csrf, authenticity_token, user_token) and re-fetch
the token before each form-based injection probe. This is a significant
design change; defer.

**Origin:** Session 6 DVWA integration, 2026-06-29.

---

### Backup check Jaccard threshold tuning

**Observed:** Session 6.2 set the Jaccard similarity threshold for "similar
backup content" at 0.5. This was a starting point based on intuition, not
real-target data. Real engagements may need this tuned.

**Fix:** Collect Jaccard scores from real-engagement findings over the
first few months of v0.1.0 use. If the operator reports backup findings
that look wrong (true positives missed, false positives included),
re-evaluate the threshold against the dataset. Could go as low as 0.3
or as high as 0.7 depending on what real backup files look like in
practice.

**Origin:** Session 6.2 design, 2026-06-29.

---

## Reporting (Session 7)

### Report generation should support multiple output formats from one scan

**Observed:** Session 7 spec calls for HTML and JSON. Real engagements often
need additional formats: Markdown for issue tracker ingestion, plain text
for email attachments, CSV for triage spreadsheets.

**Fix:** Defer to v0.2.0. Once HTML and JSON land, evaluate which additional
formats are worth the maintenance burden based on actual operator feedback.

**Origin:** Session 7 planning, 2026-06-29.

---

## Packaging and release (Session 8)

### Real-AWS validation before v0.1.0 tag

**Observed:** Session 4 was validated against Minio, a local S3-compatible
server. Real AWS has wire-level quirks (regional redirects, request-payer
headers, the virtual-hosted-vs-path-style duality, etc) that Minio does not
exercise. Shipping v0.1.0 without at least one real-AWS test risks bugs
that only surface against actual AWS endpoints.

**Fix:** Before tagging v0.1.0 in Session 8, set up two real AWS S3 test
buckets (one public-list, one private), run Suri against them, confirm the
expected single finding, delete the buckets. 20 minutes one time. Document
the procedure in a release checklist.

**Origin:** Session 4 LocalStack decision, 2026-06-29.

---

## General

### `--quiet` flag

**Observed:** Current output mixes INFO lines (cloud check skips) with the
scan summary. Operators running scans inside a tmux pane during a real
engagement would benefit from a quiet mode (suppress INFO, show only the
final summary and any findings).

**Fix:** Add `--quiet` flag to the scan command. Maps to slog level: quiet =
WARN, default = INFO. The `--debug` flag added in Session 6.6 already
covers the verbose side.

**Origin:** Session 4.5 implementation review, 2026-06-29. Cosmetic.

---

### `NO_COLOR` env var support

**Observed:** CLAUDE.md mentions `NO_COLOR` env var respect as a future
addition. Worth implementing alongside the quiet/verbose work since they
share the output-formatting code path.

**Fix:** When implementing quiet mode, also implement `NO_COLOR` env var
respect and a `--no-color` flag. Suri does not currently use colour output
so this is preventive.

**Origin:** Session 1 spec, 2026-06-23.

---

### Validate against multiple target classes before declaring a check done

**Observed:** Sessions 5.5 through 5.9 (admin discovery) and 6.0 through 6.6
(injection engine) repeatedly shipped check modules that passed unit tests
but had bugs surfacing only on real targets. Process learning: a check is
not done when its unit tests pass. It is done when integration testing
against at least one server-rendered target AND one SPA target confirms
behavior matches the design.

**Fix:** Process change, not code change. Before declaring any check
session done, run the integration test against juice-shop (SPA), DVWA
(server-rendered PHP), and vulntest (controlled vulnerable Node). All
three must pass.

**Origin:** Session 6.x iterations, 2026-06-29.
