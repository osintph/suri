# CLAUDE.md

Project context for Claude Code. Read this file before any work in this repository.

## What this project is

Suri is a web application security scanner for authorized VAPT (Vulnerability Assessment and Penetration Testing) engagements. It targets web applications, admin panels, APIs, and exposed cloud storage. It is part of the OSINT-PH brand suite alongside FalconEye and Salakay.

The full build plan lives in `SURI_BUILD_SPEC.md`. Read that before executing any session.

## Standing rules

These apply to every session, every file, every commit.

### Writing style

1. Never use em dashes. Use commas, periods, or parentheses instead.
2. Never use the phrase "it's not just X, it's Y" or "the X isn't just Y, it's Z" or similar AI-tell constructions.
3. Plain technical prose. No marketing voice. No "delve", "tapestry", "navigate the landscape", etc.

### Code style

1. Go 1.23 minimum. Use `log/slog` for all logging. Never use `fmt.Println` or `log` package for anything beyond throwaway debugging.
2. Every Go file starts with the AGPL-3.0 header block. See the template in `SURI_BUILD_SPEC.md` Section "AGPL header".
3. Errors are wrapped with `fmt.Errorf("context: %w", err)`. Never swallow errors. Never return bare strings as errors.
4. Use `context.Context` as the first parameter on any function that does I/O or can be cancelled.
5. All HTTP requests must go through `internal/http.Client`. Never call `net/http` directly outside that package. This is a hard rule because scope enforcement lives in the wrapper.
6. Nothing under `internal/` is promoted to `pkg/` without explicit instruction in the spec.
7. Tests live next to the code: `foo.go` and `foo_test.go` in the same package. Table-driven tests preferred.
8. Use `modernc.org/sqlite` for SQLite, not `mattn/go-sqlite3`. We need pure-Go for cross-compilation.
9. TOML parsing uses `github.com/pelletier/go-toml/v2`.
10. HTTP client uses `github.com/projectdiscovery/retryablehttp-go` wrapped inside `internal/http`.

### Operational rules

1. Never recommend or use `nano`. The operator uses `vi` for interactive editing and heredoc or `sudo tee` for programmatic file writes.
2. Never recommend `apt-get autoremove` or broad package operations without `apt-get -s` simulate first.
3. Surgical, reversible changes only on any system command suggestion.
4. Never make confident claims about external APIs, SDK versions, or product details without verifying current docs first. Say "needs verification" and check.

### Git workflow

1. Commit messages are freeform but descriptive. First line under 72 characters, blank line, then body if needed.
2. Push to `main` directly during early development. Branch protection is off.
3. Tag releases as `v0.1.0`, `v0.2.0`, etc. Semantic versioning.
4. Never force push to `main`.
5. Never commit secrets. The `.gitignore` must include `.env`, `*.key`, `*.pem`, `secrets/`, and any local config that holds credentials.

### Repo metadata

- Module path: `github.com/osintph/suri`
- License: AGPL-3.0
- Owner: osintph (GitHub org)
- Visibility: public
- Default branch: `main`

## How to work on this project

1. Open `SURI_BUILD_SPEC.md`.
2. Find the session number the operator names.
3. Execute the session brief literally. Do not skip steps. Do not add files outside the listed scope. Do not refactor anything outside the session scope.
4. At the end of the session, run the acceptance commands listed in the brief. Paste the output. If any acceptance check fails, fix and re-run before declaring the session done.
5. Commit with a message referencing the session number, e.g. `session 1: scope module, http wrapper, repo scaffold`.
6. Push to `main`.

## What to do if something is unclear

Ask. Do not guess. Do not invent files or features not in the spec. If a session brief contradicts a standing rule in this file, the standing rule wins. Surface the contradiction in the response and wait for resolution.

## What not to do

1. Do not bring up Blacklight, SIEM, CEF, or SARIF in any code, comment, or commit message unless the operator explicitly asks. Suri's output formats are JSON and HTML report only in v1. Any other formats wait for v2.
2. Do not add LLM features in v1. No Anthropic API calls. No OpenAI. The `internal/ai/` package does not exist in v1.
3. Do not add a UI in v1. No HTTP server. No web dashboard. CLI only.
4. Do not add browser automation, headless Chrome, Playwright, or similar in v1.
5. Do not vendor a full SecLists. Vendor only the curated subset specified in the wordlists session.
6. Do not add telemetry, phone-home, update checks, or analytics. Ever.
