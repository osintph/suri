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

package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"unicode"

	"github.com/osintph/suri/internal/checks"
	"github.com/osintph/suri/internal/crawler"
	internalhttp "github.com/osintph/suri/internal/http"
)

// BackupsCheck probes for backup file exposure. For each URL already in the
// crawler inventory it tries common backup extensions (.bak, .old, .orig, .swp).
// It also probes a small fixed list of application-specific backup filenames
// that are not covered by the interesting-paths catalogue.
//
// Input filtering (prevents DoS on large inventories):
//   - Only URLs with ResponseStatus in {200, 401, 403} are probed; 404s and
//     5xx responses indicate the URL is not a real route.
//   - URLs sharing the most-common body hash per host (the SPA catch-all shell)
//     are skipped.
//   - Total probes across the scan are capped at MaxProbes (default 200).
//
// Content verification (prevents false positives on error-page catch-alls):
//   - 200 responses are only accepted when the backup body is plausibly a copy
//     of the original: identical SHA-256 (confirmed) or Jaccard token similarity
//     >= 0.5 (firm). Mismatched content types are a hard skip.
//   - 401/403 responses are accepted without content verification (the file
//     exists but is protected).
//   - 5xx and 3xx responses are skipped.
type BackupsCheck struct {
	// MaxProbes is the maximum total HTTP probes per scan. 0 uses the default (200).
	MaxProbes int
}

func (c *BackupsCheck) ID() string                { return "web.backup.file" }
func (c *BackupsCheck) Name() string              { return "Backup File Exposure" }
func (c *BackupsCheck) Severity() checks.Severity { return checks.SeverityMedium }
func (c *BackupsCheck) Category() checks.Category { return checks.CategoryWeb }

func (c *BackupsCheck) maxProbesOrDefault() int {
	if c.MaxProbes > 0 {
		return c.MaxProbes
	}
	return 200
}

// backupSuffixes are appended to discovered URLs to probe for backup copies.
var backupSuffixes = []string{".bak", ".old", ".orig", ".swp"}

// fixedBackupPaths are additional high-value backup filenames probed against
// each active origin. These are NOT in the interesting-paths catalogue.
var fixedBackupPaths = []string{
	"application.properties.bak",
	"application.yml.bak",
	"application.yaml.bak",
	".config.bak",
	"settings.py.bak",
	"database.yml.bak",
	"config.php.bak",
	"config.inc.php.bak",
	"local_settings.py.bak",
}

// probeEntry describes one backup probe to attempt.
type probeEntry struct {
	originalURL string // empty for fixed backup paths (no content verification on 200)
	probeURL    string
}

// originalMeta caches the original URL's response body and content type so
// four suffix probes for the same original do not refetch it.
type originalMeta struct {
	body        []byte
	contentType string
	hash        string
}

// Run probes backup variants of discovered URLs and fixed backup paths.
func (c *BackupsCheck) Run(ctx context.Context, target *checks.Target) ([]*checks.Finding, error) {
	if target.Inventory == nil {
		return nil, nil
	}

	maxProbes := c.maxProbesOrDefault()

	// Build per-host SPA shell hash so we can skip catch-all SPA responses.
	shellHashes := buildShellHashes(target.Inventory)

	// Collect candidate URLs (post-filter) and track which origins have at
	// least one valid candidate (fixed backup paths only probe active origins).
	var candidates []string
	activeOrigins := make(map[string]struct{})
	for _, du := range target.Inventory.URLs {
		status := du.ResponseStatus
		if status != 200 && status != 401 && status != 403 {
			continue
		}
		if status == 200 && du.BodyHash != "" {
			if shellHashes[urlHost(du.URL)] == du.BodyHash {
				continue
			}
		}
		candidates = append(candidates, du.URL)
		if u, err := url.Parse(du.URL); err == nil && u.Scheme != "" && u.Host != "" {
			activeOrigins[u.Scheme+"://"+u.Host] = struct{}{}
		}
	}

	// Build the probe list. Inventory-derived entries carry their originalURL;
	// fixed-path entries have originalURL == "" (no content verification on 200).
	seen := make(map[string]bool)
	var entries []probeEntry

	for _, rawURL := range candidates {
		if !strings.HasPrefix(rawURL, "http") {
			continue
		}
		parsed, err := url.Parse(rawURL)
		if err != nil {
			continue
		}
		path := parsed.Path
		if path == "" || strings.HasSuffix(path, "/") {
			continue
		}
		for _, suffix := range backupSuffixes {
			p2 := *parsed
			p2.Path = path + suffix
			p2.RawQuery = ""
			probeURL := p2.String()
			if !seen[probeURL] {
				seen[probeURL] = true
				entries = append(entries, probeEntry{originalURL: rawURL, probeURL: probeURL})
			}
		}
	}

	for origin := range activeOrigins {
		for _, fp := range fixedBackupPaths {
			probeURL := origin + "/" + fp
			if !seen[probeURL] {
				seen[probeURL] = true
				entries = append(entries, probeEntry{originalURL: "", probeURL: probeURL})
			}
		}
	}

	if len(entries) > maxProbes {
		slog.Warn("backup probe cap reached, some URLs not probed",
			"total_candidates", len(entries),
			"cap", maxProbes,
			"skipped", len(entries)-maxProbes,
		)
		entries = entries[:maxProbes]
	}

	// origCache maps original URL → meta. A nil value means the fetch failed or
	// returned non-200 (so content verification is not possible).
	origCache := make(map[string]*originalMeta)

	var findings []*checks.Finding
	for _, entry := range entries {
		if ctx.Err() != nil {
			break
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, entry.probeURL, nil)
		if err != nil {
			continue
		}
		resp, err := target.HTTP.Do(ctx, req)
		if err != nil {
			continue
		}

		status := resp.StatusCode

		switch {
		case status == http.StatusNotFound:
			resp.Body.Close()

		case status >= 300 && status < 400:
			resp.Body.Close()

		case status >= 500:
			resp.Body.Close()

		case status == http.StatusUnauthorized || status == http.StatusForbidden:
			resp.Body.Close()
			findings = append(findings, c.makeFinding(
				entry.probeURL, entry.originalURL, status, "protected", nil, 0, "",
			))

		case status == http.StatusOK:
			backupCT := resp.Header.Get("Content-Type")
			backupBody := readBody(resp.Body, 32*1024)
			resp.Body.Close()
			backupHash := hashBody(backupBody)

			if entry.originalURL == "" {
				// Fixed backup path: no original to compare; skip 200 responses.
				continue
			}

			orig := fetchOriginal(ctx, entry.originalURL, origCache, target.HTTP)
			if orig == nil {
				// Cannot verify without original; skip to avoid false positives.
				continue
			}

			// Content-type check: mismatched primary types are a hard skip.
			origPrimary := primaryContentType(orig.contentType)
			backupPrimary := primaryContentType(backupCT)
			if origPrimary != "" && backupPrimary != "" && origPrimary != backupPrimary {
				continue
			}

			// Identical content.
			if backupHash == orig.hash {
				findings = append(findings, c.makeFinding(
					entry.probeURL, entry.originalURL, status,
					"identical", backupBody, 1.0, backupHash,
				))
				continue
			}

			// Similar content by Jaccard token overlap.
			score := jaccardSimilarity(tokenize(orig.body), tokenize(backupBody))
			if score >= 0.5 {
				findings = append(findings, c.makeFinding(
					entry.probeURL, entry.originalURL, status,
					fmt.Sprintf("similar:%.2f", score), backupBody, score, backupHash,
				))
			}
			// Jaccard < 0.5: unrelated content (error page, etc.) — skip.
		}
	}
	return findings, nil
}

// makeFinding builds a Finding for a confirmed backup file.
// verifiedBy is one of "identical", "similar:0.73", or "protected".
func (c *BackupsCheck) makeFinding(
	probeURL, originalURL string,
	status int,
	verifiedBy string,
	backupBody []byte,
	jaccardScore float64,
	backupHash string,
) *checks.Finding {
	var confidence checks.Confidence
	switch {
	case verifiedBy == "identical":
		confidence = checks.ConfidenceConfirmed
	case strings.HasPrefix(verifiedBy, "similar") || verifiedBy == "protected":
		confidence = checks.ConfidenceFirm
	default:
		confidence = checks.ConfidenceTentative
	}

	var origHash string
	var origURLDisplay string
	if originalURL != "" {
		origURLDisplay = " against original " + originalURL
	}

	ev := &checks.Evidence{
		ResponseStatus: status,
		ResponseBytes:  excerpt(backupBody, 200),
		OriginalURL:    originalURL,
		BackupBodyHash: backupHash,
		JaccardScore:   jaccardScore,
	}
	if originalURL != "" {
		// origHash is computed inside fetchOriginal and not easily accessible here;
		// the BackupBodyHash field is already set above and the description covers
		// the original hash when verifiedBy == "identical".
		_ = origHash
	}

	return &checks.Finding{
		CheckID:    c.ID(),
		Severity:   checks.SeverityMedium,
		Confidence: confidence,
		Title:      fmt.Sprintf("Backup file accessible at %s", probeURL),
		Description: fmt.Sprintf(
			"A backup or swap copy of a source file appears to be accessible at %s "+
				"(HTTP %d). Verified by %s%s. "+
				"Backup files can expose source code, credentials, database connection strings, "+
				"and configuration secrets.",
			probeURL, status, verifiedBy, origURLDisplay,
		),
		URL:      probeURL,
		Evidence: ev,
	}
}

// fetchOriginal returns the cached originalMeta for rawURL, fetching if needed.
// Returns nil when the fetch fails or returns a non-200 status.
func fetchOriginal(ctx context.Context, rawURL string, cache map[string]*originalMeta, client *internalhttp.Client) *originalMeta {
	if meta, ok := cache[rawURL]; ok {
		return meta // may be nil (cached failure)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		cache[rawURL] = nil
		return nil
	}
	resp, err := client.Do(ctx, req)
	if err != nil {
		cache[rawURL] = nil
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		cache[rawURL] = nil
		return nil
	}
	body := readBody(resp.Body, 32*1024)
	meta := &originalMeta{
		body:        body,
		contentType: resp.Header.Get("Content-Type"),
		hash:        hashBody(body),
	}
	cache[rawURL] = meta
	return meta
}

// hashBody returns the hex SHA-256 of up to 32 KB of body.
func hashBody(body []byte) string {
	const limit = 32 * 1024
	if len(body) > limit {
		body = body[:limit]
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// primaryContentType extracts the primary content type, stripping parameters
// such as "; charset=utf-8". Returns lowercase result.
func primaryContentType(ct string) string {
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.ToLower(strings.TrimSpace(ct))
}

// tokenize splits body into lowercase alphanumeric tokens, deduped.
// Stops once the token set reaches 5000 entries.
func tokenize(body []byte) map[string]struct{} {
	const maxTokens = 5000
	tokens := make(map[string]struct{})
	fields := bytes.FieldsFunc(body, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
	for _, f := range fields {
		if len(tokens) >= maxTokens {
			break
		}
		tokens[strings.ToLower(string(f))] = struct{}{}
	}
	return tokens
}

// jaccardSimilarity computes the Jaccard index between two token sets.
func jaccardSimilarity(a, b map[string]struct{}) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1.0
	}
	intersection := 0
	for k := range a {
		if _, ok := b[k]; ok {
			intersection++
		}
	}
	union := len(a) + len(b) - intersection
	if union == 0 {
		return 1.0
	}
	return float64(intersection) / float64(union)
}

// buildShellHashes returns a map from host to the most-common body_hash among
// 200-status URLs for that host. Only hashes appearing more than once are
// treated as a soft-200 SPA shell catch-all.
func buildShellHashes(inv *crawler.Inventory) map[string]string {
	counts := make(map[string]map[string]int)
	for _, du := range inv.URLs {
		if du.ResponseStatus != 200 || du.BodyHash == "" {
			continue
		}
		host := urlHost(du.URL)
		if counts[host] == nil {
			counts[host] = make(map[string]int)
		}
		counts[host][du.BodyHash]++
	}
	shells := make(map[string]string)
	for host, hashCounts := range counts {
		maxCount, maxHash := 0, ""
		for hash, count := range hashCounts {
			if count > maxCount {
				maxCount = count
				maxHash = hash
			}
		}
		if maxCount > 1 {
			shells[host] = maxHash
		}
	}
	return shells
}

// urlHost extracts the host (without scheme or path) from a URL string.
func urlHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return rawURL
	}
	return u.Host
}

// originSet returns the set of unique scheme://host origins from the inventory
// and seed URLs.
func originSet(inv *crawler.Inventory, seeds []string) map[string]struct{} {
	origins := make(map[string]struct{})
	add := func(rawURL string) {
		u, err := url.Parse(rawURL)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return
		}
		origins[u.Scheme+"://"+u.Host] = struct{}{}
	}
	for _, s := range seeds {
		add(s)
	}
	if inv != nil {
		for _, du := range inv.URLs {
			add(du.URL)
		}
	}
	return origins
}
