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
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/osintph/suri/internal/checks"
	"github.com/osintph/suri/internal/crawler"
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
//     are skipped; probing their .bak variants is guaranteed to return the same
//     shell anyway.
//   - Total probes across the scan are capped at MaxProbes (default 200). A
//     warning is logged when the cap is reached.
//
// This check deliberately does NOT duplicate entries in the interesting-paths
// catalogue (Session 5.9). It only probes variants derived from inventory URLs
// and a complementary fixed list.
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
// each origin. These are NOT in the interesting-paths catalogue.
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

// Run probes backup variants of discovered URLs and fixed backup paths.
func (c *BackupsCheck) Run(ctx context.Context, target *checks.Target) ([]*checks.Finding, error) {
	if target.Inventory == nil {
		return nil, nil
	}

	maxProbes := c.maxProbesOrDefault()

	// Build per-host SPA shell hash: the most-common body_hash for 200-status
	// URLs on each host. URLs matching this hash are SPA catch-all responses and
	// their .bak variants are guaranteed to return the same shell (not real files).
	shellHashes := buildShellHashes(target.Inventory)

	// Collect the candidate URLs to derive backup probes from, tracking which
	// origins have at least one valid candidate. Fixed backup paths are only
	// added for origins with a valid candidate to avoid probing completely
	// unknown/unreachable targets.
	var candidates []string
	activeOrigins := make(map[string]struct{})
	for _, du := range target.Inventory.URLs {
		status := du.ResponseStatus
		// Only probe real routes: 200, 401, 403. 0 means not fetched.
		if status != 200 && status != 401 && status != 403 {
			continue
		}
		// Skip SPA shell responses (same content for every path).
		if status == 200 && du.BodyHash != "" {
			host := urlHost(du.URL)
			if shellHashes[host] == du.BodyHash {
				continue
			}
		}
		candidates = append(candidates, du.URL)
		origin := ""
		if u, err := url.Parse(du.URL); err == nil && u.Scheme != "" && u.Host != "" {
			origin = u.Scheme + "://" + u.Host
		}
		if origin != "" {
			activeOrigins[origin] = struct{}{}
		}
	}

	// Collect all probe URLs (inventory-derived + fixed list) before probing so
	// we can apply the cap cleanly.
	seen := make(map[string]bool)
	var toProbe []string

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
				toProbe = append(toProbe, probeURL)
			}
		}
	}

	// Fixed backup paths per origin, but only for origins that had at least one
	// valid candidate URL. Probing fixed paths for origins with no valid routes
	// defeats the DoS-prevention purpose of the status filter.
	for origin := range activeOrigins {
		for _, fp := range fixedBackupPaths {
			probeURL := origin + "/" + fp
			if !seen[probeURL] {
				seen[probeURL] = true
				toProbe = append(toProbe, probeURL)
			}
		}
	}

	// Apply the cap.
	if len(toProbe) > maxProbes {
		slog.Warn("backup probe cap reached, some URLs not probed",
			"total_candidates", len(toProbe),
			"cap", maxProbes,
			"skipped", len(toProbe)-maxProbes,
		)
		toProbe = toProbe[:maxProbes]
	}

	var findings []*checks.Finding
	for _, probeURL := range toProbe {
		if ctx.Err() != nil {
			break
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
		if err != nil {
			continue
		}
		resp, err := target.HTTP.Do(ctx, req)
		if err != nil {
			continue
		}
		body := readBody(resp.Body, 4096)
		resp.Body.Close()

		status := resp.StatusCode
		if status == http.StatusNotFound {
			continue
		}
		if status >= 300 && status < 400 {
			continue
		}

		var severity checks.Severity
		var confidence checks.Confidence
		if status == http.StatusUnauthorized || status == http.StatusForbidden || status >= 500 {
			severity = checks.SeverityMedium
			confidence = checks.ConfidenceFirm
		} else if status == http.StatusOK {
			severity = checks.SeverityMedium
			confidence = checks.ConfidenceTentative
		} else {
			continue
		}

		findings = append(findings, &checks.Finding{
			CheckID:    c.ID(),
			Severity:   severity,
			Confidence: confidence,
			Title:      fmt.Sprintf("Backup file accessible at %s", probeURL),
			Description: fmt.Sprintf(
				"A backup or swap copy of a source file appears to be accessible at %s "+
					"(HTTP %d). Backup files can expose source code, credentials, database "+
					"connection strings, and configuration secrets.",
				probeURL, status,
			),
			URL: probeURL,
			Evidence: &checks.Evidence{
				ResponseStatus: status,
				ResponseBytes:  excerpt(body, 200),
			},
		})
	}
	return findings, nil
}

// buildShellHashes returns a map from host to the most-common body_hash among
// 200-status URLs for that host. Only hashes appearing more than once are
// treated as a soft-200 SPA shell.
func buildShellHashes(inv *crawler.Inventory) map[string]string {
	// host → (hash → count)
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
		maxCount := 0
		maxHash := ""
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

// urlHost extracts the scheme+host (no path) from a URL string.
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
