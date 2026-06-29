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
// This check deliberately does NOT duplicate entries in the interesting-paths
// catalogue (Session 5.9). It only probes variants derived from inventory URLs
// and a complementary fixed list.
type BackupsCheck struct{}

func (c *BackupsCheck) ID() string                { return "web.backup.file" }
func (c *BackupsCheck) Name() string              { return "Backup File Exposure" }
func (c *BackupsCheck) Severity() checks.Severity { return checks.SeverityMedium }
func (c *BackupsCheck) Category() checks.Category { return checks.CategoryWeb }

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

	var findings []*checks.Finding
	seen := make(map[string]bool)

	probe := func(probeURL string) {
		if seen[probeURL] {
			return
		}
		seen[probeURL] = true

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
		if err != nil {
			return
		}
		resp, err := target.HTTP.Do(ctx, req)
		if err != nil {
			return
		}
		body := readBody(resp.Body, 4096)
		resp.Body.Close()

		status := resp.StatusCode
		if status == http.StatusNotFound {
			return
		}
		if status >= 300 && status < 400 {
			return
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
			return
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

	// Probe suffixed variants of each discovered URL.
	for _, du := range target.Inventory.URLs {
		u := du.URL
		// Skip non-HTTP URLs, directory-style URLs, or already-probed paths.
		if !strings.HasPrefix(u, "http") {
			continue
		}
		parsed, err := url.Parse(u)
		if err != nil {
			continue
		}
		path := parsed.Path
		if path == "" || strings.HasSuffix(path, "/") {
			continue
		}
		for _, suffix := range backupSuffixes {
			parsed2 := *parsed
			parsed2.Path = path + suffix
			parsed2.RawQuery = ""
			probe(parsed2.String())
		}
	}

	// Probe fixed backup paths against each origin.
	origins := originSet(target.Inventory, target.SeedURLs)
	for origin := range origins {
		for _, fp := range fixedBackupPaths {
			probe(origin + "/" + fp)
		}
	}

	return findings, nil
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
