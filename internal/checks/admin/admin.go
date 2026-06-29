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

// Package admin implements admin panel and sensitive path discovery.
package admin

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/osintph/suri/internal/checks"
	"github.com/osintph/suri/internal/crawler"
	"github.com/osintph/suri/internal/wordlists"
)

// softResponsePatterns identifies 200 responses that are soft-404s: the server
// returns 200 for paths that do not exist, producing recognisable framework-
// specific markup. The first 4 KB of the body is checked for speed.
var softResponsePatterns = []*regexp.Regexp{
	regexp.MustCompile(`<title>Error:\s*Unexpected\s*path`), // Express error page
	regexp.MustCompile(`Cannot\s+(GET|POST|PUT|DELETE)\s+/`), // Express bare error
	regexp.MustCompile(`<app-root></app-root>`),              // Angular SPA shell
	regexp.MustCompile(`<div\s+id="root"></div>`),            // React SPA shell
	regexp.MustCompile(`<div\s+id="app"></div>`),             // Vue SPA shell
	regexp.MustCompile(`__NEXT_DATA__`),                      // Next.js
	regexp.MustCompile(`<title>404[^<]*</title>`),            // generic 404 page title
	regexp.MustCompile(`<title>Page\s+Not\s+Found</title>`),
	regexp.MustCompile(`<title>Not\s+Found</title>`),
}

// isSoftResponse returns true when the body matches any known framework
// soft-404 pattern. Only the first 4 KB is examined.
func isSoftResponse(body []byte) bool {
	preview := body
	if len(preview) > 4096 {
		preview = preview[:4096]
	}
	for _, re := range softResponsePatterns {
		if re.Match(preview) {
			return true
		}
	}
	return false
}

// AdminCheck probes a target's common admin and sensitive paths using a wordlist.
// WordlistPath overrides the default tier-based loader when non-empty.
type AdminCheck struct {
	WordlistPath string
}

func (c *AdminCheck) ID() string                { return "admin.path.discovered" }
func (c *AdminCheck) Name() string              { return "Admin Path Discovered" }
func (c *AdminCheck) Severity() checks.Severity { return checks.SeverityMedium }
func (c *AdminCheck) Category() checks.Category { return checks.CategoryAdmin }

// Run probes each admin wordlist entry against all origins derived from the target.
// Soft-404 suppression is done per-response using content fingerprinting; no
// calibration probes are made before wordlist probing starts.
func (c *AdminCheck) Run(ctx context.Context, target *checks.Target) ([]*checks.Finding, error) {
	wl, err := wordlists.Load(wordlists.AdminCommon, c.WordlistPath)
	if err != nil {
		return nil, fmt.Errorf("loading admin wordlist: %w", err)
	}

	origins := uniqueOrigins(target.SeedURLs, target.Inventory)
	if len(origins) == 0 {
		slog.Info("admin: no probe origins found, skipping")
		return nil, nil
	}

	var (
		mu       sync.Mutex
		findings []*checks.Finding
	)

	concurrency := target.Concurrency
	if concurrency <= 0 {
		concurrency = 5
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	wlSource := wl.Source.String()

	for _, origin := range origins {
		for _, path := range wl.Entries {
			select {
			case <-ctx.Done():
				wg.Wait()
				return findings, ctx.Err()
			default:
			}

			probeURL := strings.TrimRight(origin, "/") + "/" + strings.TrimLeft(path, "/")
			sem <- struct{}{}
			wg.Add(1)
			go func(pu string) {
				defer wg.Done()
				defer func() { <-sem }()
				f := probeAdminPath(ctx, target, pu, wlSource)
				if f != nil {
					mu.Lock()
					findings = append(findings, f)
					mu.Unlock()
				}
			}(probeURL)
		}
	}

	wg.Wait()
	slog.Debug("admin check complete", "findings", len(findings), "origins", len(origins), "paths", len(wl.Entries))
	return findings, nil
}

// probeAdminPath makes a single GET request and returns a Finding if the
// response is interesting (not a 404, not a redirect, not a recognised soft-404).
func probeAdminPath(ctx context.Context, target *checks.Target, rawURL, wlSource string) *checks.Finding {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil
	}

	resp, err := target.HTTP.Do(ctx, req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	status := resp.StatusCode

	// Skip genuine 404s.
	if status == http.StatusNotFound {
		return nil
	}
	// Skip redirects to avoid chasing redirect chains.
	if status >= 300 && status < 400 {
		return nil
	}
	// Suppress 200s whose content matches a known framework soft-404 pattern.
	if status == http.StatusOK && isSoftResponse(body) {
		return nil
	}

	return buildFinding(rawURL, status, body, wlSource)
}

// buildFinding constructs a Finding for an interesting admin path response.
// Unmatched 200s get tentative confidence; 401/403 and 5xx get firm confidence.
func buildFinding(rawURL string, status int, body []byte, wlSource string) *checks.Finding {
	var severity checks.Severity
	var confidence checks.Confidence
	var title, description string

	switch {
	case status == http.StatusOK:
		severity = checks.SeverityInfo
		confidence = checks.ConfidenceTentative
		title = "Sensitive path responded with 200"
		description = fmt.Sprintf(
			"Path %s returned HTTP 200. Content did not match any known framework soft-404 pattern; manual review is recommended.",
			rawURL,
		)
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		severity = checks.SeverityMedium
		confidence = checks.ConfidenceFirm
		title = "Admin path restricted"
		if status == http.StatusForbidden {
			description = fmt.Sprintf(
				"Admin or sensitive path responded with HTTP 403 Forbidden at %s (path exists, access denied).",
				rawURL,
			)
		} else {
			description = fmt.Sprintf(
				"Admin or sensitive path responded with HTTP 401 Unauthorized at %s (path exists, authentication required).",
				rawURL,
			)
		}
	default:
		severity = checks.SeverityInfo
		confidence = checks.ConfidenceFirm
		title = "Admin path responded"
		description = fmt.Sprintf("Admin or sensitive path responded with HTTP %d at %s.", status, rawURL)
	}

	evidence := &checks.Evidence{
		ResponseStatus: status,
		ResponseBytes:  body,
	}
	if len(evidence.ResponseBytes) > 4096 {
		evidence.ResponseBytes = evidence.ResponseBytes[:4096]
	}

	return &checks.Finding{
		CheckID:        "admin.path.discovered",
		Severity:       severity,
		Title:          title,
		Description:    description,
		URL:            rawURL,
		Confidence:     confidence,
		Evidence:       evidence,
		WordlistSource: wlSource,
	}
}

// uniqueOrigins extracts unique scheme+host origins from seed URLs and the
// crawl inventory. Origins are returned in the order they are first encountered.
func uniqueOrigins(seedURLs []string, inv *crawler.Inventory) []string {
	seen := make(map[string]bool)
	var result []string

	add := func(rawURL string) {
		u, err := url.Parse(rawURL)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return
		}
		origin := u.Scheme + "://" + u.Host
		if !seen[origin] {
			seen[origin] = true
			result = append(result, origin)
		}
	}

	for _, su := range seedURLs {
		add(su)
	}
	if inv != nil {
		for _, u := range inv.URLs {
			add(u.URL)
		}
	}
	return result
}
