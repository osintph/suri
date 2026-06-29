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
	"strings"
	"sync"

	"github.com/osintph/suri/internal/checks"
	"github.com/osintph/suri/internal/crawler"
	"github.com/osintph/suri/internal/wordlists"
)

// probeTier distinguishes between the two wordlist tiers used by the admin check.
// Severity and confidence differ by tier; the underlying HTTP probing is identical.
type probeTier int

const (
	// tierInteresting probes paths from interesting-paths.txt (always vendored).
	// Any response other than 404 is emitted as medium/firm: these paths carry
	// inherent security significance regardless of response shape.
	tierInteresting probeTier = iota

	// tierCommon probes paths from admin-common.txt (tiered: user > cached > vendored).
	// 200 responses are info/tentative; 401/403/5xx are info/firm. Servers that
	// return 200 for every unknown path produce thousands of info/tentative findings,
	// which are suppressed from the default summary by --include-info=false.
	tierCommon
)

// AdminCheck probes a target's common admin and sensitive paths using two wordlists.
// WordlistPath overrides the admin-common.txt tier (user > cached > vendored) only.
// The interesting-paths.txt wordlist is always loaded from the vendored copy.
type AdminCheck struct {
	WordlistPath string
}

func (c *AdminCheck) ID() string                { return "admin.path.discovered" }
func (c *AdminCheck) Name() string              { return "Admin Path Discovered" }
func (c *AdminCheck) Severity() checks.Severity { return checks.SeverityMedium }
func (c *AdminCheck) Category() checks.Category { return checks.CategoryAdmin }

// Run probes each wordlist entry against all origins derived from the target.
// Interesting paths are probed first (medium/firm on any non-404 response).
// Common admin paths follow (info/tentative on 200, info/firm on 401/403/5xx).
// Every probed URL is added to the inventory for operator audit.
func (c *AdminCheck) Run(ctx context.Context, target *checks.Target) ([]*checks.Finding, error) {
	interestingWL, err := wordlists.LoadVendored(wordlists.InterestingPaths)
	if err != nil {
		return nil, fmt.Errorf("loading interesting paths wordlist: %w", err)
	}

	commonWL, err := wordlists.Load(wordlists.AdminCommon, c.WordlistPath)
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

	interestingSource := interestingWL.Source.String()
	commonSource := commonWL.Source.String()

	dispatch := func(pu, wlSource string, tier probeTier) {
		if target.Inventory != nil {
			target.Inventory.URLs = append(target.Inventory.URLs, &crawler.DiscoveredURL{
				URL:    pu,
				Source: "admin-probe",
				Depth:  0,
			})
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		sem <- struct{}{}
		wg.Add(1)
		go func(u, src string, t probeTier) {
			defer wg.Done()
			defer func() { <-sem }()
			f := probeAdminPath(ctx, target, u, src, t)
			if f != nil {
				mu.Lock()
				findings = append(findings, f)
				mu.Unlock()
			}
		}(pu, wlSource, tier)
	}

	for _, origin := range origins {
		for _, path := range interestingWL.Entries {
			probeURL := strings.TrimRight(origin, "/") + "/" + strings.TrimLeft(path, "/")
			dispatch(probeURL, interestingSource, tierInteresting)
		}
	}

	for _, origin := range origins {
		for _, path := range commonWL.Entries {
			probeURL := strings.TrimRight(origin, "/") + "/" + strings.TrimLeft(path, "/")
			dispatch(probeURL, commonSource, tierCommon)
		}
	}

	wg.Wait()
	slog.Debug("admin check complete",
		"findings", len(findings),
		"origins", len(origins),
		"interesting_paths", len(interestingWL.Entries),
		"common_paths", len(commonWL.Entries),
	)
	return findings, nil
}

// probeAdminPath makes a single GET request and returns a Finding if the
// response is interesting for the given tier.
func probeAdminPath(ctx context.Context, target *checks.Target, rawURL, wlSource string, tier probeTier) *checks.Finding {
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

	// 404 is always skipped: the path does not exist.
	if status == http.StatusNotFound {
		return nil
	}

	switch tier {
	case tierInteresting:
		// Every non-404 response on an interesting path is noteworthy regardless
		// of content or response shape. No soft-200 detection is attempted.
		return buildFinding(rawURL, status, body, wlSource, tier)

	case tierCommon:
		// Skip redirects for common paths. The HTTP client follows redirects, so
		// a 3xx here means the redirect chain terminated early (e.g. out-of-scope
		// destination). Either way, not interesting enough to emit.
		if status >= 300 && status < 400 {
			return nil
		}
		return buildFinding(rawURL, status, body, wlSource, tier)
	}

	return nil
}

// buildFinding constructs a Finding for an interesting admin path response.
// Severity and confidence depend on the probe tier.
func buildFinding(rawURL string, status int, body []byte, wlSource string, tier probeTier) *checks.Finding {
	var severity checks.Severity
	var confidence checks.Confidence
	var title, description string

	switch tier {
	case tierInteresting:
		severity = checks.SeverityMedium
		confidence = checks.ConfidenceFirm
		switch {
		case status == http.StatusOK:
			title = "Sensitive file or directory accessible"
			description = fmt.Sprintf(
				"A sensitive path responded with HTTP 200 OK at %s. "+
					"The path is security-relevant and its presence should be reviewed.",
				rawURL,
			)
		case status == http.StatusUnauthorized || status == http.StatusForbidden:
			title = "Sensitive file exists (access restricted)"
			description = fmt.Sprintf(
				"A sensitive path responded with HTTP %d at %s. "+
					"The path exists but is access-restricted, confirming it is present on this server.",
				status, rawURL,
			)
		case status >= 500:
			title = "Sensitive path caused server error"
			description = fmt.Sprintf(
				"A sensitive path responded with HTTP %d at %s. "+
					"A server error on this path may indicate it is handled but misconfigured.",
				status, rawURL,
			)
		default:
			title = "Sensitive path responded"
			description = fmt.Sprintf(
				"A sensitive path at %s responded with HTTP %d. Manual review is recommended.",
				rawURL, status,
			)
		}

	case tierCommon:
		switch {
		case status == http.StatusOK:
			severity = checks.SeverityInfo
			confidence = checks.ConfidenceTentative
			title = "Admin path responded with 200"
			description = fmt.Sprintf(
				"Path %s returned HTTP 200. No further analysis was performed. "+
					"Servers that return 200 for all unknown paths will produce many findings of this type; "+
					"use --include-info to view them or omit it to suppress them from the summary.",
				rawURL,
			)
		case status == http.StatusUnauthorized || status == http.StatusForbidden:
			severity = checks.SeverityInfo
			confidence = checks.ConfidenceFirm
			title = "Admin path restricted"
			description = fmt.Sprintf(
				"Admin or sensitive path responded with HTTP %d at %s (path exists, access restricted).",
				status, rawURL,
			)
		default:
			severity = checks.SeverityInfo
			confidence = checks.ConfidenceFirm
			title = "Admin path responded"
			description = fmt.Sprintf(
				"Admin or sensitive path responded with HTTP %d at %s.",
				status, rawURL,
			)
		}
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
