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

// notFoundSig records the response signature of a known-missing path.
// Used to detect soft-404 responses (servers that return 200 for all paths).
type notFoundSig struct {
	status  int
	bodyLen int
}

// matches returns true when the given status and body length are consistent
// with the 404 signature, meaning the response is likely a soft-404.
func (sig *notFoundSig) matches(status, bodyLen int) bool {
	if sig == nil {
		return false
	}
	if status != sig.status {
		return false
	}
	// Body length within 5% (minimum 10-byte threshold to avoid false matches on tiny pages).
	// Strictly less-than so that exactly 5% difference is treated as distinct.
	delta := bodyLen - sig.bodyLen
	if delta < 0 {
		delta = -delta
	}
	threshold := sig.bodyLen * 5 / 100
	if threshold < 10 {
		threshold = 10
	}
	return delta < threshold
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
// It establishes a per-origin 404 signature first to suppress soft-404 false positives.
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

	for _, origin := range origins {
		sig := probe404Sig(ctx, target, origin)

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
				f := probeAdminPath(ctx, target, pu, sig, wl.Source.String())
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
// response is interesting (not a 404 or soft-404).
func probeAdminPath(ctx context.Context, target *checks.Target, rawURL string, sig *notFoundSig, wlSource string) *checks.Finding {
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
	bodyLen := len(body)

	// Skip genuine 404s.
	if status == http.StatusNotFound {
		return nil
	}
	// Skip redirects (3xx) to avoid chasing redirect chains.
	if status >= 300 && status < 400 {
		return nil
	}
	// Skip soft-404s.
	if sig.matches(status, bodyLen) {
		return nil
	}

	return buildFinding(rawURL, status, body, wlSource)
}

// buildFinding constructs a Finding for an interesting admin path response.
func buildFinding(rawURL string, status int, body []byte, wlSource string) *checks.Finding {
	var severity checks.Severity
	var title, description string

	switch {
	case status == http.StatusOK:
		severity = checks.SeverityMedium
		title = "Admin path accessible"
		description = fmt.Sprintf("Admin or sensitive path responded with HTTP 200 OK at %s.", rawURL)
	case status == http.StatusForbidden || status == http.StatusUnauthorized:
		severity = checks.SeverityInfo
		title = "Admin path restricted"
		if status == http.StatusForbidden {
			description = fmt.Sprintf("Admin or sensitive path responded with HTTP 403 Forbidden at %s (path exists, access denied).", rawURL)
		} else {
			description = fmt.Sprintf("Admin or sensitive path responded with HTTP 401 Unauthorized at %s (path exists, authentication required).", rawURL)
		}
	default:
		severity = checks.SeverityInfo
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
		Confidence:     checks.ConfidenceFirm,
		Evidence:       evidence,
		WordlistSource: wlSource,
	}
}

// probe404Sig establishes the 404 signature for a given origin by probing a path
// that is extremely unlikely to exist.
func probe404Sig(ctx context.Context, target *checks.Target, origin string) *notFoundSig {
	probeURL := strings.TrimRight(origin, "/") + "/suri-probe-nonexistent-e3b0c442"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return nil
	}
	resp, err := target.HTTP.Do(ctx, req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	return &notFoundSig{status: resp.StatusCode, bodyLen: len(body)}
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
