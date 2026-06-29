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

// Three distinct baseline paths are probed before any wordlist probe runs.
// Different path shapes (simple, nested, well-known prefix) trigger different
// server behaviours on frameworks like Express, so together they capture all
// soft-404 templates a host may serve.
const (
	baselinePath1 = "suri-baseline-3c4d5e6f7a8b9c0d"
	baselinePath2 = "suri-baseline-1a2b3c4d5e6f/7a8b9c0d1e2f"
	baselinePath3 = ".well-known/suri-baseline-3a4b5c6d7e8f"
)

// maxSigs is the maximum number of distinct soft-200 templates tracked per host.
const maxSigs = 5

// soft200Sig represents one distinct "not found" response template.
// Servers that return HTTP 200 for every path (soft-404) produce a recognisable
// signature of (status, body length). We track up to maxSigs per host.
type soft200Sig struct {
	status  int
	bodyLen int
}

// matches returns true when the given status and body length are consistent
// with this template, meaning the response is likely a soft-404.
// Body length within 5% (minimum 10-byte floor) is treated as the same template.
// Strictly less-than so that exactly 5% difference is treated as distinct.
func (s soft200Sig) matches(status, bodyLen int) bool {
	if status != s.status {
		return false
	}
	delta := bodyLen - s.bodyLen
	if delta < 0 {
		delta = -delta
	}
	threshold := s.bodyLen * 5 / 100
	if threshold < 10 {
		threshold = 10
	}
	return delta < threshold
}

// hostCache tracks up to maxSigs distinct soft-200 templates per host.
// The cache is populated during the calibration phase and is read-only during
// wordlist probing.
type hostCache struct {
	mu   sync.Mutex
	sigs []soft200Sig
}

// matchesAny reports whether the given response matches any cached template.
// Must be called with mu held.
func (c *hostCache) matchesAny(status, bodyLen int) bool {
	for _, s := range c.sigs {
		if s.matches(status, bodyLen) {
			return true
		}
	}
	return false
}

// tryAdd adds a new template to the cache if it is not already covered and
// the cache has room. Intended for use during calibration only (not thread-safe;
// the cache is not yet shared during calibration).
func (c *hostCache) tryAdd(status, bodyLen int) {
	if len(c.sigs) >= maxSigs {
		return
	}
	if c.matchesAny(status, bodyLen) {
		return
	}
	c.sigs = append(c.sigs, soft200Sig{status: status, bodyLen: bodyLen})
}

// isSoftResponse reports whether the given status and body length match any
// cached soft-200 template. Thread-safe; intended for use during probing.
func (c *hostCache) isSoftResponse(status, bodyLen int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.matchesAny(status, bodyLen)
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
// For each origin, a calibration phase probes three distinct path shapes to seed
// the per-host soft-200 cache before any wordlist probing begins. This catches
// servers that serve different "not found" templates for different path shapes.
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
		// Calibrate the soft-200 cache before any wordlist probing. The three
		// baseline paths use different structural shapes so that servers which
		// return distinct error templates for different path patterns are all
		// captured. Calibration is sequential and completes before goroutines start.
		cache := calibrateBaseline(ctx, target, origin)
		slog.Info("admin: soft-200 baseline calibrated",
			"host", origin,
			"templates", len(cache.sigs))

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
			go func(pu string, c *hostCache) {
				defer wg.Done()
				defer func() { <-sem }()
				f := probeAdminPath(ctx, target, pu, c, wlSource)
				if f != nil {
					mu.Lock()
					findings = append(findings, f)
					mu.Unlock()
				}
			}(probeURL, cache)
		}
	}

	wg.Wait()
	slog.Debug("admin check complete", "findings", len(findings), "origins", len(origins), "paths", len(wl.Entries))
	return findings, nil
}

// probeAdminPath makes a single GET request and returns a Finding if the
// response is interesting (not a 404, not a redirect, not a soft-404).
// The cache is queried but never written during probing; the calibration
// phase has already sealed the set of known soft-200 templates.
func probeAdminPath(ctx context.Context, target *checks.Target, rawURL string, cache *hostCache, wlSource string) *checks.Finding {
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
	// Skip redirects to avoid chasing redirect chains.
	if status >= 300 && status < 400 {
		return nil
	}

	// For 200 responses, check the calibrated cache. A cache hit means this
	// response matches a known soft-404 template; suppress without emitting.
	// 401, 403, and 5xx bypass the cache and are emitted directly.
	if status == http.StatusOK && cache.isSoftResponse(status, bodyLen) {
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

// calibrateBaseline probes three guaranteed-nonexistent paths with distinct
// structural shapes and populates a hostCache with any distinct response
// templates observed. The cache is sealed after this function returns; no
// further writes occur during wordlist probing.
func calibrateBaseline(ctx context.Context, target *checks.Target, origin string) *hostCache {
	cache := &hostCache{}
	for _, p := range []string{baselinePath1, baselinePath2, baselinePath3} {
		probeURL := strings.TrimRight(origin, "/") + "/" + p
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
		if err != nil {
			continue
		}
		resp, err := target.HTTP.Do(ctx, req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()
		cache.tryAdd(resp.StatusCode, len(body))
	}
	return cache
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
