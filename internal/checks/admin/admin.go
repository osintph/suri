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
	_ "embed"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"

	toml "github.com/pelletier/go-toml/v2"

	"github.com/osintph/suri/internal/checks"
	"github.com/osintph/suri/internal/crawler"
	"github.com/osintph/suri/internal/wordlists"
)

//go:embed interesting-paths.toml
var interestingPathsRaw []byte

// rawCatalogueEntry is the TOML wire format for a single interesting-paths entry.
type rawCatalogueEntry struct {
	Path                string   `toml:"path"`
	Description         string   `toml:"description"`
	ContentPatterns     []string `toml:"content_patterns"`
	SeverityIfProtected string   `toml:"severity_if_protected"`
}

type rawCatalogue struct {
	Paths []rawCatalogueEntry `toml:"paths"`
}

// interestingPath is a parsed catalogue entry ready for use at probe time.
type interestingPath struct {
	path        string
	description string
	patterns    []*regexp.Regexp
	severity    checks.Severity // applied to all non-404 findings for this entry
}

// interestingCatalogue is parsed once at package init from interesting-paths.toml.
var interestingCatalogue = mustParseCatalogue()

func mustParseCatalogue() []interestingPath {
	var raw rawCatalogue
	if err := toml.Unmarshal(interestingPathsRaw, &raw); err != nil {
		panic(fmt.Sprintf("admin: corrupted interesting-paths.toml: %v", err))
	}
	result := make([]interestingPath, 0, len(raw.Paths))
	for _, e := range raw.Paths {
		ip := interestingPath{
			path:        e.Path,
			description: e.Description,
			severity:    checks.SeverityMedium,
		}
		if e.SeverityIfProtected != "" {
			ip.severity = checks.Severity(e.SeverityIfProtected)
		}
		for _, p := range e.ContentPatterns {
			re, err := regexp.Compile("(?m)" + p)
			if err != nil {
				// Bad pattern in the embedded catalogue is a programming error.
				// Panic at startup so it is caught immediately in tests and CI.
				panic(fmt.Sprintf("admin: invalid pattern %q in interesting-paths.toml: %v", p, err))
			}
			ip.patterns = append(ip.patterns, re)
		}
		result = append(result, ip)
	}
	return result
}

const interestingCheckID = "admin.path.interesting-exposed"

// AdminCheck probes a target's common admin and sensitive paths using two tiers.
// WordlistPath overrides the admin-common.txt tier only; the interesting-paths
// catalogue is always loaded from the embedded TOML and cannot be overridden.
type AdminCheck struct {
	WordlistPath string
}

func (c *AdminCheck) ID() string                { return "admin.path.discovered" }
func (c *AdminCheck) Name() string              { return "Admin Path Discovered" }
func (c *AdminCheck) Severity() checks.Severity { return checks.SeverityMedium }
func (c *AdminCheck) Category() checks.Category { return checks.CategoryAdmin }

// Run probes each interesting-path catalogue entry then each common admin
// wordlist entry against all origins derived from the target.
//
// Interesting paths: 200 + content pattern match → medium/confirmed (or
// high/confirmed for high-severity entries); 401/403/5xx → firm; 200 without
// pattern match → skip (catches SPA catch-all servers). 404 → skip.
//
// Common paths: 200 → info/tentative; 401/403/5xx → info/firm; 404 → skip.
//
// Every probed URL is added to the inventory regardless of result.
func (c *AdminCheck) Run(ctx context.Context, target *checks.Target) ([]*checks.Finding, error) {
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

	addInventory := func(pu string) {
		if target.Inventory != nil {
			target.Inventory.URLs = append(target.Inventory.URLs, &crawler.DiscoveredURL{
				URL:    pu,
				Source: "admin-probe",
				Depth:  0,
			})
		}
	}

	collect := func(f *checks.Finding) {
		if f != nil {
			mu.Lock()
			findings = append(findings, f)
			mu.Unlock()
		}
	}

	launchInteresting := func(pu string, entry interestingPath) {
		addInventory(pu)
		select {
		case <-ctx.Done():
			return
		default:
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(u string, e interestingPath) {
			defer wg.Done()
			defer func() { <-sem }()
			collect(probeInterestingPath(ctx, target, u, e))
		}(pu, entry)
	}

	launchCommon := func(pu, src string) {
		addInventory(pu)
		select {
		case <-ctx.Done():
			return
		default:
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(u, s string) {
			defer wg.Done()
			defer func() { <-sem }()
			collect(probeCommonPath(ctx, target, u, s))
		}(pu, src)
	}

	commonSource := commonWL.Source.String()

	for _, origin := range origins {
		for _, entry := range interestingCatalogue {
			probeURL := strings.TrimRight(origin, "/") + "/" + strings.TrimLeft(entry.path, "/")
			launchInteresting(probeURL, entry)
		}
	}

	for _, origin := range origins {
		for _, path := range commonWL.Entries {
			probeURL := strings.TrimRight(origin, "/") + "/" + strings.TrimLeft(path, "/")
			launchCommon(probeURL, commonSource)
		}
	}

	wg.Wait()
	slog.Debug("admin check complete",
		"findings", len(findings),
		"origins", len(origins),
		"interesting_paths", len(interestingCatalogue),
		"common_paths", len(commonWL.Entries),
	)
	return findings, nil
}

// probeInterestingPath fetches rawURL and returns a Finding if the response
// is security-relevant for the given catalogue entry.
//
//   - 200 + any content pattern match → severity/confirmed (content verified)
//   - 200, no pattern match → nil (SPA catch-all; body is not the expected file)
//   - 401/403/5xx → severity/firm (path exists, access restricted)
//   - 404, network error → nil
func probeInterestingPath(ctx context.Context, target *checks.Target, rawURL string, entry interestingPath) *checks.Finding {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil
	}
	resp, err := target.HTTP.Do(ctx, req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	status := resp.StatusCode

	if status == http.StatusNotFound {
		return nil
	}

	if status == http.StatusUnauthorized || status == http.StatusForbidden || status >= 500 {
		evidence := &checks.Evidence{
			ResponseStatus: status,
			ResponseBytes:  body,
		}
		if len(evidence.ResponseBytes) > 4096 {
			evidence.ResponseBytes = evidence.ResponseBytes[:4096]
		}
		return &checks.Finding{
			CheckID:    interestingCheckID,
			Severity:   entry.severity,
			Confidence: checks.ConfidenceFirm,
			Title:      entry.description + " exists at " + rawURL + " (access restricted)",
			Description: fmt.Sprintf(
				"%s at %s responded with HTTP %d. The path is present but access is restricted.",
				entry.description, rawURL, status,
			),
			URL:            rawURL,
			Evidence:       evidence,
			WordlistSource: "embedded:interesting-paths.toml",
		}
	}

	if status == http.StatusOK {
		for _, re := range entry.patterns {
			if re.Match(body) {
				excerpt := body
				if len(excerpt) > 200 {
					excerpt = excerpt[:200]
				}
				return &checks.Finding{
					CheckID:    interestingCheckID,
					Severity:   entry.severity,
					Confidence: checks.ConfidenceConfirmed,
					Title:      entry.description + " exposed at " + rawURL,
					Description: fmt.Sprintf(
						"%s confirmed at %s (content pattern verified).",
						entry.description, rawURL,
					),
					URL: rawURL,
					Evidence: &checks.Evidence{
						ResponseStatus: status,
						ResponseBytes:  excerpt,
					},
					WordlistSource: "embedded:interesting-paths.toml",
				}
			}
		}
		// No pattern matched: body is not what we expected (likely SPA catch-all).
		return nil
	}

	// Other 2xx or 3xx are skipped. The HTTP client follows redirects, so a
	// 3xx here typically means the redirect chain ended out-of-scope.
	return nil
}

// probeCommonPath fetches rawURL and returns an info-severity Finding for any
// response other than 404 and redirects.
func probeCommonPath(ctx context.Context, target *checks.Target, rawURL, wlSource string) *checks.Finding {
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

	if status == http.StatusNotFound {
		return nil
	}
	if status >= 300 && status < 400 {
		return nil
	}

	var severity checks.Severity
	var confidence checks.Confidence
	var title, description string

	switch {
	case status == http.StatusOK:
		severity = checks.SeverityInfo
		confidence = checks.ConfidenceTentative
		title = "Admin path responded with 200"
		description = fmt.Sprintf(
			"Path %s returned HTTP 200. No content verification was performed. "+
				"Use --include-info to review findings of this type.",
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
		Confidence:     confidence,
		Title:          title,
		Description:    description,
		URL:            rawURL,
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
