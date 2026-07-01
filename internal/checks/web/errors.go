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
	"regexp"

	"github.com/osintph/suri/internal/checks"
)

type errorSignature struct {
	lang    string
	pattern *regexp.Regexp
}

var stackTraceSignatures = []errorSignature{
	{"Ruby", regexp.MustCompile(`(?m)^\s+from .+?:\d+:in ` + "`" + `.+?'`)},
	{"Ruby", regexp.MustCompile(`NoMethodError:`)},
	{"Rails", regexp.MustCompile(`ActionController::RoutingError`)},
	{"Rails", regexp.MustCompile(`ActiveRecord::`)},
	{"Python", regexp.MustCompile(`Traceback \(most recent call last\):`)},
	{"Python", regexp.MustCompile(`File ".+?", line \d+`)},
	{"Java", regexp.MustCompile(`\s+at [a-z]+(\.[a-zA-Z0-9_$]+)+\(`)},
	{"Java", regexp.MustCompile(`Exception in thread`)},
	{"PHP", regexp.MustCompile(`Fatal error:`)},
	{"PHP", regexp.MustCompile(`Stack trace:`)},
	{"Node.js", regexp.MustCompile(`TypeError:`)},
	{"Node.js", regexp.MustCompile(`ReferenceError:`)},
	{"Node.js", regexp.MustCompile(`at Object\.<anonymous>`)},
}

// ErrorCheck fetches seed URLs and 5xx inventory URLs looking for server-side
// stack traces or error messages in the response body.
type ErrorCheck struct{}

func (c *ErrorCheck) ID() string                { return "web.error.stack-trace" }
func (c *ErrorCheck) Name() string              { return "Application Error Disclosure" }
func (c *ErrorCheck) Severity() checks.Severity { return checks.SeverityMedium }
func (c *ErrorCheck) Category() checks.Category { return checks.CategoryWeb }

func (c *ErrorCheck) Run(ctx context.Context, target *checks.Target) ([]*checks.Finding, error) {
	seen := make(map[string]bool)
	var candidates []string
	for _, u := range target.SeedURLs {
		if !seen[u] {
			seen[u] = true
			candidates = append(candidates, u)
		}
	}
	if target.Inventory != nil {
		for _, du := range target.Inventory.URLs {
			if du.ResponseStatus >= 500 && !seen[du.URL] {
				seen[du.URL] = true
				candidates = append(candidates, du.URL)
			}
		}
	}

	var findings []*checks.Finding
	emitted := make(map[string]bool)

	for _, rawURL := range candidates {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			continue
		}
		resp, err := target.HTTP.Do(ctx, req)
		if err != nil {
			continue
		}
		body := readBody(resp.Body, 256*1024)
		resp.Body.Close()

		if resp.StatusCode < 500 {
			continue
		}

		for _, sig := range stackTraceSignatures {
			if !sig.pattern.Match(body) {
				continue
			}
			key := rawURL + "|" + sig.lang
			if emitted[key] {
				continue
			}
			emitted[key] = true
			findings = append(findings, &checks.Finding{
				CheckID:    c.ID(),
				Severity:   checks.SeverityMedium,
				Confidence: checks.ConfidenceConfirmed,
				Title:      fmt.Sprintf("Application error disclosure (%s stack trace) at %s", sig.lang, rawURL),
				Description: fmt.Sprintf(
					"A %s stack trace or error message was found in the response body at %s "+
						"(HTTP %d). Stack traces disclose internal file paths, class names, and "+
						"library versions that assist attackers in crafting targeted exploits.",
					sig.lang, rawURL, resp.StatusCode,
				),
				URL:   rawURL,
				CWE:   "CWE-209",
				OWASP: "A05:2021",
				Evidence: &checks.Evidence{
					ResponseStatus: resp.StatusCode,
					ResponseBytes:  excerpt(body, 2048),
				},
			})
			break
		}
	}
	return findings, nil
}
