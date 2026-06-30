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
	"strings"

	"github.com/osintph/suri/internal/checks"
)

// XSSCheck probes discovered parameters for reflected cross-site scripting.
// It injects canary-tagged payloads and confirms the finding only when the
// unencoded canary appears in the response body (indicating direct HTML
// reflection without entity-encoding).
type XSSCheck struct{}

func (c *XSSCheck) ID() string                { return "web.xss.reflected" }
func (c *XSSCheck) Name() string              { return "Reflected XSS" }
func (c *XSSCheck) Severity() checks.Severity { return checks.SeverityHigh }
func (c *XSSCheck) Category() checks.Category { return checks.CategoryWeb }

// Run iterates over discovered parameters and probes each with XSS payloads.
func (c *XSSCheck) Run(ctx context.Context, target *checks.Target) ([]*checks.Finding, error) {
	payloads := filterPayloads("xss")
	if len(payloads) == 0 || target.Inventory == nil {
		return nil, nil
	}

	canary := target.Canary
	if canary == "" {
		canary = checks.GenerateCanary()
	}

	var findings []*checks.Finding
	// Track (paramName, injectURL) pairs we have already found to avoid emitting
	// duplicate findings for the same injection point.
	confirmed := make(map[string]bool)

	for _, param := range target.Inventory.Parameters {
		if param.Source == "header" || param.InjectURL == "" {
			continue
		}
		key := param.InjectURL + "|" + param.Name
		if confirmed[key] {
			continue
		}

		for _, p := range payloads {
			injected := applyPlaceholders(p.Payload, canary, 0)

			req, err := buildProbeReq(ctx, param, injected)
			if err != nil {
				continue
			}
			resp, err := target.HTTP.Do(ctx, req)
			if err != nil {
				continue
			}
			body := readBody(resp.Body, 512*1024)
			resp.Body.Close()

			// Confirmed only when the canary appears unencoded in the response.
			// HTML-encoded canary (e.g. &lt;svg&gt;) means the app escapes output.
			if !strings.Contains(string(body), canary) {
				continue
			}

			confirmed[key] = true
			actualURL := findingInjectURL(param, injected)
			findings = append(findings, &checks.Finding{
				CheckID:    c.ID(),
				Severity:   checks.SeverityHigh,
				Confidence: checks.ConfidenceConfirmed,
				Title:      fmt.Sprintf("Reflected XSS in parameter %q at %s", param.Name, actualURL),
				Description: fmt.Sprintf(
					"The parameter %q at %s reflects user input unencoded into the HTML response. "+
						"The canary token %q was found verbatim in the response body after injecting "+
						"the payload. This indicates the application outputs the parameter value "+
						"without HTML entity-encoding, allowing arbitrary script execution.",
					param.Name, actualURL, canary,
				),
				URL:       actualURL,
				Parameter: param.Name,
				CWE:       "CWE-79",
				OWASP:     "A03:2021",
				Evidence: &checks.Evidence{
					ResponseStatus: resp.StatusCode,
					ResponseBytes:  excerpt(body, 2048),
				},
			})
			break // one finding per parameter; skip remaining payloads
		}
	}
	return findings, nil
}
