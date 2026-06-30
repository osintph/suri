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

// SSTICheck probes discovered parameters for server-side template injection
// by injecting arithmetic expressions and looking for evaluated output.
// The canary prefix ensures the evaluated result is traceable to this probe
// and not a coincidental occurrence of "49" in the original response.
type SSTICheck struct{}

func (c *SSTICheck) ID() string                { return "web.ssti" }
func (c *SSTICheck) Name() string              { return "Server-Side Template Injection" }
func (c *SSTICheck) Severity() checks.Severity { return checks.SeverityHigh }
func (c *SSTICheck) Category() checks.Category { return checks.CategoryWeb }

// Run iterates over discovered parameters and probes each with SSTI payloads.
func (c *SSTICheck) Run(ctx context.Context, target *checks.Target) ([]*checks.Finding, error) {
	payloads := filterPayloads("ssti")
	if len(payloads) == 0 || target.Inventory == nil {
		return nil, nil
	}

	canary := target.Canary
	if canary == "" {
		canary = checks.GenerateCanary()
	}

	var findings []*checks.Finding
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
			expectedSignal := applySignalPlaceholders(p.ExpectedSignal, canary)

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

			// The evaluated signal must appear in the response body.
			if expectedSignal == "" || !strings.Contains(string(body), expectedSignal) {
				continue
			}

			confirmed[key] = true
			actualURL := findingInjectURL(param, injected)
			findings = append(findings, &checks.Finding{
				CheckID:    c.ID(),
				Severity:   checks.SeverityHigh,
				Confidence: checks.ConfidenceConfirmed,
				Title:      fmt.Sprintf("Server-side template injection in parameter %q at %s", param.Name, actualURL),
				Description: fmt.Sprintf(
					"The parameter %q at %s evaluates the arithmetic expression %q injected via "+
						"payload %q. The expected signal %q was found in the response, confirming "+
						"that the server-side template engine evaluates user input. SSTI can lead "+
						"to remote code execution depending on the template engine and server context.",
					param.Name, actualURL, "7*7", p.Payload, expectedSignal,
				),
				URL:       actualURL,
				Parameter: param.Name,
				CWE:       "CWE-94",
				OWASP:     "A03:2021",
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
