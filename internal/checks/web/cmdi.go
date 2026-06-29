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
	"time"

	"github.com/osintph/suri/internal/checks"
)

// CMDiCheck probes for OS command injection using time-based detection only.
// No output is extracted and no destructive commands are run. A sleep payload
// is injected; if the response takes significantly longer than the baseline,
// command injection is likely.
type CMDiCheck struct {
	// TimingThresholdMs is the minimum extra response time in milliseconds that
	// triggers a finding. Zero uses the default (4000 ms).
	TimingThresholdMs int64
}

func (c *CMDiCheck) ID() string                { return "web.cmdi" }
func (c *CMDiCheck) Name() string              { return "Command Injection" }
func (c *CMDiCheck) Severity() checks.Severity { return checks.SeverityHigh }
func (c *CMDiCheck) Category() checks.Category { return checks.CategoryWeb }

func (c *CMDiCheck) threshold() time.Duration {
	if c.TimingThresholdMs > 0 {
		return time.Duration(c.TimingThresholdMs) * time.Millisecond
	}
	return 4 * time.Second
}

// Run iterates over discovered parameters and probes each with timing-based
// command injection payloads.
func (c *CMDiCheck) Run(ctx context.Context, target *checks.Target) ([]*checks.Finding, error) {
	payloads := filterPayloads("cmdi")
	if len(payloads) == 0 || target.Inventory == nil {
		return nil, nil
	}

	threshold := c.threshold()
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

		// Baseline
		baseReq, err := buildProbeReq(ctx, param, "baseline")
		if err != nil {
			continue
		}
		t0 := time.Now()
		baseResp, err := target.HTTP.Do(ctx, baseReq)
		if err != nil {
			continue
		}
		baseResp.Body.Close()
		baseline := time.Since(t0)

		for _, p := range payloads {
			sleepSecs := p.SleepSecs
			if sleepSecs <= 0 {
				sleepSecs = 5
			}
			injected := applyPlaceholders(p.Payload, "", sleepSecs)
			req, err := buildProbeReq(ctx, param, injected)
			if err != nil {
				continue
			}
			t1 := time.Now()
			resp, err := target.HTTP.Do(ctx, req)
			if err != nil {
				continue
			}
			resp.Body.Close()
			elapsed := time.Since(t1)

			if elapsed < baseline+threshold {
				continue
			}

			confirmed[key] = true
			findings = append(findings, &checks.Finding{
				CheckID:    c.ID(),
				Severity:   checks.SeverityHigh,
				Confidence: checks.ConfidenceConfirmed,
				Title:      fmt.Sprintf("Command injection (time-based) in parameter %q at %s", param.Name, param.InjectURL),
				Description: fmt.Sprintf(
					"The parameter %q at %s causes a measurable response delay (%v vs baseline %v) "+
						"when injected with an OS sleep command via payload %q. "+
						"This indicates the parameter value is passed to a shell without sanitization.",
					param.Name, param.InjectURL, elapsed.Round(time.Millisecond), baseline.Round(time.Millisecond), p.Payload,
				),
				URL:       param.InjectURL,
				Parameter: param.Name,
				CWE:       "CWE-78",
				OWASP:     "A03:2021",
				Evidence: &checks.Evidence{
					ResponseTimeMs: elapsed.Milliseconds(),
				},
			})
			break
		}
	}
	return findings, nil
}
