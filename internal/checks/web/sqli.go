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

// SQLiCheck probes for SQL injection via two methods: error-based (pattern
// matching DB error strings) and time-based (sleep payload timing).
// No data is extracted; detection only.
type SQLiCheck struct {
	// TimingThresholdMs is the minimum extra response time in milliseconds
	// needed to flag a time-based finding. Zero uses the default (4000 ms).
	TimingThresholdMs int64
}

func (c *SQLiCheck) ID() string                { return "web.sqli" }
func (c *SQLiCheck) Name() string              { return "SQL Injection" }
func (c *SQLiCheck) Severity() checks.Severity { return checks.SeverityHigh }
func (c *SQLiCheck) Category() checks.Category { return checks.CategoryWeb }

func (c *SQLiCheck) threshold() time.Duration {
	if c.TimingThresholdMs > 0 {
		return time.Duration(c.TimingThresholdMs) * time.Millisecond
	}
	return 4 * time.Second
}

// Run iterates over discovered parameters and probes each with SQLi payloads.
func (c *SQLiCheck) Run(ctx context.Context, target *checks.Target) ([]*checks.Finding, error) {
	if target.Inventory == nil {
		return nil, nil
	}

	errorPayloads := filterPayloads("sqli")
	var errorBased, timingBased []compiledPayload
	for _, p := range errorPayloads {
		switch p.ConfirmationMethod {
		case "error":
			errorBased = append(errorBased, p)
		case "timing":
			timingBased = append(timingBased, p)
		}
	}

	var findings []*checks.Finding
	confirmed := make(map[string]bool)
	threshold := c.threshold()

	for _, param := range target.Inventory.Parameters {
		if param.Source == "header" || param.InjectURL == "" {
			continue
		}
		key := param.InjectURL + "|" + param.Name
		if confirmed[key] {
			continue
		}

		// --- Error-based ---
		for _, p := range errorBased {
			injected := applyPlaceholders(p.Payload, "", 0)
			req, err := buildProbeReq(ctx, param, injected)
			if err != nil {
				continue
			}
			resp, err := target.HTTP.Do(ctx, req)
			if err != nil {
				continue
			}
			body := readBody(resp.Body, 256*1024)
			resp.Body.Close()

			if p.signal == nil || !p.signal.Match(body) {
				continue
			}

			confirmed[key] = true
			findings = append(findings, &checks.Finding{
				CheckID:    "web.sqli.error",
				Severity:   checks.SeverityHigh,
				Confidence: checks.ConfidenceConfirmed,
				Title:      fmt.Sprintf("SQL injection (error-based) in parameter %q at %s", param.Name, param.InjectURL),
				Description: fmt.Sprintf(
					"The parameter %q at %s returns a database error message when injected with "+
						"SQL metacharacters. Error-based injection allows an attacker to enumerate "+
						"schema, extract data, and in some configurations execute commands.",
					param.Name, param.InjectURL,
				),
				URL:       param.InjectURL,
				Parameter: param.Name,
				CWE:       "CWE-89",
				OWASP:     "A03:2021",
				Evidence: &checks.Evidence{
					ResponseStatus: resp.StatusCode,
					ResponseBytes:  excerpt(body, 2048),
				},
			})
			break
		}
		if confirmed[key] {
			continue
		}

		// --- Time-based ---
		// Establish a baseline response time before injecting timing payloads.
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

		for _, p := range timingBased {
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
				CheckID:    "web.sqli.timing",
				Severity:   checks.SeverityHigh,
				Confidence: checks.ConfidenceConfirmed,
				Title:      fmt.Sprintf("SQL injection (time-based) in parameter %q at %s", param.Name, param.InjectURL),
				Description: fmt.Sprintf(
					"The parameter %q at %s causes a measurable response delay (%v vs baseline %v) "+
						"when injected with a sleep-based SQL payload. Time-based blind injection "+
						"allows data extraction character-by-character.",
					param.Name, param.InjectURL, elapsed.Round(time.Millisecond), baseline.Round(time.Millisecond),
				),
				URL:       param.InjectURL,
				Parameter: param.Name,
				CWE:       "CWE-89",
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
