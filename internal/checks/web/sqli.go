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
	"log/slog"
	"sync"
	"time"

	"github.com/osintph/suri/internal/checks"
)

// SQLiCheck probes for SQL injection via two methods: error-based (pattern
// matching DB error strings) and time-based (sleep payload timing).
// No data is extracted; detection only.
//
// Timing probes are serialised per host via hostLocks: only one sleep payload
// is in-flight per host at a time. This prevents stacking server-side threads
// on timing-vulnerable endpoints when multiple parameters share the same host.
type SQLiCheck struct {
	// TimingThresholdMs is the minimum extra response time in milliseconds
	// needed to flag a time-based finding. Zero uses the default (4000 ms).
	TimingThresholdMs int64

	// hostLocks serialises timing probes per host. Each value is a *sync.Mutex.
	hostLocks sync.Map
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

// getHostLock returns the per-host mutex, creating it on first call.
func (c *SQLiCheck) getHostLock(host string) *sync.Mutex {
	mu, _ := c.hostLocks.LoadOrStore(host, &sync.Mutex{})
	return mu.(*sync.Mutex)
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
			actualURL := findingInjectURL(param, injected)
			findings = append(findings, &checks.Finding{
				CheckID:    "web.sqli.error",
				Severity:   checks.SeverityHigh,
				Confidence: checks.ConfidenceConfirmed,
				Title:      fmt.Sprintf("SQL injection (error-based) in parameter %q at %s", param.Name, actualURL),
				Description: fmt.Sprintf(
					"The parameter %q at %s returns a database error message when injected with "+
						"SQL metacharacters. Error-based injection allows an attacker to enumerate "+
						"schema, extract data, and in some configurations execute commands.",
					param.Name, actualURL,
				),
				URL:       actualURL,
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
		slog.Debug("sqli: timing probe start",
			"url", param.InjectURL, "name", param.Name, "page_url", param.PageURL)

		// Measure baseline using the parameter's original value (same reasoning as
		// cmdi.go). Two measurements, use the smaller to reduce noise.
		originalVal := baselineForParam(param)
		baseReq1, err := buildProbeReq(ctx, param, originalVal)
		if err != nil {
			continue
		}
		t0 := time.Now()
		baseResp1, err := target.HTTP.Do(ctx, baseReq1)
		if err != nil {
			continue
		}
		baseResp1.Body.Close()
		b1 := time.Since(t0)

		time.Sleep(50 * time.Millisecond)

		baseReq2, err := buildProbeReq(ctx, param, originalVal)
		if err != nil {
			continue
		}
		t0 = time.Now()
		baseResp2, err := target.HTTP.Do(ctx, baseReq2)
		if err != nil {
			continue
		}
		baseResp2.Body.Close()
		b2 := time.Since(t0)

		baseline := b1
		if b2 < b1 {
			baseline = b2
		}

		if baseline > threshold/2 {
			slog.Warn("sqli: baseline exceeds threshold/2, skipping timing probes",
				"url", param.InjectURL, "name", param.Name,
				"baseline_ms", baseline.Milliseconds(),
				"threshold_half_ms", (threshold / 2).Milliseconds())
			continue
		}

		// Serialise timing probes per host so only one sleep payload is in-flight
		// at a time on any single host.
		host := hostFromURL(param.InjectURL)
		hostLock := c.getHostLock(host)

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

			lockWaitStart := time.Now()
			hostLock.Lock()
			if wait := time.Since(lockWaitStart); wait > 30*time.Second {
				slog.Warn("sqli: per-host lock blocked >30s",
					"host", host, "waited_ms", wait.Milliseconds(), "url", param.InjectURL)
			}

			// Per-probe context is created after acquiring the lock so that lock
			// wait time does not consume the probe deadline.
			probeCtx, probeCancel := context.WithTimeout(ctx, baseline+threshold+5*time.Second)
			t1 := time.Now()
			resp, probeErr := target.HTTP.Do(probeCtx, req)
			elapsed := time.Since(t1)
			hostLock.Unlock()
			probeCancel()

			slog.Debug("sqli: timing payload attempt",
				"url", param.InjectURL, "payload_id", p.ID,
				"baseline_ms", baseline.Milliseconds(),
				"elapsed_ms", elapsed.Milliseconds(),
				"threshold_ms", threshold.Milliseconds(),
				"would_fire", elapsed >= baseline+threshold)

			fired := elapsed >= baseline+threshold
			if probeErr != nil {
				// Even on error (e.g., connection closed after the injected sleep,
				// or per-probe context expired), elapsed still reflects the delay.
				if !fired {
					continue
				}
			} else {
				resp.Body.Close()
				if !fired {
					continue
				}
			}

			confirmed[key] = true
			timingURL := findingInjectURL(param, injected)
			findings = append(findings, &checks.Finding{
				CheckID:    "web.sqli.timing",
				Severity:   checks.SeverityHigh,
				Confidence: checks.ConfidenceConfirmed,
				Title:      fmt.Sprintf("SQL injection (time-based) in parameter %q at %s", param.Name, timingURL),
				Description: fmt.Sprintf(
					"The parameter %q at %s causes a measurable response delay (%v vs baseline %v) "+
						"when injected with a sleep-based SQL payload. Time-based blind injection "+
						"allows data extraction character-by-character.",
					param.Name, timingURL, elapsed.Round(time.Millisecond), baseline.Round(time.Millisecond),
				),
				URL:       timingURL,
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
