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

// CMDiCheck probes for OS command injection using time-based detection only.
// No output is extracted and no destructive commands are run. A sleep payload
// is injected; if the response takes significantly longer than the baseline,
// command injection is likely.
//
// Timing probes are serialised per host via hostLocks: only one sleep payload
// is in-flight per host at a time. This prevents stacking server-side threads
// on timing-vulnerable endpoints when multiple parameters share the same host.
type CMDiCheck struct {
	// TimingThresholdMs is the minimum extra response time in milliseconds that
	// triggers a finding. Zero uses the default (4000 ms).
	TimingThresholdMs int64

	// hostLocks serialises timing probes per host. Each value is a *sync.Mutex.
	hostLocks sync.Map
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

// getHostLock returns the per-host mutex, creating it on first call.
func (c *CMDiCheck) getHostLock(host string) *sync.Mutex {
	mu, _ := c.hostLocks.LoadOrStore(host, &sync.Mutex{})
	return mu.(*sync.Mutex)
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

		slog.Debug("cmdi: probing parameter",
			"url", param.InjectURL, "name", param.Name, "page_url", param.PageURL)

		// Measure baseline response time using the parameter's original value so
		// backend processing (DNS, DB lookup, file access, etc.) that the probe
		// string would also trigger does not inflate the baseline. Two measurements
		// are taken and the smaller is used to reduce single-sample noise.
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

		// If the baseline already exceeds half the threshold the backend is too
		// slow to reliably distinguish an injected sleep from normal latency.
		if baseline > threshold/2 {
			slog.Warn("cmdi: baseline exceeds threshold/2, skipping timing probes",
				"url", param.InjectURL, "name", param.Name,
				"baseline_ms", baseline.Milliseconds(),
				"threshold_half_ms", (threshold / 2).Milliseconds())
			continue
		}

		// Serialise timing probes per host.
		host := hostFromURL(param.InjectURL)
		hostLock := c.getHostLock(host)

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

			lockWaitStart := time.Now()
			hostLock.Lock()
			if wait := time.Since(lockWaitStart); wait > 30*time.Second {
				slog.Warn("cmdi: per-host lock blocked >30s",
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

			slog.Debug("cmdi: payload attempt",
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
			actualURL := findingInjectURL(param, injected)
			findings = append(findings, &checks.Finding{
				CheckID:    c.ID(),
				Severity:   checks.SeverityHigh,
				Confidence: checks.ConfidenceConfirmed,
				Title:      fmt.Sprintf("Command injection (time-based) in parameter %q at %s", param.Name, actualURL),
				Description: fmt.Sprintf(
					"The parameter %q at %s causes a measurable response delay (%v vs baseline %v) "+
						"when injected with an OS sleep command via payload %q. "+
						"This indicates the parameter value is passed to a shell without sanitization.%s",
					param.Name, actualURL, elapsed.Round(time.Millisecond), baseline.Round(time.Millisecond), p.Payload,
					paramSourceSuffix(param.Source),
				),
				URL:       actualURL,
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
