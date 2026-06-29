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
	"net/url"
	"strings"

	"github.com/osintph/suri/internal/checks"
)

// RedirectCheck probes parameters that look like redirect targets for open
// redirect vulnerabilities. It injects a canary URL and checks whether the
// server sends a 3xx Location header pointing to that canary, without
// following the redirect. This avoids triggering scope enforcement on the
// canary destination and keeps detection passive.
type RedirectCheck struct{}

func (c *RedirectCheck) ID() string                { return "web.redirect.open" }
func (c *RedirectCheck) Name() string              { return "Open Redirect" }
func (c *RedirectCheck) Severity() checks.Severity { return checks.SeverityMedium }
func (c *RedirectCheck) Category() checks.Category { return checks.CategoryWeb }

// redirectParamNames lists URL parameter names that typically hold redirect
// destinations. Only parameters with these names are probed.
var redirectParamNames = map[string]bool{
	"next":        true,
	"redirect":    true,
	"redirect_to": true,
	"redirect_uri": true,
	"redirecturl": true,
	"url":         true,
	"return":      true,
	"returnto":    true,
	"returnurl":   true,
	"dest":        true,
	"destination": true,
	"target":      true,
	"location":    true,
	"goto":        true,
	"back":        true,
	"forward":     true,
	"continue":    true,
}

// Run probes redirect-like parameters for open redirect.
func (c *RedirectCheck) Run(ctx context.Context, target *checks.Target) ([]*checks.Finding, error) {
	if target.Inventory == nil {
		return nil, nil
	}

	canary := target.Canary
	if canary == "" {
		canary = checks.GenerateCanary()
	}
	// Canary URL: a clearly synthetic domain using the reserved .test TLD.
	// The HTTP client will reject any attempt to follow this redirect due to
	// scope enforcement. We read the Location header directly instead.
	canaryURL := "https://suri-redirect-" + canary + ".test/"

	var findings []*checks.Finding
	confirmed := make(map[string]bool)

	for _, param := range target.Inventory.Parameters {
		if param.Source == "header" || param.InjectURL == "" {
			continue
		}
		// Only probe parameters whose names suggest redirect destinations.
		if !redirectParamNames[strings.ToLower(param.Name)] {
			continue
		}
		key := param.InjectURL + "|" + param.Name
		if confirmed[key] {
			continue
		}

		req, err := buildProbeReq(ctx, param, canaryURL)
		if err != nil {
			continue
		}

		// Use DoNoRedirect so we get the raw 3xx response and can inspect the
		// Location header without following the redirect into an out-of-scope host.
		resp, err := target.HTTP.DoNoRedirect(ctx, req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode < 300 || resp.StatusCode >= 400 {
			continue
		}

		location := resp.Header.Get("Location")
		if location == "" {
			continue
		}

		// Confirm: the Location header must reference our canary domain.
		locParsed, err := url.Parse(location)
		if err != nil || !strings.Contains(strings.ToLower(locParsed.Host), "suri-redirect-"+canary) {
			continue
		}

		confirmed[key] = true
		findings = append(findings, &checks.Finding{
			CheckID:    c.ID(),
			Severity:   checks.SeverityMedium,
			Confidence: checks.ConfidenceConfirmed,
			Title:      fmt.Sprintf("Open redirect via parameter %q at %s", param.Name, param.InjectURL),
			Description: fmt.Sprintf(
				"The parameter %q at %s redirects to an attacker-controlled URL. "+
					"When set to %q, the server responded with HTTP %d and "+
					"Location: %s. An attacker can craft a link that appears to "+
					"point to the legitimate site but redirects victims to a phishing page.",
				param.Name, param.InjectURL, canaryURL, resp.StatusCode, location,
			),
			URL:       param.InjectURL,
			Parameter: param.Name,
			CWE:       "CWE-601",
			OWASP:     "A01:2021",
			Evidence: &checks.Evidence{
				ResponseStatus: resp.StatusCode,
				ResponseBytes:  []byte("Location: " + location),
			},
		})
	}
	return findings, nil
}

