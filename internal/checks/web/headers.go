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
	"strings"

	"github.com/osintph/suri/internal/checks"
)

// HeadersCheck audits HTTP response headers for missing or weak security
// controls on each seed URL. Each missing header produces a separate finding.
type HeadersCheck struct{}

func (c *HeadersCheck) ID() string                { return "web.headers" }
func (c *HeadersCheck) Name() string              { return "Security Header Audit" }
func (c *HeadersCheck) Severity() checks.Severity { return checks.SeverityLow }
func (c *HeadersCheck) Category() checks.Category { return checks.CategoryWeb }

type headerRule struct {
	header      string // canonical header name (Title-Case)
	checkID     string
	title       string
	description string
	severity    checks.Severity
	// validate is optional; if nil, merely checks presence. When set, the
	// header is considered weak if validate returns a non-empty issue string.
	validate func(val string) string
}

var headerRules = []headerRule{
	{
		header:  "Strict-Transport-Security",
		checkID: "web.headers.hsts",
		title:   "Missing Strict-Transport-Security header",
		description: "HTTPS responses should include Strict-Transport-Security (HSTS) to prevent " +
			"protocol downgrade attacks. Without it, browsers may allow plain-HTTP connections " +
			"to this site, enabling man-in-the-middle attacks.",
		severity: checks.SeverityMedium,
	},
	{
		header:  "Content-Security-Policy",
		checkID: "web.headers.csp",
		title:   "Missing Content-Security-Policy header",
		description: "Content-Security-Policy (CSP) restricts the sources from which the browser " +
			"loads scripts, styles, and other resources. Its absence increases the impact of any " +
			"cross-site scripting (XSS) vulnerability present on the site.",
		severity: checks.SeverityLow,
	},
	{
		header:  "X-Frame-Options",
		checkID: "web.headers.xfo",
		title:   "Missing X-Frame-Options header",
		description: "X-Frame-Options (or a CSP frame-ancestors directive) prevents the page " +
			"from being embedded in an iframe on a different origin, mitigating clickjacking attacks.",
		severity: checks.SeverityLow,
		validate: func(val string) string {
			upper := strings.ToUpper(strings.TrimSpace(val))
			if upper == "DENY" || upper == "SAMEORIGIN" {
				return ""
			}
			if strings.HasPrefix(upper, "ALLOW-FROM") {
				return "" // deprecated but not dangerous
			}
			return fmt.Sprintf("unexpected value %q (want DENY or SAMEORIGIN)", val)
		},
	},
	{
		header:  "X-Content-Type-Options",
		checkID: "web.headers.xcto",
		title:   "Missing X-Content-Type-Options header",
		description: "X-Content-Type-Options: nosniff prevents the browser from MIME-type-sniffing " +
			"a response away from the declared Content-Type, reducing the risk of script injection " +
			"via uploaded files served with a permissive MIME type.",
		severity: checks.SeverityLow,
		validate: func(val string) string {
			if strings.EqualFold(strings.TrimSpace(val), "nosniff") {
				return ""
			}
			return fmt.Sprintf("unexpected value %q (want nosniff)", val)
		},
	},
	{
		header:  "Referrer-Policy",
		checkID: "web.headers.referrer",
		title:   "Missing Referrer-Policy header",
		description: "A Referrer-Policy header controls how much referrer information is included " +
			"in requests. Without it, the browser default may leak sensitive URL fragments to " +
			"third-party resources.",
		severity: checks.SeverityInfo,
	},
	{
		header:  "Permissions-Policy",
		checkID: "web.headers.permissions",
		title:   "Missing Permissions-Policy header",
		description: "Permissions-Policy (formerly Feature-Policy) limits which browser features " +
			"the page and any embedded iframes can use. Its absence allows third-party content " +
			"to request powerful features (camera, microphone, geolocation).",
		severity: checks.SeverityInfo,
	},
}

// Run makes one GET request per seed URL and audits the response headers.
func (c *HeadersCheck) Run(ctx context.Context, target *checks.Target) ([]*checks.Finding, error) {
	var findings []*checks.Finding
	seen := make(map[string]bool)

	for _, seedURL := range target.SeedURLs {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, seedURL, nil)
		if err != nil {
			continue
		}
		resp, err := target.HTTP.Do(ctx, req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		isHTTPS := strings.HasPrefix(strings.ToLower(seedURL), "https://")

		for _, rule := range headerRules {
			// HSTS only applies to HTTPS responses.
			if rule.checkID == "web.headers.hsts" && !isHTTPS {
				continue
			}

			dedupeKey := rule.checkID + "|" + seedURL
			if seen[dedupeKey] {
				continue
			}
			seen[dedupeKey] = true

			val := resp.Header.Get(rule.header)
			if val == "" {
				findings = append(findings, &checks.Finding{
					CheckID:     rule.checkID,
					Severity:    rule.severity,
					Confidence:  checks.ConfidenceConfirmed,
					Title:       rule.title,
					Description: rule.description,
					URL:         seedURL,
				})
				continue
			}
			// Header is present; run validator if one exists.
			if rule.validate != nil {
				if issue := rule.validate(val); issue != "" {
					findings = append(findings, &checks.Finding{
						CheckID:    rule.checkID,
						Severity:   rule.severity,
						Confidence: checks.ConfidenceConfirmed,
						Title:      "Weak " + rule.header + " header",
						Description: fmt.Sprintf(
							"%s header is present but value is unexpected: %s", rule.header, issue,
						),
						URL: seedURL,
					})
				}
			}
		}
	}
	return findings, nil
}
