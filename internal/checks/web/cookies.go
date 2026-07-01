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

	"github.com/osintph/suri/internal/checks"
)

// CookieCheck inspects Set-Cookie headers from seed and discovered URLs.
// It emits a low finding for each cookie missing the Secure, HttpOnly,
// or SameSite attribute.
type CookieCheck struct{}

func (c *CookieCheck) ID() string                { return "web.cookies.missing-flags" }
func (c *CookieCheck) Name() string              { return "Cookie Security Flags" }
func (c *CookieCheck) Severity() checks.Severity { return checks.SeverityLow }
func (c *CookieCheck) Category() checks.Category { return checks.CategoryWeb }

func (c *CookieCheck) Run(ctx context.Context, target *checks.Target) ([]*checks.Finding, error) {
	seen := make(map[string]bool)
	var urls []string
	for _, u := range target.SeedURLs {
		if !seen[u] {
			seen[u] = true
			urls = append(urls, u)
		}
	}
	if target.Inventory != nil {
		for _, du := range target.Inventory.URLs {
			if !seen[du.URL] {
				seen[du.URL] = true
				urls = append(urls, du.URL)
			}
		}
	}

	type flagKey struct{ url, name, flag string }
	emitted := make(map[flagKey]bool)
	var findings []*checks.Finding

	for _, rawURL := range urls {
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
		cookies := resp.Cookies()
		resp.Body.Close()

		for _, cookie := range cookies {
			if !cookie.Secure {
				k := flagKey{rawURL, cookie.Name, "secure"}
				if !emitted[k] {
					emitted[k] = true
					findings = append(findings, &checks.Finding{
						CheckID:    c.ID(),
						Severity:   checks.SeverityLow,
						Confidence: checks.ConfidenceConfirmed,
						Title:      fmt.Sprintf("Cookie %q missing Secure flag at %s", cookie.Name, rawURL),
						Description: fmt.Sprintf(
							"The cookie %q is set without the Secure attribute. Without Secure, "+
								"the browser may transmit the cookie over unencrypted HTTP connections, "+
								"exposing it to interception.",
							cookie.Name,
						),
						URL:       rawURL,
						Parameter: cookie.Name,
						CWE:       "CWE-614",
						OWASP:     "A05:2021",
					})
				}
			}
			if !cookie.HttpOnly {
				k := flagKey{rawURL, cookie.Name, "httponly"}
				if !emitted[k] {
					emitted[k] = true
					findings = append(findings, &checks.Finding{
						CheckID:    c.ID(),
						Severity:   checks.SeverityLow,
						Confidence: checks.ConfidenceConfirmed,
						Title:      fmt.Sprintf("Cookie %q missing HttpOnly flag at %s", cookie.Name, rawURL),
						Description: fmt.Sprintf(
							"The cookie %q is set without the HttpOnly attribute. Without HttpOnly, "+
								"the cookie is accessible to JavaScript via document.cookie, making it "+
								"vulnerable to theft by cross-site scripting attacks.",
							cookie.Name,
						),
						URL:       rawURL,
						Parameter: cookie.Name,
						CWE:       "CWE-1004",
						OWASP:     "A05:2021",
					})
				}
			}
			// SameSite == 0 means the attribute was not present in the Set-Cookie header.
			if cookie.SameSite == 0 {
				k := flagKey{rawURL, cookie.Name, "samesite"}
				if !emitted[k] {
					emitted[k] = true
					findings = append(findings, &checks.Finding{
						CheckID:    c.ID(),
						Severity:   checks.SeverityLow,
						Confidence: checks.ConfidenceConfirmed,
						Title:      fmt.Sprintf("Cookie %q missing SameSite attribute at %s", cookie.Name, rawURL),
						Description: fmt.Sprintf(
							"The cookie %q is set without a SameSite attribute. Without SameSite=Lax "+
								"or SameSite=Strict, the browser sends the cookie on cross-site requests, "+
								"increasing the risk of cross-site request forgery.",
							cookie.Name,
						),
						URL:       rawURL,
						Parameter: cookie.Name,
						CWE:       "CWE-352",
						OWASP:     "A01:2021",
					})
				}
			}
		}
	}
	return findings, nil
}
