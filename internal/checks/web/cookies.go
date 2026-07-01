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

	"github.com/osintph/suri/internal/checks"
)

// CookieCheck inspects Set-Cookie headers cached by the crawler in
// Inventory.URLs. It emits a low finding for each cookie missing the
// Secure, HttpOnly, or SameSite attribute.
//
// No fresh HTTP requests are made: all data comes from cookies collected
// during the initial crawl and stored in DiscoveredURL.Cookies.
type CookieCheck struct{}

func (c *CookieCheck) ID() string                { return "web.cookies.missing-flags" }
func (c *CookieCheck) Name() string              { return "Cookie Security Flags" }
func (c *CookieCheck) Severity() checks.Severity { return checks.SeverityLow }
func (c *CookieCheck) Category() checks.Category { return checks.CategoryWeb }

func (c *CookieCheck) Run(ctx context.Context, target *checks.Target) ([]*checks.Finding, error) {
	if target.Inventory == nil {
		return nil, nil
	}

	type flagKey struct{ url, name, flag string }
	emitted := make(map[flagKey]bool)
	var findings []*checks.Finding

	for _, du := range target.Inventory.URLs {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}
		for _, cookie := range du.Cookies {
			if !cookie.Secure {
				k := flagKey{du.URL, cookie.Name, "secure"}
				if !emitted[k] {
					emitted[k] = true
					findings = append(findings, &checks.Finding{
						CheckID:    c.ID(),
						Severity:   checks.SeverityLow,
						Confidence: checks.ConfidenceConfirmed,
						Title:      fmt.Sprintf("Cookie %q missing Secure flag at %s", cookie.Name, du.URL),
						Description: fmt.Sprintf(
							"The cookie %q is set without the Secure attribute. Without Secure, "+
								"the browser may transmit the cookie over unencrypted HTTP connections, "+
								"exposing it to interception.",
							cookie.Name,
						),
						URL:       du.URL,
						Parameter: cookie.Name,
						CWE:       "CWE-614",
						OWASP:     "A05:2021",
					})
				}
			}
			if !cookie.HttpOnly {
				k := flagKey{du.URL, cookie.Name, "httponly"}
				if !emitted[k] {
					emitted[k] = true
					findings = append(findings, &checks.Finding{
						CheckID:    c.ID(),
						Severity:   checks.SeverityLow,
						Confidence: checks.ConfidenceConfirmed,
						Title:      fmt.Sprintf("Cookie %q missing HttpOnly flag at %s", cookie.Name, du.URL),
						Description: fmt.Sprintf(
							"The cookie %q is set without the HttpOnly attribute. Without HttpOnly, "+
								"the cookie is accessible to JavaScript via document.cookie, making it "+
								"vulnerable to theft by cross-site scripting attacks.",
							cookie.Name,
						),
						URL:       du.URL,
						Parameter: cookie.Name,
						CWE:       "CWE-1004",
						OWASP:     "A05:2021",
					})
				}
			}
			// SameSite == 0 means the attribute was not present in the Set-Cookie header.
			if cookie.SameSite == 0 {
				k := flagKey{du.URL, cookie.Name, "samesite"}
				if !emitted[k] {
					emitted[k] = true
					findings = append(findings, &checks.Finding{
						CheckID:    c.ID(),
						Severity:   checks.SeverityLow,
						Confidence: checks.ConfidenceConfirmed,
						Title:      fmt.Sprintf("Cookie %q missing SameSite attribute at %s", cookie.Name, du.URL),
						Description: fmt.Sprintf(
							"The cookie %q is set without a SameSite attribute. Without SameSite=Lax "+
								"or SameSite=Strict, the browser sends the cookie on cross-site requests, "+
								"increasing the risk of cross-site request forgery.",
							cookie.Name,
						),
						URL:       du.URL,
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
