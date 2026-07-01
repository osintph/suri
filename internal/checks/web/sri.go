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
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/html"

	"github.com/osintph/suri/internal/checks"
)

// SRICheck fetches HTML pages from seed and discovered URLs and flags
// cross-origin <script> tags that lack an integrity attribute. Missing
// Subresource Integrity on CDN-hosted scripts allows supply-chain attacks
// if the CDN is compromised.
type SRICheck struct{}

func (c *SRICheck) ID() string                { return "web.sri.missing" }
func (c *SRICheck) Name() string              { return "Missing Subresource Integrity" }
func (c *SRICheck) Severity() checks.Severity { return checks.SeverityLow }
func (c *SRICheck) Category() checks.Category { return checks.CategoryWeb }

func (c *SRICheck) Run(ctx context.Context, target *checks.Target) ([]*checks.Finding, error) {
	seen := make(map[string]bool)
	var candidates []string
	for _, u := range target.SeedURLs {
		if !seen[u] {
			seen[u] = true
			candidates = append(candidates, u)
		}
	}
	if target.Inventory != nil {
		const maxInventory = 50
		added := 0
		for _, du := range target.Inventory.URLs {
			if added >= maxInventory {
				break
			}
			if du.ResponseStatus == http.StatusOK && !seen[du.URL] {
				seen[du.URL] = true
				candidates = append(candidates, du.URL)
				added++
			}
		}
	}

	emitted := make(map[string]bool)
	var findings []*checks.Finding

	for _, pageURL := range candidates {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
		if err != nil {
			continue
		}
		resp, err := target.HTTP.Do(ctx, req)
		if err != nil {
			continue
		}
		body := readBody(resp.Body, 1*1024*1024)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			continue
		}
		ct := resp.Header.Get("Content-Type")
		if !strings.Contains(ct, "html") {
			continue
		}

		pageOrigin := urlOrigin(pageURL)
		doc, err := html.Parse(bytes.NewReader(body))
		if err != nil {
			continue
		}

		var walkHTML func(*html.Node)
		walkHTML = func(n *html.Node) {
			if n.Type == html.ElementNode && n.Data == "script" {
				src := htmlAttr(n, "src")
				integrity := htmlAttr(n, "integrity")
				if src != "" && integrity == "" {
					abs := toAbsoluteForSRI(pageURL, src)
					if abs != "" && urlOrigin(abs) != pageOrigin {
						key := pageURL + "|" + abs
						if !emitted[key] {
							emitted[key] = true
							findings = append(findings, &checks.Finding{
								CheckID:    c.ID(),
								Severity:   checks.SeverityLow,
								Confidence: checks.ConfidenceConfirmed,
								Title:      fmt.Sprintf("Cross-origin script without integrity at %s", pageURL),
								Description: fmt.Sprintf(
									"The page at %s loads a cross-origin script from %s without an "+
										"integrity attribute. Without Subresource Integrity, the browser "+
										"cannot verify the script has not been tampered with if the "+
										"third-party host is compromised.",
									pageURL, abs,
								),
								URL:   pageURL,
								CWE:   "CWE-353",
								OWASP: "A08:2021",
								Evidence: &checks.Evidence{
									ResponseBytes: []byte("script src=" + abs),
								},
							})
						}
					}
				}
			}
			for child := n.FirstChild; child != nil; child = child.NextSibling {
				walkHTML(child)
			}
		}
		walkHTML(doc)
	}
	return findings, nil
}

// urlOrigin returns "scheme://host" for a URL, or "" on error.
func urlOrigin(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// toAbsoluteForSRI converts a (possibly relative) src into an absolute URL
// relative to pageURL.
func toAbsoluteForSRI(pageURL, src string) string {
	base, err := url.Parse(pageURL)
	if err != nil {
		return ""
	}
	ref, err := url.Parse(src)
	if err != nil {
		return ""
	}
	return base.ResolveReference(ref).String()
}

// htmlAttr returns the value of the named attribute on n, or "".
func htmlAttr(n *html.Node, name string) string {
	for _, a := range n.Attr {
		if a.Key == name {
			return a.Val
		}
	}
	return ""
}
