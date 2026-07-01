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

// SRICheck scans HTML page bodies cached by the crawler and flags cross-origin
// <script> tags that lack an integrity attribute. No fresh HTTP requests are made.
type SRICheck struct{}

func (c *SRICheck) ID() string                { return "web.sri.missing" }
func (c *SRICheck) Name() string              { return "Missing Subresource Integrity" }
func (c *SRICheck) Severity() checks.Severity { return checks.SeverityLow }
func (c *SRICheck) Category() checks.Category { return checks.CategoryWeb }

func (c *SRICheck) Run(ctx context.Context, target *checks.Target) ([]*checks.Finding, error) {
	if target.Inventory == nil {
		return nil, nil
	}

	emitted := make(map[string]bool)
	var findings []*checks.Finding

	for _, du := range target.Inventory.URLs {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}
		if du.ResponseStatus != http.StatusOK || len(du.ResponseBody) == 0 {
			continue
		}
		if !strings.Contains(du.ContentType, "html") {
			continue
		}

		pageOrigin := urlOrigin(du.URL)
		doc, err := html.Parse(bytes.NewReader(du.ResponseBody))
		if err != nil {
			continue
		}

		var walkHTML func(*html.Node)
		walkHTML = func(n *html.Node) {
			if n.Type == html.ElementNode && n.Data == "script" {
				src := htmlAttr(n, "src")
				integrity := htmlAttr(n, "integrity")
				if src != "" && integrity == "" {
					abs := toAbsoluteForSRI(du.URL, src)
					if abs != "" && urlOrigin(abs) != pageOrigin {
						key := du.URL + "|" + abs
						if !emitted[key] {
							emitted[key] = true
							findings = append(findings, &checks.Finding{
								CheckID:    c.ID(),
								Severity:   checks.SeverityLow,
								Confidence: checks.ConfidenceConfirmed,
								Title:      fmt.Sprintf("Cross-origin script without integrity at %s", du.URL),
								Description: fmt.Sprintf(
									"The page at %s loads a cross-origin script from %s without an "+
										"integrity attribute. Without Subresource Integrity, the browser "+
										"cannot verify the script has not been tampered with if the "+
										"third-party host is compromised.",
									du.URL, abs,
								),
								URL:   du.URL,
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
