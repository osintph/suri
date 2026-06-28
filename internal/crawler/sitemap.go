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

package crawler

import (
	"encoding/xml"
	"fmt"
)

// sitemapURLSet is the standard sitemap format.
type sitemapURLSet struct {
	XMLName xml.Name      `xml:"urlset"`
	URLs    []sitemapLoc  `xml:"url"`
}

// sitemapIndex is the sitemap index format that references child sitemaps.
type sitemapIndex struct {
	XMLName  xml.Name        `xml:"sitemapindex"`
	Sitemaps []sitemapLoc    `xml:"sitemap"`
}

type sitemapLoc struct {
	Loc string `xml:"loc"`
}

// SitemapResult holds URLs extracted from a sitemap document.
type SitemapResult struct {
	// PageURLs are the <loc> entries from a standard urlset sitemap.
	PageURLs []string
	// ChildSitemaps are <loc> entries from a sitemap index pointing to
	// nested sitemaps. The crawler should fetch and parse these too.
	ChildSitemaps []string
}

// ParseSitemap parses a sitemap.xml or sitemap index payload and returns the
// discovered URLs. It auto-detects which format the document uses.
func ParseSitemap(data []byte) (SitemapResult, error) {
	var res SitemapResult

	// Try sitemap index first.
	var idx sitemapIndex
	if err := xml.Unmarshal(data, &idx); err == nil && idx.XMLName.Local == "sitemapindex" {
		for _, s := range idx.Sitemaps {
			if s.Loc != "" {
				res.ChildSitemaps = append(res.ChildSitemaps, s.Loc)
			}
		}
		return res, nil
	}

	// Try standard urlset.
	var urlset sitemapURLSet
	if err := xml.Unmarshal(data, &urlset); err != nil {
		return res, fmt.Errorf("parsing sitemap XML: %w", err)
	}
	for _, u := range urlset.URLs {
		if u.Loc != "" {
			res.PageURLs = append(res.PageURLs, u.Loc)
		}
	}
	return res, nil
}
