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
	"testing"
)

func TestParseSitemapURLSet(t *testing.T) {
	data := `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/</loc></url>
  <url><loc>https://example.com/about</loc></url>
  <url><loc>https://example.com/products</loc></url>
</urlset>`

	res, err := ParseSitemap([]byte(data))
	if err != nil {
		t.Fatalf("ParseSitemap: %v", err)
	}
	if len(res.PageURLs) != 3 {
		t.Errorf("PageURLs: want 3, got %d: %v", len(res.PageURLs), res.PageURLs)
	}
	if res.PageURLs[1] != "https://example.com/about" {
		t.Errorf("PageURLs[1]: got %s", res.PageURLs[1])
	}
	if len(res.ChildSitemaps) != 0 {
		t.Errorf("ChildSitemaps should be empty for urlset")
	}
}

func TestParseSitemapIndex(t *testing.T) {
	data := `<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap><loc>https://example.com/sitemap-1.xml</loc></sitemap>
  <sitemap><loc>https://example.com/sitemap-2.xml</loc></sitemap>
</sitemapindex>`

	res, err := ParseSitemap([]byte(data))
	if err != nil {
		t.Fatalf("ParseSitemap index: %v", err)
	}
	if len(res.ChildSitemaps) != 2 {
		t.Errorf("ChildSitemaps: want 2, got %d", len(res.ChildSitemaps))
	}
	if len(res.PageURLs) != 0 {
		t.Errorf("PageURLs should be empty for sitemap index")
	}
}

func TestParseSitemapInvalid(t *testing.T) {
	_, err := ParseSitemap([]byte("not xml <<>>"))
	if err == nil {
		t.Error("expected error for invalid XML")
	}
}
