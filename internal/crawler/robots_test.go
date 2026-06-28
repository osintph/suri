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

func TestParseRobots(t *testing.T) {
	input := `User-agent: *
Disallow: /admin/
Disallow: /private/
Disallow: /api/internal/
Allow: /api/public/
Sitemap: https://example.com/sitemap.xml

# Another agent
User-agent: Googlebot
Disallow: /secret/
`
	res := ParseRobots([]byte(input))

	wantDisallow := []string{"/admin/", "/private/", "/api/internal/", "/secret/"}
	if len(res.DisallowPaths) != len(wantDisallow) {
		t.Fatalf("DisallowPaths: want %d, got %d: %v", len(wantDisallow), len(res.DisallowPaths), res.DisallowPaths)
	}
	for i, p := range wantDisallow {
		if res.DisallowPaths[i] != p {
			t.Errorf("DisallowPaths[%d]: want %q, got %q", i, p, res.DisallowPaths[i])
		}
	}

	if len(res.SitemapURLs) != 1 || res.SitemapURLs[0] != "https://example.com/sitemap.xml" {
		t.Errorf("SitemapURLs: got %v", res.SitemapURLs)
	}
}

func TestParseRobotsEmpty(t *testing.T) {
	res := ParseRobots([]byte(""))
	if len(res.DisallowPaths) != 0 {
		t.Errorf("expected no paths for empty robots.txt")
	}
}

func TestParseRobotsRootDisallowIgnored(t *testing.T) {
	// A bare "Disallow: /" means "disallow all" which the crawler
	// should not add as a path to visit.
	res := ParseRobots([]byte("User-agent: *\nDisallow: /\n"))
	if len(res.DisallowPaths) != 0 {
		t.Errorf("root Disallow should be ignored, got %v", res.DisallowPaths)
	}
}
