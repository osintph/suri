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
	"bufio"
	"bytes"
	"strings"
)

// RobotsResult holds paths extracted from robots.txt.
type RobotsResult struct {
	// DisallowPaths are paths the site tried to hide. Worth checking.
	DisallowPaths []string
	// SitemapURLs are absolute sitemap URLs declared in the file.
	SitemapURLs []string
}

// ParseRobots extracts Disallow paths and Sitemap directives from a
// robots.txt payload. All user-agent blocks are merged; the caller decides
// which paths to follow.
func ParseRobots(data []byte) RobotsResult {
	var res RobotsResult
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "disallow:") {
			path := strings.TrimSpace(line[len("disallow:"):])
			if path != "" && path != "/" {
				res.DisallowPaths = append(res.DisallowPaths, path)
			}
		} else if strings.HasPrefix(lower, "sitemap:") {
			u := strings.TrimSpace(line[len("sitemap:"):])
			if u != "" {
				res.SitemapURLs = append(res.SitemapURLs, u)
			}
		}
	}
	return res
}
