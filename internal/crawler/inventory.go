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

// Inventory is the output of a crawl. It collects all discovered URLs, forms,
// parameters, and JavaScript-extracted artifacts ready for check modules.
type Inventory struct {
	URLs        []*DiscoveredURL
	Forms       []*Form
	Parameters  []*Parameter
	JSArtifacts []*JSArtifact
}

// DiscoveredURL records a URL found during crawling together with where it
// came from and the crawl depth at which it was first seen.
type DiscoveredURL struct {
	URL    string
	Source string // "seed", "html", "sitemap", "robots", "js"
	Depth  int
}

// Form holds a discovered HTML form and its fields.
type Form struct {
	PageURL string
	Action  string
	Method  string
	Fields  []string
}

// Parameter is a named input found on a page.
type Parameter struct {
	PageURL string
	Name    string
	Source  string // "query", "form", "header"
}

// JSArtifact is a value extracted from a JavaScript file by the miner.
type JSArtifact struct {
	SourceURL string
	Type      string // "api-path", "s3", "azure-blob", "gcs", "auth-header", "role"
	Value     string
}
