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
	"regexp"
)

// minePattern pairs a compiled regex with the artifact type it produces.
// Each pattern's first capture group is the extracted value.
type minePattern struct {
	re       *regexp.Regexp
	category string
}

// miners is the curated set of patterns applied to every JavaScript payload.
// Order matters for readability; deduplication inside MineJS prevents the same
// value from appearing twice even if multiple patterns match it.
var miners = []minePattern{
	{
		// API-style URL paths: /api/..., /v1/..., /graphql, /rest/..., etc.
		re:       regexp.MustCompile(`["` + "`" + `'](/(?:api|v\d+|graphql|gql|rest|admin|internal|service|auth|oauth|user|account|data|stream|endpoint)[/a-zA-Z0-9_\-\.]*)`),
		category: "api-path",
	},
	{
		// Generic full HTTP(S) URLs quoted in JS. Catches same-host endpoints,
		// third-party CDN calls, and cloud storage URLs not matched below.
		// The value is already absolute so no base-URL resolution is needed.
		re:       regexp.MustCompile(`["` + "`" + `'](https?://[a-zA-Z0-9][a-zA-Z0-9\-\.]+(?::\d+)?/[^"` + "`" + `'\s<>]*)["` + "`" + `']`),
		category: "url-full",
	},
	{
		// Protocol-relative URLs: //hostname/path or //hostname:port/path.
		// The crawl code prepends the page scheme before dispatching.
		re:       regexp.MustCompile(`["` + "`" + `'](//[a-zA-Z0-9][a-zA-Z0-9\-\.]+(?::\d+)?/[^"` + "`" + `'\s<>]*)["` + "`" + `']`),
		category: "url-proto-relative",
	},
	{
		// AWS S3 bucket references.
		re:       regexp.MustCompile(`(https?://[a-z0-9][a-z0-9\-]+\.s3(?:\.[a-z0-9\-]+)?\.amazonaws\.com[^"` + "`" + `'\s<>]*)`),
		category: "s3",
	},
	{
		// Azure Blob storage.
		re:       regexp.MustCompile(`(https?://[a-z0-9][a-z0-9\-]+\.blob\.core\.windows\.net[^"` + "`" + `'\s<>]*)`),
		category: "azure-blob",
	},
	{
		// Google Cloud Storage.
		re:       regexp.MustCompile(`(https?://storage\.googleapis\.com/[^"` + "`" + `'\s<>]+)`),
		category: "gcs",
	},
	{
		// Hardcoded Authorization header values (Bearer tokens, API keys).
		re:       regexp.MustCompile(`(?i)(?:"Authorization"\s*:\s*|authorization\s*[:=]\s*)["` + "`" + `']([^"` + "`" + `']{8,})["` + "`" + `']`),
		category: "auth-header",
	},
	{
		// Role strings: role:admin, role:superuser, etc.
		re:       regexp.MustCompile(`"(role:[^"]+)"`),
		category: "role",
	},
	{
		// Permission strings: permission:write, etc.
		re:       regexp.MustCompile(`"(permission:[^"]+)"`),
		category: "role",
	},
}

// MineJS runs the curated pattern library against a JavaScript payload and
// returns all extracted artifacts. Duplicate values within the same category
// are deduplicated.
func MineJS(sourceURL string, data []byte) []*JSArtifact {
	seen := make(map[string]bool)
	var artifacts []*JSArtifact

	for _, m := range miners {
		for _, match := range m.re.FindAllSubmatch(data, -1) {
			if len(match) < 2 {
				continue
			}
			val := string(match[1])
			key := m.category + ":" + val
			if seen[key] {
				continue
			}
			seen[key] = true
			artifacts = append(artifacts, &JSArtifact{
				SourceURL: sourceURL,
				Type:      m.category,
				Value:     val,
			})
		}
	}
	return artifacts
}
