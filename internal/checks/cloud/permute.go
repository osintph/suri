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

package cloud

import "strings"

// variantFmts is the ordered list of name templates applied to the stem.
// %s is replaced with the stem in each template.
var variantFmts = []string{
	"%s",
	"%s-prod",
	"%s-dev",
	"%s-backup",
	"%s-assets",
	"%s-static",
	"%s-data",
	"%s-uploads",
	"%s-tf-state",
	"%s-logs",
	"prod-%s",
	"dev-%s",
}

// Names returns the full list of candidate bucket name stems for the given base
// name by applying variantFmts.
func Names(stem string) []string {
	out := make([]string, len(variantFmts))
	for i, f := range variantFmts {
		out[i] = strings.ReplaceAll(f, "%s", stem)
	}
	return out
}

// DomainStem extracts the likely company name from a domain for use in bucket
// name permutation. For "example.com" returns "example"; for multi-label
// domains like "api.example.com" it returns "example" (second-to-last label).
func DomainStem(domain string) string {
	domain = strings.ToLower(strings.TrimPrefix(domain, "*."))
	parts := strings.Split(domain, ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2]
	}
	return parts[0]
}
