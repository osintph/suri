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
	"net/http"
	"strings"

	"github.com/osintph/suri/internal/crawler"
)

// pathSegmentEncode encodes s for embedding in a URL path segment.
// It keeps only RFC 3986 unreserved characters (ALPHA, DIGIT, -, ., _, ~)
// unencoded and percent-encodes everything else. This is stricter than
// url.PathEscape, which leaves sub-delimiters (including ;) unencoded.
// The conservative encoding is necessary because some web frameworks
// (e.g. Express.js) interpret ; in path segments as a separator and strip
// everything after it before the route handler sees the value.
func pathSegmentEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if ('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z') || ('0' <= c && c <= '9') ||
			c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// buildPathInjectURL substitutes the {paramName} placeholder in template with
// the path-segment-encoded payload. Other {placeholders} are left as-is.
func buildPathInjectURL(template, paramName, payload string) string {
	placeholder := "{" + paramName + "}"
	return strings.ReplaceAll(template, placeholder, pathSegmentEncode(payload))
}

// buildPathProbeReq builds a GET request by substituting payload into the
// URL template's {paramName} placeholder (path-segment-encoded).
func buildPathProbeReq(ctx context.Context, injectURL, paramName, payload string) (*http.Request, error) {
	finalURL := buildPathInjectURL(injectURL, paramName, payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, finalURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building path probe request for %q: %w", finalURL, err)
	}
	return req, nil
}

// findingInjectURL returns the URL to record in a finding for the given param
// and payload. For path params it resolves the template to the actual probed
// URL; for query/form params it returns param.InjectURL unchanged.
func findingInjectURL(param *crawler.Parameter, payload string) string {
	if param.Source == "swagger-path" {
		return buildPathInjectURL(param.InjectURL, param.Name, payload)
	}
	return param.InjectURL
}
