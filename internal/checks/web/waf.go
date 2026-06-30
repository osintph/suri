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
	"regexp"
	"sync"
)

// WAFType identifies a detected WAF vendor.
type WAFType int

const (
	WAFNone       WAFType = iota
	WAFCloudflare         // Cloudflare block / challenge page
	WAFAkamai             // Akamai Kona Site Defender
	WAFImperva            // Imperva / Incapsula
	WAFAWS                // AWS WAF
)

// String returns the lowercase vendor name suitable for log attrs and WAFTracker keys.
func (w WAFType) String() string {
	switch w {
	case WAFCloudflare:
		return "cloudflare"
	case WAFAkamai:
		return "akamai"
	case WAFImperva:
		return "imperva"
	case WAFAWS:
		return "aws-waf"
	default:
		return "none"
	}
}

type wafPattern struct {
	wafType  WAFType
	patterns []*regexp.Regexp
}

var (
	compiledMatchers []wafPattern
	compileOnce      sync.Once
)

func getMatchers() []wafPattern {
	compileOnce.Do(func() {
		compiledMatchers = []wafPattern{
			{
				wafType: WAFCloudflare,
				patterns: []*regexp.Regexp{
					regexp.MustCompile(`Sorry, you have been blocked`),
					regexp.MustCompile(`Cloudflare Ray ID:`),
					regexp.MustCompile(`cf-error-details`),
					regexp.MustCompile(`Performance &amp; security by Cloudflare`),
				},
			},
			{
				wafType: WAFAkamai,
				patterns: []*regexp.Regexp{
					// "Reference #" with HTML character entities — Akamai's incident reference format.
					regexp.MustCompile(`Reference&#32;&#35;`),
					regexp.MustCompile(`akamai\.com`),
				},
			},
			{
				wafType: WAFImperva,
				patterns: []*regexp.Regexp{
					regexp.MustCompile(`Incapsula incident ID:`),
					regexp.MustCompile(`_Incapsula_Resource`),
					regexp.MustCompile(`incident_id=`),
				},
			},
			{
				wafType: WAFAWS,
				patterns: []*regexp.Regexp{
					regexp.MustCompile(`<title>Request blocked</title>`),
					regexp.MustCompile(`AWS Request ID`),
				},
			},
		}
	})
	return compiledMatchers
}

// reAkamaiAccessDenied and reAkamaiRef support the Akamai compound check.
var (
	reAkamaiAccessDenied = regexp.MustCompile(`(?i)Access Denied`)
	reAkamaiRef          = regexp.MustCompile(`(?i)akamai`)
)

// DetectWAF inspects up to the first 16 KB of body and returns the first
// matched WAF vendor. Returns WAFNone if no known WAF signature is found.
func DetectWAF(body []byte) WAFType {
	const limit = 16 * 1024
	if len(body) > limit {
		body = body[:limit]
	}

	for _, m := range getMatchers() {
		for _, re := range m.patterns {
			if re.Match(body) {
				return m.wafType
			}
		}
	}

	// Akamai compound check: "Access Denied" AND "akamai" both present.
	// The individual strings can appear on legitimate pages; together they
	// are a reliable indicator of an Akamai error response.
	if reAkamaiAccessDenied.Match(body) && reAkamaiRef.Match(body) {
		return WAFAkamai
	}

	return WAFNone
}
