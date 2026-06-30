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
	"os"
	"path/filepath"
	"testing"
)

func readWAFFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "waf", name))
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	return b
}

func TestDetectCloudflare(t *testing.T) {
	body := readWAFFixture(t, "cloudflare-block.html")
	if got := DetectWAF(body); got != WAFCloudflare {
		t.Errorf("DetectWAF(cloudflare-block.html) = %v (%s), want WAFCloudflare", got, got)
	}
}

func TestDetectAkamai(t *testing.T) {
	body := readWAFFixture(t, "akamai-block.html")
	if got := DetectWAF(body); got != WAFAkamai {
		t.Errorf("DetectWAF(akamai-block.html) = %v (%s), want WAFAkamai", got, got)
	}
}

func TestDetectImperva(t *testing.T) {
	body := readWAFFixture(t, "imperva-block.html")
	if got := DetectWAF(body); got != WAFImperva {
		t.Errorf("DetectWAF(imperva-block.html) = %v (%s), want WAFImperva", got, got)
	}
}

func TestDetectAWS(t *testing.T) {
	body := readWAFFixture(t, "aws-waf-block.html")
	if got := DetectWAF(body); got != WAFAWS {
		t.Errorf("DetectWAF(aws-waf-block.html) = %v (%s), want WAFAWS", got, got)
	}
}

func TestDetectNone(t *testing.T) {
	body := readWAFFixture(t, "normal-page.html")
	if got := DetectWAF(body); got != WAFNone {
		t.Errorf("DetectWAF(normal-page.html) = %v (%s), want WAFNone", got, got)
	}
}

func TestDetectTruncated(t *testing.T) {
	body := []byte("hello world — short body without any WAF block-page signatures")
	if got := DetectWAF(body); got != WAFNone {
		t.Errorf("DetectWAF(short body) = %v (%s), want WAFNone", got, got)
	}
}

func TestWAFTypeString(t *testing.T) {
	tests := []struct {
		waf  WAFType
		want string
	}{
		{WAFNone, "none"},
		{WAFCloudflare, "cloudflare"},
		{WAFAkamai, "akamai"},
		{WAFImperva, "imperva"},
		{WAFAWS, "aws-waf"},
	}
	for _, tt := range tests {
		if got := tt.waf.String(); got != tt.want {
			t.Errorf("WAFType(%d).String() = %q, want %q", int(tt.waf), got, tt.want)
		}
	}
}

// TestDetectOnlyInspectsFirst16KB verifies that DetectWAF examines only the
// first 16 KB even when the body is much larger.
func TestDetectOnlyInspectsFirst16KB(t *testing.T) {
	// Build a body where the Cloudflare signature appears only after 16 KB.
	padding := make([]byte, 16*1024+1)
	for i := range padding {
		padding[i] = 'X'
	}
	body := append(padding, []byte("Sorry, you have been blocked")...)
	if got := DetectWAF(body); got != WAFNone {
		t.Errorf("DetectWAF matched signature beyond 16 KB boundary: got %s, want none", got)
	}
}
