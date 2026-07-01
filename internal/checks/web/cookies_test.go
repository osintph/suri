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
	"net/http"
	"testing"

	"github.com/osintph/suri/internal/checks"
	"github.com/osintph/suri/internal/crawler"
)

// inventoryTarget returns a Target with no HTTP client (nil) to assert that
// checks reading from inventory make zero HTTP calls.
func inventoryTarget(urls []*crawler.DiscoveredURL) *checks.Target {
	return &checks.Target{
		Inventory: &crawler.Inventory{URLs: urls},
		HTTP:      nil, // panics on any Do call -- proves no HTTP requests are made
	}
}

func TestCookieCheckDetectsMissingFlags(t *testing.T) {
	// Cookie with no Secure, no HttpOnly, no SameSite -- expects 3 findings.
	urls := []*crawler.DiscoveredURL{
		{
			URL:            "http://example.com/",
			ResponseStatus: 200,
			Cookies: []*http.Cookie{
				{Name: "session", Value: "abc123"},
			},
		},
	}
	ck := &CookieCheck{}
	findings, err := ck.Run(context.Background(), inventoryTarget(urls))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) < 3 {
		t.Errorf("expected at least 3 cookie flag findings, got %d", len(findings))
	}
	for _, f := range findings {
		if f.CheckID != "web.cookies.missing-flags" {
			t.Errorf("unexpected CheckID %q", f.CheckID)
		}
		if f.Parameter != "session" {
			t.Errorf("expected parameter=session, got %q", f.Parameter)
		}
	}
}

func TestCookieCheckNoCookies(t *testing.T) {
	urls := []*crawler.DiscoveredURL{
		{URL: "http://example.com/", ResponseStatus: 200, Cookies: nil},
	}
	ck := &CookieCheck{}
	findings, err := ck.Run(context.Background(), inventoryTarget(urls))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestCookiesCheckReadsInventoryNotHTTP(t *testing.T) {
	// HTTP is nil: any target.HTTP.Do call would panic. Assert no panic.
	urls := []*crawler.DiscoveredURL{
		{
			URL:            "http://example.com/",
			ResponseStatus: 200,
			Cookies: []*http.Cookie{
				{Name: "sess", Value: "x"},
			},
		},
	}
	ck := &CookieCheck{}
	findings, err := ck.Run(context.Background(), inventoryTarget(urls))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected findings from inventory cookies")
	}
}

func TestCookieCheckSecureAndHttpOnlySet(t *testing.T) {
	// Cookie that is Secure and HttpOnly but missing SameSite -- expects 1 finding.
	urls := []*crawler.DiscoveredURL{
		{
			URL:            "https://example.com/",
			ResponseStatus: 200,
			Cookies: []*http.Cookie{
				{Name: "session", Value: "abc123", Secure: true, HttpOnly: true},
			},
		},
	}
	ck := &CookieCheck{}
	findings, err := ck.Run(context.Background(), inventoryTarget(urls))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Errorf("expected 1 finding (missing SameSite), got %d", len(findings))
	}
}
