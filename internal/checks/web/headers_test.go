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
	"net/http/httptest"
	"testing"

	"github.com/osintph/suri/internal/checks"
	"github.com/osintph/suri/internal/crawler"
	internalhttp "github.com/osintph/suri/internal/http"
	"github.com/osintph/suri/internal/scope"
)

func webTarget(srv *httptest.Server) *checks.Target {
	sc := &scope.Scope{
		Hostnames: []string{"127.0.0.1"},
		IPs:       []string{"127.0.0.1"},
	}
	return &checks.Target{
		Inventory: &crawler.Inventory{},
		Scope:     sc,
		HTTP:      internalhttp.New(sc),
		SeedURLs:  []string{srv.URL},
		Canary:    "deadbeef",
	}
}

func TestHeadersCheckMissingAll(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No security headers.
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello"))
	}))
	defer srv.Close()

	ck := &HeadersCheck{}
	findings, err := ck.Run(context.Background(), webTarget(srv))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Without HTTPS, HSTS finding is not expected. We expect:
	// CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
	if len(findings) < 3 {
		t.Errorf("expected at least 3 header findings for response with no security headers, got %d", len(findings))
	}

	// Verify specific check IDs are present.
	ids := make(map[string]bool)
	for _, f := range findings {
		ids[f.CheckID] = true
	}
	for _, want := range []string{"web.headers.csp", "web.headers.xfo", "web.headers.xcto"} {
		if !ids[want] {
			t.Errorf("expected finding %q, not found (got %v)", want, ids)
		}
	}
}

func TestHeadersCheckAllPresent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "geolocation=()")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("secure"))
	}))
	defer srv.Close()

	ck := &HeadersCheck{}
	findings, err := ck.Run(context.Background(), webTarget(srv))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// HSTS not expected (not HTTPS). All other headers present. Should be 0 findings.
	for _, f := range findings {
		if f.CheckID != "web.headers.hsts" {
			t.Errorf("unexpected finding %q when all security headers are present", f.CheckID)
		}
	}
}

func TestHeadersCheckWeakXFrameOptions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "ALLOWALL") // not a valid value
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "geolocation=()")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test"))
	}))
	defer srv.Close()

	ck := &HeadersCheck{}
	findings, err := ck.Run(context.Background(), webTarget(srv))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.CheckID == "web.headers.xfo" {
			found = true
		}
	}
	if !found {
		t.Error("expected a finding for weak X-Frame-Options value, got none")
	}
}

func TestHeadersCheckNoSeedURLs(t *testing.T) {
	ck := &HeadersCheck{}
	findings, err := ck.Run(context.Background(), &checks.Target{
		Inventory: &crawler.Inventory{},
		SeedURLs:  nil,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings with no seed URLs, got %d", len(findings))
	}
}
