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

package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/osintph/suri/internal/checks"
	"github.com/osintph/suri/internal/crawler"
	internalhttp "github.com/osintph/suri/internal/http"
	"github.com/osintph/suri/internal/scope"
)

func testScope(srv *httptest.Server) *scope.Scope {
	return &scope.Scope{
		Hostnames: []string{"127.0.0.1"},
		IPs:       []string{"127.0.0.1"},
	}
}

func testTarget(srv *httptest.Server) *checks.Target {
	sc := testScope(srv)
	client := internalhttp.New(sc)
	return &checks.Target{
		Inventory:   &crawler.Inventory{},
		Scope:       sc,
		HTTP:        client,
		Domain:      "example.com",
		Concurrency: 2,
		SeedURLs:    []string{srv.URL},
	}
}

// miniWordlist writes a small temporary wordlist file for testing.
func miniWordlist(t *testing.T, paths ...string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "wl-*.txt")
	if err != nil {
		t.Fatalf("TempFile: %v", err)
	}
	for _, p := range paths {
		f.WriteString(p + "\n")
	}
	f.Close()
	return f.Name()
}

// TestAdminCheckFound200 verifies that a 200 response whose body does not match
// any soft-response pattern emits an info/tentative finding.
func TestAdminCheckFound200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(strings.Repeat("admin panel content", 20)))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
	}))
	defer srv.Close()

	target := testTarget(srv)
	ck := &AdminCheck{WordlistPath: miniWordlist(t, "/admin", "/login")}

	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for /admin")
	}
	found := false
	for _, f := range findings {
		if strings.Contains(f.URL, "/admin") {
			if f.Severity != checks.SeverityInfo {
				t.Errorf("Severity: want info for unmatched 200, got %q", f.Severity)
			}
			if f.Confidence != checks.ConfidenceTentative {
				t.Errorf("Confidence: want tentative for unmatched 200, got %q", f.Confidence)
			}
			found = true
		}
	}
	if !found {
		t.Errorf("expected finding for /admin, got %+v", findings)
	}
}

// TestAdminCheckSoft404Filtered verifies that a 200 response whose body matches
// a known soft-response pattern (Angular SPA shell) is suppressed entirely.
func TestAdminCheckSoft404Filtered(t *testing.T) {
	const body = `<html><body><app-root></app-root></body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(body))
	}))
	defer srv.Close()

	target := testTarget(srv)
	ck := &AdminCheck{WordlistPath: miniWordlist(t, "/admin", "/login", "/dashboard")}

	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected Angular SPA shell 200 responses to be suppressed, got %d finding(s): %+v", len(findings), findings)
	}
}

// TestAdminCheck403IsMedium verifies that a 403 response emits a medium/firm finding.
func TestAdminCheck403IsMedium(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("access denied"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found page content"))
	}))
	defer srv.Close()

	target := testTarget(srv)
	ck := &AdminCheck{WordlistPath: miniWordlist(t, "/admin")}

	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for 403 path")
	}
	f := findings[0]
	if f.Severity != checks.SeverityMedium {
		t.Errorf("Severity: want medium, got %q", f.Severity)
	}
	if f.Confidence != checks.ConfidenceFirm {
		t.Errorf("Confidence: want firm, got %q", f.Confidence)
	}
	if !strings.Contains(f.URL, "/admin") {
		t.Errorf("URL: expected /admin in %q", f.URL)
	}
}

func TestAdminCheck404Skipped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
	}))
	defer srv.Close()

	target := testTarget(srv)
	ck := &AdminCheck{WordlistPath: miniWordlist(t, "/admin", "/login")}

	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for 404 responses, got %d", len(findings))
	}
}

func TestAdminCheckRedirectSkipped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			http.Redirect(w, r, "/login", http.StatusMovedPermanently)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
	}))
	defer srv.Close()

	target := testTarget(srv)
	ck := &AdminCheck{WordlistPath: miniWordlist(t, "/admin")}

	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected redirects to be skipped, got %d finding(s)", len(findings))
	}
}

func TestAdminCheckWordlistSource(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(strings.Repeat("admin page content here", 10)))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
	}))
	defer srv.Close()

	wlPath := miniWordlist(t, "/admin")
	target := testTarget(srv)
	ck := &AdminCheck{WordlistPath: wlPath}

	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding")
	}
	if !strings.HasPrefix(findings[0].WordlistSource, "user:") {
		t.Errorf("WordlistSource: want user:..., got %q", findings[0].WordlistSource)
	}
}

// TestAdminCheckSPAShellSuppression verifies that Angular SPA shell content
// (<app-root></app-root>) in a 200 response is suppressed.
func TestAdminCheckSPAShellSuppression(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<!DOCTYPE html><html><body><app-root></app-root></body></html>`))
	}))
	defer srv.Close()

	target := testTarget(srv)
	ck := &AdminCheck{WordlistPath: miniWordlist(t, "/admin", "/dashboard", "/config")}

	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected Angular SPA shell to be suppressed, got %d finding(s)", len(findings))
	}
}

// TestAdminCheckExpressErrorSuppression verifies that Express "Unexpected path"
// error pages in a 200 response are suppressed.
func TestAdminCheckExpressErrorSuppression(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><head><title>Error: Unexpected path: /admin</title></head><body>Error</body></html>`))
	}))
	defer srv.Close()

	target := testTarget(srv)
	ck := &AdminCheck{WordlistPath: miniWordlist(t, "/admin", "/login")}

	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected Express error page to be suppressed, got %d finding(s)", len(findings))
	}
}

// TestAdminCheckUnmatchedTwoHundredIsTentative verifies that a 200 response
// with arbitrary content (no pattern match) emits a finding with
// severity info and confidence tentative.
func TestAdminCheckUnmatchedTwoHundredIsTentative(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Welcome to the admin area. Please log in."))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	target := testTarget(srv)
	ck := &AdminCheck{WordlistPath: miniWordlist(t, "/admin")}

	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != checks.SeverityInfo {
		t.Errorf("Severity: want info for unmatched 200, got %q", f.Severity)
	}
	if f.Confidence != checks.ConfidenceTentative {
		t.Errorf("Confidence: want tentative for unmatched 200, got %q", f.Confidence)
	}
}

// TestAdminCheckFourOhOneIsFirm verifies that a 401 response emits a finding
// with severity medium and confidence firm.
func TestAdminCheckFourOhOneIsFirm(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.Header().Set("WWW-Authenticate", `Basic realm="Admin"`)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("authentication required"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	target := testTarget(srv)
	ck := &AdminCheck{WordlistPath: miniWordlist(t, "/admin")}

	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != checks.SeverityMedium {
		t.Errorf("Severity: want medium for 401, got %q", f.Severity)
	}
	if f.Confidence != checks.ConfidenceFirm {
		t.Errorf("Confidence: want firm for 401, got %q", f.Confidence)
	}
}

func TestUniqueOrigins(t *testing.T) {
	inv := &crawler.Inventory{
		URLs: []*crawler.DiscoveredURL{
			{URL: "http://example.com/page"},
			{URL: "http://example.com/other"},
			{URL: "https://api.example.com/v1"},
		},
	}
	seeds := []string{"http://example.com/"}
	got := uniqueOrigins(seeds, inv)

	if len(got) != 2 {
		t.Errorf("expected 2 unique origins, got %d: %v", len(got), got)
	}
	if got[0] != "http://example.com" {
		t.Errorf("first origin: want http://example.com, got %q", got[0])
	}
	if got[1] != "https://api.example.com" {
		t.Errorf("second origin: want https://api.example.com, got %q", got[1])
	}
}
