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

// TestAdminCheckInterestingPathFinding verifies that a 200 response on a path
// from interesting-paths.txt (.git/HEAD) emits a medium/firm finding.
func TestAdminCheckInterestingPathFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.git/HEAD" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ref: refs/heads/main\n"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	// Use an empty common wordlist to isolate the interesting-paths tier.
	target := testTarget(srv)
	ck := &AdminCheck{WordlistPath: miniWordlist(t)}

	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	var found *checks.Finding
	for _, f := range findings {
		if strings.Contains(f.URL, "/.git/HEAD") {
			found = f
			break
		}
	}
	if found == nil {
		t.Fatal("expected a finding for /.git/HEAD, got none")
	}
	if found.Severity != checks.SeverityMedium {
		t.Errorf("Severity: want medium, got %q", found.Severity)
	}
	if found.Confidence != checks.ConfidenceFirm {
		t.Errorf("Confidence: want firm, got %q", found.Confidence)
	}
}

// TestAdminCheckInterestingPathStillEmittedOn403 verifies that a 403 response
// on an interesting path (.env) still emits a medium/firm finding (path exists,
// access restricted, still security-relevant).
func TestAdminCheckInterestingPathStillEmittedOn403(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Forbidden"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	target := testTarget(srv)
	ck := &AdminCheck{WordlistPath: miniWordlist(t)}

	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	var found *checks.Finding
	for _, f := range findings {
		if strings.Contains(f.URL, "/.env") {
			found = f
			break
		}
	}
	if found == nil {
		t.Fatal("expected a finding for /.env (403), got none")
	}
	if found.Severity != checks.SeverityMedium {
		t.Errorf("Severity: want medium, got %q", found.Severity)
	}
	if found.Confidence != checks.ConfidenceFirm {
		t.Errorf("Confidence: want firm, got %q", found.Confidence)
	}
}

// TestAdminCheckCommonPath200IsInfoTentative verifies that a 200 response on a
// common admin path emits an info/tentative finding (no soft-200 detection; the
// operator decides whether to review these via --include-info).
func TestAdminCheckCommonPath200IsInfoTentative(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("admin area"))
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

	var found *checks.Finding
	for _, f := range findings {
		if strings.Contains(f.URL, "/admin") {
			found = f
			break
		}
	}
	if found == nil {
		t.Fatal("expected a finding for /admin (200), got none")
	}
	if found.Severity != checks.SeverityInfo {
		t.Errorf("Severity: want info, got %q", found.Severity)
	}
	if found.Confidence != checks.ConfidenceTentative {
		t.Errorf("Confidence: want tentative, got %q", found.Confidence)
	}
}

// TestAdminCheckCommonPath401IsInfoFirm verifies that a 401 response on a
// common admin path emits an info/firm finding.
func TestAdminCheckCommonPath401IsInfoFirm(t *testing.T) {
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

	var found *checks.Finding
	for _, f := range findings {
		if strings.Contains(f.URL, "/admin") {
			found = f
			break
		}
	}
	if found == nil {
		t.Fatal("expected a finding for /admin (401), got none")
	}
	if found.Severity != checks.SeverityInfo {
		t.Errorf("Severity: want info, got %q", found.Severity)
	}
	if found.Confidence != checks.ConfidenceFirm {
		t.Errorf("Confidence: want firm, got %q", found.Confidence)
	}
}

// TestAdminCheckNoFindingOn404 verifies that 404 responses produce no findings
// for either wordlist tier.
func TestAdminCheckNoFindingOn404(t *testing.T) {
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
		t.Errorf("expected 0 findings for all-404 server, got %d", len(findings))
	}
}

// TestAdminCheckRedirectSkipped verifies that a redirect on a common admin path
// does not emit a finding when the redirect destination returns 404.
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
	// /admin redirects to /login which returns 404. The client follows the redirect
	// and sees 404, which is skipped. Interesting paths also return 404 (skipped).
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when redirect leads to 404, got %d", len(findings))
	}
}

// TestAdminCheckWordlistSource verifies that the WordlistSource field on a
// finding reflects the user-supplied wordlist tier when -w is given.
func TestAdminCheckWordlistSource(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("admin page content"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	wlPath := miniWordlist(t, "/admin")
	target := testTarget(srv)
	ck := &AdminCheck{WordlistPath: wlPath}

	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	var adminFinding *checks.Finding
	for _, f := range findings {
		if strings.Contains(f.URL, "/admin") {
			adminFinding = f
			break
		}
	}
	if adminFinding == nil {
		t.Fatal("expected a finding for /admin")
	}
	if !strings.HasPrefix(adminFinding.WordlistSource, "user:") {
		t.Errorf("WordlistSource: want user:..., got %q", adminFinding.WordlistSource)
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
