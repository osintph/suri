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
	"sync"
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

func TestAdminCheckFound200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(strings.Repeat("admin panel content", 20)))
			return
		}
		// All other paths (including the baseline probes) return a short distinct body.
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
		if strings.Contains(f.URL, "/admin") && f.Severity == checks.SeverityMedium {
			found = true
		}
	}
	if !found {
		t.Errorf("expected medium-severity finding for /admin, got %+v", findings)
	}
}

func TestAdminCheckSoft404Filtered(t *testing.T) {
	const body = "custom not found page with fixed length padding to be consistent"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Server returns 200 for every path (soft-404).
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
		t.Errorf("expected soft-404 responses to be filtered, got %d finding(s): %+v", len(findings), findings)
	}
}

func TestAdminCheck403IsInfo(t *testing.T) {
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
	if f.Severity != checks.SeverityInfo {
		t.Errorf("Severity: want info, got %q", f.Severity)
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

func TestSoft200SigMatches(t *testing.T) {
	sig := soft200Sig{status: 200, bodyLen: 1000}
	cases := []struct {
		status  int
		bodyLen int
		want    bool
	}{
		{200, 1000, true},  // exact match
		{200, 1049, true},  // within 5%
		{200, 1050, false}, // at the boundary (5% = 50, delta=50 is not < 50)
		{200, 800, false},  // too different
		{404, 1000, false}, // different status
	}
	for _, tc := range cases {
		got := sig.matches(tc.status, tc.bodyLen)
		if got != tc.want {
			t.Errorf("sig.matches(%d, %d) = %v, want %v", tc.status, tc.bodyLen, got, tc.want)
		}
	}
}

// TestAdminCheckMultiTemplateSoft200 verifies that a host serving two distinct
// soft-200 templates is fully suppressed when both templates are captured during
// the three-probe baseline calibration.
//
// The three baseline paths use different structural shapes:
//   - baselinePath1 (simple)      → template A (9900 bytes, e.g. Angular SPA)
//   - baselinePath2 (nested)      → template B (2400 bytes, e.g. Express error)
//   - baselinePath3 (well-known)  → template A again (deduped in cache)
//
// All wordlist probes returning either template must be suppressed, producing
// zero findings. This is the key difference from the 5.5 approach, which would
// have emitted a finding for the first wordlist probe hitting template B.
func TestAdminCheckMultiTemplateSoft200(t *testing.T) {
	const (
		templateALen = 9900 // Angular SPA
		templateBLen = 2400 // Express error page
	)
	templateA := strings.Repeat("a", templateALen)
	templateB := strings.Repeat("b", templateBLen)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/" + baselinePath1, "/" + baselinePath3:
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(templateA))
		case "/" + baselinePath2:
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(templateB))
		case "/path-a-1", "/path-a-2":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(templateA))
		case "/path-b-1", "/path-b-2", "/path-b-3":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(templateB))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	target := testTarget(srv)
	target.Concurrency = 1 // sequential for determinism

	ck := &AdminCheck{
		WordlistPath: miniWordlist(t, "/path-a-1", "/path-a-2", "/path-b-1", "/path-b-2", "/path-b-3"),
	}

	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Both templates were captured during baseline calibration, so every
	// wordlist probe matches the cache. Expected: zero findings.
	if len(findings) != 0 {
		t.Errorf("expected 0 findings (both templates suppressed by baseline), got %d: %v", len(findings), findings)
	}
}

// TestAdminCheckThreeBaselineProbes verifies that exactly three calibration
// probes are issued before any wordlist probing begins, and that those probes
// use the three defined baseline path shapes.
func TestAdminCheckThreeBaselineProbes(t *testing.T) {
	var mu sync.Mutex
	var requestPaths []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestPaths = append(requestPaths, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	target := testTarget(srv)
	target.Concurrency = 1 // sequential so request order is deterministic

	ck := &AdminCheck{
		WordlistPath: miniWordlist(t, "/admin"),
	}

	_, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// The first three requests must be the calibration probes.
	wantBaseline := []string{
		"/" + baselinePath1,
		"/" + baselinePath2,
		"/" + baselinePath3,
	}
	if len(requestPaths) < len(wantBaseline) {
		t.Fatalf("expected at least %d requests, got %d", len(wantBaseline), len(requestPaths))
	}
	for i, want := range wantBaseline {
		if requestPaths[i] != want {
			t.Errorf("request[%d]: want %s, got %s", i, want, requestPaths[i])
		}
	}

	// No baseline path must appear after the calibration phase ends.
	baselineSet := make(map[string]bool)
	for _, bp := range wantBaseline {
		baselineSet[bp] = true
	}
	for i, p := range requestPaths[len(wantBaseline):] {
		if baselineSet[p] {
			t.Errorf("baseline probe path %s appeared at position %d (after calibration)", p, len(wantBaseline)+i)
		}
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
