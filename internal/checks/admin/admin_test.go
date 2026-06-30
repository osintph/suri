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

// findFinding returns the first finding whose URL contains the given substring.
func findFinding(findings []*checks.Finding, urlSubstr string) *checks.Finding {
	for _, f := range findings {
		if strings.Contains(f.URL, urlSubstr) {
			return f
		}
	}
	return nil
}

// --- Interesting-paths catalogue tests ---

// TestInterestingPathContentVerified verifies that .git/HEAD returning a body
// that matches the content pattern emits a medium/confirmed finding.
func TestInterestingPathContentVerified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.git/HEAD" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ref: refs/heads/main\n"))
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

	f := findFinding(findings, "/.git/HEAD")
	if f == nil {
		t.Fatal("expected a finding for /.git/HEAD, got none")
	}
	if f.CheckID != interestingCheckID {
		t.Errorf("CheckID: want %q, got %q", interestingCheckID, f.CheckID)
	}
	if f.Severity != checks.SeverityMedium {
		t.Errorf("Severity: want medium, got %q", f.Severity)
	}
	if f.Confidence != checks.ConfidenceConfirmed {
		t.Errorf("Confidence: want confirmed, got %q", f.Confidence)
	}
	if !strings.Contains(f.Title, "Git repository HEAD reference") {
		t.Errorf("Title should contain catalogue description, got %q", f.Title)
	}
}

// TestInterestingPathSPACatchAll verifies that .git/HEAD returning an Angular
// SPA shell (no content pattern match) does not emit a finding.
func TestInterestingPathSPACatchAll(t *testing.T) {
	spaBody := `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>OWASP Juice Shop</title>
<base href="/">
<link rel="stylesheet" href="styles.css">
</head><body><app-root></app-root>
<script src="runtime.js"></script>
<script src="main.js"></script>
</body></html>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Angular SPA: every URL returns 200 with the app shell.
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(spaBody))
	}))
	defer srv.Close()

	target := testTarget(srv)
	ck := &AdminCheck{WordlistPath: miniWordlist(t)}

	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// No interesting-path finding should be emitted; SPA bodies never match.
	for _, f := range findings {
		if f.CheckID == interestingCheckID {
			t.Errorf("unexpected interesting-path finding for SPA catch-all: %s %s", f.URL, f.Title)
		}
	}
}

// TestInterestingPath403StillFlags verifies that a 403 response on an
// interesting path emits a medium/firm finding even without content verification.
func TestInterestingPath403StillFlags(t *testing.T) {
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

	f := findFinding(findings, "/.env")
	if f == nil {
		t.Fatal("expected a finding for /.env (403), got none")
	}
	if f.Severity != checks.SeverityMedium {
		t.Errorf("Severity: want medium, got %q", f.Severity)
	}
	if f.Confidence != checks.ConfidenceFirm {
		t.Errorf("Confidence: want firm, got %q", f.Confidence)
	}
}

// TestInterestingPathHighSeverity verifies that entries with severity_if_protected
// = "high" emit a high/confirmed finding when a content pattern matches.
func TestInterestingPathHighSeverity(t *testing.T) {
	privateKey := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\n"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/id_rsa" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(privateKey))
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

	f := findFinding(findings, "/id_rsa")
	if f == nil {
		t.Fatal("expected a finding for /id_rsa, got none")
	}
	if f.Severity != checks.SeverityHigh {
		t.Errorf("Severity: want high, got %q", f.Severity)
	}
	if f.Confidence != checks.ConfidenceConfirmed {
		t.Errorf("Confidence: want confirmed, got %q", f.Confidence)
	}
}

// TestInterestingPath404NoFinding verifies that a 404 response on any
// interesting-paths catalogue entry emits no finding.
func TestInterestingPath404NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
	}))
	defer srv.Close()

	target := testTarget(srv)
	ck := &AdminCheck{WordlistPath: miniWordlist(t)}

	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	for _, f := range findings {
		if f.CheckID == interestingCheckID {
			t.Errorf("unexpected interesting-path finding on all-404 server: %s", f.URL)
		}
	}
}

// TestInterestingPathBodyExcerptInEvidence verifies that a confirmed interesting-path
// finding includes at most 200 bytes of the response body in its evidence.
func TestInterestingPathBodyExcerptInEvidence(t *testing.T) {
	longBody := "ref: refs/heads/main\n" + strings.Repeat("X", 500)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.git/HEAD" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(longBody))
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

	f := findFinding(findings, "/.git/HEAD")
	if f == nil {
		t.Fatal("expected a finding for /.git/HEAD, got none")
	}
	if f.Evidence == nil {
		t.Fatal("expected Evidence to be set on confirmed finding")
	}
	if len(f.Evidence.ResponseBytes) > 200 {
		t.Errorf("Evidence.ResponseBytes: want at most 200 bytes, got %d", len(f.Evidence.ResponseBytes))
	}
}

// --- Common-path wordlist tests ---

// TestAdminCheckCommonPath200IsInfoTentative verifies that a 200 response on a
// common admin path emits an info/tentative finding.
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

	f := findFinding(findings, "/admin")
	if f == nil {
		t.Fatal("expected a finding for /admin (200), got none")
	}
	if f.Severity != checks.SeverityInfo {
		t.Errorf("Severity: want info, got %q", f.Severity)
	}
	if f.Confidence != checks.ConfidenceTentative {
		t.Errorf("Confidence: want tentative, got %q", f.Confidence)
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

	f := findFinding(findings, "/admin")
	if f == nil {
		t.Fatal("expected a finding for /admin (401), got none")
	}
	if f.Severity != checks.SeverityInfo {
		t.Errorf("Severity: want info, got %q", f.Severity)
	}
	if f.Confidence != checks.ConfidenceFirm {
		t.Errorf("Confidence: want firm, got %q", f.Confidence)
	}
}

// TestAdminCheckNoFindingOn404 verifies that 404 responses produce no findings
// from either probe tier.
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
	// /admin redirects to /login which returns 404. Interesting paths also 404.
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when redirect leads to 404, got %d", len(findings))
	}
}

// TestAdminCheckWordlistSource verifies that the WordlistSource on a common-path
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

	// /admin returns 200 without matching any interesting-path pattern,
	// so the finding comes from the common wordlist tier.
	f := findFinding(findings, "/admin")
	if f == nil {
		t.Fatal("expected a finding for /admin")
	}
	if !strings.HasPrefix(f.WordlistSource, "user:") {
		t.Errorf("WordlistSource: want user:..., got %q", f.WordlistSource)
	}
}

// TestAdminProbeWritesStatusBack verifies that after Run completes, every URL
// added to the inventory by a probe has its ResponseStatus set to a non-zero
// value and its BodyHash set to a non-empty string.
func TestAdminProbeWritesStatusBack(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("admin panel"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
	}))
	defer srv.Close()

	target := testTarget(srv)
	ck := &AdminCheck{WordlistPath: miniWordlist(t, "/admin")}

	_, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(target.Inventory.URLs) == 0 {
		t.Fatal("expected probe URLs in inventory, got none")
	}
	for _, u := range target.Inventory.URLs {
		if u.Source != "admin-probe" {
			continue
		}
		if u.ResponseStatus == 0 {
			t.Errorf("URL %s: ResponseStatus not set (got 0)", u.URL)
		}
		if u.BodyHash == "" {
			t.Errorf("URL %s: BodyHash not set", u.URL)
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

// cloudflareBlockPageAdmin is a minimal Cloudflare WAF 403 block body for admin tests.
// Cloudflare's 1020 rule returns 403 with the block-page HTML rather than the
// 200-challenge style, making it the actual trigger for firm interesting-path findings.
const cloudflareBlockPageAdmin = `<!DOCTYPE html>
<html lang="en-US">
<head><title>Attention Required! | Cloudflare</title></head>
<body>
<div class="cf-error-details">
<h1>Sorry, you have been blocked</h1>
<p>Cloudflare Ray ID: a13467dd6c97d437</p>
</div>
</body></html>`

// TestInterestingPathSkipsWAFBlockPage verifies that a Cloudflare WAF block page
// (403 response) on an interesting path is NOT emitted as a finding.
// Without the WAF fix, a 403 with a WAF body triggers a firm finding because
// probeInterestingPath does not inspect the response body for 401/403 responses.
func TestInterestingPathSkipsWAFBlockPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/wp-config.php" {
			// Cloudflare 1020 block: 403 status with WAF block-page body.
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(cloudflareBlockPageAdmin))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	target := testTarget(srv)
	target.WAFTracker = checks.NewWAFTracker()
	ck := &AdminCheck{WordlistPath: miniWordlist(t)}

	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	for _, f := range findings {
		if f.CheckID == interestingCheckID && strings.Contains(f.URL, "wp-config.php") {
			t.Errorf("unexpected interesting-path finding for WAF block page: URL=%s title=%q", f.URL, f.Title)
		}
	}
}

// TestInterestingPathFiresOnRealMatch is a regression guard confirming that WAF
// detection does not accidentally suppress legitimate content-verified findings.
func TestInterestingPathFiresOnRealMatch(t *testing.T) {
	wpConfigBody := "<?php\ndefine('DB_NAME', 'wordpress');\ndefine('DB_PASSWORD', 'hunter2');\ndefine('AUTH_KEY', 'abc123');\n?>"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/wp-config.php" {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(wpConfigBody))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	target := testTarget(srv)
	target.WAFTracker = checks.NewWAFTracker()
	ck := &AdminCheck{WordlistPath: miniWordlist(t)}

	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	f := findFinding(findings, "/wp-config.php")
	if f == nil {
		t.Fatal("expected a finding for /wp-config.php with real content, got none")
	}
	if f.CheckID != interestingCheckID {
		t.Errorf("CheckID: want %q, got %q", interestingCheckID, f.CheckID)
	}
	if f.Confidence != checks.ConfidenceConfirmed {
		t.Errorf("Confidence: want confirmed, got %q", f.Confidence)
	}
}
