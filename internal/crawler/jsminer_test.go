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

package crawler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	internalhttp "github.com/osintph/suri/internal/http"
)

func TestMineJSFromFixture(t *testing.T) {
	data, err := os.ReadFile("testdata/crawler/app.js")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	artifacts := MineJS("http://target.local/app.js", data)

	typeCount := make(map[string]int)
	for _, a := range artifacts {
		typeCount[a.Type]++
	}

	cases := []struct {
		typ  string
		want int
	}{
		{"api-path", 2},  // /api/v1/users, /api/v1/admin/roles
		{"s3", 1},
		{"azure-blob", 1},
		{"gcs", 1},
		{"auth-header", 1},
		{"role", 2}, // role:admin, permission:write
	}
	for _, tc := range cases {
		if typeCount[tc.typ] < tc.want {
			t.Errorf("type %q: want at least %d, got %d", tc.typ, tc.want, typeCount[tc.typ])
		}
	}
}

func TestMineJSDeduplication(t *testing.T) {
	data := []byte(`fetch("/api/v1/users"); fetch("/api/v1/users");`)
	artifacts := MineJS("http://x.invalid/app.js", data)
	count := 0
	for _, a := range artifacts {
		if a.Type == "api-path" && a.Value == "/api/v1/users" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 deduplicated entry, got %d", count)
	}
}

func TestMineJSEmpty(t *testing.T) {
	artifacts := MineJS("http://x.invalid/empty.js", []byte(""))
	if len(artifacts) != 0 {
		t.Errorf("expected 0 artifacts for empty JS, got %d", len(artifacts))
	}
}

// TestJSURLsFeedCrawlQueue verifies that URL-like JS artifacts are resolved and
// dispatched back into the crawl queue, while out-of-scope URLs are retained as
// artifacts but never fetched.
func TestJSURLsFeedCrawlQueue(t *testing.T) {
	var (
		srv     *httptest.Server
		fetchMu sync.Mutex
		fetched = make(map[string]bool)
	)

	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchMu.Lock()
		fetched[r.URL.Path] = true
		fetchMu.Unlock()

		switch r.URL.Path {
		case "/js-mine-page.html":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, `<!DOCTYPE html><html><body>`+
				`<script src="/js-linked.js"></script>`+
				`</body></html>`)

		case "/js-linked.js":
			// Four URL-like patterns to exercise the dispatch wiring:
			//   1. Absolute path   → api-path miner       → in scope → dispatched
			//   2. Full same-host  → url-full miner        → in scope → dispatched
			//   3. Full other-host → url-full miner        → out of scope → artifact only
			//   4. Proto-relative  → url-proto-relative    → in scope → dispatched
			addr := srv.Listener.Addr().String()
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprintf(w,
				`fetch("/api/v1/items"); `+
					`fetch("http://%s/api/v1/users"); `+
					`var ext="https://external.example.com/data"; `+
					`var proto="//%s/api/v1/status";`,
				addr, addr,
			)

		case "/api/v1/items", "/api/v1/users", "/api/v1/status":
			w.WriteHeader(http.StatusOK)

		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	sc := localhostScope()
	client := internalhttp.New(sc)
	cfg := Config{MaxDepth: 3, MaxURLs: 50, Concurrency: 2, RatePerHost: 1000}
	cr := New(sc, client, cfg)

	inv, err := cr.Crawl(context.Background(), []string{srv.URL + "/js-mine-page.html"})
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}

	// Build a set of all URLs that ended up in the crawl inventory.
	inQueue := make(map[string]bool)
	for _, u := range inv.URLs {
		inQueue[u.URL] = true
	}

	// Same-host URLs must appear in the crawl queue (and therefore be fetched).
	for _, wantPath := range []string{"/api/v1/items", "/api/v1/users", "/api/v1/status"} {
		wantURL := srv.URL + wantPath
		if !inQueue[wantURL] {
			t.Errorf("same-host URL not dispatched to crawl queue: %s", wantURL)
		}
		fetchMu.Lock()
		wasFetched := fetched[wantPath]
		fetchMu.Unlock()
		if !wasFetched {
			t.Errorf("same-host URL was queued but never fetched: %s", wantPath)
		}
	}

	// Out-of-scope URL must appear in JS artifacts.
	foundArtifact := false
	for _, a := range inv.JSArtifacts {
		if strings.Contains(a.Value, "external.example.com") {
			foundArtifact = true
			break
		}
	}
	if !foundArtifact {
		t.Error("out-of-scope URL not found in JS artifacts")
	}

	// Out-of-scope URL must NOT be in the crawl queue.
	for _, u := range inv.URLs {
		if strings.Contains(u.URL, "external.example.com") {
			t.Errorf("out-of-scope URL was dispatched to crawl queue: %s", u.URL)
		}
	}
}
