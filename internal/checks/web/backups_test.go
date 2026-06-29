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
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/osintph/suri/internal/crawler"
)

func TestBackupsCheckFoundBak(t *testing.T) {
	// Server returns 200 for .bak files and 404 for everything else.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".bak") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("DB_PASSWORD=secret"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	target := webTarget(srv)
	target.SeedURLs = []string{srv.URL}
	target.Inventory.URLs = []*crawler.DiscoveredURL{
		{URL: srv.URL + "/config.php", Source: "html", Depth: 1, ResponseStatus: 200, BodyHash: "aabbcc"},
	}

	ck := &BackupsCheck{}
	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected at least 1 backup finding for .bak file, got 0")
	}
	if findings[0].CheckID != "web.backup.file" {
		t.Errorf("unexpected check ID %q", findings[0].CheckID)
	}
}

func TestBackupsCheckFoundForbidden(t *testing.T) {
	// Server returns 403 for .bak files: firm confidence.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".bak") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	target := webTarget(srv)
	target.SeedURLs = []string{srv.URL}
	target.Inventory.URLs = []*crawler.DiscoveredURL{
		{URL: srv.URL + "/settings.py", Source: "html", Depth: 1, ResponseStatus: 200, BodyHash: "deadbeef"},
	}

	ck := &BackupsCheck{}
	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected at least 1 backup finding for 403 response, got 0")
	}
}

func TestBackupsCheckClean(t *testing.T) {
	// Server returns 404 for everything: no findings.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	target := webTarget(srv)
	target.SeedURLs = []string{srv.URL}
	target.Inventory.URLs = []*crawler.DiscoveredURL{
		{URL: srv.URL + "/login.php", Source: "html", Depth: 1, ResponseStatus: 200, BodyHash: "11223344"},
	}

	ck := &BackupsCheck{}
	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 backup findings for 404-only server, got %d", len(findings))
	}
}

// TestBackupCheckFiltersOutNon200 verifies that URLs with non-200/401/403
// response status are not probed. A server that returns 200 for .bak files
// should produce no findings because the only inventory URL had status 404.
func TestBackupCheckFiltersOutNon200(t *testing.T) {
	// Server returns 200 for all .bak paths (would be found if probed).
	var probeCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".bak") {
			atomic.AddInt32(&probeCount, 1)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("secret"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	target := webTarget(srv)
	target.SeedURLs = []string{srv.URL}
	// URL has status 404 from crawl: should be skipped entirely.
	target.Inventory.URLs = []*crawler.DiscoveredURL{
		{URL: srv.URL + "/config.php", Source: "html", Depth: 1, ResponseStatus: 404, BodyHash: ""},
	}

	ck := &BackupsCheck{}
	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// The 404-status URL must have been filtered out; the server's .bak path
	// must not have been probed.
	if atomic.LoadInt32(&probeCount) > 0 {
		t.Errorf("backup check probed a 404-status URL (%d probes), should have been skipped", probeCount)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for 404-status inventory URL, got %d", len(findings))
	}
}

// TestBackupCheckFiltersOutSoftShellHash verifies that URLs whose body hash
// matches the most-common hash for the host (the SPA shell) are excluded from
// backup probing. Only URLs with distinct hashes should be probed.
func TestBackupCheckFiltersOutSoftShellHash(t *testing.T) {
	const shellHash = "spa-shell-hash-aabbccddeeff"
	const uniqueHash = "unique-page-hash-11223344"

	var probeCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".bak") {
			atomic.AddInt32(&probeCount, 1)
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	target := webTarget(srv)
	target.SeedURLs = []string{srv.URL}

	// 50 URLs all sharing the SPA shell hash. The most-common hash is "shellHash"
	// (count=50, clearly dominant). These must not be probed.
	var urls []*crawler.DiscoveredURL
	for i := 0; i < 50; i++ {
		urls = append(urls, &crawler.DiscoveredURL{
			URL:            fmt.Sprintf("%s/page%d.html", srv.URL, i),
			Source:         "html",
			Depth:          1,
			ResponseStatus: 200,
			BodyHash:       shellHash,
		})
	}
	// 3 URLs with distinct body hashes: these SHOULD be probed.
	for i := 0; i < 3; i++ {
		urls = append(urls, &crawler.DiscoveredURL{
			URL:            fmt.Sprintf("%s/real%d.php", srv.URL, i),
			Source:         "html",
			Depth:          1,
			ResponseStatus: 200,
			BodyHash:       fmt.Sprintf("%s-%d", uniqueHash, i),
		})
	}
	target.Inventory.URLs = urls

	ck := &BackupsCheck{}
	_, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Only the 3 real URLs should be probed (4 suffixes each = 12 probes).
	// None of the 50 SPA-shell URLs should be probed.
	// The fixed list adds probes from origins, but those are not from the 50 URLs.
	got := int(atomic.LoadInt32(&probeCount))
	// 3 URLs * 4 suffixes = 12 inventory-derived probes.
	// Plus fixed list per origin (9 paths). But those are always included
	// and they don't come from inventory URLs. We test that
	// the SPA-shell URLs contribute ZERO probes.
	//
	// Upper bound: only the 3 real URLs contribute suffix probes (12 max).
	// The 50 SPA-shell URLs must contribute 0.
	if got > 12+9+5 { // 12 inventory + 9 fixed list + small buffer
		t.Errorf("backup check probed too many URLs (%d probes), SPA shell URLs may not be filtered", got)
	}
	// At least the 3 real URLs should have been probed (some suffix must be tried).
	if got == 0 {
		t.Error("expected at least some probes for the real URLs, got 0")
	}
}

// TestBackupCheckRespectsMaxProbes verifies that total probes never exceed
// MaxProbes regardless of inventory size.
func TestBackupCheckRespectsMaxProbes(t *testing.T) {
	const maxProbes = 10

	var probeCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&probeCount, 1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	target := webTarget(srv)
	target.SeedURLs = []string{srv.URL}

	// 500 distinct URLs, all status 200, all with unique body hashes.
	var urls []*crawler.DiscoveredURL
	for i := 0; i < 500; i++ {
		urls = append(urls, &crawler.DiscoveredURL{
			URL:            fmt.Sprintf("%s/page%d.php", srv.URL, i),
			Source:         "html",
			Depth:          1,
			ResponseStatus: 200,
			BodyHash:       fmt.Sprintf("unique-%d", i),
		})
	}
	target.Inventory.URLs = urls

	ck := &BackupsCheck{MaxProbes: maxProbes}
	_, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	got := int(atomic.LoadInt32(&probeCount))
	if got > maxProbes {
		t.Errorf("backup check made %d probes, exceeds MaxProbes=%d", got, maxProbes)
	}
	if got == 0 {
		t.Error("expected some probes, got 0")
	}
}
