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
	"strings"
	"testing"

	"github.com/osintph/suri/internal/crawler"
)

func TestBackupsCheckFoundBak(t *testing.T) {
	// Server returns 200 for .bak files and 404 for everything else.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".bak") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("DB_PASSWORD=secret\nDB_HOST=prod-db.internal"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	target := webTarget(srv)
	target.SeedURLs = []string{srv.URL}
	target.Inventory.URLs = []*crawler.DiscoveredURL{
		{URL: srv.URL + "/config.php", Source: "html", Depth: 1},
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
		{URL: srv.URL + "/settings.py", Source: "html", Depth: 1},
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
		{URL: srv.URL + "/login.php", Source: "html", Depth: 1},
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
