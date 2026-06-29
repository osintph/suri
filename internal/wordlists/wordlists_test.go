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

package wordlists

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadEmbeddedAdminCommon(t *testing.T) {
	wl, err := Load(AdminCommon, "")
	if err != nil {
		t.Fatalf("Load(%q): %v", AdminCommon, err)
	}
	if wl.Source.Kind != "vendored" {
		t.Errorf("Source.Kind: want vendored, got %q", wl.Source.Kind)
	}
	if len(wl.Entries) == 0 {
		t.Error("expected non-empty admin-common wordlist")
	}
	t.Logf("admin-common.txt: %d entries", len(wl.Entries))
}

func TestLoadEmbeddedAPIPaths(t *testing.T) {
	wl, err := Load(APIPaths, "")
	if err != nil {
		t.Fatalf("Load(%q): %v", APIPaths, err)
	}
	if wl.Source.Kind != "vendored" {
		t.Errorf("Source.Kind: want vendored, got %q", wl.Source.Kind)
	}
	if len(wl.Entries) == 0 {
		t.Error("expected non-empty api-paths wordlist")
	}
	t.Logf("api-paths.txt: %d entries", len(wl.Entries))
}

func TestLoadEmbeddedSwaggerPaths(t *testing.T) {
	wl, err := Load(SwaggerPaths, "")
	if err != nil {
		t.Fatalf("Load(%q): %v", SwaggerPaths, err)
	}
	if wl.Source.Kind != "vendored" {
		t.Errorf("Source.Kind: want vendored, got %q", wl.Source.Kind)
	}
	if len(wl.Entries) == 0 {
		t.Error("expected non-empty swagger-paths wordlist")
	}
	t.Logf("swagger-paths.txt: %d entries", len(wl.Entries))
}

func TestLoadUserSupplied(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "wl-*.txt")
	if err != nil {
		t.Fatalf("TempFile: %v", err)
	}
	f.WriteString("# comment line\n/admin\n/login\n\n/dashboard\n")
	f.Close()

	wl, err := Load(AdminCommon, f.Name())
	if err != nil {
		t.Fatalf("Load user supplied: %v", err)
	}
	if wl.Source.Kind != "user" {
		t.Errorf("Source.Kind: want user, got %q", wl.Source.Kind)
	}
	if len(wl.Entries) != 3 {
		t.Errorf("Entries count: want 3, got %d: %v", len(wl.Entries), wl.Entries)
	}
	if wl.Entries[0] != "/admin" {
		t.Errorf("first entry: want /admin, got %q", wl.Entries[0])
	}
}

func TestLoadCachedFallback(t *testing.T) {
	dir := t.TempDir()
	cachedPath := filepath.Join(dir, AdminCommon)
	os.WriteFile(cachedPath, []byte("# cached\n/cached-admin\n/cached-login\n"), 0o644)

	wl, err := loadFile(cachedPath, Source{Kind: "cached", Path: "seclists/" + AdminCommon})
	if err != nil {
		t.Fatalf("loadFile: %v", err)
	}
	if wl.Source.Kind != "cached" {
		t.Errorf("Source.Kind: want cached, got %q", wl.Source.Kind)
	}
	if len(wl.Entries) != 2 {
		t.Errorf("Entries count: want 2, got %d: %v", len(wl.Entries), wl.Entries)
	}
}

func TestSourceString(t *testing.T) {
	cases := []struct {
		src  Source
		want string
	}{
		{Source{Kind: "vendored", Path: "admin-common.txt"}, "vendored:admin-common.txt"},
		{Source{Kind: "cached", Path: "seclists/common.txt"}, "cached:seclists/common.txt"},
		{Source{Kind: "user", Path: "/tmp/list.txt"}, "user:/tmp/list.txt"},
	}
	for _, tc := range cases {
		if got := tc.src.String(); got != tc.want {
			t.Errorf("Source{%q,%q}.String() = %q, want %q",
				tc.src.Kind, tc.src.Path, got, tc.want)
		}
	}
}

func TestListAllContainsVendored(t *testing.T) {
	entries, err := ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	names := make(map[string]bool)
	for _, e := range entries {
		if e.Source.Kind == "vendored" {
			names[e.Name] = true
		}
	}
	for _, want := range []string{AdminCommon, APIPaths, SwaggerPaths} {
		if !names[want] {
			t.Errorf("ListAll: missing vendored %q", want)
		}
	}
}

func TestIsPinStale(t *testing.T) {
	// The pin 2024.4 (approx 2024-10-01) is stale from any build date in 2025+.
	stale := IsPinStale()
	t.Logf("IsPinStale() = %v (pin: %s, date: %s)", stale, PinnedCommit, pinnedCommitDate)
	// We just verify the function does not panic; staleness is expected to be true.
}

func TestDownloadFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("# fake seclists\n/admin\n/login\n"))
	}))
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "test-download.txt")
	if err := downloadFile(context.Background(), srv.URL+"/Discovery/Web-Content/common.txt", dst); err != nil {
		t.Fatalf("downloadFile: %v", err)
	}

	data, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("reading downloaded file: %v", err)
	}
	if len(data) == 0 {
		t.Error("downloaded file should not be empty")
	}
	wl, err := loadFile(dst, Source{Kind: "cached", Path: "seclists/common.txt"})
	if err != nil {
		t.Fatalf("loadFile downloaded: %v", err)
	}
	if len(wl.Entries) != 2 {
		t.Errorf("expected 2 entries (comments filtered), got %d", len(wl.Entries))
	}
}

func TestDownloadFileNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "missing.txt")
	err := downloadFile(context.Background(), srv.URL+"/no-such-file.txt", dst)
	if err == nil {
		t.Error("expected error for 404 response, got nil")
	}
}
