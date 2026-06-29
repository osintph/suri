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

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/osintph/suri/internal/crawler"
)

// TestScanRespectsTimeout verifies that a scan stopped by --scan-timeout
// returns exit code 124 and finishes within a reasonable wall-clock time.
func TestScanRespectsTimeout(t *testing.T) {
	// Slow server: every request blocks for 5 seconds. The scan timeout (100ms)
	// fires long before any response arrives.
	slowSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer slowSrv.Close()

	// Write a minimal scope file that allows 127.0.0.1 (where httptest binds).
	tmpDir := t.TempDir()
	scopeFile := filepath.Join(tmpDir, "scope.toml")
	if err := os.WriteFile(scopeFile, []byte(`
engagement_name = "timeout-test"
ips             = ["127.0.0.1"]
`), 0600); err != nil {
		t.Fatalf("writing scope file: %v", err)
	}
	dbPath := filepath.Join(tmpDir, "test.db")

	ctx := context.Background()
	start := time.Now()
	code := runScan(
		ctx,
		scopeFile, slowSrv.URL, dbPath,
		"",         // domain
		"", "", "", // s3/azure/gcs endpoints
		"",    // admin wordlist
		0,     // maxBackupProbes
		1,     // threads
		false, // includeInfo
		crawler.Config{MaxDepth: 1, MaxURLs: 10, Concurrency: 1, RatePerHost: 100},
		100*time.Millisecond, // scan timeout
	)
	elapsed := time.Since(start)

	if code != 124 {
		t.Errorf("expected exit code 124 (timeout), got %d", code)
	}
	// The scan should stop within 500ms: 100ms timeout + overhead for crawl cleanup
	// and store finalization. If it takes longer the timeout is not propagating.
	if elapsed > 500*time.Millisecond {
		t.Errorf("scan did not stop after timeout: elapsed %v (want < 500ms)", elapsed)
	}
}
