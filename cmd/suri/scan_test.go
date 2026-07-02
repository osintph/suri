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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/osintph/suri/internal/crawler"
	"github.com/osintph/suri/internal/store"
)

func minimalSrv() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintln(w, "<html><body><h1>hello</h1></body></html>")
	}))
}

func minimalCrawlCfg() crawler.Config {
	cfg := crawler.DefaultConfig()
	cfg.MaxDepth = 1
	cfg.MaxURLs = 10
	cfg.Concurrency = 2
	return cfg
}

func TestRunScanImplicitScope(t *testing.T) {
	srv := minimalSrv()
	defer srv.Close()

	tmpDir := t.TempDir()

	code := runScan(
		context.Background(),
		"", // no scope file; implicit scope derived from seed URL
		srv.URL,
		"",    // dbFlag
		"",    // domain
		"",    // s3Endpoint
		"",    // azureEndpoint
		"",    // gcsEndpoint
		"",    // adminWordlist
		0,     // maxBackupProbes
		2,     // threads
		false, // includeInfo
		minimalCrawlCfg(),
		30*time.Second,
		true,   // noReport: keep test fast, report tested separately
		"html", // reportFormat
		tmpDir, // outputDirFlag
	)

	if code != 0 {
		t.Errorf("expected exit code 0 for implicit-scope scan, got %d", code)
	}
}

func TestScanAutoGeneratesHTMLReport(t *testing.T) {
	srv := minimalSrv()
	defer srv.Close()

	tmpDir := t.TempDir()

	code := runScan(
		context.Background(),
		"", srv.URL,
		"", "", "", "", "", "",
		0, 2, false,
		minimalCrawlCfg(),
		30*time.Second,
		false, "html",
		tmpDir,
	)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	matches, err := filepath.Glob(filepath.Join(tmpDir, "*", "*", "scan.html"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 scan.html, found %d: %v", len(matches), matches)
	}

	data, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatalf("reading report: %v", err)
	}
	if len(data) == 0 {
		t.Error("report file is empty")
	}
	// The scan ID is the parent directory name.
	scanID := filepath.Base(filepath.Dir(matches[0]))
	if !strings.Contains(string(data), scanID) {
		t.Errorf("HTML report does not contain scan ID %q", scanID)
	}
}

func TestScanNoReportFlag(t *testing.T) {
	srv := minimalSrv()
	defer srv.Close()

	tmpDir := t.TempDir()

	code := runScan(
		context.Background(),
		"", srv.URL,
		"", "", "", "", "", "",
		0, 2, false,
		minimalCrawlCfg(),
		30*time.Second,
		true, "html", // noReport=true
		tmpDir,
	)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	matches, _ := filepath.Glob(filepath.Join(tmpDir, "*", "*", "scan.html"))
	if len(matches) != 0 {
		t.Errorf("expected no scan.html with --no-report, found %d: %v", len(matches), matches)
	}
}

func TestScanReportFormatJSON(t *testing.T) {
	srv := minimalSrv()
	defer srv.Close()

	tmpDir := t.TempDir()

	code := runScan(
		context.Background(),
		"", srv.URL,
		"", "", "", "", "", "",
		0, 2, false,
		minimalCrawlCfg(),
		30*time.Second,
		false, "json",
		tmpDir,
	)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	htmlMatches, _ := filepath.Glob(filepath.Join(tmpDir, "*", "*", "scan.html"))
	if len(htmlMatches) != 0 {
		t.Errorf("expected no scan.html with --report-format json, found %d", len(htmlMatches))
	}
	jsonMatches, _ := filepath.Glob(filepath.Join(tmpDir, "*", "*", "scan.json"))
	if len(jsonMatches) != 1 {
		t.Errorf("expected 1 scan.json, found %d: %v", len(jsonMatches), jsonMatches)
	}
}

func TestScanReportFormatBoth(t *testing.T) {
	srv := minimalSrv()
	defer srv.Close()

	tmpDir := t.TempDir()

	code := runScan(
		context.Background(),
		"", srv.URL,
		"", "", "", "", "", "",
		0, 2, false,
		minimalCrawlCfg(),
		30*time.Second,
		false, "both",
		tmpDir,
	)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	htmlMatches, _ := filepath.Glob(filepath.Join(tmpDir, "*", "*", "scan.html"))
	if len(htmlMatches) != 1 {
		t.Errorf("expected 1 scan.html with --report-format both, found %d", len(htmlMatches))
	}
	jsonMatches, _ := filepath.Glob(filepath.Join(tmpDir, "*", "*", "scan.json"))
	if len(jsonMatches) != 1 {
		t.Errorf("expected 1 scan.json with --report-format both, found %d", len(jsonMatches))
	}
}

func TestScanContinuesIfReportFails(t *testing.T) {
	srv := minimalSrv()
	defer srv.Close()

	orig := autoReportFn
	autoReportFn = func(_ context.Context, _ *store.Store, _, _, _, _ string) error {
		return errors.New("simulated disk full")
	}
	defer func() { autoReportFn = orig }()

	tmpDir := t.TempDir()

	code := runScan(
		context.Background(),
		"", srv.URL,
		"", "", "", "", "", "",
		0, 2, false,
		minimalCrawlCfg(),
		30*time.Second,
		false, "html",
		tmpDir,
	)
	if code != 0 {
		t.Errorf("scan should succeed even when report generation fails, got exit code %d", code)
	}
}

func TestScanWritesMetadataJSON(t *testing.T) {
	srv := minimalSrv()
	defer srv.Close()

	tmpDir := t.TempDir()

	code := runScan(
		context.Background(),
		"", srv.URL,
		"", "", "", "", "", "",
		0, 2, false,
		minimalCrawlCfg(),
		30*time.Second,
		true, "html",
		tmpDir,
	)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	matches, err := filepath.Glob(filepath.Join(tmpDir, "*", "*", "metadata.json"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 metadata.json, got %d: %v", len(matches), matches)
	}

	data, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatalf("reading metadata: %v", err)
	}
	var meta ScanMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		t.Fatalf("parsing metadata.json: %v", err)
	}
	if meta.ScanID == "" {
		t.Error("metadata.scan_id is empty")
	}
	if meta.StartedAt == "" {
		t.Error("metadata.started_at is empty")
	}
	if meta.TargetURL != srv.URL {
		t.Errorf("metadata.target_url = %q, want %q", meta.TargetURL, srv.URL)
	}
}

func TestScanStructuredDirLayout(t *testing.T) {
	srv := minimalSrv()
	defer srv.Close()

	tmpDir := t.TempDir()

	code := runScan(
		context.Background(),
		"", srv.URL,
		"", "", "", "", "", "",
		0, 2, false,
		minimalCrawlCfg(),
		30*time.Second,
		false, "html",
		tmpDir,
	)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	dbMatches, _ := filepath.Glob(filepath.Join(tmpDir, "*", "*", "scan.db"))
	if len(dbMatches) != 1 {
		t.Errorf("expected 1 scan.db, got %d: %v", len(dbMatches), dbMatches)
	}
	htmlMatches, _ := filepath.Glob(filepath.Join(tmpDir, "*", "*", "scan.html"))
	if len(htmlMatches) != 1 {
		t.Errorf("expected 1 scan.html, got %d: %v", len(htmlMatches), htmlMatches)
	}
	metaMatches, _ := filepath.Glob(filepath.Join(tmpDir, "*", "*", "metadata.json"))
	if len(metaMatches) != 1 {
		t.Errorf("expected 1 metadata.json, got %d: %v", len(metaMatches), metaMatches)
	}
}

func TestScanOutputDirFlag(t *testing.T) {
	srv := minimalSrv()
	defer srv.Close()

	customDir := t.TempDir()

	code := runScan(
		context.Background(),
		"", srv.URL,
		"", "", "", "", "", "",
		0, 2, false,
		minimalCrawlCfg(),
		30*time.Second,
		true, "html",
		customDir,
	)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	matches, _ := filepath.Glob(filepath.Join(customDir, "*", "*", "scan.db"))
	if len(matches) != 1 {
		t.Errorf("expected scan.db under custom output dir, got %d matches: %v", len(matches), matches)
	}
}

func TestFindScanDB(t *testing.T) {
	root := t.TempDir()
	scanDir := filepath.Join(root, "acme", "scan-abc")
	if err := os.MkdirAll(scanDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	dbPath := filepath.Join(scanDir, "scan.db")
	if err := os.WriteFile(dbPath, []byte{}, 0o600); err != nil {
		t.Fatalf("creating db: %v", err)
	}

	got, err := findScanDB(root, "scan-abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != dbPath {
		t.Errorf("findScanDB got %q, want %q", got, dbPath)
	}

	// Not found.
	if _, err := findScanDB(root, "nonexistent"); err == nil {
		t.Error("expected error for missing scan ID")
	}
}
