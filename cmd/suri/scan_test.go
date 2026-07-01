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
		filepath.Join(tmpDir, "test.db"),
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
		filepath.Join(tmpDir, "test.db"),
		"", "", "", "", "",
		0, 2, false,
		minimalCrawlCfg(),
		30*time.Second,
		false, "html",
	)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	matches, err := filepath.Glob(filepath.Join(tmpDir, "*.html"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 .html report, found %d: %v", len(matches), matches)
	}

	data, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatalf("reading report: %v", err)
	}
	if len(data) == 0 {
		t.Error("report file is empty")
	}
	// The scan ID is the base name of the report file without extension.
	// RenderHTML embeds it in the template output.
	scanID := strings.TrimSuffix(filepath.Base(matches[0]), ".html")
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
		filepath.Join(tmpDir, "test.db"),
		"", "", "", "", "",
		0, 2, false,
		minimalCrawlCfg(),
		30*time.Second,
		true, "html", // noReport=true
	)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	matches, _ := filepath.Glob(filepath.Join(tmpDir, "*.html"))
	if len(matches) != 0 {
		t.Errorf("expected no .html files with --no-report, found %d: %v", len(matches), matches)
	}
}

func TestScanReportFormatJSON(t *testing.T) {
	srv := minimalSrv()
	defer srv.Close()

	tmpDir := t.TempDir()

	code := runScan(
		context.Background(),
		"", srv.URL,
		filepath.Join(tmpDir, "test.db"),
		"", "", "", "", "",
		0, 2, false,
		minimalCrawlCfg(),
		30*time.Second,
		false, "json",
	)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	htmlMatches, _ := filepath.Glob(filepath.Join(tmpDir, "*.html"))
	if len(htmlMatches) != 0 {
		t.Errorf("expected no .html files with --report-format json, found %d", len(htmlMatches))
	}
	jsonMatches, _ := filepath.Glob(filepath.Join(tmpDir, "*.json"))
	if len(jsonMatches) != 1 {
		t.Errorf("expected 1 .json file, found %d: %v", len(jsonMatches), jsonMatches)
	}
}

func TestScanReportFormatBoth(t *testing.T) {
	srv := minimalSrv()
	defer srv.Close()

	tmpDir := t.TempDir()

	code := runScan(
		context.Background(),
		"", srv.URL,
		filepath.Join(tmpDir, "test.db"),
		"", "", "", "", "",
		0, 2, false,
		minimalCrawlCfg(),
		30*time.Second,
		false, "both",
	)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	htmlMatches, _ := filepath.Glob(filepath.Join(tmpDir, "*.html"))
	if len(htmlMatches) != 1 {
		t.Errorf("expected 1 .html file with --report-format both, found %d", len(htmlMatches))
	}
	jsonMatches, _ := filepath.Glob(filepath.Join(tmpDir, "*.json"))
	if len(jsonMatches) != 1 {
		t.Errorf("expected 1 .json file with --report-format both, found %d", len(jsonMatches))
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
		filepath.Join(tmpDir, "test.db"),
		"", "", "", "", "",
		0, 2, false,
		minimalCrawlCfg(),
		30*time.Second,
		false, "html",
	)
	if code != 0 {
		t.Errorf("scan should succeed even when report generation fails, got exit code %d", code)
	}
}
