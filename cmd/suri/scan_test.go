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
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/osintph/suri/internal/crawler"
)

func TestRunScanImplicitScope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "<html><body><h1>hello</h1></body></html>")
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	cfg := crawler.DefaultConfig()
	cfg.MaxDepth = 1
	cfg.MaxURLs = 10
	cfg.Concurrency = 2

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
		cfg,
		30*time.Second,
	)

	if code != 0 {
		t.Errorf("expected exit code 0 for implicit-scope scan, got %d", code)
	}
}
