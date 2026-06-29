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

package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/osintph/suri/internal/crawler"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestOpenCreatesDatabase(t *testing.T) {
	openTestStore(t) // just verify it does not error
}

func TestOpenAppliesSchema(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	// Each required table must exist. Querying an absent table would return
	// an error; querying an empty table returns 0 rows.
	tables := []string{
		"schema_migrations", "scope_snapshots", "scans",
		"evidence", "findings",
		"urls_discovered", "forms_discovered", "parameters_discovered", "js_artifacts",
	}
	for _, tbl := range tables {
		var n int
		if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+tbl).Scan(&n); err != nil {
			t.Errorf("table %q missing or unreadable: %v", tbl, err)
		}
	}
}

func TestOpenIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "idem.db")

	s1, err := Open(path)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	s1.Close()

	// Second open on the same file should not re-apply migrations.
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	defer s2.Close()

	var ver int
	if err := s2.db.QueryRowContext(context.Background(),
		`SELECT MAX(version) FROM schema_migrations`).Scan(&ver); err != nil {
		t.Fatalf("reading version: %v", err)
	}
	if ver != SchemaVersion {
		t.Errorf("version: want %d, got %d", SchemaVersion, ver)
	}
}

func TestInsertScopeSnapshotDedup(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	const content = `engagement_name = "test"`
	id1, err := s.InsertScopeSnapshot(ctx, "test", content)
	if err != nil {
		t.Fatalf("first InsertScopeSnapshot: %v", err)
	}

	id2, err := s.InsertScopeSnapshot(ctx, "test", content)
	if err != nil {
		t.Fatalf("second InsertScopeSnapshot: %v", err)
	}
	if id1 != id2 {
		t.Errorf("duplicate scope content got different IDs: %d vs %d", id1, id2)
	}

	// Different content should get a different ID.
	id3, err := s.InsertScopeSnapshot(ctx, "other", `engagement_name = "other"`)
	if err != nil {
		t.Fatalf("third InsertScopeSnapshot: %v", err)
	}
	if id3 == id1 {
		t.Errorf("different scope content got same ID as first: %d", id3)
	}
}

func TestInsertScan(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	snapID, err := s.InsertScopeSnapshot(ctx, "engagement", `engagement_name = "e"`)
	if err != nil {
		t.Fatalf("InsertScopeSnapshot: %v", err)
	}

	scanID, err := NewScanID()
	if err != nil {
		t.Fatalf("NewScanID: %v", err)
	}

	rec := ScanRecord{
		ID:              scanID,
		StartTime:       time.Now().UTC(),
		ScopeFilePath:   "/tmp/scope.toml",
		ScopeSnapshotID: snapID,
		SeedURLs:        []string{"https://example.com"},
		SuriVersion:     "0.1.0-test",
	}
	if err := s.InsertScan(ctx, rec); err != nil {
		t.Fatalf("InsertScan: %v", err)
	}

	var gotID, gotVersion string
	if err := s.db.QueryRowContext(ctx,
		`SELECT id, suri_version FROM scans WHERE id = ?`, scanID,
	).Scan(&gotID, &gotVersion); err != nil {
		t.Fatalf("reading scan row: %v", err)
	}
	if gotID != scanID {
		t.Errorf("scan id: want %s, got %s", scanID, gotID)
	}
	if gotVersion != "0.1.0-test" {
		t.Errorf("suri_version: want 0.1.0-test, got %s", gotVersion)
	}
}

func TestFinalizeScan(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	snapID, _ := s.InsertScopeSnapshot(ctx, "", `engagement_name = "x"`)
	scanID, _ := NewScanID()
	_ = s.InsertScan(ctx, ScanRecord{
		ID: scanID, StartTime: time.Now(), ScopeFilePath: "/tmp/s.toml",
		ScopeSnapshotID: snapID, SeedURLs: []string{"http://x"}, SuriVersion: "0.1.0-test",
	})

	if err := s.FinalizeScan(ctx, scanID, 0); err != nil {
		t.Fatalf("FinalizeScan: %v", err)
	}

	var exitStatus int
	var endTime string
	if err := s.db.QueryRowContext(ctx,
		`SELECT exit_status, end_time FROM scans WHERE id = ?`, scanID,
	).Scan(&exitStatus, &endTime); err != nil {
		t.Fatalf("reading scan after finalize: %v", err)
	}
	if exitStatus != 0 {
		t.Errorf("exit_status: want 0, got %d", exitStatus)
	}
	if endTime == "" {
		t.Error("end_time should be set after FinalizeScan")
	}
}

func TestSaveInventory(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	snapID, _ := s.InsertScopeSnapshot(ctx, "", `engagement_name = "y"`)
	scanID, _ := NewScanID()
	_ = s.InsertScan(ctx, ScanRecord{
		ID: scanID, StartTime: time.Now(), ScopeFilePath: "/tmp/s.toml",
		ScopeSnapshotID: snapID, SeedURLs: []string{"http://x"}, SuriVersion: "0.1.0-test",
	})

	inv := &crawler.Inventory{
		URLs: []*crawler.DiscoveredURL{
			{URL: "http://target.test/", Source: "seed", Depth: 0},
			{URL: "http://target.test/about", Source: "html", Depth: 1},
		},
		Forms: []*crawler.Form{
			{PageURL: "http://target.test/", Action: "/login", Method: "POST", Fields: []string{"username", "password"}},
		},
		Parameters: []*crawler.Parameter{
			{PageURL: "http://target.test/search", Name: "q", Source: "query"},
			{PageURL: "http://target.test/login", Name: "username", Source: "form"},
		},
		JSArtifacts: []*crawler.JSArtifact{
			{SourceURL: "http://target.test/app.js", Type: "api-path", Value: "/api/v1/users"},
		},
	}

	if err := s.SaveInventory(ctx, scanID, inv); err != nil {
		t.Fatalf("SaveInventory: %v", err)
	}

	counts := map[string]int{
		"urls_discovered":        2,
		"forms_discovered":       1,
		"parameters_discovered":  2,
		"js_artifacts":           1,
	}
	for tbl, want := range counts {
		var got int
		if err := s.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM `+tbl+` WHERE scan_id = ?`, scanID,
		).Scan(&got); err != nil {
			t.Errorf("counting %s: %v", tbl, err)
			continue
		}
		if got != want {
			t.Errorf("%s: want %d rows, got %d", tbl, want, got)
		}
	}
}

func TestInsertEvidence(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	snapID, _ := s.InsertScopeSnapshot(ctx, "", `engagement_name = "z"`)
	scanID, _ := NewScanID()
	_ = s.InsertScan(ctx, ScanRecord{
		ID: scanID, StartTime: time.Now(), ScopeFilePath: "/tmp/s.toml",
		ScopeSnapshotID: snapID, SeedURLs: []string{"http://x"}, SuriVersion: "0.1.0-test",
	})

	rec := EvidenceRecord{
		ScanID:         scanID,
		RequestBytes:   []byte("GET / HTTP/1.1\r\nHost: target.test\r\n\r\n"),
		ResponseBytes:  []byte("HTTP/1.1 200 OK\r\n\r\nHello"),
		ResponseStatus: 200,
		ResponseHeaders: map[string][]string{
			"Content-Type": {"text/html"},
		},
		ResponseTimeMs: 42,
	}

	id, err := s.InsertEvidence(ctx, rec)
	if err != nil {
		t.Fatalf("InsertEvidence: %v", err)
	}
	if id <= 0 {
		t.Errorf("InsertEvidence returned id %d, want > 0", id)
	}
}

func TestInsertFinding(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	snapID, _ := s.InsertScopeSnapshot(ctx, "", `engagement_name = "f"`)
	scanID, _ := NewScanID()
	_ = s.InsertScan(ctx, ScanRecord{
		ID: scanID, StartTime: time.Now(), ScopeFilePath: "/tmp/s.toml",
		ScopeSnapshotID: snapID, SeedURLs: []string{"http://x"}, SuriVersion: "0.1.0-test",
	})

	rec := FindingRecord{
		ScanID:          scanID,
		FirstSeenScanID: scanID,
		CheckID:         "cloud.s3.public-bucket",
		Severity:        "high",
		Title:           "Public S3 bucket",
		Description:     "Bucket allows anonymous listing.",
		URL:             "https://bucket.s3.amazonaws.com/",
		Parameter:       "",
		CWE:             "CWE-284",
		OWASP:           "A01",
		Confidence:      "confirmed",
	}

	id, err := s.InsertFinding(ctx, rec)
	if err != nil {
		t.Fatalf("InsertFinding: %v", err)
	}
	if id <= 0 {
		t.Errorf("InsertFinding returned id %d, want > 0", id)
	}

	// Identity hash must be non-empty and deterministic.
	var hash1, hash2 string
	_ = s.db.QueryRowContext(ctx, `SELECT identity_hash FROM findings WHERE id = ?`, id).Scan(&hash1)

	id2, _ := s.InsertFinding(ctx, rec) // same inputs, same hash
	_ = s.db.QueryRowContext(ctx, `SELECT identity_hash FROM findings WHERE id = ?`, id2).Scan(&hash2)

	if hash1 == "" {
		t.Error("identity_hash must not be empty")
	}
	if hash1 != hash2 {
		t.Errorf("identity_hash not deterministic: %s vs %s", hash1, hash2)
	}
}
