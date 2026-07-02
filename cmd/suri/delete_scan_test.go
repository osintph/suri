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
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeMetaForDelete(t *testing.T, dir string, startedAt time.Time) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	meta := ScanMetadata{
		ScanID:    filepath.Base(dir),
		StartedAt: startedAt.UTC().Format(time.RFC3339),
	}
	data, _ := json.MarshalIndent(meta, "", "  ")
	_ = os.WriteFile(filepath.Join(dir, "metadata.json"), data, 0o600)
}

func TestRunDeleteScanByID(t *testing.T) {
	root := t.TempDir()
	scanDir := filepath.Join(root, "acme", "scan-xyz")
	if err := os.MkdirAll(scanDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	if err := runDeleteScan(root, "scan-xyz", "", 0, false, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := os.Stat(scanDir); !os.IsNotExist(err) {
		t.Errorf("expected scan dir to be deleted")
	}
}

func TestRunDeleteScanDryRun(t *testing.T) {
	root := t.TempDir()
	scanDir := filepath.Join(root, "acme", "scan-abc")
	if err := os.MkdirAll(scanDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	if err := runDeleteScan(root, "scan-abc", "", 0, true, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := os.Stat(scanDir); err != nil {
		t.Errorf("dry run should not delete scan dir: %v", err)
	}
}

func TestRunDeleteScanOlderThan(t *testing.T) {
	root := t.TempDir()

	oldScan := filepath.Join(root, "acme", "scan-old")
	writeMetaForDelete(t, oldScan, time.Now().AddDate(0, 0, -60))

	newScan := filepath.Join(root, "acme", "scan-new")
	writeMetaForDelete(t, newScan, time.Now())

	if err := runDeleteScan(root, "", "", 30, false, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := os.Stat(oldScan); !os.IsNotExist(err) {
		t.Errorf("expected old scan to be deleted")
	}
	if _, err := os.Stat(newScan); err != nil {
		t.Errorf("expected new scan to survive, got: %v", err)
	}
}

func TestRunDeleteScanNotFound(t *testing.T) {
	root := t.TempDir()
	err := runDeleteScan(root, "nonexistent-id", "", 0, false, true)
	if err == nil {
		t.Error("expected error for missing scan ID")
	}
}
