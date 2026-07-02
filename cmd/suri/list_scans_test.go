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
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeMetadata(t *testing.T, dir string, meta ScanMetadata) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		t.Fatalf("marshal metadata: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "metadata.json"), data, 0o600); err != nil {
		t.Fatalf("write metadata: %v", err)
	}
}

func TestRunListScansEmpty(t *testing.T) {
	root := t.TempDir()
	var buf bytes.Buffer
	if err := runListScans(&buf, root, "", 20); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "No scans found") {
		t.Errorf("expected 'No scans found', got: %q", buf.String())
	}
}

func TestRunListScansOneEngagement(t *testing.T) {
	root := t.TempDir()
	scanDir := filepath.Join(root, "acme-2026", "scan-001")
	writeMetadata(t, scanDir, ScanMetadata{
		ScanID:         "scan-001",
		EngagementName: "acme-2026",
		StartedAt:      "2026-07-01T10:00:00Z",
		FindingsTotal:  5,
		SuriVersion:    "dev",
	})

	var buf bytes.Buffer
	if err := runListScans(&buf, root, "", 20); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "scan-001") {
		t.Errorf("expected scan ID in output, got: %q", out)
	}
	if !strings.Contains(out, "acme-2026") {
		t.Errorf("expected engagement name in output, got: %q", out)
	}
}

func TestRunListScansFilterEngagement(t *testing.T) {
	root := t.TempDir()

	scanA := filepath.Join(root, "acme-2026", "scan-aaa")
	writeMetadata(t, scanA, ScanMetadata{
		ScanID:         "scan-aaa",
		EngagementName: "acme-2026",
		StartedAt:      "2026-07-01T10:00:00Z",
	})
	scanB := filepath.Join(root, "beta-corp", "scan-bbb")
	writeMetadata(t, scanB, ScanMetadata{
		ScanID:         "scan-bbb",
		EngagementName: "beta-corp",
		StartedAt:      "2026-07-01T11:00:00Z",
	})

	var buf bytes.Buffer
	if err := runListScans(&buf, root, "acme-2026", 20); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "scan-aaa") {
		t.Errorf("expected acme scan in output, got: %q", out)
	}
	if strings.Contains(out, "scan-bbb") {
		t.Errorf("expected beta-corp scan to be filtered out, got: %q", out)
	}
}

func TestRunListScansLimit(t *testing.T) {
	root := t.TempDir()
	for i := 1; i <= 5; i++ {
		dir := filepath.Join(root, "eng", "scan-00"+string(rune('0'+i)))
		writeMetadata(t, dir, ScanMetadata{
			ScanID:         "scan-00" + string(rune('0'+i)),
			EngagementName: "eng",
			StartedAt:      "2026-07-01T10:0" + string(rune('0'+i)) + ":00Z",
		})
	}

	var buf bytes.Buffer
	if err := runListScans(&buf, root, "", 2); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	// Header + separator + 2 data rows.
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 4 {
		t.Errorf("expected 4 lines (header+sep+2 rows), got %d:\n%s", len(lines), out)
	}
}
