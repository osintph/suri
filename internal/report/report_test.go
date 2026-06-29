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

package report_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/osintph/suri/internal/report"
	"github.com/osintph/suri/internal/store"
)

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func insertTestScan(t *testing.T, st *store.Store, ctx context.Context) string {
	t.Helper()
	snapshotID, err := st.InsertScopeSnapshot(ctx, "test-engagement", "[scope]\nhostnames=[\"example.com\"]")
	if err != nil {
		t.Fatalf("InsertScopeSnapshot: %v", err)
	}
	scanID, err := store.NewScanID()
	if err != nil {
		t.Fatalf("NewScanID: %v", err)
	}
	if err := st.InsertScan(ctx, store.ScanRecord{
		ID:              scanID,
		StartTime:       time.Now(),
		ScopeFilePath:   "examples/scope.toml",
		ScopeSnapshotID: snapshotID,
		SeedURLs:        []string{"http://example.com"},
		SuriVersion:     "0.1.0-test",
	}); err != nil {
		t.Fatalf("InsertScan: %v", err)
	}
	return scanID
}

func TestReportHTMLBasic(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	scanID := insertTestScan(t, st, ctx)

	titles := []string{"High finding alpha", "Medium finding beta", "Low finding gamma"}
	severities := []string{"high", "medium", "low"}
	for i, title := range titles {
		_, err := st.InsertFinding(ctx, store.FindingRecord{
			ScanID:          scanID,
			FirstSeenScanID: scanID,
			CheckID:         fmt.Sprintf("web.test.%d", i),
			Severity:        severities[i],
			Title:           title,
			URL:             "http://example.com",
			Confidence:      "confirmed",
		})
		if err != nil {
			t.Fatalf("InsertFinding %d: %v", i, err)
		}
	}

	var buf bytes.Buffer
	if err := report.RenderHTML(ctx, st, scanID, "0.1.0-test", &buf); err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	out := buf.String()
	for _, title := range titles {
		if !strings.Contains(out, title) {
			t.Errorf("HTML output missing finding title %q", title)
		}
	}
}

func TestReportJSONBasic(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	scanID := insertTestScan(t, st, ctx)

	for i := 0; i < 3; i++ {
		if _, err := st.InsertFinding(ctx, store.FindingRecord{
			ScanID:          scanID,
			FirstSeenScanID: scanID,
			CheckID:         fmt.Sprintf("web.check.%d", i),
			Severity:        "high",
			Title:           fmt.Sprintf("Finding %d", i),
			URL:             "http://example.com",
			Confidence:      "confirmed",
		}); err != nil {
			t.Fatalf("InsertFinding %d: %v", i, err)
		}
	}

	var buf bytes.Buffer
	if err := report.RenderJSON(ctx, st, scanID, &buf); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}

	var result struct {
		Findings []json.RawMessage `json:"findings"`
		Summary  struct {
			Total int `json:"total"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("JSON unmarshal: %v", err)
	}
	if len(result.Findings) != 3 {
		t.Errorf("expected 3 findings, got %d", len(result.Findings))
	}
	if result.Summary.Total != 3 {
		t.Errorf("expected summary.total=3, got %d", result.Summary.Total)
	}
}

func TestReportEvidenceTruncation(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	scanID := insertTestScan(t, st, ctx)

	// 640 * 16 = 10240 bytes — well over 4096.
	bigBody := []byte(strings.Repeat("EVIDENCE_CONTENT_", 640))
	eid, err := st.InsertEvidence(ctx, store.EvidenceRecord{
		ScanID:         scanID,
		ResponseBytes:  bigBody,
		ResponseStatus: 200,
	})
	if err != nil {
		t.Fatalf("InsertEvidence: %v", err)
	}
	if _, err := st.InsertFinding(ctx, store.FindingRecord{
		ScanID:          scanID,
		FirstSeenScanID: scanID,
		CheckID:         "web.xss",
		Severity:        "high",
		Title:           "XSS with big evidence",
		URL:             "http://example.com",
		Confidence:      "confirmed",
		EvidenceID:      &eid,
	}); err != nil {
		t.Fatalf("InsertFinding: %v", err)
	}

	var buf bytes.Buffer
	if err := report.RenderHTML(ctx, st, scanID, "0.1.0-test", &buf); err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "EVIDENCE_CONTENT_") {
		t.Error("HTML should contain evidence content but it does not")
	}
	// 257 repetitions = 4112 bytes which is more than 4096; must not appear.
	if strings.Contains(out, strings.Repeat("EVIDENCE_CONTENT_", 257)) {
		t.Error("HTML contains more than 4096 bytes of evidence (truncation did not work)")
	}
	if !strings.Contains(out, "truncated at 4 KB") {
		t.Error("HTML should indicate evidence was truncated")
	}
}

func TestReportXSSDefense(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	scanID := insertTestScan(t, st, ctx)

	if _, err := st.InsertFinding(ctx, store.FindingRecord{
		ScanID:          scanID,
		FirstSeenScanID: scanID,
		CheckID:         "web.xss",
		Severity:        "high",
		Title:           "<script>alert(1)</script>",
		URL:             "http://example.com",
		Confidence:      "confirmed",
	}); err != nil {
		t.Fatalf("InsertFinding: %v", err)
	}

	var buf bytes.Buffer
	if err := report.RenderHTML(ctx, st, scanID, "0.1.0-test", &buf); err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	out := buf.String()

	if strings.Contains(out, "<script>alert(1)</script>") {
		t.Error("HTML output contains unescaped <script> tag (XSS vulnerability in report)")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Error("HTML output should contain &lt;script&gt; (escaped version)")
	}
}

func TestReportCurlReproduction(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	scanID := insertTestScan(t, st, ctx)

	if _, err := st.InsertFinding(ctx, store.FindingRecord{
		ScanID:          scanID,
		FirstSeenScanID: scanID,
		CheckID:         "web.sqli",
		Severity:        "high",
		Title:           "SQLi in q",
		URL:             "http://example.com/test?q=x'y",
		Confidence:      "confirmed",
	}); err != nil {
		t.Fatalf("InsertFinding: %v", err)
	}

	var buf bytes.Buffer
	if err := report.RenderHTML(ctx, st, scanID, "0.1.0-test", &buf); err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	out := buf.String()

	want := "curl -s 'http://example.com/test?q=x%27y'"
	if !strings.Contains(out, want) {
		t.Errorf("HTML missing curl command %q\ngot output snippet: %s",
			want, out[max(0, strings.Index(out, "curl")-50):min(len(out), strings.Index(out, "curl")+200)])
	}
}

func TestDiffNewPersistentResolved(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)

	scanAID := insertTestScan(t, st, ctx)
	scanBID := insertTestScan(t, st, ctx)

	// Baseline: check-a, check-b, check-c
	for _, checkID := range []string{"check-a", "check-b", "check-c"} {
		if _, err := st.InsertFinding(ctx, store.FindingRecord{
			ScanID:          scanAID,
			FirstSeenScanID: scanAID,
			CheckID:         checkID,
			Severity:        "high",
			Title:           "Finding " + checkID,
			URL:             "http://example.com",
			Confidence:      "confirmed",
		}); err != nil {
			t.Fatalf("InsertFinding baseline %s: %v", checkID, err)
		}
	}

	// Current: check-b, check-c, check-d
	for _, checkID := range []string{"check-b", "check-c", "check-d"} {
		if _, err := st.InsertFinding(ctx, store.FindingRecord{
			ScanID:          scanBID,
			FirstSeenScanID: scanBID,
			CheckID:         checkID,
			Severity:        "high",
			Title:           "Finding " + checkID,
			URL:             "http://example.com",
			Confidence:      "confirmed",
		}); err != nil {
			t.Fatalf("InsertFinding current %s: %v", checkID, err)
		}
	}

	diff, err := st.DiffScans(ctx, scanAID, scanBID)
	if err != nil {
		t.Fatalf("DiffScans: %v", err)
	}

	if len(diff.New) != 1 {
		t.Errorf("expected 1 new finding, got %d", len(diff.New))
	} else if diff.New[0].CheckID != "check-d" {
		t.Errorf("expected new finding check-d, got %q", diff.New[0].CheckID)
	}

	if len(diff.Persistent) != 2 {
		t.Errorf("expected 2 persistent findings, got %d", len(diff.Persistent))
	}

	if len(diff.Resolved) != 1 {
		t.Errorf("expected 1 resolved finding, got %d", len(diff.Resolved))
	} else if diff.Resolved[0].CheckID != "check-a" {
		t.Errorf("expected resolved finding check-a, got %q", diff.Resolved[0].CheckID)
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
