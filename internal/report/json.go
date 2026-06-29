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

package report

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/osintph/suri/internal/store"
)

// JSONReport is the top-level structure for a JSON scan report.
type JSONReport struct {
	ScanMetadata JSONScanMeta  `json:"scan_metadata"`
	Findings     []JSONFinding `json:"findings"`
	Summary      JSONSummary   `json:"summary"`
	GeneratedAt  string        `json:"generated_at"`
}

// JSONScanMeta holds the scan metadata block in a JSON report.
type JSONScanMeta struct {
	ID             string   `json:"id"`
	StartTime      string   `json:"start_time"`
	EndTime        string   `json:"end_time,omitempty"`
	EngagementName string   `json:"engagement_name"`
	SuriVersion    string   `json:"suri_version"`
	SeedURLs       []string `json:"seed_urls"`
	ExitStatus     *int     `json:"exit_status,omitempty"`
	ScopeFilePath  string   `json:"scope_file_path"`
}

// JSONFinding is a single finding in a JSON report.
type JSONFinding struct {
	ID           int64         `json:"id"`
	CheckID      string        `json:"check_id"`
	Severity     string        `json:"severity"`
	Title        string        `json:"title"`
	Description  string        `json:"description,omitempty"`
	URL          string        `json:"url"`
	Parameter    string        `json:"parameter,omitempty"`
	CWE          string        `json:"cwe,omitempty"`
	OWASP        string        `json:"owasp,omitempty"`
	Confidence   string        `json:"confidence"`
	IdentityHash string        `json:"identity_hash"`
	Evidence     *JSONEvidence `json:"evidence,omitempty"`
}

// JSONEvidence holds raw HTTP evidence with bytes base64-encoded.
type JSONEvidence struct {
	ResponseStatus int    `json:"response_status,omitempty"`
	ResponseTimeMs int64  `json:"response_time_ms,omitempty"`
	RequestBytes   string `json:"request_bytes,omitempty"`
	ResponseBytes  string `json:"response_bytes,omitempty"`
}

// JSONSummary provides totals grouped by severity and check ID.
type JSONSummary struct {
	BySeverity map[string]int `json:"by_severity"`
	ByCheckID  map[string]int `json:"by_check_id"`
	Total      int            `json:"total"`
}

func truncate4KB(b []byte) []byte {
	if len(b) > 4096 {
		return b[:4096]
	}
	return b
}

func toJSONFinding(f *store.FindingDetail) JSONFinding {
	jf := JSONFinding{
		ID:           f.ID,
		CheckID:      f.CheckID,
		Severity:     f.Severity,
		Title:        f.Title,
		Description:  f.Description,
		URL:          f.URL,
		Parameter:    f.Parameter,
		CWE:          f.CWE,
		OWASP:        f.OWASP,
		Confidence:   f.Confidence,
		IdentityHash: f.IdentityHash,
	}
	if f.Evidence != nil {
		je := &JSONEvidence{
			ResponseStatus: f.Evidence.ResponseStatus,
			ResponseTimeMs: f.Evidence.ResponseTimeMs,
		}
		if len(f.Evidence.RequestBytes) > 0 {
			je.RequestBytes = base64.StdEncoding.EncodeToString(truncate4KB(f.Evidence.RequestBytes))
		}
		if len(f.Evidence.ResponseBytes) > 0 {
			je.ResponseBytes = base64.StdEncoding.EncodeToString(truncate4KB(f.Evidence.ResponseBytes))
		}
		jf.Evidence = je
	}
	return jf
}

func buildJSONSummary(findings []JSONFinding) JSONSummary {
	bySeverity := make(map[string]int)
	byCheckID := make(map[string]int)
	for _, f := range findings {
		bySeverity[f.Severity]++
		byCheckID[f.CheckID]++
	}
	return JSONSummary{
		BySeverity: bySeverity,
		ByCheckID:  byCheckID,
		Total:      len(findings),
	}
}

// RenderJSON writes a JSON report for scanID to w.
func RenderJSON(ctx context.Context, st *store.Store, scanID string, w io.Writer) error {
	scan, err := st.GetScan(ctx, scanID)
	if err != nil {
		return fmt.Errorf("RenderJSON: loading scan: %w", err)
	}
	findings, err := st.GetFindings(ctx, scanID)
	if err != nil {
		return fmt.Errorf("RenderJSON: loading findings: %w", err)
	}

	meta := JSONScanMeta{
		ID:             scan.ID,
		StartTime:      scan.StartTime.UTC().Format(time.RFC3339),
		EngagementName: scan.EngagementName,
		SuriVersion:    scan.SuriVersion,
		SeedURLs:       scan.SeedURLs,
		ExitStatus:     scan.ExitStatus,
		ScopeFilePath:  scan.ScopeFilePath,
	}
	if scan.EndTime != nil {
		meta.EndTime = scan.EndTime.UTC().Format(time.RFC3339)
	}
	if meta.SeedURLs == nil {
		meta.SeedURLs = []string{}
	}

	jFindings := make([]JSONFinding, 0, len(findings))
	for _, f := range findings {
		jFindings = append(jFindings, toJSONFinding(f))
	}

	report := JSONReport{
		ScanMetadata: meta,
		Findings:     jFindings,
		Summary:      buildJSONSummary(jFindings),
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		return fmt.Errorf("RenderJSON: encoding report: %w", err)
	}
	return nil
}
