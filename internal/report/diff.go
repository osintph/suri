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
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/osintph/suri/internal/store"
)

type diffScanMeta struct {
	ScanID    string
	StartTime string
}

type diffSummary struct {
	NewCount        int
	PersistentCount int
	ResolvedCount   int
}

type diffTemplateData struct {
	BaselineScan diffScanMeta
	CurrentScan  diffScanMeta
	Summary      diffSummary
	New          []htmlFinding
	Persistent   []htmlFinding
	Resolved     []htmlFinding
	SuriVersion  string
	GeneratedAt  string
}

func toHTMLFindings(findings []*store.FindingDetail) []htmlFinding {
	out := make([]htmlFinding, 0, len(findings))
	for _, f := range findings {
		out = append(out, buildHTMLFinding(f))
	}
	return out
}

// RenderDiffHTML writes a self-contained HTML diff report comparing two scans.
func RenderDiffHTML(ctx context.Context, st *store.Store, baselineID, currentID, suriVersion string, w io.Writer) error {
	diff, err := st.DiffScans(ctx, baselineID, currentID)
	if err != nil {
		return fmt.Errorf("RenderDiffHTML: diff query: %w", err)
	}
	baseline, err := st.GetScan(ctx, baselineID)
	if err != nil {
		return fmt.Errorf("RenderDiffHTML: loading baseline scan: %w", err)
	}
	current, err := st.GetScan(ctx, currentID)
	if err != nil {
		return fmt.Errorf("RenderDiffHTML: loading current scan: %w", err)
	}

	data := diffTemplateData{
		BaselineScan: diffScanMeta{
			ScanID:    baseline.ID,
			StartTime: baseline.StartTime.UTC().Format(time.RFC3339),
		},
		CurrentScan: diffScanMeta{
			ScanID:    current.ID,
			StartTime: current.StartTime.UTC().Format(time.RFC3339),
		},
		Summary: diffSummary{
			NewCount:        len(diff.New),
			PersistentCount: len(diff.Persistent),
			ResolvedCount:   len(diff.Resolved),
		},
		New:         toHTMLFindings(diff.New),
		Persistent:  toHTMLFindings(diff.Persistent),
		Resolved:    toHTMLFindings(diff.Resolved),
		SuriVersion: suriVersion,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}

	if err := diffTmpl.Execute(w, data); err != nil {
		return fmt.Errorf("RenderDiffHTML: executing template: %w", err)
	}
	return nil
}

// JSONDiffReport is the top-level structure for a JSON diff report.
type JSONDiffReport struct {
	DiffMetadata JSONDiffMeta  `json:"diff_metadata"`
	New          []JSONFinding `json:"new"`
	Persistent   []JSONFinding `json:"persistent"`
	Resolved     []JSONFinding `json:"resolved"`
	GeneratedAt  string        `json:"generated_at"`
}

// JSONDiffMeta identifies the two scans being compared.
type JSONDiffMeta struct {
	BaselineID string `json:"baseline_id"`
	CurrentID  string `json:"current_id"`
}

func toJSONFindings(findings []*store.FindingDetail) []JSONFinding {
	out := make([]JSONFinding, 0, len(findings))
	for _, f := range findings {
		out = append(out, toJSONFinding(f))
	}
	return out
}

// RenderDiffJSON writes a JSON diff report comparing two scans.
func RenderDiffJSON(ctx context.Context, st *store.Store, baselineID, currentID string, w io.Writer) error {
	diff, err := st.DiffScans(ctx, baselineID, currentID)
	if err != nil {
		return fmt.Errorf("RenderDiffJSON: diff query: %w", err)
	}

	report := JSONDiffReport{
		DiffMetadata: JSONDiffMeta{
			BaselineID: baselineID,
			CurrentID:  currentID,
		},
		New:         toJSONFindings(diff.New),
		Persistent:  toJSONFindings(diff.Persistent),
		Resolved:    toJSONFindings(diff.Resolved),
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if report.New == nil {
		report.New = []JSONFinding{}
	}
	if report.Persistent == nil {
		report.Persistent = []JSONFinding{}
	}
	if report.Resolved == nil {
		report.Resolved = []JSONFinding{}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		return fmt.Errorf("RenderDiffJSON: encoding report: %w", err)
	}
	return nil
}
