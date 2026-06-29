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

// Package report generates HTML and JSON reports from Suri scan results.
package report

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/osintph/suri/internal/store"
)

//go:embed templates/report.html.tmpl
var reportTmplStr string

//go:embed templates/diff.html.tmpl
var diffTmplStr string

var (
	reportTmpl *template.Template
	diffTmpl   *template.Template
)

func init() {
	reportTmpl = template.Must(template.New("report").Parse(reportTmplStr))
	diffTmpl = template.Must(template.New("diff").Parse(diffTmplStr))
}

type scanMeta struct {
	ScanID         string
	EngagementName string
	SuriVersion    string
	StartTime      string
	EndTime        string
	SeedURLs       string
	ScopeFilePath  string
}

type severityRow struct {
	Class string
	Label string
	Count int
}

type reportSummary struct {
	Total int
	Rows  []severityRow
}

type htmlFinding struct {
	SeverityClass string
	Severity      string
	Confidence    string
	Title         string
	URL           string
	Parameter     string
	Description   string
	CWE           string
	OWASP         string
	// CurlCmd is pre-sanitised and marked safe so single quotes render literally.
	CurlCmd         template.HTML
	HasEvidence     bool
	RequestDisplay  string
	ReqTruncated    bool
	ResponseDisplay string
	RespTruncated   bool
	ResponseStatus  int
	ResponseTimeMs  int64
}

type reportTemplateData struct {
	Meta        scanMeta
	Summary     reportSummary
	Findings    []htmlFinding
	GeneratedAt string
}

func buildScanMeta(scan *store.ScanDetail, suriVersion string) scanMeta {
	endTime := "n/a"
	if scan.EndTime != nil {
		endTime = scan.EndTime.UTC().Format(time.RFC3339)
	}
	return scanMeta{
		ScanID:         scan.ID,
		EngagementName: scan.EngagementName,
		SuriVersion:    suriVersion,
		StartTime:      scan.StartTime.UTC().Format(time.RFC3339),
		EndTime:        endTime,
		SeedURLs:       strings.Join(scan.SeedURLs, ", "),
		ScopeFilePath:  scan.ScopeFilePath,
	}
}

var severityOrder = []string{"critical", "high", "medium", "low", "info"}

func buildSummary(findings []*store.FindingDetail) reportSummary {
	counts := make(map[string]int)
	for _, f := range findings {
		counts[strings.ToLower(f.Severity)]++
	}

	var rows []severityRow
	for _, sev := range severityOrder {
		if n := counts[sev]; n > 0 {
			rows = append(rows, severityRow{
				Class: sev,
				Label: strings.ToUpper(sev[:1]) + sev[1:],
				Count: n,
			})
		}
	}
	return reportSummary{Total: len(findings), Rows: rows}
}

// evidenceDisplay converts raw bytes to a display string, truncating at 4096
// bytes. Returns the display string and whether truncation occurred.
// Non-UTF-8 bytes fall back to a hex dump.
func evidenceDisplay(b []byte) (string, bool) {
	if len(b) == 0 {
		return "", false
	}
	truncated := false
	if len(b) > 4096 {
		b = b[:4096]
		truncated = true
	}
	if utf8.Valid(b) {
		return string(b), truncated
	}
	// Hex dump: 16 bytes per line.
	var sb strings.Builder
	for i := 0; i < len(b); i += 16 {
		end := i + 16
		if end > len(b) {
			end = len(b)
		}
		for j, by := range b[i:end] {
			if j > 0 {
				sb.WriteByte(' ')
			}
			fmt.Fprintf(&sb, "%02x", by)
		}
		sb.WriteByte('\n')
	}
	return sb.String(), truncated
}

// curlCommand builds a reproduction curl command marked as safe HTML.
// Single quotes in the URL are replaced with %27 so they do not break the
// curl quoting. The URL is then HTML-escaped so the output is XSS-safe.
// The return type is template.HTML so the enclosing single quotes render
// literally instead of being escaped to &#39; by html/template.
func curlCommand(f *store.FindingDetail) template.HTML {
	rawURL := f.URL
	method := "GET"
	if f.Evidence != nil && len(f.Evidence.RequestBytes) > 0 {
		req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(f.Evidence.RequestBytes)))
		if err == nil {
			method = req.Method
			scheme := "https"
			host := req.Host
			if host == "" {
				host = req.URL.Host
			}
			rawURL = scheme + "://" + host + req.URL.RequestURI()
		}
	}
	safeURL := template.HTMLEscapeString(strings.ReplaceAll(rawURL, "'", "%27"))
	if method == "GET" {
		return template.HTML("curl -s '" + safeURL + "'")
	}
	return template.HTML(fmt.Sprintf("curl -s -X %s '%s'", method, safeURL))
}

func buildHTMLFinding(f *store.FindingDetail) htmlFinding {
	sev := strings.ToLower(f.Severity)
	if sev == "" {
		sev = "info"
	}
	hf := htmlFinding{
		SeverityClass: sev,
		Severity:      f.Severity,
		Confidence:    strings.ToLower(f.Confidence),
		Title:         f.Title,
		URL:           f.URL,
		Parameter:     f.Parameter,
		Description:   f.Description,
		CWE:           f.CWE,
		OWASP:         f.OWASP,
		CurlCmd:       curlCommand(f),
	}
	if f.Evidence != nil {
		hf.HasEvidence = true
		hf.ResponseStatus = f.Evidence.ResponseStatus
		hf.ResponseTimeMs = f.Evidence.ResponseTimeMs
		hf.RequestDisplay, hf.ReqTruncated = evidenceDisplay(f.Evidence.RequestBytes)
		hf.ResponseDisplay, hf.RespTruncated = evidenceDisplay(f.Evidence.ResponseBytes)
	}
	return hf
}

// RenderHTML writes a self-contained HTML report for scanID to w.
func RenderHTML(ctx context.Context, st *store.Store, scanID, suriVersion string, w io.Writer) error {
	scan, err := st.GetScan(ctx, scanID)
	if err != nil {
		return fmt.Errorf("RenderHTML: loading scan: %w", err)
	}
	findings, err := st.GetFindings(ctx, scanID)
	if err != nil {
		return fmt.Errorf("RenderHTML: loading findings: %w", err)
	}

	htmlFindings := make([]htmlFinding, 0, len(findings))
	for _, f := range findings {
		htmlFindings = append(htmlFindings, buildHTMLFinding(f))
	}

	data := reportTemplateData{
		Meta:        buildScanMeta(scan, suriVersion),
		Summary:     buildSummary(findings),
		Findings:    htmlFindings,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}

	if err := reportTmpl.Execute(w, data); err != nil {
		return fmt.Errorf("RenderHTML: executing template: %w", err)
	}
	return nil
}
