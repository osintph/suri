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
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ScanDetail holds the metadata for a completed scan.
type ScanDetail struct {
	ID             string
	StartTime      time.Time
	EndTime        *time.Time
	ScopeFilePath  string
	SeedURLs       []string
	SuriVersion    string
	ExitStatus     *int
	EngagementName string
}

// EvidenceDetail holds the raw HTTP exchange captured with a finding.
type EvidenceDetail struct {
	RequestBytes   []byte
	ResponseBytes  []byte
	ResponseStatus int
	ResponseTimeMs int64
}

// FindingDetail holds a single finding row joined with its evidence.
type FindingDetail struct {
	ID             int64
	ScanID         string
	CheckID        string
	Severity       string
	Title          string
	Description    string
	URL            string
	Parameter      string
	CWE            string
	OWASP          string
	Confidence     string
	IdentityHash   string
	CreatedAt      time.Time
	WordlistSource string
	Evidence       *EvidenceDetail
}

// DiffResult holds the categorised findings from a diff of two scans.
type DiffResult struct {
	BaselineID string
	CurrentID  string
	New        []*FindingDetail
	Persistent []*FindingDetail
	Resolved   []*FindingDetail
}

// GetScan returns metadata for a single scan, including the engagement name
// from the scope snapshot. Returns a descriptive error when the scan is not found.
func (s *Store) GetScan(ctx context.Context, scanID string) (*ScanDetail, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT s.id, s.start_time, s.end_time, s.scope_file_path, s.seed_urls,
		       s.suri_version, s.exit_status,
		       COALESCE(ss.engagement_name, '') AS engagement_name
		FROM scans s
		LEFT JOIN scope_snapshots ss ON s.scope_snapshot_id = ss.id
		WHERE s.id = ?`, scanID)

	var (
		d           ScanDetail
		startStr    string
		endStr      sql.NullString
		exitStatus  sql.NullInt64
		seedURLsRaw string
	)
	if err := row.Scan(
		&d.ID, &startStr, &endStr, &d.ScopeFilePath, &seedURLsRaw,
		&d.SuriVersion, &exitStatus, &d.EngagementName,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("scan %q not found", scanID)
		}
		return nil, fmt.Errorf("querying scan %q: %w", scanID, err)
	}

	t, err := time.Parse(time.RFC3339, startStr)
	if err != nil {
		return nil, fmt.Errorf("parsing start_time for scan %q: %w", scanID, err)
	}
	d.StartTime = t

	if endStr.Valid && endStr.String != "" {
		et, err := time.Parse(time.RFC3339, endStr.String)
		if err != nil {
			return nil, fmt.Errorf("parsing end_time for scan %q: %w", scanID, err)
		}
		d.EndTime = &et
	}

	if exitStatus.Valid {
		v := int(exitStatus.Int64)
		d.ExitStatus = &v
	}

	if err := json.Unmarshal([]byte(seedURLsRaw), &d.SeedURLs); err != nil {
		return nil, fmt.Errorf("parsing seed_urls for scan %q: %w", scanID, err)
	}

	return &d, nil
}

// findingsQuery is the common SELECT list used by GetFindings and DiffScans.
// The caller appends a WHERE clause and optional ORDER BY.
const findingsQuery = `
	SELECT f.id, f.scan_id, f.check_id, f.severity, f.title,
	       COALESCE(f.description, '') AS description,
	       f.url,
	       COALESCE(f.parameter, '') AS parameter,
	       COALESCE(f.cwe, '') AS cwe,
	       COALESCE(f.owasp, '') AS owasp,
	       f.confidence, f.identity_hash, f.created_at,
	       COALESCE(f.wordlist_source, '') AS wordlist_source,
	       e.request_bytes, e.response_bytes,
	       COALESCE(e.response_status, 0) AS response_status,
	       COALESCE(e.response_time_ms, 0) AS response_time_ms
	FROM findings f
	LEFT JOIN evidence e ON f.evidence_id = e.id`

// scanFindings executes findingsQuery with the given suffix (WHERE + ORDER BY)
// and arguments, returning the rows as FindingDetail slices.
func (s *Store) scanFindings(ctx context.Context, suffix string, args ...interface{}) ([]*FindingDetail, error) {
	rows, err := s.db.QueryContext(ctx, findingsQuery+suffix, args...)
	if err != nil {
		return nil, fmt.Errorf("querying findings: %w", err)
	}
	defer rows.Close()

	var out []*FindingDetail
	for rows.Next() {
		var (
			f              FindingDetail
			createdAtStr   string
			reqBytes       []byte
			respBytes      []byte
			responseStatus int64
			responseTimeMs int64
		)
		if err := rows.Scan(
			&f.ID, &f.ScanID, &f.CheckID, &f.Severity, &f.Title,
			&f.Description, &f.URL, &f.Parameter, &f.CWE, &f.OWASP,
			&f.Confidence, &f.IdentityHash, &createdAtStr, &f.WordlistSource,
			&reqBytes, &respBytes, &responseStatus, &responseTimeMs,
		); err != nil {
			return nil, fmt.Errorf("scanning finding row: %w", err)
		}

		t, err := time.Parse(time.RFC3339, createdAtStr)
		if err != nil {
			// SQLite may store a slightly different format; fall back to zero value.
			t = time.Time{}
		}
		f.CreatedAt = t

		if len(reqBytes) > 0 || len(respBytes) > 0 || responseStatus != 0 || responseTimeMs != 0 {
			f.Evidence = &EvidenceDetail{
				RequestBytes:   reqBytes,
				ResponseBytes:  respBytes,
				ResponseStatus: int(responseStatus),
				ResponseTimeMs: responseTimeMs,
			}
		}

		out = append(out, &f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating finding rows: %w", err)
	}
	return out, nil
}

// GetFindings returns all findings for a scan, ordered by severity then ID.
func (s *Store) GetFindings(ctx context.Context, scanID string) ([]*FindingDetail, error) {
	suffix := `
	WHERE f.scan_id = ?
	ORDER BY CASE f.severity
		WHEN 'critical' THEN 1
		WHEN 'high'     THEN 2
		WHEN 'medium'   THEN 3
		WHEN 'low'      THEN 4
		ELSE 5
	END, f.id`
	findings, err := s.scanFindings(ctx, suffix, scanID)
	if err != nil {
		return nil, fmt.Errorf("GetFindings for scan %q: %w", scanID, err)
	}
	return findings, nil
}

// DiffScans compares findings from two scans using identity_hash and returns
// them categorised as New, Persistent, or Resolved.
func (s *Store) DiffScans(ctx context.Context, baselineID, currentID string) (*DiffResult, error) {
	orderSuffix := `
	ORDER BY CASE f.severity
		WHEN 'critical' THEN 1
		WHEN 'high'     THEN 2
		WHEN 'medium'   THEN 3
		WHEN 'low'      THEN 4
		ELSE 5
	END, f.id`

	newSuffix := `
	WHERE f.scan_id = ?
	  AND f.identity_hash NOT IN (SELECT identity_hash FROM findings WHERE scan_id = ?)` + orderSuffix

	persistentSuffix := `
	WHERE f.scan_id = ?
	  AND f.identity_hash IN (SELECT identity_hash FROM findings WHERE scan_id = ?)` + orderSuffix

	resolvedSuffix := `
	WHERE f.scan_id = ?
	  AND f.identity_hash NOT IN (SELECT identity_hash FROM findings WHERE scan_id = ?)` + orderSuffix

	newFindings, err := s.scanFindings(ctx, newSuffix, currentID, baselineID)
	if err != nil {
		return nil, fmt.Errorf("DiffScans new findings: %w", err)
	}

	persistent, err := s.scanFindings(ctx, persistentSuffix, currentID, baselineID)
	if err != nil {
		return nil, fmt.Errorf("DiffScans persistent findings: %w", err)
	}

	resolved, err := s.scanFindings(ctx, resolvedSuffix, baselineID, currentID)
	if err != nil {
		return nil, fmt.Errorf("DiffScans resolved findings: %w", err)
	}

	return &DiffResult{
		BaselineID: baselineID,
		CurrentID:  currentID,
		New:        newFindings,
		Persistent: persistent,
		Resolved:   resolved,
	}, nil
}

// FindLatestDB returns the path to the most recently modified .db file in dir.
// Returns an error if no .db files are found.
func FindLatestDB(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("reading directory %s: %w", dir, err)
	}

	var latestPath string
	var latestMod time.Time

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".db") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if latestPath == "" || info.ModTime().After(latestMod) {
			latestPath = filepath.Join(dir, e.Name())
			latestMod = info.ModTime()
		}
	}

	if latestPath == "" {
		return "", fmt.Errorf("no .db files found in %s", dir)
	}
	return latestPath, nil
}
