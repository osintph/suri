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

// Package store implements the SQLite findings store for Suri scan results.
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	_ "modernc.org/sqlite"

	"github.com/osintph/suri/internal/crawler"
)

// Store wraps a SQLite database connection.
type Store struct {
	db *sql.DB
}

// ScanRecord holds the fields inserted when a scan begins.
type ScanRecord struct {
	ID              string
	StartTime       time.Time
	ScopeFilePath   string
	ScopeSnapshotID int64
	SeedURLs        []string
	SuriVersion     string
}

// EvidenceRecord holds the raw HTTP exchange captured alongside a finding.
type EvidenceRecord struct {
	ScanID          string
	RequestBytes    []byte
	ResponseBytes   []byte
	ResponseStatus  int
	ResponseHeaders map[string][]string
	ResponseTimeMs  int64
}

// FindingRecord holds a finding for insertion. identity_hash is computed
// from CheckID, URL, and Parameter at insert time.
type FindingRecord struct {
	ScanID          string
	FirstSeenScanID string
	CheckID         string
	Severity        string
	Title           string
	Description     string
	URL             string
	Parameter       string
	CWE             string
	OWASP           string
	Confidence      string
	EvidenceID      *int64
}

// Open opens or creates a SQLite database at path and applies schema
// migrations. The caller must call Close when done.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("opening database %s: %w", path, err)
	}
	// SQLite handles concurrent reads well but serialises writes. A single
	// open connection avoids the overhead of the busy-wait loop in multi-conn
	// setups and is safe for a CLI tool with one writer at a time.
	db.SetMaxOpenConns(1)

	s := &Store{db: db}
	if err := s.applyMigrations(context.Background()); err != nil {
		db.Close()
		return nil, fmt.Errorf("applying migrations to %s: %w", path, err)
	}
	return s, nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// NewScanID generates a random UUID v4 string suitable for use as a scan ID.
func NewScanID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating scan ID: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

// InsertScopeSnapshot stores the full TOML content of a scope file,
// deduplicating by SHA-256 hash. If the same content was stored in a
// previous scan, the existing row ID is returned.
func (s *Store) InsertScopeSnapshot(ctx context.Context, engagementName, content string) (int64, error) {
	sum := sha256.Sum256([]byte(content))
	hash := hex.EncodeToString(sum[:])

	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO scope_snapshots (content_hash, content, engagement_name)
		 VALUES (?, ?, ?)
		 ON CONFLICT(content_hash) DO NOTHING`,
		hash, content, engagementName,
	); err != nil {
		return 0, fmt.Errorf("inserting scope snapshot: %w", err)
	}

	var id int64
	if err := s.db.QueryRowContext(ctx,
		`SELECT id FROM scope_snapshots WHERE content_hash = ?`, hash,
	).Scan(&id); err != nil {
		return 0, fmt.Errorf("fetching scope snapshot id: %w", err)
	}
	return id, nil
}

// InsertScan records the start of a new scan. rec.ID must be set (use
// NewScanID). FinalizeScan must be called when the scan completes.
func (s *Store) InsertScan(ctx context.Context, rec ScanRecord) error {
	seedsJSON, err := json.Marshal(rec.SeedURLs)
	if err != nil {
		return fmt.Errorf("marshaling seed URLs: %w", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO scans
		 (id, start_time, scope_file_path, scope_snapshot_id, seed_urls, suri_version)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		rec.ID,
		rec.StartTime.UTC().Format(time.RFC3339),
		rec.ScopeFilePath,
		rec.ScopeSnapshotID,
		string(seedsJSON),
		rec.SuriVersion,
	); err != nil {
		return fmt.Errorf("inserting scan: %w", err)
	}
	return nil
}

// FinalizeScan records the end time and exit status on a scan row.
func (s *Store) FinalizeScan(ctx context.Context, scanID string, exitStatus int) error {
	if _, err := s.db.ExecContext(ctx,
		`UPDATE scans SET end_time = ?, exit_status = ? WHERE id = ?`,
		time.Now().UTC().Format(time.RFC3339),
		exitStatus,
		scanID,
	); err != nil {
		return fmt.Errorf("finalizing scan %s: %w", scanID, err)
	}
	return nil
}

// SaveInventory writes all crawler discoveries for scanID inside a single
// transaction. It is safe to call with an empty inventory.
func (s *Store) SaveInventory(ctx context.Context, scanID string, inv *crawler.Inventory) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	urlStmt, err := tx.PrepareContext(ctx,
		`INSERT INTO urls_discovered (scan_id, url, source, depth) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("preparing url stmt: %w", err)
	}
	defer urlStmt.Close()
	for _, u := range inv.URLs {
		if _, err := urlStmt.ExecContext(ctx, scanID, u.URL, u.Source, u.Depth); err != nil {
			return fmt.Errorf("inserting url %s: %w", u.URL, err)
		}
	}

	formStmt, err := tx.PrepareContext(ctx,
		`INSERT INTO forms_discovered (scan_id, page_url, action, method, fields) VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("preparing form stmt: %w", err)
	}
	defer formStmt.Close()
	for _, f := range inv.Forms {
		fieldsJSON, err := json.Marshal(f.Fields)
		if err != nil {
			return fmt.Errorf("marshaling form fields: %w", err)
		}
		if _, err := formStmt.ExecContext(ctx, scanID, f.PageURL, f.Action, f.Method, string(fieldsJSON)); err != nil {
			return fmt.Errorf("inserting form: %w", err)
		}
	}

	paramStmt, err := tx.PrepareContext(ctx,
		`INSERT INTO parameters_discovered (scan_id, page_url, name, source) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("preparing param stmt: %w", err)
	}
	defer paramStmt.Close()
	for _, p := range inv.Parameters {
		if _, err := paramStmt.ExecContext(ctx, scanID, p.PageURL, p.Name, p.Source); err != nil {
			return fmt.Errorf("inserting parameter: %w", err)
		}
	}

	jsStmt, err := tx.PrepareContext(ctx,
		`INSERT INTO js_artifacts (scan_id, source_url, type, value) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("preparing js artifact stmt: %w", err)
	}
	defer jsStmt.Close()
	for _, a := range inv.JSArtifacts {
		if _, err := jsStmt.ExecContext(ctx, scanID, a.SourceURL, a.Type, a.Value); err != nil {
			return fmt.Errorf("inserting js artifact: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing inventory: %w", err)
	}

	slog.Debug("inventory saved",
		"scan_id", scanID,
		"urls", len(inv.URLs),
		"forms", len(inv.Forms),
		"params", len(inv.Parameters),
		"artifacts", len(inv.JSArtifacts),
	)
	return nil
}

// InsertEvidence stores a raw HTTP exchange and returns the row ID. The
// returned ID is used as EvidenceID on associated findings.
func (s *Store) InsertEvidence(ctx context.Context, rec EvidenceRecord) (int64, error) {
	headersJSON, err := json.Marshal(rec.ResponseHeaders)
	if err != nil {
		return 0, fmt.Errorf("marshaling response headers: %w", err)
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO evidence
		 (scan_id, request_bytes, response_bytes, response_status, response_headers, response_time_ms)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		rec.ScanID, rec.RequestBytes, rec.ResponseBytes,
		rec.ResponseStatus, string(headersJSON), rec.ResponseTimeMs,
	)
	if err != nil {
		return 0, fmt.Errorf("inserting evidence: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("getting evidence id: %w", err)
	}
	return id, nil
}

// InsertFinding stores a finding and returns the row ID. The identity_hash
// is computed from CheckID, URL, and Parameter so the diff engine can match
// findings across scans without a separate lookup.
func (s *Store) InsertFinding(ctx context.Context, rec FindingRecord) (int64, error) {
	h := sha256.Sum256([]byte(rec.CheckID + "|" + rec.URL + "|" + rec.Parameter))
	identityHash := hex.EncodeToString(h[:])

	res, err := s.db.ExecContext(ctx,
		`INSERT INTO findings
		 (scan_id, first_seen_scan_id, check_id, severity, title, description,
		  url, parameter, cwe, owasp, confidence, evidence_id, identity_hash)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.ScanID, rec.FirstSeenScanID, rec.CheckID, rec.Severity, rec.Title,
		rec.Description, rec.URL, rec.Parameter, rec.CWE, rec.OWASP,
		rec.Confidence, rec.EvidenceID, identityHash,
	)
	if err != nil {
		return 0, fmt.Errorf("inserting finding: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("getting finding id: %w", err)
	}
	return id, nil
}
