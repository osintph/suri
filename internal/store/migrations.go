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
	_ "embed"
	"fmt"
	"time"
)

//go:embed schema.sql
var schemaSQL string

// SchemaVersion is the version number recorded in schema_migrations after a
// fresh database is initialised. Increment when adding new migrations.
const SchemaVersion = 1

// applyMigrations ensures the database schema is at SchemaVersion.
// It bootstraps the schema_migrations table unconditionally so that the
// version check is always safe, then applies schema.sql exactly once.
func (s *Store) applyMigrations(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    INTEGER PRIMARY KEY,
			applied_at TEXT    NOT NULL
		)`,
	); err != nil {
		return fmt.Errorf("creating migrations table: %w", err)
	}

	var current int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`,
	).Scan(&current); err != nil {
		return fmt.Errorf("reading schema version: %w", err)
	}

	if current >= SchemaVersion {
		return nil
	}

	// Version 1: apply the full schema. Future versions add ALTER TABLE
	// statements or new CREATE TABLE blocks in additional if-branches below.
	if current < 1 {
		if _, err := s.db.ExecContext(ctx, schemaSQL); err != nil {
			return fmt.Errorf("applying schema v1: %w", err)
		}
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO schema_migrations (version, applied_at) VALUES (1, ?)`,
			time.Now().UTC().Format(time.RFC3339),
		); err != nil {
			return fmt.Errorf("recording migration v1: %w", err)
		}
	}

	return nil
}
