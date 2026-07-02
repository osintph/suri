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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/osintph/suri/internal/paths"
)

func newListScansCmd() *cobra.Command {
	var (
		engagement string
		limit      int
		outputDir  string
	)
	cmd := &cobra.Command{
		Use:   "list-scans",
		Short: "List scans in the output directory",
		Long: `List scans stored under the scans root (~/.suri/scans by default).

Use --engagement to filter by engagement name and --limit to cap the number of
rows returned (default 20, newest first).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			root := outputDir
			if root == "" {
				var err error
				root, err = paths.ScansRoot()
				if err != nil {
					return fmt.Errorf("resolving scans root: %w", err)
				}
			}
			return runListScans(os.Stdout, root, engagement, limit)
		},
	}
	cmd.Flags().StringVar(&engagement, "engagement", "", "filter by engagement name")
	cmd.Flags().IntVar(&limit, "limit", 20, "maximum number of rows to show (0 = all)")
	cmd.Flags().StringVar(&outputDir, "output-dir", "", "scans root to search (default: ~/.suri/scans)")
	return cmd
}

type scanRow struct {
	scanID     string
	engagement string
	startedAt  string
	findings   int
	hasMeta    bool
}

func runListScans(w io.Writer, root, engagement string, limit int) error {
	engPattern := filepath.Join(root, "*")
	engDirs, err := filepath.Glob(engPattern)
	if err != nil {
		return fmt.Errorf("listing engagements: %w", err)
	}

	var rows []scanRow
	for _, engDir := range engDirs {
		fi, err := os.Stat(engDir)
		if err != nil || !fi.IsDir() {
			continue
		}
		engName := filepath.Base(engDir)
		if engagement != "" && !strings.EqualFold(engName, engagement) {
			continue
		}

		scanDirs, err := filepath.Glob(filepath.Join(engDir, "*"))
		if err != nil {
			continue
		}
		for _, scanDir := range scanDirs {
			fi, err := os.Stat(scanDir)
			if err != nil || !fi.IsDir() {
				continue
			}
			scanID := filepath.Base(scanDir)
			row := scanRow{
				scanID:     scanID,
				engagement: engName,
				startedAt:  fi.ModTime().UTC().Format("2006-01-02 15:04:05"),
			}

			metaPath := filepath.Join(scanDir, "metadata.json")
			if data, err := os.ReadFile(metaPath); err == nil {
				var meta ScanMetadata
				if json.Unmarshal(data, &meta) == nil {
					row.hasMeta = true
					row.findings = meta.FindingsTotal
					if meta.StartedAt != "" {
						// Parse RFC3339 and reformat for display.
						if t, err := parseRFC3339(meta.StartedAt); err == nil {
							row.startedAt = t
						}
					}
				}
			}
			rows = append(rows, row)
		}
	}

	// Sort newest first by startedAt string (RFC3339 sorts lexicographically).
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].startedAt > rows[j].startedAt
	})

	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}

	if len(rows) == 0 {
		fmt.Fprintln(w, "No scans found.")
		return nil
	}

	fmt.Fprintf(w, "%-36s  %-28s  %-19s  %s\n", "SCAN ID", "ENGAGEMENT", "STARTED", "FINDINGS")
	fmt.Fprintf(w, "%s  %s  %s  %s\n",
		strings.Repeat("-", 36),
		strings.Repeat("-", 28),
		strings.Repeat("-", 19),
		strings.Repeat("-", 8),
	)
	for _, r := range rows {
		fmt.Fprintf(w, "%-36s  %-28s  %-19s  %d\n", r.scanID, r.engagement, r.startedAt, r.findings)
	}
	return nil
}

// parseRFC3339 parses an RFC3339 timestamp and returns a display-formatted string.
func parseRFC3339(s string) (string, error) {
	// Use manual parsing to avoid importing time in a display-only helper.
	// RFC3339: 2006-01-02T15:04:05Z or 2006-01-02T15:04:05+07:00
	if len(s) < 19 {
		return "", fmt.Errorf("too short")
	}
	// Replace T with space for display.
	display := s[:10] + " " + s[11:19]
	return display, nil
}
