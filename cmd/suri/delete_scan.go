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
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/osintph/suri/internal/paths"
)

func newDeleteScanCmd() *cobra.Command {
	var (
		engagement string
		olderThan  string
		dryRun     bool
		yes        bool
		outputDir  string
	)
	cmd := &cobra.Command{
		Use:   "delete-scan [scan-id]",
		Short: "Delete a scan directory or bulk-remove scans by age",
		Long: `Delete one scan by ID, or bulk-remove scans using filters.

Examples:
  # Delete a specific scan
  suri delete-scan <scan-id>

  # Delete all scans for an engagement older than 30 days
  suri delete-scan --engagement acme-2026 --older-than 30d

  # Preview what would be deleted without removing anything
  suri delete-scan --older-than 90d --dry-run

At least one of: positional scan-id, --engagement, or --older-than must be
provided. Without --yes, the command asks for confirmation before deleting.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root := outputDir
			if root == "" {
				var err error
				root, err = paths.ScansRoot()
				if err != nil {
					return fmt.Errorf("resolving scans root: %w", err)
				}
			}
			scanID := ""
			if len(args) == 1 {
				scanID = args[0]
			}
			olderThanDays := 0
			if olderThan != "" {
				var err error
				olderThanDays, err = parseOlderThan(olderThan)
				if err != nil {
					return err
				}
			}
			if scanID == "" && engagement == "" && olderThanDays == 0 {
				return fmt.Errorf("provide a scan ID, --engagement, or --older-than")
			}
			return runDeleteScan(root, scanID, engagement, olderThanDays, dryRun, yes)
		},
	}
	cmd.Flags().StringVar(&engagement, "engagement", "", "filter by engagement name")
	cmd.Flags().StringVar(&olderThan, "older-than", "", "delete scans older than this duration (e.g. 30d)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print what would be deleted without removing anything")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "skip confirmation prompt")
	cmd.Flags().StringVar(&outputDir, "output-dir", "", "scans root to search (default: ~/.suri/scans)")
	return cmd
}

func parseOlderThan(s string) (int, error) {
	if !strings.HasSuffix(s, "d") {
		return 0, fmt.Errorf("--older-than must be in the form Nd (e.g. 30d), got %q", s)
	}
	n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("--older-than must be a positive integer followed by d, got %q", s)
	}
	return n, nil
}

func runDeleteScan(root, scanID, engagement string, olderThanDays int, dryRun, yes bool) error {
	var targets []string

	if scanID != "" {
		// By-ID mode: find <root>/*/<scanID>/.
		matches, err := filepath.Glob(filepath.Join(root, "*", scanID))
		if err != nil {
			return fmt.Errorf("searching for scan: %w", err)
		}
		switch len(matches) {
		case 0:
			return fmt.Errorf("scan %q not found in %s", scanID, root)
		case 1:
			targets = matches
		default:
			return fmt.Errorf("scan ID %q is ambiguous (%d matches), provide --engagement to narrow down", scanID, len(matches))
		}
	} else {
		// Bulk mode: enumerate all scan dirs and apply filters.
		engPattern := filepath.Join(root, "*")
		engDirs, err := filepath.Glob(engPattern)
		if err != nil {
			return fmt.Errorf("listing engagements: %w", err)
		}

		cutoff := time.Time{}
		if olderThanDays > 0 {
			cutoff = time.Now().UTC().AddDate(0, 0, -olderThanDays)
		}

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
			for _, sd := range scanDirs {
				if fi, err := os.Stat(sd); err != nil || !fi.IsDir() {
					continue
				}
				if !cutoff.IsZero() {
					startedAt := fi.ModTime().UTC()
					metaPath := filepath.Join(sd, "metadata.json")
					if data, err := os.ReadFile(metaPath); err == nil {
						var meta ScanMetadata
						if json.Unmarshal(data, &meta) == nil && meta.StartedAt != "" {
							if t, err := time.Parse(time.RFC3339, meta.StartedAt); err == nil {
								startedAt = t.UTC()
							}
						}
					}
					if !startedAt.Before(cutoff) {
						continue
					}
				}
				targets = append(targets, sd)
			}
		}
	}

	if len(targets) == 0 {
		fmt.Println("No matching scans found.")
		return nil
	}

	for _, t := range targets {
		fmt.Printf("  %s\n", t)
	}

	if dryRun {
		fmt.Printf("Dry run: %d scan(s) would be deleted.\n", len(targets))
		return nil
	}

	if !yes {
		fmt.Printf("Delete %d scan(s)? [y/N] ", len(targets))
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		if !strings.EqualFold(strings.TrimSpace(scanner.Text()), "y") {
			fmt.Println("Aborted.")
			return nil
		}
	}

	for _, t := range targets {
		if err := os.RemoveAll(t); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to remove %s: %v\n", t, err)
		}
	}
	fmt.Printf("Deleted %d scan(s).\n", len(targets))

	// Remove empty engagement directories.
	engDirs, _ := filepath.Glob(filepath.Join(root, "*"))
	for _, engDir := range engDirs {
		entries, err := os.ReadDir(engDir)
		if err == nil && len(entries) == 0 {
			_ = os.Remove(engDir)
		}
	}

	return nil
}
