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
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/osintph/suri/internal/config"
	"github.com/osintph/suri/internal/crawler"
	internalhttp "github.com/osintph/suri/internal/http"
	"github.com/osintph/suri/internal/scope"
	"github.com/osintph/suri/internal/store"
)

// Version is the binary version string embedded at build time.
const Version = "0.1.0-dev"

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	root := &cobra.Command{
		Use:   "suri",
		Short: "Web application security scanner for authorized VAPT engagements",
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
	}

	root.AddCommand(
		newScanCmd(),
		newStubCmd("report", "Report generation is not yet implemented."),
		newStubCmd("diff", "Diff engine is not yet implemented."),
		newStubCmd("wordlists", "Wordlist management is not yet implemented."),
	)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func newStubCmd(name, msg string) *cobra.Command {
	return &cobra.Command{
		Use:   name,
		Short: msg,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintln(os.Stderr, msg)
		},
	}
}

func newScanCmd() *cobra.Command {
	var (
		scopeFile string
		dbPath    string
		maxDepth  int
		maxURLs   int
		threads   int
		rate      float64
	)

	cmd := &cobra.Command{
		Use:   "scan --scope <file> <url>",
		Short: "Crawl a target URL and persist a discovery inventory",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := crawler.Config{
				MaxDepth:    maxDepth,
				MaxURLs:     maxURLs,
				Concurrency: threads,
				RatePerHost: rate,
			}
			return runScan(cmd.Context(), scopeFile, args[0], dbPath, cfg)
		},
	}

	cmd.Flags().StringVar(&scopeFile, "scope", "", "path to the TOML scope file (required)")
	_ = cmd.MarkFlagRequired("scope")
	cmd.Flags().StringVar(&dbPath, "db", "", "path for the findings database (default: <output_dir>/<scan-id>.db)")
	cmd.Flags().IntVar(&maxDepth, "max-depth", 3, "maximum crawl depth")
	cmd.Flags().IntVar(&maxURLs, "max-urls", 500, "maximum number of URLs to crawl")
	cmd.Flags().IntVar(&threads, "threads", 10, "number of concurrent HTTP workers")
	cmd.Flags().Float64Var(&rate, "rate", 10, "maximum requests per second per host")

	return cmd
}

func runScan(ctx context.Context, scopePath, seedURL, dbFlag string, crawlCfg crawler.Config) error {
	conf := config.Default()

	sc, err := scope.Load(scopePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot load scope file: %v\n", err)
		os.Exit(2)
	}

	scopeContent, err := os.ReadFile(scopePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot read scope file: %v\n", err)
		os.Exit(2)
	}

	// Generate a scan ID and resolve the database path.
	scanID, err := store.NewScanID()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	resolvedDBPath := dbFlag
	if resolvedDBPath == "" {
		resolvedDBPath = filepath.Join(conf.OutputDir, scanID+".db")
	}

	st, err := store.Open(resolvedDBPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot open database: %v\n", err)
		os.Exit(1)
	}
	defer st.Close()

	snapshotID, err := st.InsertScopeSnapshot(ctx, sc.EngagementName, string(scopeContent))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot store scope snapshot: %v\n", err)
		os.Exit(1)
	}

	if err := st.InsertScan(ctx, store.ScanRecord{
		ID:              scanID,
		StartTime:       time.Now(),
		ScopeFilePath:   scopePath,
		ScopeSnapshotID: snapshotID,
		SeedURLs:        []string{seedURL},
		SuriVersion:     Version,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot record scan: %v\n", err)
		os.Exit(1)
	}

	client := internalhttp.New(sc)
	cr := crawler.New(sc, client, crawlCfg)

	inv, err := cr.Crawl(ctx, []string{seedURL})
	exitStatus := 0
	if err != nil {
		var oos *internalhttp.ErrOutOfScope
		if errors.As(err, &oos) {
			fmt.Fprintf(os.Stderr, "blocked: %s\n", oos.Error())
			exitStatus = 3
		} else {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			exitStatus = 1
		}
	}

	if inv != nil {
		if saveErr := st.SaveInventory(ctx, scanID, inv); saveErr != nil {
			slog.Error("failed to persist inventory", "err", saveErr)
		}
	}

	if finalErr := st.FinalizeScan(ctx, scanID, exitStatus); finalErr != nil {
		slog.Error("failed to finalize scan record", "err", finalErr)
	}

	if inv != nil {
		paramSet := make(map[string]bool)
		for _, p := range inv.Parameters {
			paramSet[p.Name] = true
		}
		fmt.Printf("Scan complete\n")
		fmt.Printf("  URLs discovered:      %d\n", len(inv.URLs))
		fmt.Printf("  Forms found:          %d\n", len(inv.Forms))
		fmt.Printf("  Unique parameters:    %d\n", len(paramSet))
		fmt.Printf("  JS artifacts:         %d\n", len(inv.JSArtifacts))
	}

	fmt.Printf("  DB: %s\n", resolvedDBPath)

	if exitStatus != 0 {
		os.Exit(exitStatus)
	}
	return nil
}
