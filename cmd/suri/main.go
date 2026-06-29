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

	"github.com/osintph/suri/internal/checks"
	"github.com/osintph/suri/internal/checks/admin"
	"github.com/osintph/suri/internal/checks/api"
	"github.com/osintph/suri/internal/checks/cloud"
	"github.com/osintph/suri/internal/config"
	"github.com/osintph/suri/internal/crawler"
	internalhttp "github.com/osintph/suri/internal/http"
	"github.com/osintph/suri/internal/scope"
	"github.com/osintph/suri/internal/store"
	"github.com/osintph/suri/internal/wordlists"
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
		newWordlistsCmd(),
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

func newWordlistsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "wordlists",
		Short: "Manage wordlists used for path and API probing",
	}
	cmd.AddCommand(newWordlistsListCmd(), newWordlistsUpdateCmd())
	return cmd
}

func newWordlistsListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List available wordlists and their entry counts",
		RunE: func(cmd *cobra.Command, args []string) error {
			entries, err := wordlists.ListAll()
			if err != nil {
				return fmt.Errorf("listing wordlists: %w", err)
			}

			vendored := make([]wordlists.ListEntry, 0)
			cached := make([]wordlists.ListEntry, 0)
			for _, e := range entries {
				switch e.Source.Kind {
				case "vendored":
					vendored = append(vendored, e)
				case "cached":
					cached = append(cached, e)
				}
			}

			fmt.Printf("Vendored (embedded in binary):\n")
			if len(vendored) == 0 {
				fmt.Printf("  (none)\n")
			}
			for _, e := range vendored {
				fmt.Printf("  %-28s %5d entries\n", e.Name, e.Count)
			}

			cacheDir, _ := wordlists.CacheDir()
			fmt.Printf("\nCached (%s):\n", cacheDir)
			if len(cached) == 0 {
				fmt.Printf("  (no cached wordlists - run \"suri wordlists update\" to download)\n")
			}
			for _, e := range cached {
				fmt.Printf("  %-28s %5d entries\n", e.Name, e.Count)
			}
			return nil
		},
	}
}

func newWordlistsUpdateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "update",
		Short: "Download SecLists wordlists at the pinned commit to the local cache",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("Downloading SecLists %s to cache...\n", wordlists.PinnedCommit)
			if err := wordlists.Update(cmd.Context()); err != nil {
				fmt.Fprintf(os.Stderr, "warning: one or more downloads failed: %v\n", err)
				fmt.Fprintf(os.Stderr, "Run \"suri wordlists list\" to see what was cached successfully.\n")
				return nil
			}
			fmt.Printf("Update complete.\n")
			return nil
		},
	}
}

func newScanCmd() *cobra.Command {
	var (
		scopeFile       string
		dbPath          string
		domain          string
		s3Endpoint      string
		azureEndpoint   string
		gcsEndpoint     string
		adminWordlist   string
		maxDepth        int
		maxURLs         int
		threads         int
		rate            float64
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
			return runScan(cmd.Context(), scopeFile, args[0], dbPath, domain,
				s3Endpoint, azureEndpoint, gcsEndpoint, adminWordlist, threads, cfg)
		},
	}

	cmd.Flags().StringVar(&scopeFile, "scope", "", "path to the TOML scope file (required)")
	_ = cmd.MarkFlagRequired("scope")
	cmd.Flags().StringVar(&dbPath, "db", "", "path for the findings database (default: <output_dir>/<scan-id>.db)")
	cmd.Flags().StringVar(&domain, "domain", "", "primary domain of the engagement (used for cloud bucket permutation)")
	cmd.Flags().StringVar(&s3Endpoint, "s3-endpoint", "", "custom S3-compatible endpoint URL, e.g. http://localhost:9000 for Minio (overrides s3_endpoint in scope file)")
	cmd.Flags().StringVar(&azureEndpoint, "azure-endpoint", "", "custom Azure Blob-compatible endpoint URL (overrides azure_endpoint in scope file)")
	cmd.Flags().StringVar(&gcsEndpoint, "gcs-endpoint", "", "custom GCS-compatible endpoint URL (overrides gcs_endpoint in scope file)")
	cmd.Flags().StringVarP(&adminWordlist, "wordlist", "w", "", "path to a custom admin path wordlist (overrides embedded list)")
	cmd.Flags().IntVar(&maxDepth, "max-depth", 3, "maximum crawl depth")
	cmd.Flags().IntVar(&maxURLs, "max-urls", 500, "maximum number of URLs to crawl")
	cmd.Flags().IntVar(&threads, "threads", 10, "number of concurrent HTTP workers")
	cmd.Flags().Float64Var(&rate, "rate", 10, "maximum requests per second per host")

	return cmd
}

func runScan(
	ctx context.Context,
	scopePath, seedURL, dbFlag, domain string,
	s3EndpointFlag, azureEndpointFlag, gcsEndpointFlag string,
	adminWordlistFlag string,
	threads int,
	crawlCfg crawler.Config,
) error {
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

	// Resolve custom endpoints: CLI flag takes precedence over scope file value.
	resolvedS3Endpoint := s3EndpointFlag
	if resolvedS3Endpoint == "" {
		resolvedS3Endpoint = sc.S3Endpoint
	}
	resolvedAzureEndpoint := azureEndpointFlag
	if resolvedAzureEndpoint == "" {
		resolvedAzureEndpoint = sc.AzureEndpoint
	}
	resolvedGCSEndpoint := gcsEndpointFlag
	if resolvedGCSEndpoint == "" {
		resolvedGCSEndpoint = sc.GCSEndpoint
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

	// Ensure inventory is non-nil so checks can run even after a partial crawl.
	if inv == nil {
		inv = &crawler.Inventory{}
	}

	// Build the check target. Inventory may be extended by API checks (e.g. swagger
	// endpoint enumeration) before SaveInventory is called below.
	checkTarget := &checks.Target{
		Inventory:   inv,
		Scope:       sc,
		HTTP:        client,
		Domain:      domain,
		Concurrency: threads,
		SeedURLs:    []string{seedURL},
	}

	allChecks := []checks.Check{
		// Cloud storage checks.
		&cloud.S3Check{Endpoint: resolvedS3Endpoint, PathStyle: resolvedS3Endpoint != ""},
		&cloud.AzureCheck{Endpoint: resolvedAzureEndpoint},
		&cloud.GCSCheck{Endpoint: resolvedGCSEndpoint},
		// Admin panel and sensitive path discovery.
		&admin.AdminCheck{WordlistPath: adminWordlistFlag},
		// API spec and GraphQL discovery.
		&api.SwaggerCheck{},
		&api.GraphQLCheck{},
	}

	totalFindings := 0
	for _, ck := range allChecks {
		findings, ckErr := ck.Run(ctx, checkTarget)
		if ckErr != nil {
			slog.Error("check failed", "check", ck.ID(), "err", ckErr)
			continue
		}
		for _, f := range findings {
			var evidenceID *int64
			if f.Evidence != nil {
				eid, eErr := st.InsertEvidence(ctx, store.EvidenceRecord{
					ScanID:         scanID,
					RequestBytes:   f.Evidence.RequestBytes,
					ResponseBytes:  f.Evidence.ResponseBytes,
					ResponseStatus: f.Evidence.ResponseStatus,
					ResponseTimeMs: f.Evidence.ResponseTimeMs,
				})
				if eErr != nil {
					slog.Error("failed to persist evidence", "check", ck.ID(), "err", eErr)
				} else {
					evidenceID = &eid
				}
			}
			if _, fErr := st.InsertFinding(ctx, store.FindingRecord{
				ScanID:          scanID,
				FirstSeenScanID: scanID,
				CheckID:         f.CheckID,
				Severity:        string(f.Severity),
				Title:           f.Title,
				Description:     f.Description,
				URL:             f.URL,
				Parameter:       f.Parameter,
				CWE:             f.CWE,
				OWASP:           f.OWASP,
				Confidence:      string(f.Confidence),
				EvidenceID:      evidenceID,
				WordlistSource:  f.WordlistSource,
			}); fErr != nil {
				slog.Error("failed to persist finding", "check", ck.ID(), "err", fErr)
			} else {
				totalFindings++
			}
		}
	}

	// Save inventory after checks so that API-discovered endpoints (e.g. from
	// swagger spec enumeration) are persisted alongside the crawler inventory.
	if saveErr := st.SaveInventory(ctx, scanID, inv); saveErr != nil {
		slog.Error("failed to persist inventory", "err", saveErr)
	}

	// Emit a single summary of any out-of-scope blocks rather than per-request
	// WARN lines (which are suppressed after the first occurrence per host).
	client.LogBlockSummary()

	if finalErr := st.FinalizeScan(ctx, scanID, exitStatus); finalErr != nil {
		slog.Error("failed to finalize scan record", "err", finalErr)
	}

	paramSet := make(map[string]bool)
	for _, p := range inv.Parameters {
		paramSet[p.Name] = true
	}
	fmt.Printf("Scan complete\n")
	fmt.Printf("  URLs discovered:      %d\n", len(inv.URLs))
	fmt.Printf("  Forms found:          %d\n", len(inv.Forms))
	fmt.Printf("  Unique parameters:    %d\n", len(paramSet))
	fmt.Printf("  JS artifacts:         %d\n", len(inv.JSArtifacts))
	fmt.Printf("  Findings:             %d\n", totalFindings)
	fmt.Printf("  DB: %s\n", resolvedDBPath)

	if exitStatus != 0 {
		os.Exit(exitStatus)
	}
	return nil
}
