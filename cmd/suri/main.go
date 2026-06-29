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
	"github.com/osintph/suri/internal/checks/web"
	"github.com/osintph/suri/internal/config"
	"github.com/osintph/suri/internal/crawler"
	internalhttp "github.com/osintph/suri/internal/http"
	"github.com/osintph/suri/internal/report"
	"github.com/osintph/suri/internal/scope"
	"github.com/osintph/suri/internal/store"
	"github.com/osintph/suri/internal/wordlists"
)

// version is set at build time via ldflags: -X main.version=<tag>.
// The default "dev" is used for local builds outside the release pipeline.
var version = "dev"

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	root := &cobra.Command{
		Use:               "suri",
		Short:             "Web application security scanner for authorized VAPT engagements",
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
		Version:           version,
	}
	root.SetVersionTemplate("suri {{.Version}}\n")

	root.AddCommand(
		newScanCmd(),
		newReportCmd(),
		newDiffCmd(),
		newWordlistsCmd(),
		newVersionCmd(),
	)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the Suri version and exit",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("suri %s\n", version)
		},
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

func newReportCmd() *cobra.Command {
	var (
		scanID  string
		format  string
		outPath string
		dbPath  string
	)
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate a report from a scan",
		RunE: func(cmd *cobra.Command, args []string) error {
			resolvedDB := dbPath
			if resolvedDB == "" {
				var err error
				resolvedDB, err = store.FindLatestDB(".")
				if err != nil {
					fmt.Fprintf(os.Stderr, "error: %v\n", err)
					os.Exit(1)
				}
			}
			st, err := store.Open(resolvedDB)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: cannot open database: %v\n", err)
				os.Exit(1)
			}
			defer st.Close()

			f, err := os.Create(outPath)
			if err != nil {
				return fmt.Errorf("creating output file: %w", err)
			}
			defer f.Close()

			ctx := cmd.Context()
			switch format {
			case "html":
				if err := report.RenderHTML(ctx, st, scanID, version, f); err != nil {
					return fmt.Errorf("rendering HTML report: %w", err)
				}
			case "json":
				if err := report.RenderJSON(ctx, st, scanID, f); err != nil {
					return fmt.Errorf("rendering JSON report: %w", err)
				}
			default:
				return fmt.Errorf("unsupported format %q (use html or json)", format)
			}

			fmt.Printf("report written to %s\n", outPath)
			return nil
		},
	}
	cmd.Flags().StringVar(&scanID, "scan", "", "scan ID to report on (required)")
	_ = cmd.MarkFlagRequired("scan")
	cmd.Flags().StringVar(&format, "format", "", "output format: html or json (required)")
	_ = cmd.MarkFlagRequired("format")
	cmd.Flags().StringVar(&outPath, "out", "", "output file path (required)")
	_ = cmd.MarkFlagRequired("out")
	cmd.Flags().StringVar(&dbPath, "db", "", "path to findings database (default: most recent .db in current directory)")
	return cmd
}

func newDiffCmd() *cobra.Command {
	var (
		baselineID string
		currentID  string
		format     string
		outPath    string
		dbPath     string
	)
	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Compare two scans and report new, persistent, and resolved findings",
		RunE: func(cmd *cobra.Command, args []string) error {
			resolvedDB := dbPath
			if resolvedDB == "" {
				var err error
				resolvedDB, err = store.FindLatestDB(".")
				if err != nil {
					fmt.Fprintf(os.Stderr, "error: %v\n", err)
					os.Exit(1)
				}
			}
			st, err := store.Open(resolvedDB)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: cannot open database: %v\n", err)
				os.Exit(1)
			}
			defer st.Close()

			f, err := os.Create(outPath)
			if err != nil {
				return fmt.Errorf("creating output file: %w", err)
			}
			defer f.Close()

			ctx := cmd.Context()
			switch format {
			case "html":
				if err := report.RenderDiffHTML(ctx, st, baselineID, currentID, version, f); err != nil {
					return fmt.Errorf("rendering HTML diff: %w", err)
				}
			case "json":
				if err := report.RenderDiffJSON(ctx, st, baselineID, currentID, f); err != nil {
					return fmt.Errorf("rendering JSON diff: %w", err)
				}
			default:
				return fmt.Errorf("unsupported format %q (use html or json)", format)
			}

			fmt.Printf("diff written to %s\n", outPath)
			return nil
		},
	}
	cmd.Flags().StringVar(&baselineID, "baseline", "", "baseline scan ID (required)")
	_ = cmd.MarkFlagRequired("baseline")
	cmd.Flags().StringVar(&currentID, "current", "", "current scan ID (required)")
	_ = cmd.MarkFlagRequired("current")
	cmd.Flags().StringVar(&format, "format", "", "output format: html or json (required)")
	_ = cmd.MarkFlagRequired("format")
	cmd.Flags().StringVar(&outPath, "out", "", "output file path (required)")
	_ = cmd.MarkFlagRequired("out")
	cmd.Flags().StringVar(&dbPath, "db", "", "path to findings database (default: most recent .db in current directory)")
	return cmd
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
		includeInfo     bool
		scanTimeout     time.Duration
		maxBackupProbes int
		debug           bool
	)

	cmd := &cobra.Command{
		Use:   "scan --scope <file> <url>",
		Short: "Crawl a target URL and persist a discovery inventory",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if debug {
				slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
					Level: slog.LevelDebug,
				})))
			}
			cfg := crawler.Config{
				MaxDepth:    maxDepth,
				MaxURLs:     maxURLs,
				Concurrency: threads,
				RatePerHost: rate,
			}
			code := runScan(cmd.Context(), scopeFile, args[0], dbPath, domain,
				s3Endpoint, azureEndpoint, gcsEndpoint, adminWordlist,
				maxBackupProbes, threads, includeInfo, cfg, scanTimeout)
			if code != 0 {
				os.Exit(code)
			}
			return nil
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
	cmd.Flags().BoolVar(&includeInfo, "include-info", false, "include info-severity findings in the scan summary (info findings are always written to the database)")
	cmd.Flags().DurationVar(&scanTimeout, "scan-timeout", 15*time.Minute, "hard time limit for the entire scan; scan stops cleanly when exceeded (exit status 124)")
	cmd.Flags().IntVar(&maxBackupProbes, "max-backup-probes", 0, "maximum HTTP probes made by the backup file check (0 = default 200)")
	cmd.Flags().BoolVar(&debug, "debug", false, "enable debug-level logging (default: info)")

	return cmd
}

// runScan executes a full scan and returns an OS exit code:
//
//	0   success
//	1   scan or crawl error
//	2   configuration / scope file error
//	3   seed URL out of scope
//	124 scan stopped due to --scan-timeout
//
// runScan does not call os.Exit itself; callers are responsible.
func runScan(
	ctx context.Context,
	scopePath, seedURL, dbFlag, domain string,
	s3EndpointFlag, azureEndpointFlag, gcsEndpointFlag string,
	adminWordlistFlag string,
	maxBackupProbes int,
	threads int,
	includeInfo bool,
	crawlCfg crawler.Config,
	scanTimeout time.Duration,
) int {
	conf := config.Default()

	sc, err := scope.Load(scopePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot load scope file: %v\n", err)
		return 2
	}

	scopeContent, err := os.ReadFile(scopePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot read scope file: %v\n", err)
		return 2
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
		return 1
	}

	resolvedDBPath := dbFlag
	if resolvedDBPath == "" {
		resolvedDBPath = filepath.Join(conf.OutputDir, scanID+".db")
	}

	st, err := store.Open(resolvedDBPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot open database: %v\n", err)
		return 1
	}
	defer st.Close()

	snapshotID, err := st.InsertScopeSnapshot(ctx, sc.EngagementName, string(scopeContent))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot store scope snapshot: %v\n", err)
		return 1
	}

	if err := st.InsertScan(ctx, store.ScanRecord{
		ID:              scanID,
		StartTime:       time.Now(),
		ScopeFilePath:   scopePath,
		ScopeSnapshotID: snapshotID,
		SeedURLs:        []string{seedURL},
		SuriVersion:     version,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot record scan: %v\n", err)
		return 1
	}

	// scanCtx carries the hard scan timeout. All crawl and check operations use
	// scanCtx so they respect the timeout. Store operations use ctx (no timeout)
	// so findings are persisted even after the scan is interrupted.
	scanCtx, cancelScan := context.WithTimeout(ctx, scanTimeout)
	defer cancelScan()

	client := internalhttp.New(sc)
	cr := crawler.New(sc, client, crawlCfg)

	inv, crawlErr := cr.Crawl(scanCtx, []string{seedURL})
	exitStatus := 0
	if crawlErr != nil {
		var oos *internalhttp.ErrOutOfScope
		if errors.As(crawlErr, &oos) {
			fmt.Fprintf(os.Stderr, "blocked: %s\n", oos.Error())
			exitStatus = 3
		} else if !errors.Is(crawlErr, context.Canceled) && !errors.Is(crawlErr, context.DeadlineExceeded) {
			fmt.Fprintf(os.Stderr, "error: %v\n", crawlErr)
			exitStatus = 1
		}
	}

	// Ensure inventory is non-nil so checks can run even after a partial crawl.
	if inv == nil {
		inv = &crawler.Inventory{}
	}

	// Generate a per-scan canary token shared across all injection checks.
	canary := checks.GenerateCanary()

	// Build the check target. Inventory may be extended by API checks (e.g. swagger
	// endpoint enumeration) before SaveInventory is called below.
	checkTarget := &checks.Target{
		Inventory:   inv,
		Scope:       sc,
		HTTP:        client,
		Domain:      domain,
		Concurrency: threads,
		SeedURLs:    []string{seedURL},
		Canary:      canary,
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
		// Web injection and security header checks.
		&web.HeadersCheck{},
		&web.XSSCheck{},
		&web.SQLiCheck{},
		&web.SSTICheck{},
		&web.CMDiCheck{},
		&web.RedirectCheck{},
		&web.BackupsCheck{MaxProbes: maxBackupProbes},
	}

	var mediumPlusFindings, infoFindings int
	for _, ck := range allChecks {
		if scanCtx.Err() != nil {
			break // scan timed out; no point starting new checks
		}
		findings, ckErr := ck.Run(scanCtx, checkTarget)
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
				if f.Severity == checks.SeverityInfo {
					infoFindings++
				} else {
					mediumPlusFindings++
				}
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

	// Override exit status with 124 when the scan timeout fired.
	if errors.Is(scanCtx.Err(), context.DeadlineExceeded) {
		exitStatus = 124
	}

	if finalErr := st.FinalizeScan(ctx, scanID, exitStatus); finalErr != nil {
		slog.Error("failed to finalize scan record", "err", finalErr)
	}

	if exitStatus == 124 {
		fmt.Printf("scan stopped after timeout, partial results in %s\n", resolvedDBPath)
		return exitStatus
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
	if includeInfo {
		fmt.Printf("  Findings:             %d\n", mediumPlusFindings+infoFindings)
	} else if infoFindings > 0 {
		fmt.Printf("  Findings:             %d (info: %d suppressed)\n", mediumPlusFindings, infoFindings)
	} else {
		fmt.Printf("  Findings:             %d\n", mediumPlusFindings)
	}
	fmt.Printf("  DB: %s\n", resolvedDBPath)

	return exitStatus
}
