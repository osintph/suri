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
	"net/http"
	"os"

	"github.com/spf13/cobra"

	internalhttp "github.com/osintph/suri/internal/http"
	"github.com/osintph/suri/internal/scope"
)

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
	var scopeFile string

	cmd := &cobra.Command{
		Use:   "scan --scope <file> <url>",
		Short: "Send a scoped GET request to the target URL",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cmd.Context(), scopeFile, args[0])
		},
	}

	cmd.Flags().StringVar(&scopeFile, "scope", "", "path to the TOML scope file (required)")
	_ = cmd.MarkFlagRequired("scope")

	return cmd
}

func runScan(ctx context.Context, scopePath, rawURL string) error {
	sc, err := scope.Load(scopePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot load scope file: %v\n", err)
		os.Exit(2)
	}

	client := internalhttp.New(sc)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid URL %q: %v\n", rawURL, err)
		os.Exit(1)
	}

	resp, err := client.Do(ctx, req)
	if err != nil {
		var oos *internalhttp.ErrOutOfScope
		if errors.As(err, &oos) {
			fmt.Fprintf(os.Stderr, "blocked: %s\n", oos.Error())
			slog.Warn("request blocked", "url", rawURL, "reason", oos.Reason)
			os.Exit(3)
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	fmt.Printf("%s %s\n", resp.Status, resp.Request.URL)
	return nil
}
