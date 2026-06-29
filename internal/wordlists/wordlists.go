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

// Package wordlists provides tier-aware wordlist loading for Suri scan checks.
//
// Loading precedence (highest first):
//  1. User-supplied path (passed explicitly, e.g. via -w flag)
//  2. Cached at os.UserCacheDir()/suri/wordlists/ (populated by "suri wordlists update")
//  3. Vendored lists embedded in the binary via go:embed
package wordlists

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	wlfs "github.com/osintph/suri/wordlists"
)

// Standard wordlist names used by scan checks.
const (
	AdminCommon  = "admin-common.txt"
	APIPaths     = "api-paths.txt"
	SwaggerPaths = "swagger-paths.txt"
)

// PinnedCommit is the SecLists tag or commit reference used by "wordlists update".
// Bump this constant when refreshing the pin. Verify the reference exists in
// https://github.com/danielmiessler/SecLists before committing the bump.
const PinnedCommit = "2024.4"

// pinnedCommitDate is the approximate date of PinnedCommit (YYYY-MM-DD).
// Used to warn when the pin is more than 6 months old.
const pinnedCommitDate = "2024-10-01"

const seclistsBase = "https://raw.githubusercontent.com/danielmiessler/SecLists/" + PinnedCommit + "/"

// seclistsFetches maps local wordlist names to SecLists paths at the pinned commit.
// Verify that each remote path exists before bumping PinnedCommit.
var seclistsFetches = []struct {
	remotePath string
	localName  string
}{
	{remotePath: "Discovery/Web-Content/common.txt", localName: AdminCommon},
	{remotePath: "Discovery/Web-Content/directory-list-2.3-small.txt", localName: APIPaths},
}

// Source records where a wordlist or an individual probe came from.
type Source struct {
	Kind string // "vendored", "cached", or "user"
	Path string // e.g. "admin-common.txt", "seclists/admin-common.txt", "/home/op/list.txt"
}

// String returns the colon-separated source tag stored in finding metadata.
func (s Source) String() string {
	return s.Kind + ":" + s.Path
}

// Wordlist is a loaded set of path entries with its originating source.
type Wordlist struct {
	Source  Source
	Entries []string
}

// ListEntry describes a discoverable wordlist for the "wordlists list" subcommand.
type ListEntry struct {
	Source Source
	Name   string
	Count  int
}

// LoadVendored loads a wordlist exclusively from the embedded vendored tier,
// ignoring the cache and any user-supplied path. Use this for security-critical
// lists (e.g. InterestingPaths) that must always be the canonical vendored copy.
func LoadVendored(name string) (*Wordlist, error) {
	return loadEmbedded(name)
}

// Load returns the best available wordlist for name, following the tier order.
// If userPath is non-empty, that file is loaded as tier-1 and tiers 2 and 3 are skipped.
func Load(name, userPath string) (*Wordlist, error) {
	if userPath != "" {
		return loadFile(userPath, Source{Kind: "user", Path: userPath})
	}
	if wl, err := loadCached(name); err == nil {
		return wl, nil
	}
	return loadEmbedded(name)
}

// CacheDir returns the directory where "wordlists update" stores downloaded lists.
func CacheDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("resolving user cache dir: %w", err)
	}
	return filepath.Join(base, "suri", "wordlists"), nil
}

// IsPinStale reports whether PinnedCommit is more than 6 months old.
func IsPinStale() bool {
	t, err := time.Parse("2006-01-02", pinnedCommitDate)
	if err != nil {
		return false
	}
	return time.Since(t) > 6*30*24*time.Hour
}

// ListAll returns an entry for every wordlist available in the vendored and cached tiers.
// User-supplied lists are not included because they are per-invocation.
func ListAll() ([]ListEntry, error) {
	var entries []ListEntry

	for _, name := range []string{AdminCommon, APIPaths, SwaggerPaths} {
		wl, err := loadEmbedded(name)
		if err != nil {
			continue
		}
		entries = append(entries, ListEntry{Source: wl.Source, Name: name, Count: len(wl.Entries)})
	}

	dir, err := CacheDir()
	if err != nil {
		return entries, nil
	}
	fis, err := os.ReadDir(dir)
	if err != nil {
		return entries, nil
	}
	for _, fi := range fis {
		if fi.IsDir() || !strings.HasSuffix(fi.Name(), ".txt") {
			continue
		}
		wl, err := loadCached(fi.Name())
		if err != nil {
			continue
		}
		entries = append(entries, ListEntry{Source: wl.Source, Name: fi.Name(), Count: len(wl.Entries)})
	}

	return entries, nil
}

// Update downloads SecLists files at the pinned commit to the cache directory.
// This function uses net/http directly because it is an operator maintenance command
// that downloads from GitHub, not a scan request against an engagement target.
// Scope enforcement does not apply here.
func Update(ctx context.Context) error {
	if IsPinStale() {
		fmt.Fprintf(os.Stderr, "warning: SecLists pin %s (approx. %s) is more than 6 months old;"+
			" consider bumping PinnedCommit in internal/wordlists/wordlists.go and rebuilding\n",
			PinnedCommit, pinnedCommitDate)
	}

	dir, err := CacheDir()
	if err != nil {
		return fmt.Errorf("resolving cache dir: %w", err)
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("creating cache dir %s: %w", dir, err)
	}

	var lastErr error
	for _, fetch := range seclistsFetches {
		rawURL := seclistsBase + fetch.remotePath
		dst := filepath.Join(dir, fetch.localName)
		if err := downloadFile(ctx, rawURL, dst); err != nil {
			fmt.Fprintf(os.Stderr, "warning: skipping %s: %v\n", fetch.localName, err)
			lastErr = err
			continue
		}
		fmt.Printf("  downloaded %-24s <- %s\n", fetch.localName, fetch.remotePath)
	}

	if lastErr == nil {
		fmt.Printf("  commit/tag: %s\n", PinnedCommit)
	}
	return lastErr
}

func downloadFile(ctx context.Context, rawURL, dst string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("User-Agent", "suri/"+PinnedCommit+"-wordlists-update")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetching %s: %w", rawURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetching %s: HTTP %d", rawURL, resp.StatusCode)
	}

	f, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("creating %s: %w", dst, err)
	}
	defer f.Close()

	if _, err := io.Copy(f, resp.Body); err != nil {
		return fmt.Errorf("writing %s: %w", dst, err)
	}
	return nil
}

func loadCached(name string) (*Wordlist, error) {
	dir, err := CacheDir()
	if err != nil {
		return nil, err
	}
	return loadFile(filepath.Join(dir, name), Source{Kind: "cached", Path: "seclists/" + name})
}

func loadFile(path string, src Source) (*Wordlist, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening wordlist %s: %w", path, err)
	}
	defer f.Close()
	entries := scanEntries(bufio.NewScanner(f))
	return &Wordlist{Source: src, Entries: entries}, nil
}

func loadEmbedded(name string) (*Wordlist, error) {
	data, err := wlfs.FS.ReadFile("embedded/" + name)
	if err != nil {
		return nil, fmt.Errorf("embedded wordlist %q not found: %w", name, err)
	}
	entries := scanEntries(bufio.NewScanner(bytes.NewReader(data)))
	return &Wordlist{
		Source:  Source{Kind: "vendored", Path: name},
		Entries: entries,
	}, nil
}

// scanEntries reads non-blank, non-comment lines from a scanner.
func scanEntries(s *bufio.Scanner) []string {
	var lines []string
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines
}
