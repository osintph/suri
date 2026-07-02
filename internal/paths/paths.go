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

// Package paths resolves the Suri data directory layout.
package paths

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// UserDataDir returns the Suri application data directory.
//
//   - $XDG_DATA_HOME/suri when $XDG_DATA_HOME is set
//   - $HOME/.suri on Unix
//   - %LOCALAPPDATA%\suri on Windows
func UserDataDir() (string, error) {
	if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
		return filepath.Join(xdg, "suri"), nil
	}
	if runtime.GOOS == "windows" {
		la := os.Getenv("LOCALAPPDATA")
		if la == "" {
			return "", fmt.Errorf("%%LOCALAPPDATA%% is not set")
		}
		return filepath.Join(la, "suri"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("user home directory: %w", err)
	}
	return filepath.Join(home, ".suri"), nil
}

// ScansRoot returns <UserDataDir>/scans.
func ScansRoot() (string, error) {
	base, err := UserDataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "scans"), nil
}

// ScanDir returns the path <root>/<engagement>/<scanID> without creating it.
func ScanDir(root, engagement, scanID string) string {
	return filepath.Join(root, engagement, scanID)
}

// EnsureScanDir creates <root>/<engagement>/<scanID> (and all parents) with
// mode 0700 and returns its path.
func EnsureScanDir(root, engagement, scanID string) (string, error) {
	dir := ScanDir(root, engagement, scanID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("creating scan dir: %w", err)
	}
	return dir, nil
}

var unsafeChars = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

// SanitizeEngagementName replaces characters unsafe for directory names with
// a single hyphen, trims leading/trailing hyphens, and truncates to 64 chars.
// Returns "unnamed" if the result would be empty.
func SanitizeEngagementName(name string) string {
	s := unsafeChars.ReplaceAllString(name, "-")
	s = strings.Trim(s, "-")
	if len(s) > 64 {
		s = s[:64]
	}
	if s == "" {
		return "unnamed"
	}
	return s
}
