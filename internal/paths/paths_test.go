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

package paths_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/osintph/suri/internal/paths"
)

func TestUserDataDirXDG(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "/tmp/xdg-test")
	dir, err := paths.UserDataDir()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := filepath.Join("/tmp/xdg-test", "suri")
	if dir != want {
		t.Errorf("got %q, want %q", dir, want)
	}
}

func TestUserDataDirFallback(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "")
	dir, err := paths.UserDataDir()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// On Windows the fallback is %LOCALAPPDATA%\suri (no leading dot).
	// On Unix it is $HOME/.suri.
	var wantSuffix string
	if runtime.GOOS == "windows" {
		wantSuffix = filepath.Join("Local", "suri")
	} else {
		wantSuffix = ".suri"
	}
	if !strings.Contains(dir, wantSuffix) {
		t.Errorf("expected dir to contain %q, got %q", wantSuffix, dir)
	}
	if !filepath.IsAbs(dir) {
		t.Errorf("expected absolute path, got %q", dir)
	}
}

func TestScansRootComposition(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "/tmp/xdg-test")
	root, err := paths.ScansRoot()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := filepath.Join("/tmp/xdg-test", "suri", "scans")
	if root != want {
		t.Errorf("got %q, want %q", root, want)
	}
}

func TestEnsureScanDirCreates(t *testing.T) {
	base := t.TempDir()
	scanID := "abc123"
	eng := "my-engagement"

	dir, err := paths.EnsureScanDir(base, eng, scanID)
	if err != nil {
		t.Fatalf("EnsureScanDir: %v", err)
	}
	want := filepath.Join(base, eng, scanID)
	if dir != want {
		t.Errorf("got %q, want %q", dir, want)
	}
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		t.Errorf("expected directory to exist at %q", dir)
	}
}

func TestSanitizeEngagementName(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"acme-vapt-2026-q1", "acme-vapt-2026-q1"},
		{"Acme Corp Q1!", "Acme-Corp-Q1"},
		{"", "unnamed"},
		{"  spaces  ", "spaces"},
		{strings.Repeat("a", 80), strings.Repeat("a", 64)},
	}
	for _, tc := range cases {
		got := paths.SanitizeEngagementName(tc.in)
		if got != tc.want {
			t.Errorf("SanitizeEngagementName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
