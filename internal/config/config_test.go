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

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefault(t *testing.T) {
	cfg := Default()
	if cfg.Threads <= 0 {
		t.Errorf("default threads must be positive, got %d", cfg.Threads)
	}
	if cfg.RateLimit <= 0 {
		t.Errorf("default rate_limit must be positive, got %d", cfg.RateLimit)
	}
	if cfg.OutputDir == "" {
		t.Error("default output_dir must not be empty")
	}
}

func TestDefaultPath(t *testing.T) {
	p := DefaultPath()
	if p == "" {
		t.Error("DefaultPath returned empty string")
	}
}

func TestLoadMissingFile(t *testing.T) {
	cfg, err := Load("/no/such/path/suri/config.toml")
	if err != nil {
		t.Fatalf("Load on missing file should return defaults, got error: %v", err)
	}
	def := Default()
	if cfg.Threads != def.Threads {
		t.Errorf("expected default threads %d, got %d", def.Threads, cfg.Threads)
	}
}

func TestLoadHappyPath(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(f, []byte(`output_dir = "/tmp/scans"
log_file   = "/var/log/suri.log"
threads    = 20
rate_limit = 5
`), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(f)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.OutputDir != "/tmp/scans" {
		t.Errorf("output_dir: want /tmp/scans, got %s", cfg.OutputDir)
	}
	if cfg.Threads != 20 {
		t.Errorf("threads: want 20, got %d", cfg.Threads)
	}
	if cfg.RateLimit != 5 {
		t.Errorf("rate_limit: want 5, got %d", cfg.RateLimit)
	}
	if cfg.LogFile != "/var/log/suri.log" {
		t.Errorf("log_file: want /var/log/suri.log, got %s", cfg.LogFile)
	}
}

func TestLoadMalformedFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "bad.toml")
	if err := os.WriteFile(f, []byte("[[[[not valid toml"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(f)
	if err == nil {
		t.Error("Load on malformed TOML should return an error")
	}
}
