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
	"fmt"
	"os"
	"path/filepath"

	"github.com/pelletier/go-toml/v2"
)

// Config holds operator-level settings that persist across engagements.
type Config struct {
	OutputDir string `toml:"output_dir"`
	LogFile   string `toml:"log_file"`
	Threads   int    `toml:"threads"`
	RateLimit int    `toml:"rate_limit"`
}

// Default returns a Config with sensible values for running without a config file.
func Default() *Config {
	return &Config{
		OutputDir: ".",
		LogFile:   "",
		Threads:   10,
		RateLimit: 10,
	}
}

// DefaultPath returns the platform-standard path for the config file.
func DefaultPath() string {
	base, err := os.UserConfigDir()
	if err != nil {
		return "suri/config.toml"
	}
	return filepath.Join(base, "suri", "config.toml")
}

// Load parses the TOML config file at path. If the file does not exist,
// Load returns Default() without error so the tool runs out of the box.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return Default(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}

	cfg := Default()
	if err := toml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}
	return cfg, nil
}
