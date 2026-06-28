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

package crawler

import (
	"os"
	"testing"
)

func TestMineJSFromFixture(t *testing.T) {
	data, err := os.ReadFile("testdata/crawler/app.js")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	artifacts := MineJS("http://target.local/app.js", data)

	typeCount := make(map[string]int)
	for _, a := range artifacts {
		typeCount[a.Type]++
	}

	cases := []struct {
		typ  string
		want int
	}{
		{"api-path", 2},  // /api/v1/users, /api/v1/admin/roles
		{"s3", 1},
		{"azure-blob", 1},
		{"gcs", 1},
		{"auth-header", 1},
		{"role", 2}, // role:admin, permission:write
	}
	for _, tc := range cases {
		if typeCount[tc.typ] < tc.want {
			t.Errorf("type %q: want at least %d, got %d", tc.typ, tc.want, typeCount[tc.typ])
		}
	}
}

func TestMineJSDeduplication(t *testing.T) {
	data := []byte(`fetch("/api/v1/users"); fetch("/api/v1/users");`)
	artifacts := MineJS("http://x.invalid/app.js", data)
	count := 0
	for _, a := range artifacts {
		if a.Type == "api-path" && a.Value == "/api/v1/users" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 deduplicated entry, got %d", count)
	}
}

func TestMineJSEmpty(t *testing.T) {
	artifacts := MineJS("http://x.invalid/empty.js", []byte(""))
	if len(artifacts) != 0 {
		t.Errorf("expected 0 artifacts for empty JS, got %d", len(artifacts))
	}
}
