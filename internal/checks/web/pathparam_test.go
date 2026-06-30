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

package web

import "testing"

func TestBuildPathInjectURLSimple(t *testing.T) {
	got := buildPathInjectURL("http://example.com/api/user/{id}", "id", "42")
	want := "http://example.com/api/user/42"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBuildPathInjectURLEncodesSpecials(t *testing.T) {
	got := buildPathInjectURL("http://example.com/api/ping/host/{host}", "host", ";sleep 5")
	want := "http://example.com/api/ping/host/%3Bsleep%205"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBuildPathInjectURLPreservesPath(t *testing.T) {
	got := buildPathInjectURL("http://example.com/api/v2/users/{id}/posts", "id", "42")
	want := "http://example.com/api/v2/users/42/posts"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBuildPathInjectURLMultipleParams(t *testing.T) {
	got := buildPathInjectURL("http://example.com/{a}/{b}", "a", "42")
	want := "http://example.com/42/{b}"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
