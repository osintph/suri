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

package scope

import (
	"testing"
)

func TestImplicitScopeParsesHTTPS(t *testing.T) {
	sc, err := ImplicitScope("https://example.com/some/path?q=1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sc.Hostnames) != 1 || sc.Hostnames[0] != "example.com" {
		t.Errorf("expected hostname example.com, got %v", sc.Hostnames)
	}
	if len(sc.Ports) != 1 || sc.Ports[0] != 443 {
		t.Errorf("expected port 443, got %v", sc.Ports)
	}
	if sc.EngagementName == "" {
		t.Error("engagement name should not be empty")
	}
}

func TestImplicitScopeParsesHTTP(t *testing.T) {
	sc, err := ImplicitScope("http://example.org/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sc.Hostnames) != 1 || sc.Hostnames[0] != "example.org" {
		t.Errorf("expected hostname example.org, got %v", sc.Hostnames)
	}
	if len(sc.Ports) != 1 || sc.Ports[0] != 80 {
		t.Errorf("expected port 80, got %v", sc.Ports)
	}
}

func TestImplicitScopeExplicitPort(t *testing.T) {
	sc, err := ImplicitScope("http://localhost:9090")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sc.Ports) != 1 || sc.Ports[0] != 9090 {
		t.Errorf("expected port 9090, got %v", sc.Ports)
	}
}

func TestImplicitScopeRejectsInvalidURL(t *testing.T) {
	_, err := ImplicitScope("not a url")
	if err == nil {
		t.Error("expected error for invalid URL, got nil")
	}
}

func TestImplicitScopeSetsCloudBucketsEmpty(t *testing.T) {
	sc, err := ImplicitScope("https://example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sc.CloudBuckets == nil {
		t.Error("CloudBuckets must be an empty slice, not nil")
	}
	if len(sc.CloudBuckets) != 0 {
		t.Errorf("expected empty CloudBuckets, got %v", sc.CloudBuckets)
	}
}

func TestImplicitScopeAllows(t *testing.T) {
	sc, err := ImplicitScope("https://target.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ok, _ := sc.Allows("target.example.com", 443)
	if !ok {
		t.Error("implicit scope should allow the derived hostname and port")
	}
	ok, _ = sc.Allows("other.example.com", 443)
	if ok {
		t.Error("implicit scope should not allow other hostnames")
	}
	ok, _ = sc.Allows("target.example.com", 80)
	if ok {
		t.Error("implicit scope should not allow port 80 when derived from https")
	}
}
