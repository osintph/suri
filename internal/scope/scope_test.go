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
	"net"
	"os"
	"path/filepath"
	"testing"
)

// makeScope constructs a Scope without file I/O for unit testing.
func makeScope(hostnames, ips, cidrs []string, ports []int) *Scope {
	return makeScopeOpts(hostnames, ips, cidrs, ports, false)
}

// makeScopeRecursive is like makeScope but sets WildcardsRecursive=true.
func makeScopeRecursive(hostnames []string) *Scope {
	return makeScopeOpts(hostnames, nil, nil, nil, true)
}

func makeScopeOpts(hostnames, ips, cidrs []string, ports []int, recursive bool) *Scope {
	s := &Scope{
		Hostnames:          hostnames,
		IPs:                ips,
		Ports:              ports,
		WildcardsRecursive: recursive,
	}
	for _, c := range cidrs {
		_, cidr, err := net.ParseCIDR(c)
		if err != nil {
			panic(err)
		}
		s.CIDRs = append(s.CIDRs, cidr)
	}
	return s
}

func TestAllows(t *testing.T) {
	cases := []struct {
		name    string
		scope   *Scope
		host    string
		port    int
		allowed bool
	}{
		{
			name:    "exact hostname match",
			scope:   makeScope([]string{"example.com"}, nil, nil, nil),
			host:    "example.com",
			port:    443,
			allowed: true,
		},
		{
			name:    "wildcard allows subdomain",
			scope:   makeScope([]string{"*.example.com"}, nil, nil, nil),
			host:    "api.example.com",
			port:    443,
			allowed: true,
		},
		{
			name:    "wildcard does not match apex",
			scope:   makeScope([]string{"*.example.com"}, nil, nil, nil),
			host:    "example.com",
			port:    443,
			allowed: false,
		},
		{
			name:    "wildcard does not match second-level subdomain",
			scope:   makeScope([]string{"*.example.com"}, nil, nil, nil),
			host:    "sub.api.example.com",
			port:    443,
			allowed: false,
		},
		{
			name:    "host not in scope",
			scope:   makeScope([]string{"example.com"}, nil, nil, nil),
			host:    "evil.com",
			port:    443,
			allowed: false,
		},
		{
			name:    "IP literal match via IPs list",
			scope:   makeScope(nil, []string{"10.10.0.5"}, nil, nil),
			host:    "10.10.0.5",
			port:    80,
			allowed: true,
		},
		{
			name:    "IP literal not in scope",
			scope:   makeScope(nil, []string{"10.10.0.5"}, nil, nil),
			host:    "10.10.0.6",
			port:    80,
			allowed: false,
		},
		{
			name:    "CIDR first usable in /24",
			scope:   makeScope(nil, nil, []string{"192.168.1.0/24"}, nil),
			host:    "192.168.1.1",
			port:    80,
			allowed: true,
		},
		{
			name:    "CIDR last usable in /24",
			scope:   makeScope(nil, nil, []string{"192.168.1.0/24"}, nil),
			host:    "192.168.1.254",
			port:    80,
			allowed: true,
		},
		{
			name:    "CIDR excludes next network",
			scope:   makeScope(nil, nil, []string{"192.168.1.0/24"}, nil),
			host:    "192.168.2.1",
			port:    80,
			allowed: false,
		},
		{
			name:    "port restriction allows matching port",
			scope:   makeScope([]string{"example.com"}, nil, nil, []int{443}),
			host:    "example.com",
			port:    443,
			allowed: true,
		},
		{
			name:    "port restriction blocks non-matching port",
			scope:   makeScope([]string{"example.com"}, nil, nil, []int{443}),
			host:    "example.com",
			port:    80,
			allowed: false,
		},
		{
			name:    "empty port list allows all ports",
			scope:   makeScope([]string{"example.com"}, nil, nil, nil),
			host:    "example.com",
			port:    9999,
			allowed: true,
		},
		{
			name:    "case-insensitive hostname match",
			scope:   makeScope([]string{"Example.COM"}, nil, nil, nil),
			host:    "example.com",
			port:    443,
			allowed: true,
		},
		{
			name:    "trailing dot tolerance",
			scope:   makeScope([]string{"example.com"}, nil, nil, nil),
			host:    "example.com.",
			port:    443,
			allowed: true,
		},
		{
			name:    "IPv6 CIDR match",
			scope:   makeScope(nil, nil, []string{"2001:db8::/32"}, nil),
			host:    "2001:db8::1",
			port:    443,
			allowed: true,
		},
		{
			name:    "IPv6 CIDR excludes out-of-range address",
			scope:   makeScope(nil, nil, []string{"2001:db8::/32"}, nil),
			host:    "2001:db9::1",
			port:    443,
			allowed: false,
		},

		// Amendment B: WildcardsRecursive mode.
		{
			name:    "recursive wildcard matches one level deep",
			scope:   makeScopeRecursive([]string{"*.example.com"}),
			host:    "api.example.com",
			port:    443,
			allowed: true,
		},
		{
			name:    "recursive wildcard matches two levels deep",
			scope:   makeScopeRecursive([]string{"*.example.com"}),
			host:    "sub.api.example.com",
			port:    443,
			allowed: true,
		},
		{
			name:    "recursive wildcard matches three levels deep",
			scope:   makeScopeRecursive([]string{"*.example.com"}),
			host:    "a.b.c.example.com",
			port:    443,
			allowed: true,
		},
		{
			name:    "recursive wildcard still does not match apex",
			scope:   makeScopeRecursive([]string{"*.example.com"}),
			host:    "example.com",
			port:    443,
			allowed: false,
		},
		{
			name:    "non-recursive wildcard still blocks two levels",
			scope:   makeScope([]string{"*.example.com"}, nil, nil, nil),
			host:    "a.b.example.com",
			port:    443,
			allowed: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, reason := tc.scope.Allows(tc.host, tc.port)
			if ok != tc.allowed {
				t.Errorf("Allows(%q, %d) = %v (%s), want %v", tc.host, tc.port, ok, reason, tc.allowed)
			}
		})
	}
}

func TestLoadMalformedScopeFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "scope.toml")
	if err := os.WriteFile(f, []byte("[[[[bad toml"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(f)
	if err == nil {
		t.Error("Load on malformed scope file should return an error")
	}
}

func TestLoadInvalidCIDR(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "scope.toml")
	content := `engagement_name = "test"
cidrs = ["not-a-cidr"]
`
	if err := os.WriteFile(f, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(f)
	if err == nil {
		t.Error("Load with invalid CIDR should return an error")
	}
}

func TestLoadHappyPath(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "scope.toml")
	content := `engagement_name = "test-vapt"
notes          = "test only"
hostnames      = ["*.example.com", "example.com"]
ips            = ["10.0.0.1"]
cidrs          = ["10.0.0.0/24"]
ports          = [80, 443]
`
	if err := os.WriteFile(f, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	s, err := Load(f)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if s.EngagementName != "test-vapt" {
		t.Errorf("engagement_name: got %s", s.EngagementName)
	}
	if len(s.Hostnames) != 2 {
		t.Errorf("hostnames: want 2, got %d", len(s.Hostnames))
	}
	if len(s.CIDRs) != 1 {
		t.Errorf("cidrs: want 1, got %d", len(s.CIDRs))
	}
}

func TestCloudBucketAllowed(t *testing.T) {
	sc := &Scope{
		CloudBuckets: []string{
			"*.s3.amazonaws.com",
			"*.s3.*.amazonaws.com",
			"*.blob.core.windows.net",
		},
	}

	cases := []struct {
		host string
		want bool
	}{
		{"bucket.s3.amazonaws.com", true},
		{"my-app.s3.amazonaws.com", true},
		{"bucket.s3.us-east-1.amazonaws.com", true},
		{"bucket.s3.eu-west-1.amazonaws.com", true},
		{"myapp.blob.core.windows.net", true},
		{"evil.com", false},
		{"s3.amazonaws.com", false}, // no prefix before the wildcard
		{"storage.googleapis.com", false},
	}

	for _, tc := range cases {
		got := sc.CloudBucketAllowed(tc.host)
		if got != tc.want {
			t.Errorf("CloudBucketAllowed(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

func TestAllowsCloudBucketsBypassesHostnameAndPort(t *testing.T) {
	sc := &Scope{
		Hostnames:    []string{"example.com"},
		Ports:        []int{80},
		CloudBuckets: []string{"*.s3.amazonaws.com"},
	}

	// Cloud bucket host not in Hostnames, on port 443 which is not in Ports.
	ok, reason := sc.Allows("bucket.s3.amazonaws.com", 443)
	if !ok {
		t.Errorf("expected cloud bucket to be allowed, got blocked: %s", reason)
	}

	// Regular out-of-scope host is still blocked.
	ok2, _ := sc.Allows("other.com", 80)
	if ok2 {
		t.Error("out-of-scope host should still be blocked")
	}
}

func TestHasCloudBuckets(t *testing.T) {
	if (&Scope{}).HasCloudBuckets() {
		t.Error("empty scope should not have cloud buckets")
	}
	if !(&Scope{CloudBuckets: []string{"*.s3.amazonaws.com"}}).HasCloudBuckets() {
		t.Error("scope with cloud_buckets should return true")
	}
}

func TestCloudBucketMatchesEdgeCases(t *testing.T) {
	cases := []struct {
		host    string
		pattern string
		want    bool
	}{
		// Exact match (no wildcard).
		{"127.0.0.1", "127.0.0.1", true},
		{"127.0.0.2", "127.0.0.1", false},
		// Single leading wildcard.
		{"a.b.com", "*.b.com", true},
		{"b.com", "*.b.com", false}, // nothing before the suffix
		// Double wildcard (regional S3 pattern).
		{"bkt.s3.us-east-1.amazonaws.com", "*.s3.*.amazonaws.com", true},
		{"bkt.s3.eu-west-1.amazonaws.com", "*.s3.*.amazonaws.com", true},
		{"bkt.s3.amazonaws.com", "*.s3.*.amazonaws.com", false}, // missing middle segment
	}
	for _, tc := range cases {
		got := cloudBucketMatches(tc.host, tc.pattern)
		if got != tc.want {
			t.Errorf("cloudBucketMatches(%q, %q) = %v, want %v", tc.host, tc.pattern, got, tc.want)
		}
	}
}

func TestProviderAuthorisation(t *testing.T) {
	cases := []struct {
		name      string
		buckets   []string
		wantS3    bool
		wantAzure bool
		wantGCS   bool
	}{
		{
			name:      "s3 patterns only",
			buckets:   []string{"*.s3.amazonaws.com", "*.s3.*.amazonaws.com"},
			wantS3:    true,
			wantAzure: false,
			wantGCS:   false,
		},
		{
			name:      "s3 via broad amazonaws",
			buckets:   []string{"*.amazonaws.com"},
			wantS3:    true,
			wantAzure: false,
			wantGCS:   false,
		},
		{
			name:      "azure only",
			buckets:   []string{"*.blob.core.windows.net"},
			wantS3:    false,
			wantAzure: true,
			wantGCS:   false,
		},
		{
			name:      "gcs exact host",
			buckets:   []string{"storage.googleapis.com"},
			wantS3:    false,
			wantAzure: false,
			wantGCS:   true,
		},
		{
			name:      "gcs wildcard",
			buckets:   []string{"*.googleapis.com"},
			wantS3:    false,
			wantAzure: false,
			wantGCS:   true,
		},
		{
			name:      "mixed s3 and azure",
			buckets:   []string{"*.s3.amazonaws.com", "*.blob.core.windows.net"},
			wantS3:    true,
			wantAzure: true,
			wantGCS:   false,
		},
		{
			name:      "all three providers",
			buckets:   []string{"*.s3.amazonaws.com", "*.blob.core.windows.net", "storage.googleapis.com"},
			wantS3:    true,
			wantAzure: true,
			wantGCS:   true,
		},
		{
			name:      "empty cloud_buckets",
			buckets:   []string{},
			wantS3:    false,
			wantAzure: false,
			wantGCS:   false,
		},
		{
			name:      "127.0.0.1 only (no cloud provider)",
			buckets:   []string{"127.0.0.1"},
			wantS3:    false,
			wantAzure: false,
			wantGCS:   false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sc := &Scope{CloudBuckets: tc.buckets}
			if got := sc.HasS3Authorisation(); got != tc.wantS3 {
				t.Errorf("HasS3Authorisation = %v, want %v", got, tc.wantS3)
			}
			if got := sc.HasAzureAuthorisation(); got != tc.wantAzure {
				t.Errorf("HasAzureAuthorisation = %v, want %v", got, tc.wantAzure)
			}
			if got := sc.HasGCSAuthorisation(); got != tc.wantGCS {
				t.Errorf("HasGCSAuthorisation = %v, want %v", got, tc.wantGCS)
			}
			wantAny := tc.wantS3 || tc.wantAzure || tc.wantGCS
			if got := sc.HasCloudBuckets(); got != wantAny {
				t.Errorf("HasCloudBuckets = %v, want %v", got, wantAny)
			}
		})
	}
}
