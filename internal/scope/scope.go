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
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// scopeFile is the raw unmarshaled form of the TOML scope file.
type scopeFile struct {
	EngagementName     string   `toml:"engagement_name"`
	Notes              string   `toml:"notes"`
	Hostnames          []string `toml:"hostnames"`
	IPs                []string `toml:"ips"`
	CIDRs              []string `toml:"cidrs"`
	Ports              []int    `toml:"ports"`
	WildcardsRecursive bool     `toml:"wildcards_recursive"`
	CloudBuckets       []string `toml:"cloud_buckets"`
}

// Scope holds the parsed and validated engagement scope.
// All requests must pass through Allows before being dispatched.
type Scope struct {
	EngagementName string
	Notes          string
	Hostnames      []string
	IPs            []string
	CIDRs          []*net.IPNet
	Ports          []int
	// WildcardsRecursive controls how *.example.com is interpreted.
	// When false (default), it matches exactly one label: api.example.com but
	// not sub.api.example.com. When true, it matches any depth.
	WildcardsRecursive bool
	// CloudBuckets is the explicit list of cloud storage host patterns that are
	// authorised for probing. If empty, cloud check modules refuse to run.
	// Patterns use the same *.host syntax as Hostnames but a single * may span
	// multiple labels (e.g. *.s3.*.amazonaws.com matches bucket.s3.us-east-1.amazonaws.com).
	CloudBuckets []string
}

// Load parses a TOML scope file and returns a validated Scope.
func Load(path string) (*Scope, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading scope file %s: %w", path, err)
	}

	var raw scopeFile
	if err := toml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing scope file %s: %w", path, err)
	}

	s := &Scope{
		EngagementName:     raw.EngagementName,
		Notes:              raw.Notes,
		Hostnames:          raw.Hostnames,
		IPs:                raw.IPs,
		Ports:              raw.Ports,
		WildcardsRecursive: raw.WildcardsRecursive,
		CloudBuckets:       raw.CloudBuckets,
	}

	for _, cidrStr := range raw.CIDRs {
		_, cidr, err := net.ParseCIDR(cidrStr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q in scope file %s: %w", cidrStr, path, err)
		}
		s.CIDRs = append(s.CIDRs, cidr)
	}

	return s, nil
}

// Allows reports whether a request to host:port is permitted by this scope.
// It returns a human-readable reason suitable for logging.
// Cloud bucket hosts listed in cloud_buckets bypass hostname and port checks
// so cloud check modules can reach their targets unconditionally.
func (s *Scope) Allows(host string, port int) (bool, string) {
	host = normalize(host)

	// cloud_buckets is explicit written authorisation to probe bucket endpoints.
	// It takes precedence over the regular hostname and port restrictions.
	if s.cloudBucketAllowed(host) {
		return true, "cloud bucket authorised"
	}

	ip := net.ParseIP(host)
	if ip != nil {
		if !s.ipAllowed(ip) {
			return false, fmt.Sprintf("IP %s not in scope", host)
		}
	} else {
		if !s.hostnameAllowed(host) {
			return false, fmt.Sprintf("host %s not in scope", host)
		}
	}

	if len(s.Ports) > 0 && !s.portAllowed(port) {
		return false, fmt.Sprintf("port %d not in scope", port)
	}

	return true, "in scope"
}

// CloudBucketAllowed reports whether host is covered by this scope's
// cloud_buckets list. Use this in cloud check modules to guard against running
// without explicit operator authorisation.
func (s *Scope) CloudBucketAllowed(host string) bool {
	return s.cloudBucketAllowed(normalize(host))
}

// HasCloudBuckets reports whether any cloud_buckets patterns are configured.
func (s *Scope) HasCloudBuckets() bool {
	return len(s.CloudBuckets) > 0
}

func (s *Scope) cloudBucketAllowed(host string) bool {
	for _, pattern := range s.CloudBuckets {
		if cloudBucketMatches(host, normalize(pattern)) {
			return true
		}
	}
	return false
}

// cloudBucketMatches matches host against a cloud_buckets pattern where '*'
// may span one or more hostname labels. This is more permissive than the
// regular hostnameAllowed wildcard (which is single-label only) because cloud
// storage endpoints often have variable-depth subdomains
// (e.g. *.s3.*.amazonaws.com matching bucket.s3.us-east-1.amazonaws.com).
func cloudBucketMatches(host, pattern string) bool {
	if !strings.Contains(pattern, "*") {
		return host == pattern
	}
	parts := strings.Split(pattern, "*")
	// Verify that host starts with the prefix before the first *.
	if !strings.HasPrefix(host, parts[0]) {
		return false
	}
	remaining := host[len(parts[0]):]
	// Walk through interior segments between successive * tokens.
	for _, seg := range parts[1 : len(parts)-1] {
		idx := strings.Index(remaining, seg)
		if idx < 0 {
			return false
		}
		remaining = remaining[idx+len(seg):]
	}
	// The final segment must be a suffix of what remains.
	return strings.HasSuffix(remaining, parts[len(parts)-1])
}

func normalize(host string) string {
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

func (s *Scope) hostnameAllowed(host string) bool {
	for _, pattern := range s.Hostnames {
		pattern = normalize(pattern)
		if pattern == host {
			return true
		}
		if strings.HasPrefix(pattern, "*.") {
			suffix := pattern[1:] // ".example.com"
			if strings.HasSuffix(host, suffix) {
				prefix := host[:len(host)-len(suffix)]
				if len(prefix) == 0 {
					continue
				}
				if s.WildcardsRecursive {
					// Any depth: a.b.c.example.com matches *.example.com.
					return true
				}
				// Default: one label deep only.
				if !strings.Contains(prefix, ".") {
					return true
				}
			}
		}
	}
	return false
}

func (s *Scope) ipAllowed(ip net.IP) bool {
	for _, raw := range s.IPs {
		if parsed := net.ParseIP(raw); parsed != nil && parsed.Equal(ip) {
			return true
		}
	}
	for _, cidr := range s.CIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *Scope) portAllowed(port int) bool {
	for _, p := range s.Ports {
		if p == port {
			return true
		}
	}
	return false
}
