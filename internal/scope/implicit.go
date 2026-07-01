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
	"net/url"
	"time"
)

// ImplicitScope derives a Scope from a target URL when no explicit scope file
// has been provided. The resulting scope permits only the host and port parsed
// from targetURL. Cloud bucket checks are disabled (empty CloudBuckets).
func ImplicitScope(targetURL string) (*Scope, error) {
	u, err := url.Parse(targetURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("cannot derive implicit scope: invalid or unsupported target URL %q", targetURL)
	}

	hostname := u.Hostname()
	if hostname == "" {
		return nil, fmt.Errorf("cannot derive implicit scope: no hostname in %q", targetURL)
	}

	port := 80
	if rawPort := u.Port(); rawPort != "" {
		var p int
		if _, scanErr := fmt.Sscanf(rawPort, "%d", &p); scanErr != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("cannot derive implicit scope: invalid port in %q", targetURL)
		}
		port = p
	} else if u.Scheme == "https" {
		port = 443
	}

	ts := time.Now().UTC().Format("2006-01-02T15-04-05")
	engName := fmt.Sprintf("%s-%s", hostname, ts)

	return &Scope{
		EngagementName: engName,
		Hostnames:      []string{hostname},
		Ports:          []int{port},
		CloudBuckets:   []string{},
	}, nil
}
