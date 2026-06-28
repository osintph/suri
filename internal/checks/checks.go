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

// Package checks defines the Check interface and registry. Implementations
// are in sub-packages (web, admin, api, cloud). Full check modules come in
// Session 4 and beyond.
package checks

import "context"

// Severity classifies finding risk.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Category groups checks by type.
type Category string

const (
	CategoryWeb   Category = "web"
	CategoryAdmin Category = "admin"
	CategoryAPI   Category = "api"
	CategoryCloud Category = "cloud"
)

// Check is the interface every scan module implements.
type Check interface {
	ID() string
	Name() string
	Severity() Severity
	Category() Category
	Run(ctx context.Context, target *Target) ([]*Finding, error)
}

// Target packages everything a Check needs to run against a single engagement
// target. Full fields are populated starting in Session 4.
type Target struct {
	Domain string
}

// Finding records a single discovered issue.
type Finding struct {
	CheckID     string
	Severity    Severity
	Title       string
	Description string
	URL         string
	Parameter   string
	CWE         string
	OWASP       string
}
