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

// Package checks defines the Check interface and shared types. Implementations
// live in sub-packages: checks/cloud, checks/web, checks/api, checks/admin.
package checks

import (
	"context"
	"crypto/rand"
	"encoding/hex"

	"github.com/osintph/suri/internal/crawler"
	internalhttp "github.com/osintph/suri/internal/http"
	"github.com/osintph/suri/internal/scope"
)

// GenerateCanary returns a random 8-character lowercase hex token. Each scan
// should generate one canary shared across all injection checks so that
// findings from the same scan share a traceable token.
func GenerateCanary() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		// Extremely unlikely; fall back to a fixed string that is still unique
		// enough for a single scan session.
		return "deadbeef"
	}
	return hex.EncodeToString(b)
}

// Severity classifies finding risk.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Confidence describes how certain the check is that the finding is real.
type Confidence string

const (
	ConfidenceConfirmed Confidence = "confirmed"
	ConfidenceFirm      Confidence = "firm"
	ConfidenceTentative Confidence = "tentative"
)

// Category groups checks by type.
type Category string

const (
	CategoryCloud Category = "cloud"
	CategoryWeb   Category = "web"
	CategoryAPI   Category = "api"
	CategoryAdmin Category = "admin"
	CategoryRecon Category = "recon"
)

// Evidence captures the raw HTTP exchange that confirms a finding.
type Evidence struct {
	RequestBytes   []byte
	ResponseBytes  []byte
	ResponseStatus int
	ResponseTimeMs int64

	// Backup-file check fields. Only set by BackupsCheck.
	OriginalURL      string  // URL of the original file the backup was derived from
	OriginalBodyHash string  // hex SHA-256 of original body (first 32 KB)
	BackupBodyHash   string  // hex SHA-256 of backup body (first 32 KB)
	JaccardScore     float64 // Jaccard token-set similarity between original and backup (0–1)
}

// Finding is a potential vulnerability or misconfiguration discovered by a check.
type Finding struct {
	CheckID        string
	Severity       Severity
	Title          string
	Description    string
	URL            string
	Parameter      string
	Evidence       *Evidence
	CWE            string
	OWASP          string
	Confidence     Confidence
	WordlistSource string // non-empty when the finding came from a wordlist probe
}

// Target packages everything a Check needs to run against a single engagement.
type Target struct {
	Inventory   *crawler.Inventory
	Scope       *scope.Scope
	HTTP        *internalhttp.Client
	Domain      string
	Concurrency int
	Notes       map[string]string
	SeedURLs    []string // base URLs for admin/API path probing
	Canary      string   // 8-char hex token shared across all injection checks in a scan
}

// Check is the interface every scan module implements.
type Check interface {
	ID() string
	Name() string
	Severity() Severity
	Category() Category
	Run(ctx context.Context, target *Target) ([]*Finding, error)
}
