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

package cloud

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/osintph/suri/internal/checks"
)

// azureContainers is the list of common container names probed during active
// permutation. Passive probing uses the container extracted from the artifact.
var azureContainers = []string{
	"$web", "public", "assets", "static", "images",
	"data", "uploads", "files", "media",
}

// AzureCheck probes Azure Blob Storage containers (or Azure Blob-compatible
// endpoints) for anonymous list access. When Endpoint is empty, the standard
// Azure endpoint format is used. When Endpoint is set, path-style addressing
// against the custom endpoint is used.
type AzureCheck struct {
	Endpoint string
}

func (c *AzureCheck) ID() string                { return "cloud.azure.public-container" }
func (c *AzureCheck) Name() string              { return "Azure Blob Container Public List" }
func (c *AzureCheck) Severity() checks.Severity { return checks.SeverityHigh }
func (c *AzureCheck) Category() checks.Category { return checks.CategoryCloud }

// Run probes candidate Azure Blob containers. Passive extraction uses
// azure-blob artifacts from the crawl inventory; active permutation derives
// account names from the engagement domain.
func (c *AzureCheck) Run(ctx context.Context, target *checks.Target) ([]*checks.Finding, error) {
	if c.Endpoint != "" {
		if !target.Scope.HasCustomEndpointAuthorisation(c.Endpoint) {
			slog.Info("cloud.azure: custom endpoint not authorised in scope, skipping",
				"endpoint", c.Endpoint,
				"hint", "add the endpoint host to cloud_buckets in scope file")
			return nil, nil
		}
	} else {
		if !target.Scope.HasAzureAuthorisation() {
			slog.Info("cloud.azure: azure probing not authorised in scope, skipping",
				"hint", "add *.blob.core.windows.net to cloud_buckets in scope file")
			return nil, nil
		}
	}

	var candidates []string

	// Passive: azure-blob artifacts from the crawler inventory.
	for _, a := range target.Inventory.JSArtifacts {
		if a.Type == "azure-blob" {
			account, container := azureParseArtifact(a.Value)
			if account != "" && container != "" {
				candidates = append(candidates, c.listURL(account, container))
			}
		}
	}

	// Active: permutation from the engagement domain.
	if target.Domain != "" {
		stem := DomainStem(target.Domain)
		for _, name := range Names(stem) {
			for _, container := range azureContainers {
				candidates = append(candidates, c.listURL(name, container))
			}
		}
	}

	return probeAll(ctx, target, candidates, detectAzurePublicContainer, c.ID())
}

// listURL builds the Azure container listing URL. Uses path-style against the
// custom endpoint when set; otherwise uses the standard Azure virtual-hosted URL.
func (c *AzureCheck) listURL(account, container string) string {
	const suffix = "?restype=container&comp=list"
	if c.Endpoint != "" {
		return strings.TrimRight(c.Endpoint, "/") + "/" + account + "/" + container + suffix
	}
	return "https://" + account + ".blob.core.windows.net/" + container + suffix
}

// azureParseArtifact extracts the account name and container from an Azure
// Blob URL such as https://myaccount.blob.core.windows.net/mycontainer/blob.
func azureParseArtifact(rawURL string) (account, container string) {
	after := rawURL
	if idx := strings.Index(rawURL, "://"); idx >= 0 {
		after = rawURL[idx+3:]
	}
	// Host is the first component before /.
	slashIdx := strings.Index(after, "/")
	if slashIdx < 0 {
		return "", ""
	}
	host := after[:slashIdx]
	path := strings.TrimPrefix(after[slashIdx:], "/")

	// Account is the first label of the hostname.
	dotIdx := strings.Index(host, ".")
	if dotIdx < 0 {
		return "", ""
	}
	account = host[:dotIdx]

	// Container is the first path segment.
	if pathSlash := strings.Index(path, "/"); pathSlash >= 0 {
		container = path[:pathSlash]
	} else {
		container = path
	}
	return account, container
}

// detectAzurePublicContainer returns true when the response looks like an
// Azure container listing (200 OK with EnumerationResults XML).
func detectAzurePublicContainer(status int, body []byte) bool {
	return status == http.StatusOK && strings.Contains(string(body), "<EnumerationResults")
}
