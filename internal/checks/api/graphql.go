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

package api

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/osintph/suri/internal/checks"
)

// introspectionQuery is the GraphQL introspection query that reveals the full schema.
const introspectionQuery = `{"query":"{ __schema { queryType { name } types { name kind description fields(includeDeprecated: true) { name } } } }"}`

// graphqlProbePaths are the common GraphQL endpoint paths probed by this check.
// These are short and well-known enough to not need a wordlist.
var graphqlProbePaths = []string{
	"/graphql",
	"/api/graphql",
	"/graphql/v1",
	"/graphql/v2",
	"/graphiql",
	"/playground",
	"/graph",
	"/api/graph",
	"/api/v1/graphql",
	"/api/v2/graphql",
	"/v1/graphql",
	"/v2/graphql",
	"/console/graphql",
	"/graphql/console",
	"/altair",
}

// GraphQLCheck probes common GraphQL endpoints for open introspection.
// Open introspection exposes the full API schema to unauthenticated callers.
type GraphQLCheck struct{}

func (c *GraphQLCheck) ID() string                { return "api.graphql.introspection-open" }
func (c *GraphQLCheck) Name() string              { return "GraphQL Introspection Open" }
func (c *GraphQLCheck) Severity() checks.Severity { return checks.SeverityMedium }
func (c *GraphQLCheck) Category() checks.Category { return checks.CategoryAPI }

// Run probes each candidate GraphQL path against all origins derived from the target.
// A finding is returned for each endpoint that answers an introspection query.
func (c *GraphQLCheck) Run(ctx context.Context, target *checks.Target) ([]*checks.Finding, error) {
	origins := uniqueOrigins(target.SeedURLs, target.Inventory)
	if len(origins) == 0 {
		slog.Info("api.graphql: no probe origins found, skipping")
		return nil, nil
	}

	var findings []*checks.Finding

	for _, origin := range origins {
		for _, path := range graphqlProbePaths {
			select {
			case <-ctx.Done():
				return findings, ctx.Err()
			default:
			}

			endpointURL := strings.TrimRight(origin, "/") + path
			f := probeGraphQL(ctx, target, endpointURL)
			if f != nil {
				findings = append(findings, f)
				// One finding per origin is enough; don't probe remaining paths.
				break
			}
		}
	}

	slog.Debug("api.graphql check complete", "findings", len(findings))
	return findings, nil
}

// probeGraphQL sends an introspection query to endpointURL and returns a Finding
// if the response reveals the GraphQL schema.
func probeGraphQL(ctx context.Context, target *checks.Target, endpointURL string) *checks.Finding {
	body := []byte(introspectionQuery)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpointURL, bytes.NewReader(body))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := target.HTTP.Do(ctx, req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return nil
	}

	if !isGraphQLIntrospectionResponse(resp.StatusCode, respBody) {
		return nil
	}

	// Truncate evidence to 8 KB to avoid bloating the database.
	evidence := respBody
	if len(evidence) > 8192 {
		evidence = evidence[:8192]
	}

	return &checks.Finding{
		CheckID:  "api.graphql.introspection-open",
		Severity: checks.SeverityMedium,
		Title:    "GraphQL introspection enabled",
		Description: fmt.Sprintf(
			"GraphQL introspection query succeeded at %s. The full API schema is exposed to unauthenticated callers. "+
				"Disable introspection in production environments to prevent schema enumeration.",
			endpointURL,
		),
		URL:        endpointURL,
		CWE:        "CWE-200",
		OWASP:      "A05:2021",
		Confidence: checks.ConfidenceConfirmed,
		Evidence: &checks.Evidence{
			RequestBytes:   body,
			ResponseStatus: resp.StatusCode,
			ResponseBytes:  evidence,
		},
	}
}

// isGraphQLIntrospectionResponse returns true when the response body contains
// the "__schema" key that indicates a successful introspection response.
func isGraphQLIntrospectionResponse(status int, body []byte) bool {
	if status != http.StatusOK {
		return false
	}
	return bytes.Contains(body, []byte(`"__schema"`))
}
