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

// Package api implements Swagger/OpenAPI and GraphQL discovery checks.
package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/osintph/suri/internal/checks"
	"github.com/osintph/suri/internal/crawler"
	"github.com/osintph/suri/internal/wordlists"
)

// openAPISpec holds the fields we extract from Swagger 2.0 and OpenAPI 3.x specs.
type openAPISpec struct {
	Swagger  string `json:"swagger"` // "2.0"
	OpenAPI  string `json:"openapi"` // "3.0.x"
	BasePath string `json:"basePath"` // Swagger 2.0
	Info     struct {
		Title   string `json:"title"`
		Version string `json:"version"`
	} `json:"info"`
	Paths map[string]json.RawMessage `json:"paths"`
}

// pathItem holds per-method parameter definitions at a minimal level.
type pathItem struct {
	Get    *operation `json:"get"`
	Post   *operation `json:"post"`
	Put    *operation `json:"put"`
	Delete *operation `json:"delete"`
	Patch  *operation `json:"patch"`
}

type operation struct {
	Parameters []struct {
		Name string `json:"name"`
		In   string `json:"in"`
	} `json:"parameters"`
}

// SwaggerCheck probes common paths for Swagger/OpenAPI specs and inventories
// any discovered API endpoints and parameters.
type SwaggerCheck struct{}

func (c *SwaggerCheck) ID() string                { return "api.openapi.spec-exposed" }
func (c *SwaggerCheck) Name() string              { return "OpenAPI Specification Exposed" }
func (c *SwaggerCheck) Severity() checks.Severity { return checks.SeverityMedium }
func (c *SwaggerCheck) Category() checks.Category { return checks.CategoryAPI }

// Run probes each swagger-paths.txt entry against all target origins.
// Every probed URL is recorded in the inventory regardless of outcome so the
// operator can audit what was attempted by querying urls_discovered.
// If a spec is found, its endpoints are also added to target.Inventory and a finding is recorded.
func (c *SwaggerCheck) Run(ctx context.Context, target *checks.Target) ([]*checks.Finding, error) {
	wl, err := wordlists.Load(wordlists.SwaggerPaths, "")
	if err != nil {
		return nil, fmt.Errorf("loading swagger wordlist: %w", err)
	}

	origins := uniqueOrigins(target.SeedURLs, target.Inventory)
	if len(origins) == 0 {
		slog.Info("api.swagger: no probe origins found, skipping")
		return nil, nil
	}

	wlSource := wl.Source.String()
	var findings []*checks.Finding

	for _, origin := range origins {
		for _, path := range wl.Entries {
			select {
			case <-ctx.Done():
				return findings, ctx.Err()
			default:
			}

			specURL := strings.TrimRight(origin, "/") + "/" + strings.TrimLeft(path, "/")

			// Record every probed URL in the inventory for operator audit.
			var du *crawler.DiscoveredURL
			if target.Inventory != nil {
				du = &crawler.DiscoveredURL{URL: specURL, Source: "swagger-probe", Depth: 0}
				target.Inventory.URLs = append(target.Inventory.URLs, du)
			}

			f, status, hash := probeSwaggerPath(ctx, target, specURL, wlSource)
			if du != nil {
				du.ResponseStatus = status
				du.BodyHash = hash
			}
			if f != nil {
				findings = append(findings, f)
			}
		}
	}

	slog.Debug("api.swagger check complete", "findings", len(findings))
	return findings, nil
}

// probeSwaggerPath fetches specURL and, if it looks like an OpenAPI spec,
// inventories its endpoints and returns a finding. The second and third return
// values are the HTTP status code and hex body hash, used to update the probe
// URL's entry in urls_discovered.
func probeSwaggerPath(ctx context.Context, target *checks.Target, specURL, wlSource string) (*checks.Finding, int, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, specURL, nil)
	if err != nil {
		return nil, 0, ""
	}
	req.Header.Set("Accept", "application/json")

	resp, err := target.HTTP.Do(ctx, req)
	if err != nil {
		return nil, 0, ""
	}
	defer resp.Body.Close()

	status := resp.StatusCode
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024)) // 2 MB limit
	if err != nil {
		return nil, status, ""
	}
	bodyHash := swaggerHashBody(body)

	if status != http.StatusOK {
		return nil, status, bodyHash
	}

	if !looksLikeOpenAPISpec(body) {
		return nil, status, bodyHash
	}

	var spec openAPISpec
	if err := json.Unmarshal(body, &spec); err != nil {
		return nil, status, bodyHash
	}

	// Determine spec version.
	specVersion := spec.OpenAPI
	if specVersion == "" {
		specVersion = "2.0 (swagger)"
	}

	pathCount := len(spec.Paths)
	if pathCount == 0 {
		return nil, status, bodyHash
	}

	// Add discovered endpoints to inventory.
	base := specBase(specURL, spec.BasePath)
	inventoryEndpoints(target.Inventory, specURL, base, spec.Paths)

	evidence := body
	if len(evidence) > 4096 {
		evidence = evidence[:4096]
	}

	return &checks.Finding{
		CheckID:  "api.openapi.spec-exposed",
		Severity: checks.SeverityMedium,
		Title:    "OpenAPI specification publicly accessible",
		Description: fmt.Sprintf(
			"OpenAPI/Swagger specification (version %s, title %q) found at %s with %d paths defined. Endpoints have been added to the scan inventory.",
			specVersion, spec.Info.Title, specURL, pathCount,
		),
		URL:        specURL,
		Confidence: checks.ConfidenceConfirmed,
		CWE:        "CWE-200",
		OWASP:      "A05:2021",
		Evidence: &checks.Evidence{
			ResponseStatus: http.StatusOK,
			ResponseBytes:  evidence,
		},
		WordlistSource: wlSource,
	}, status, bodyHash
}

// swaggerHashBody returns the hex SHA-256 of up to 32 KB of body.
func swaggerHashBody(body []byte) string {
	const limit = 32 * 1024
	if len(body) > limit {
		body = body[:limit]
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// looksLikeOpenAPISpec performs a quick heuristic check before full JSON parsing.
func looksLikeOpenAPISpec(body []byte) bool {
	if len(body) < 20 {
		return false
	}
	trimmed := bytes.TrimLeft(body, " \t\n\r")
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return false
	}
	// Check for key indicators in the first 1 KB, then full body for "paths".
	preview := string(body)
	if len(preview) > 1024 {
		preview = preview[:1024]
	}
	hasSwagger := strings.Contains(preview, `"swagger"`) || strings.Contains(preview, `"openapi"`)
	hasPaths := strings.Contains(preview, `"paths"`) || strings.Contains(string(body), `"paths"`)
	return hasSwagger && hasPaths
}

// specBase constructs the URL prefix for expanding spec paths into full URLs.
// It uses basePath from Swagger 2.0 specs; OpenAPI 3.x uses the server URL
// (which we approximate as the spec's origin for simplicity in v1).
func specBase(specURL, basePath string) string {
	u, err := url.Parse(specURL)
	if err != nil {
		return ""
	}
	origin := u.Scheme + "://" + u.Host
	if basePath != "" && basePath != "/" {
		return strings.TrimRight(origin, "/") + "/" + strings.TrimLeft(basePath, "/")
	}
	return origin
}

// inventoryEndpoints adds each path from the spec into the crawl inventory.
func inventoryEndpoints(inv *crawler.Inventory, specURL, base string, paths map[string]json.RawMessage) {
	if inv == nil {
		return
	}
	for path, rawItem := range paths {
		if path == "" {
			continue
		}
		fullURL := strings.TrimRight(base, "/") + "/" + strings.TrimLeft(path, "/")
		inv.URLs = append(inv.URLs, &crawler.DiscoveredURL{
			URL:    fullURL,
			Source: "swagger",
			Depth:  0,
		})

		// Extract parameters from each HTTP method on this path.
		var item pathItem
		if err := json.Unmarshal(rawItem, &item); err != nil {
			continue
		}
		for _, op := range []*operation{item.Get, item.Post, item.Put, item.Delete, item.Patch} {
			if op == nil {
				continue
			}
			for _, p := range op.Parameters {
				if p.Name == "" {
					continue
				}
				source := "swagger"
				if p.In != "" {
					source = "swagger-" + p.In
				}
				inv.Parameters = append(inv.Parameters, &crawler.Parameter{
					PageURL: fullURL,
					Name:    p.Name,
					Source:  source,
				})
			}
		}
	}
}

// uniqueOrigins is shared with the admin package logic but duplicated to keep
// packages independent and avoid a shared utility package in v1.
func uniqueOrigins(seedURLs []string, inv *crawler.Inventory) []string {
	seen := make(map[string]bool)
	var result []string

	add := func(rawURL string) {
		u, err := url.Parse(rawURL)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return
		}
		origin := u.Scheme + "://" + u.Host
		if !seen[origin] {
			seen[origin] = true
			result = append(result, origin)
		}
	}

	for _, su := range seedURLs {
		add(su)
	}
	if inv != nil {
		for _, u := range inv.URLs {
			add(u.URL)
		}
	}
	return result
}
