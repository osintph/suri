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
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/osintph/suri/internal/checks"
	"github.com/osintph/suri/internal/crawler"
	internalhttp "github.com/osintph/suri/internal/http"
	"github.com/osintph/suri/internal/scope"
)

// minimalSwaggerJSON is a valid Swagger 2.0 spec with two paths.
const minimalSwaggerJSON = `{
  "swagger": "2.0",
  "info": {"title": "Test API", "version": "1.0"},
  "basePath": "/api",
  "paths": {
    "/users": {
      "get": {
        "parameters": [
          {"name": "limit", "in": "query"},
          {"name": "offset", "in": "query"}
        ]
      }
    },
    "/products": {
      "get": {"parameters": []}
    }
  }
}`

// minimalOpenAPI3JSON is a minimal OpenAPI 3.0 spec.
const minimalOpenAPI3JSON = `{
  "openapi": "3.0.0",
  "info": {"title": "Juice Shop API", "version": "2.0"},
  "paths": {
    "/api/users": {},
    "/api/products": {}
  }
}`

func testAPIScope(srv *httptest.Server) *scope.Scope {
	return &scope.Scope{
		IPs: []string{"127.0.0.1"},
	}
}

func testAPITarget(srv *httptest.Server) *checks.Target {
	sc := testAPIScope(srv)
	client := internalhttp.New(sc)
	return &checks.Target{
		Inventory:   &crawler.Inventory{},
		Scope:       sc,
		HTTP:        client,
		Domain:      "example.com",
		Concurrency: 2,
		SeedURLs:    []string{srv.URL},
	}
}

func TestSwaggerCheckFindsSpec(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/swagger.json" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(minimalSwaggerJSON))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	target := testAPITarget(srv)
	ck := &SwaggerCheck{}

	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for swagger.json")
	}

	f := findings[0]
	if f.CheckID != "api.openapi.spec-exposed" {
		t.Errorf("CheckID: want api.openapi.spec-exposed, got %q", f.CheckID)
	}
	if f.Severity != checks.SeverityMedium {
		t.Errorf("Severity: want medium, got %q", f.Severity)
	}
	if !strings.Contains(f.URL, "/swagger.json") {
		t.Errorf("URL: expected /swagger.json in %q", f.URL)
	}
	if f.Confidence != checks.ConfidenceConfirmed {
		t.Errorf("Confidence: want confirmed, got %q", f.Confidence)
	}
}

func TestSwaggerCheckInventoriesEndpoints(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/swagger.json" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(minimalSwaggerJSON))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	target := testAPITarget(srv)
	ck := &SwaggerCheck{}

	_, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Build a map of spec-enumerated URLs (source == "swagger").
	swaggerURLs := make(map[string]bool)
	for _, u := range target.Inventory.URLs {
		if u.Source == "swagger" {
			swaggerURLs[u.URL] = true
		}
	}

	if !swaggerURLs[srv.URL+"/api/users"] {
		t.Errorf("expected %s/api/users in inventory with source swagger", srv.URL)
	}
	if !swaggerURLs[srv.URL+"/api/products"] {
		t.Errorf("expected %s/api/products in inventory with source swagger", srv.URL)
	}

	// Parameters extracted from the spec should be inventoried.
	paramNames := make(map[string]bool)
	for _, p := range target.Inventory.Parameters {
		paramNames[p.Name] = true
	}
	if !paramNames["limit"] {
		t.Error("expected parameter 'limit' in inventory")
	}
	if !paramNames["offset"] {
		t.Error("expected parameter 'offset' in inventory")
	}
}

func TestSwaggerCheckOpenAPI3(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openapi.json" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(minimalOpenAPI3JSON))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	target := testAPITarget(srv)
	ck := &SwaggerCheck{}

	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for openapi.json")
	}
	if !strings.Contains(findings[0].Description, "3.0") {
		t.Errorf("Description should mention version: %s", findings[0].Description)
	}
}

func TestSwaggerCheckNoSpec(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	target := testAPITarget(srv)
	ck := &SwaggerCheck{}

	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}

	// Even with no spec found, every probed URL must appear in the inventory.
	if len(target.Inventory.URLs) == 0 {
		t.Error("expected probe URLs in inventory even when no spec was found")
	}
	for _, u := range target.Inventory.URLs {
		if u.Source != "swagger-probe" {
			t.Errorf("expected source swagger-probe for %s, got %q", u.URL, u.Source)
		}
	}
}

func TestSwaggerCheckRecordsProbeURLs(t *testing.T) {
	// Server returns a valid spec only on /swagger.json; all other paths return 404.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/swagger.json" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(minimalSwaggerJSON))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	target := testAPITarget(srv)
	ck := &SwaggerCheck{}

	_, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Probe URLs must be present for every wordlist entry, including those that returned 404.
	probeURLs := make(map[string]bool)
	for _, u := range target.Inventory.URLs {
		if u.Source == "swagger-probe" {
			probeURLs[u.URL] = true
		}
	}

	// The probe for /swagger.json must appear even though it returned a spec.
	if !probeURLs[srv.URL+"/swagger.json"] {
		t.Errorf("expected %s/swagger.json recorded as swagger-probe in inventory", srv.URL)
	}
	// A path that returned 404 must also be recorded.
	if !probeURLs[srv.URL+"/openapi.json"] {
		t.Errorf("expected %s/openapi.json recorded as swagger-probe in inventory", srv.URL)
	}
	// There must be more than one probe entry.
	if len(probeURLs) < 2 {
		t.Errorf("expected multiple probe URLs in inventory, got %d", len(probeURLs))
	}
}

// TestSwaggerProbeWritesStatusBack verifies that after Run completes, every URL
// recorded in the inventory with source "swagger-probe" has a non-zero
// ResponseStatus and a non-empty BodyHash.
func TestSwaggerProbeWritesStatusBack(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/swagger.json" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(minimalSwaggerJSON))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
	}))
	defer srv.Close()

	target := testAPITarget(srv)
	ck := &SwaggerCheck{}

	_, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	var probeURLs []*crawler.DiscoveredURL
	for _, u := range target.Inventory.URLs {
		if u.Source == "swagger-probe" {
			probeURLs = append(probeURLs, u)
		}
	}
	if len(probeURLs) == 0 {
		t.Fatal("expected swagger-probe URLs in inventory, got none")
	}
	for _, u := range probeURLs {
		if u.ResponseStatus == 0 {
			t.Errorf("swagger-probe URL %s: ResponseStatus not set (got 0)", u.URL)
		}
		if u.BodyHash == "" {
			t.Errorf("swagger-probe URL %s: BodyHash not set", u.URL)
		}
	}
}

func TestLooksLikeOpenAPISpec(t *testing.T) {
	cases := []struct {
		body []byte
		want bool
	}{
		{[]byte(minimalSwaggerJSON), true},
		{[]byte(minimalOpenAPI3JSON), true},
		{[]byte(`{"not": "a swagger spec"}`), false},
		{[]byte(`<html><body>not json</body></html>`), false},
		{[]byte(`{"openapi": "3.0.0", "info": {}}`), false}, // no paths
		{[]byte(`{}`), false},
		{[]byte(""), false},
	}
	for i, tc := range cases {
		got := looksLikeOpenAPISpec(tc.body)
		if got != tc.want {
			t.Errorf("case %d: looksLikeOpenAPISpec(%q) = %v, want %v", i, tc.body, got, tc.want)
		}
	}
}

func TestSpecBase(t *testing.T) {
	cases := []struct {
		specURL  string
		basePath string
		want     string
	}{
		{"http://example.com/swagger.json", "/api", "http://example.com/api"},
		{"http://example.com/swagger.json", "", "http://example.com"},
		{"http://example.com/swagger.json", "/", "http://example.com"},
		{"https://api.example.com/v1/swagger.json", "/v1", "https://api.example.com/v1"},
	}
	for _, tc := range cases {
		got := specBase(tc.specURL, tc.basePath)
		if got != tc.want {
			t.Errorf("specBase(%q, %q) = %q, want %q", tc.specURL, tc.basePath, got, tc.want)
		}
	}
}
