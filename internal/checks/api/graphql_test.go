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
)

// minimalIntrospectionResponse simulates a GraphQL server returning the schema.
const minimalIntrospectionResponse = `{
  "data": {
    "__schema": {
      "queryType": {"name": "Query"},
      "types": [
        {"name": "Query", "kind": "OBJECT", "description": null},
        {"name": "String", "kind": "SCALAR", "description": null}
      ]
    }
  }
}`

func TestGraphQLCheckIntrospectionOpen(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/graphql" && r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(minimalIntrospectionResponse))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	target := testAPITarget(srv)
	ck := &GraphQLCheck{}

	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for open GraphQL introspection")
	}

	f := findings[0]
	if f.CheckID != "api.graphql.introspection-open" {
		t.Errorf("CheckID: want api.graphql.introspection-open, got %q", f.CheckID)
	}
	if f.Severity != checks.SeverityMedium {
		t.Errorf("Severity: want medium, got %q", f.Severity)
	}
	if f.CWE != "CWE-200" {
		t.Errorf("CWE: want CWE-200, got %q", f.CWE)
	}
	if f.OWASP != "A05:2021" {
		t.Errorf("OWASP: want A05:2021, got %q", f.OWASP)
	}
	if f.Confidence != checks.ConfidenceConfirmed {
		t.Errorf("Confidence: want confirmed, got %q", f.Confidence)
	}
	if !strings.Contains(f.URL, "/graphql") {
		t.Errorf("URL: expected /graphql in %q", f.URL)
	}
	if f.Evidence == nil {
		t.Error("Evidence should not be nil")
	}
	if f.Evidence != nil && !strings.Contains(string(f.Evidence.ResponseBytes), `"__schema"`) {
		t.Error("Evidence should contain __schema")
	}
}

func TestGraphQLCheckIntrospectionDisabled(t *testing.T) {
	// Server exists but returns an error for introspection.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/graphql" && r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"errors":[{"message":"GraphQL introspection is not allowed"}]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	target := testAPITarget(srv)
	ck := &GraphQLCheck{}

	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings when introspection is disabled, got %d", len(findings))
	}
}

func TestGraphQLCheckNoEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	target := testAPITarget(srv)
	ck := &GraphQLCheck{}

	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for target with no GraphQL, got %d", len(findings))
	}
}

func TestGraphQLCheckAlternativePath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/graphql" && r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(minimalIntrospectionResponse))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	target := testAPITarget(srv)
	ck := &GraphQLCheck{}

	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for /api/graphql path")
	}
	if !strings.Contains(findings[0].URL, "/api/graphql") {
		t.Errorf("URL: expected /api/graphql in %q", findings[0].URL)
	}
}

func TestIsGraphQLIntrospectionResponse(t *testing.T) {
	cases := []struct {
		status int
		body   []byte
		want   bool
	}{
		{200, []byte(minimalIntrospectionResponse), true},
		{200, []byte(`{"data": {"users": []}}`), false},
		{200, []byte(`{"errors": [{"message": "introspection disabled"}]}`), false},
		{400, []byte(minimalIntrospectionResponse), false},
		{500, []byte(minimalIntrospectionResponse), false},
	}
	for i, tc := range cases {
		got := isGraphQLIntrospectionResponse(tc.status, tc.body)
		if got != tc.want {
			t.Errorf("case %d: isGraphQLIntrospectionResponse(%d, ...) = %v, want %v", i, tc.status, got, tc.want)
		}
	}
}
