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

package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/osintph/suri/internal/crawler"
)

func TestXSSCheckReflection(t *testing.T) {
	// Vulnerable: reflects the q param verbatim into the response.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "<html><body>%s</body></html>", val)
	}))
	defer srv.Close()

	target := webTarget(srv)
	target.Inventory.Parameters = []*crawler.Parameter{
		{PageURL: srv.URL, Name: "q", Source: "query", InjectURL: srv.URL, Method: "GET"},
	}

	ck := &XSSCheck{}
	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected at least 1 XSS finding for reflective server, got 0")
	}
	if findings[0].CheckID != "web.xss.reflected" {
		t.Errorf("unexpected check ID %q", findings[0].CheckID)
	}
}

func TestXSSCheckNoReflection(t *testing.T) {
	// Safe: ignores the parameter and returns fixed content.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>Welcome</body></html>"))
	}))
	defer srv.Close()

	target := webTarget(srv)
	target.Inventory.Parameters = []*crawler.Parameter{
		{PageURL: srv.URL, Name: "q", Source: "query", InjectURL: srv.URL, Method: "GET"},
	}

	ck := &XSSCheck{}
	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 XSS findings for non-reflective server, got %d", len(findings))
	}
}

func TestXSSCheckNoParameters(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	target := webTarget(srv)
	// Empty parameter list.
	ck := &XSSCheck{}
	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings with empty inventory, got %d", len(findings))
	}
}

func TestXSSPathParameterReflected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.TrimRight(r.URL.Path, "/"), "/")
		raw := parts[len(parts)-1]
		decoded, _ := url.PathUnescape(raw)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body>%s</body></html>", decoded)
	}))
	defer srv.Close()

	template := srv.URL + "/api/user/lookup/{name}"
	target := webTarget(srv)
	target.Inventory.Parameters = []*crawler.Parameter{
		{PageURL: template, Name: "name", Source: "swagger-path", InjectURL: template},
	}

	ck := &XSSCheck{}
	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected XSS finding for path-param reflective server, got 0")
	}
	f := findings[0]
	if f.CheckID != "web.xss.reflected" {
		t.Errorf("unexpected check ID %q", f.CheckID)
	}
	if f.Parameter != "name" {
		t.Errorf("expected parameter=name, got %q", f.Parameter)
	}
	if strings.Contains(f.URL, "{name}") {
		t.Errorf("finding URL should be the actual injected URL, not the template; got %q", f.URL)
	}
}

func TestXSSSwaggerBodyReflected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		val := body["query"]
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body>%s</body></html>", val)
	}))
	defer srv.Close()

	endpointURL := srv.URL + "/api/json/search"
	target := webTarget(srv)
	target.Inventory.Parameters = []*crawler.Parameter{
		{PageURL: endpointURL, Name: "query", Source: "swagger-body", InjectURL: endpointURL},
	}

	ck := &XSSCheck{}
	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected XSS finding for JSON-body reflective server, got 0")
	}
	f := findings[0]
	if f.CheckID != "web.xss.reflected" {
		t.Errorf("unexpected check ID %q", f.CheckID)
	}
	if f.Parameter != "query" {
		t.Errorf("expected parameter=query, got %q", f.Parameter)
	}
}
