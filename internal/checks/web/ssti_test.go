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

func TestSSTICheckVulnerable(t *testing.T) {
	// Simulates a template engine that evaluates {{7*7}} by returning "49"
	// when the input contains that expression. The server also echoes the
	// canary prefix so the signal matches "{canary}49".
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.URL.Query().Get("name")
		var result string
		if strings.Contains(val, "{{7*7}}") {
			// Evaluate the expression: replace the template expression with 49.
			result = strings.ReplaceAll(val, "{{7*7}}", "49")
		} else if strings.Contains(val, "${7*7}") {
			result = strings.ReplaceAll(val, "${7*7}", "49")
		} else {
			result = val
		}
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "<html><body>Hello %s</body></html>", result)
	}))
	defer srv.Close()

	target := webTarget(srv)
	target.Inventory.Parameters = []*crawler.Parameter{
		{PageURL: srv.URL, Name: "name", Source: "query", InjectURL: srv.URL, Method: "GET"},
	}

	ck := &SSTICheck{}
	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected at least 1 SSTI finding for evaluating server, got 0")
	}
	if findings[0].CheckID != "web.ssti" {
		t.Errorf("unexpected check ID %q", findings[0].CheckID)
	}
}

func TestSSTICheckSafe(t *testing.T) {
	// Safe: returns the input literally without evaluating expressions.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.URL.Query().Get("name")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		// HTML-escape the input and return it literally; signal "deadbeef49" never appears.
		safe := strings.NewReplacer("<", "&lt;", ">", "&gt;", "{", "&#123;", "}", "&#125;").Replace(val)
		fmt.Fprintf(w, "<html><body>Hello %s</body></html>", safe)
	}))
	defer srv.Close()

	target := webTarget(srv)
	target.Inventory.Parameters = []*crawler.Parameter{
		{PageURL: srv.URL, Name: "name", Source: "query", InjectURL: srv.URL, Method: "GET"},
	}

	ck := &SSTICheck{}
	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 SSTI findings for safe server, got %d", len(findings))
	}
}

func TestSSTIPathParameter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.TrimRight(r.URL.Path, "/"), "/")
		raw := parts[len(parts)-1]
		decoded, _ := url.PathUnescape(raw)
		result := decoded
		if strings.Contains(decoded, "{{7*7}}") {
			result = strings.ReplaceAll(decoded, "{{7*7}}", "49")
		} else if strings.Contains(decoded, "${7*7}") {
			result = strings.ReplaceAll(decoded, "${7*7}", "49")
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "<html><body>%s</body></html>", result)
	}))
	defer srv.Close()

	template := srv.URL + "/api/render/template/{t}"
	target := webTarget(srv)
	target.Inventory.Parameters = []*crawler.Parameter{
		{PageURL: template, Name: "t", Source: "swagger-path", InjectURL: template},
	}

	ck := &SSTICheck{}
	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected SSTI finding for path-param template-evaluating server, got 0")
	}
	if findings[0].CheckID != "web.ssti" {
		t.Errorf("unexpected check ID %q", findings[0].CheckID)
	}
	if findings[0].Parameter != "t" {
		t.Errorf("expected parameter=t, got %q", findings[0].Parameter)
	}
}

func TestSSTISwaggerBody(t *testing.T) {
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
		val := body["template"]
		result := val
		if strings.Contains(val, "{{7*7}}") {
			result = strings.ReplaceAll(val, "{{7*7}}", "49")
		} else if strings.Contains(val, "${7*7}") {
			result = strings.ReplaceAll(val, "${7*7}", "49")
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "<html><body>%s</body></html>", result)
	}))
	defer srv.Close()

	endpointURL := srv.URL + "/api/json/render"
	target := webTarget(srv)
	target.Inventory.Parameters = []*crawler.Parameter{
		{PageURL: endpointURL, Name: "template", Source: "swagger-body", InjectURL: endpointURL},
	}

	ck := &SSTICheck{}
	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected SSTI finding for JSON-body template server, got 0")
	}
	if findings[0].CheckID != "web.ssti" {
		t.Errorf("unexpected check ID %q", findings[0].CheckID)
	}
	if findings[0].Parameter != "template" {
		t.Errorf("expected parameter=template, got %q", findings[0].Parameter)
	}
}
