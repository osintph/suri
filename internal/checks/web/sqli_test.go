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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/osintph/suri/internal/crawler"
)

func TestSQLiErrorBased(t *testing.T) {
	// Simulates a MySQL error in the response body when SQL metacharacters appear.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.URL.Query().Get("id")
		w.Header().Set("Content-Type", "text/html")
		if strings.Contains(val, "'") {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("product info here"))
	}))
	defer srv.Close()

	target := webTarget(srv)
	target.Inventory.Parameters = []*crawler.Parameter{
		{PageURL: srv.URL, Name: "id", Source: "query", InjectURL: srv.URL, Method: "GET"},
	}

	ck := &SQLiCheck{}
	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected at least 1 SQLi finding for error-based response, got 0")
	}
	if findings[0].CheckID != "web.sqli.error" {
		t.Errorf("unexpected check ID %q", findings[0].CheckID)
	}
}

func TestSQLiTimingBased(t *testing.T) {
	// Simulates a timed response when the parameter value contains "sleep".
	// Uses a very low TimingThresholdMs so the test completes quickly.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.URL.Query().Get("id")
		if strings.Contains(strings.ToLower(val), "sleep") {
			time.Sleep(100 * time.Millisecond)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	target := webTarget(srv)
	target.Inventory.Parameters = []*crawler.Parameter{
		{PageURL: srv.URL, Name: "id", Source: "query", InjectURL: srv.URL, Method: "GET"},
	}

	ck := &SQLiCheck{TimingThresholdMs: 50}
	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected at least 1 timing SQLi finding, got 0")
	}
	for _, f := range findings {
		if f.CheckID == "web.sqli.timing" {
			return // found the right one
		}
	}
	t.Errorf("expected web.sqli.timing finding, got: %v", findings)
}

func TestSQLiClean(t *testing.T) {
	// No errors, no delays: expect no finding.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("safe product page"))
	}))
	defer srv.Close()

	target := webTarget(srv)
	target.Inventory.Parameters = []*crawler.Parameter{
		{PageURL: srv.URL, Name: "id", Source: "query", InjectURL: srv.URL, Method: "GET"},
	}

	ck := &SQLiCheck{TimingThresholdMs: 50}
	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 SQLi findings for clean server, got %d", len(findings))
	}
}
