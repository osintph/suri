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

func TestCMDiCheckTimingVulnerable(t *testing.T) {
	// Simulates a server that processes the "host" param with a shell command.
	// When the value contains "sleep", the test server introduces a delay.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.URL.Query().Get("host")
		if strings.Contains(strings.ToLower(val), "sleep") {
			time.Sleep(100 * time.Millisecond)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ping result"))
	}))
	defer srv.Close()

	target := webTarget(srv)
	target.Inventory.Parameters = []*crawler.Parameter{
		{PageURL: srv.URL, Name: "host", Source: "query", InjectURL: srv.URL, Method: "GET"},
	}

	ck := &CMDiCheck{TimingThresholdMs: 50}
	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected at least 1 CMDi finding for timing-vulnerable server, got 0")
	}
	if findings[0].CheckID != "web.cmdi" {
		t.Errorf("unexpected check ID %q", findings[0].CheckID)
	}
}

func TestCMDiCheckTimingClean(t *testing.T) {
	// Clean: responds immediately regardless of input.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("pong"))
	}))
	defer srv.Close()

	target := webTarget(srv)
	target.Inventory.Parameters = []*crawler.Parameter{
		{PageURL: srv.URL, Name: "host", Source: "query", InjectURL: srv.URL, Method: "GET"},
	}

	ck := &CMDiCheck{TimingThresholdMs: 50}
	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 CMDi findings for clean server, got %d", len(findings))
	}
}
