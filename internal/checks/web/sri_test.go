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
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSRICheckDetectsMissingIntegrity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `<html><head><script src="https://cdn.example.com/lib.js"></script></head><body>hello</body></html>`)
	}))
	defer srv.Close()

	target := webTarget(srv)
	ck := &SRICheck{}
	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected SRI finding for cross-origin script without integrity, got 0")
	}
	if len(findings) > 0 && findings[0].CheckID != "web.sri.missing" {
		t.Errorf("unexpected CheckID %q", findings[0].CheckID)
	}
}

func TestSRICheckSkipsSameOrigin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `<html><head><script src="/static/app.js"></script></head><body>ok</body></html>`)
	}))
	defer srv.Close()

	target := webTarget(srv)
	ck := &SRICheck{}
	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for same-origin script, got %d", len(findings))
	}
}

func TestSRICheckAcceptsIntegrity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `<html><head><script src="https://cdn.example.com/lib.js" integrity="sha384-abc123" crossorigin="anonymous"></script></head><body>ok</body></html>`)
	}))
	defer srv.Close()

	target := webTarget(srv)
	ck := &SRICheck{}
	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for script with integrity attribute, got %d", len(findings))
	}
}
