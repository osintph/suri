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
	"testing"

	"github.com/osintph/suri/internal/crawler"
)

func TestRedirectCheckVulnerable(t *testing.T) {
	// Open redirect: the server redirects to whatever the "next" param says.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dst := r.URL.Query().Get("next")
		if dst != "" {
			http.Redirect(w, r, dst, http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("home"))
	}))
	defer srv.Close()

	target := webTarget(srv)
	target.Inventory.Parameters = []*crawler.Parameter{
		{PageURL: srv.URL, Name: "next", Source: "query", InjectURL: srv.URL, Method: "GET"},
	}

	ck := &RedirectCheck{}
	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected at least 1 open redirect finding, got 0")
	}
	if findings[0].CheckID != "web.redirect.open" {
		t.Errorf("unexpected check ID %q", findings[0].CheckID)
	}
}

func TestRedirectCheckNoRedirect(t *testing.T) {
	// Safe: ignores the next param and always returns 200.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("home page"))
	}))
	defer srv.Close()

	target := webTarget(srv)
	target.Inventory.Parameters = []*crawler.Parameter{
		{PageURL: srv.URL, Name: "next", Source: "query", InjectURL: srv.URL, Method: "GET"},
	}

	ck := &RedirectCheck{}
	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 redirect findings for safe server, got %d", len(findings))
	}
}

func TestRedirectCheckNonRedirectParam(t *testing.T) {
	// The parameter name is not in the redirect allowlist, so it should not be probed.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dst := r.URL.Query().Get("q")
		if dst != "" {
			http.Redirect(w, r, dst, http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	target := webTarget(srv)
	target.Inventory.Parameters = []*crawler.Parameter{
		{PageURL: srv.URL, Name: "q", Source: "query", InjectURL: srv.URL, Method: "GET"},
	}

	ck := &RedirectCheck{}
	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// "q" is not in redirectParamNames, so no probe should be made.
	if len(findings) != 0 {
		t.Errorf("expected 0 redirect findings for non-redirect param name, got %d", len(findings))
	}
}
