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

func TestCookieCheckDetectsMissingFlags(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:  "session",
			Value: "abc123",
		})
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "hello")
	}))
	defer srv.Close()

	target := webTarget(srv)
	ck := &CookieCheck{}
	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) < 3 {
		t.Errorf("expected at least 3 cookie flag findings, got %d", len(findings))
	}
	for _, f := range findings {
		if f.CheckID != "web.cookies.missing-flags" {
			t.Errorf("unexpected CheckID %q", f.CheckID)
		}
		if f.Parameter != "session" {
			t.Errorf("expected parameter=session, got %q", f.Parameter)
		}
	}
}

func TestCookieCheckNoCookies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "hello")
	}))
	defer srv.Close()

	target := webTarget(srv)
	ck := &CookieCheck{}
	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}
