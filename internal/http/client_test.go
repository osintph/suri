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

package http

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/osintph/suri/internal/scope"
)

// inScopeScope builds a Scope that allows 127.0.0.1 on all ports.
func inScopeScope() *scope.Scope {
	_, cidr, _ := net.ParseCIDR("127.0.0.1/32")
	return &scope.Scope{
		CIDRs: []*net.IPNet{cidr},
	}
}

// outOfScopeScope builds a Scope that only allows example.com.
func outOfScopeScope() *scope.Scope {
	return &scope.Scope{
		Hostnames: []string{"example.com"},
	}
}

func TestDoInScope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sc := inScopeScope()
	client := New(sc)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	resp, err := client.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: want 200, got %d", resp.StatusCode)
	}
}

func TestDoOutOfScope(t *testing.T) {
	// Use a scope that does not allow 127.0.0.1.
	sc := outOfScopeScope()
	client := New(sc)

	// Point at localhost; the scope does not allow this host.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1:9999", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	_, err = client.Do(context.Background(), req)
	if err == nil {
		t.Fatal("expected out-of-scope error, got nil")
	}

	var oos *ErrOutOfScope
	if !errors.As(err, &oos) {
		t.Errorf("expected *ErrOutOfScope, got %T: %v", err, err)
	}
	if oos.Host != "127.0.0.1" {
		t.Errorf("ErrOutOfScope.Host: want 127.0.0.1, got %s", oos.Host)
	}
}

func TestErrOutOfScopeMessage(t *testing.T) {
	e := &ErrOutOfScope{Host: "evil.com", Port: 443, Reason: "not in scope"}
	msg := e.Error()
	if msg == "" {
		t.Error("ErrOutOfScope.Error() returned empty string")
	}
}
