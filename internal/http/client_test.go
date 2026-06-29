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
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
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

// countingHandler is a slog.Handler that counts records at each level.
type countingHandler struct {
	mu    sync.Mutex
	warns int
}

func (h *countingHandler) Enabled(_ context.Context, l slog.Level) bool { return true }
func (h *countingHandler) WithAttrs(_ []slog.Attr) slog.Handler         { return h }
func (h *countingHandler) WithGroup(_ string) slog.Handler              { return h }
func (h *countingHandler) Handle(_ context.Context, r slog.Record) error {
	if r.Level == slog.LevelWarn {
		h.mu.Lock()
		h.warns++
		h.mu.Unlock()
	}
	return nil
}

func (h *countingHandler) warnCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.warns
}

func TestBlockSummaryDeduplicates(t *testing.T) {
	counter := &countingHandler{}
	oldLogger := slog.Default()
	slog.SetDefault(slog.New(counter))
	defer slog.SetDefault(oldLogger)

	sc := outOfScopeScope()
	client := New(sc)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1:9999", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	// Send 100 identical out-of-scope requests.
	for i := 0; i < 100; i++ {
		_, _ = client.Do(context.Background(), req)
	}

	// Only the first block should have produced a WARN.
	if got := counter.warnCount(); got != 1 {
		t.Errorf("want 1 WARN before summary, got %d", got)
	}

	// LogBlockSummary should emit one more WARN and return correct counts.
	total, unique := client.LogBlockSummary()
	if total != 100 {
		t.Errorf("total blocked: want 100, got %d", total)
	}
	if unique != 1 {
		t.Errorf("unique blocked hosts: want 1, got %d", unique)
	}
	if got := counter.warnCount(); got != 2 {
		t.Errorf("want 2 WARNs total (first block + summary), got %d", got)
	}
}

func TestBlockSummaryEmpty(t *testing.T) {
	sc := inScopeScope()
	client := New(sc)
	total, unique := client.LogBlockSummary()
	if total != 0 || unique != 0 {
		t.Errorf("empty client: want 0/0, got %d/%d", total, unique)
	}
}
