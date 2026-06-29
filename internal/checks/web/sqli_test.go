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
	"strings"
	"sync"
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

// timingSleepServer creates a test server that sleeps 100ms when any query
// parameter value contains "sleep" (case-insensitive), and responds immediately
// otherwise. The goroutine parameter name is read from the "param" query key so
// multiple concurrent goroutines can each use a distinct parameter name without
// the server needing to know it in advance.
func timingSleepServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, v := range r.URL.Query() {
			for _, val := range v {
				if strings.Contains(strings.ToLower(val), "sleep") {
					time.Sleep(100 * time.Millisecond)
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("ok"))
					return
				}
			}
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
}

// targetWithParam returns a checks.Target for srv with one query parameter
// named paramName. Uses webTarget so the scope matches 127.0.0.1 correctly.
func targetWithParam(srv *httptest.Server, paramName string) *crawler.Parameter {
	return &crawler.Parameter{
		Name:      paramName,
		Source:    "query",
		InjectURL: srv.URL,
		Method:    "GET",
	}
}

// TestTimingProbesSerialisePerHost verifies that concurrent timing probes
// against the same host are serialised. With N goroutines each sleeping 100ms
// per probe, total elapsed time must be >= (N-1)*100ms (serial), not ~100ms
// (parallel).
func TestTimingProbesSerialisePerHost(t *testing.T) {
	srv := timingSleepServer(t)
	defer srv.Close()

	const N = 5
	ck := &SQLiCheck{TimingThresholdMs: 50}

	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Each goroutine has a different parameter name to avoid the confirmed-key
			// dedup, but all point to the same host so the lock serialises them.
			tgt := webTarget(srv)
			tgt.Inventory.Parameters = []*crawler.Parameter{
				targetWithParam(srv, fmt.Sprintf("id%d", i)),
			}
			ck.Run(context.Background(), tgt) //nolint:errcheck
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)

	// With serialisation: (N-1) probes wait behind the lock, so elapsed >= 4*80ms.
	// Without: all 5 probes overlap and finish in ~100ms.
	minExpected := time.Duration(N-1) * 80 * time.Millisecond
	if elapsed < minExpected {
		t.Errorf("timing probes appear to have run in parallel (elapsed %v < expected serial lower-bound %v)", elapsed, minExpected)
	}
}

// TestSQLiTimingBaselineUsesOriginalValue verifies that timing baseline probes
// use the parameter's original value from InjectURL rather than a hardcoded
// probe string. Same rationale as TestCMDiBaselineUsesOriginalValue.
func TestSQLiTimingBaselineUsesOriginalValue(t *testing.T) {
	var mu sync.Mutex
	var receivedValues []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.URL.Query().Get("id")
		mu.Lock()
		receivedValues = append(receivedValues, val)
		mu.Unlock()
		// Return safe output so error-based check does not fire, allowing the
		// timing baseline to run.
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("safe output"))
	}))
	defer srv.Close()

	injectURL := srv.URL + "?id=1"
	target := webTarget(srv)
	target.Inventory.Parameters = []*crawler.Parameter{
		{PageURL: srv.URL, Name: "id", Source: "query", InjectURL: injectURL, Method: "GET"},
	}

	ck := &SQLiCheck{TimingThresholdMs: 50}
	ck.Run(context.Background(), target) //nolint:errcheck

	mu.Lock()
	defer mu.Unlock()

	count := 0
	for _, v := range receivedValues {
		if v == "1" {
			count++
		}
	}
	if count < 2 {
		t.Errorf("expected at least 2 baseline probes with original value \"1\", got %d (values: %v)", count, receivedValues)
	}
}

// TestSQLiSlowBaselineSkipped verifies that timing checks are skipped when the
// baseline is too slow for reliable injection detection.
func TestSQLiSlowBaselineSkipped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond) // always slow, no SQL error strings
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("safe output"))
	}))
	defer srv.Close()

	target := webTarget(srv)
	target.Inventory.Parameters = []*crawler.Parameter{
		{PageURL: srv.URL, Name: "id", Source: "query",
			InjectURL: srv.URL + "?id=1", Method: "GET"},
	}

	// threshold=50ms, threshold/2=25ms. Baseline≈100ms > 25ms → timing skipped.
	// Error-based also returns no match (safe output). Expect 0 findings.
	ck := &SQLiCheck{TimingThresholdMs: 50}
	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when baseline exceeds threshold/2, got %d", len(findings))
	}
}

// TestSQLiErrorSQLite verifies that SQLite-specific error messages are matched
// by the error-based payload signal regex. The patterns were added in session 6.5
// after integration testing surfaced that the regex only covered MySQL/Postgres.
func TestSQLiErrorSQLite(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.URL.Query().Get("id")
		w.Header().Set("Content-Type", "text/plain")
		if strings.Contains(val, "'") {
			w.WriteHeader(http.StatusInternalServerError)
			// Real SQLite error from better-sqlite3 / sqlite3 node modules.
			w.Write([]byte(`unrecognized token: "'" at offset 15`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("user info"))
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
		t.Error("expected SQLi finding for SQLite error message, got 0")
	}
	if len(findings) > 0 && findings[0].CheckID != "web.sqli.error" {
		t.Errorf("expected web.sqli.error, got %q", findings[0].CheckID)
	}
}

// TestTimingProbesParallelAcrossHosts verifies that timing probes against
// different hosts are NOT serialised: N goroutines on N distinct servers should
// all run concurrently and finish in approximately one probe's time.
func TestTimingProbesParallelAcrossHosts(t *testing.T) {
	const N = 5
	srvs := make([]*httptest.Server, N)
	for i := range srvs {
		srvs[i] = timingSleepServer(t)
		defer srvs[i].Close()
	}

	ck := &SQLiCheck{TimingThresholdMs: 50}

	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(srv *httptest.Server) {
			defer wg.Done()
			tgt := webTarget(srv)
			tgt.Inventory.Parameters = []*crawler.Parameter{
				targetWithParam(srv, "id"),
			}
			ck.Run(context.Background(), tgt) //nolint:errcheck
		}(srvs[i])
	}
	wg.Wait()
	elapsed := time.Since(start)

	// If probes run in parallel the elapsed time is approximately one sleep (100ms)
	// plus overhead. 400ms is a generous upper-bound: if elapsed > 400ms the probes
	// must have been serialised (5 x 100ms = 500ms) even though they target distinct hosts.
	maxExpected := 400 * time.Millisecond
	if elapsed > maxExpected {
		t.Errorf("timing probes across different hosts took %v (want < %v), may not be running in parallel", elapsed, maxExpected)
	}
}
