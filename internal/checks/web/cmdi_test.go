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
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
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

// TestCMDiBaselineUsesOriginalValue verifies that the two baseline probes use
// the parameter's original value from InjectURL, not a hardcoded probe string.
// A hardcoded string like "baseline" can trigger backend processing (DNS, file
// I/O, regex) that inflates the baseline and masks real injection delays.
func TestCMDiBaselineUsesOriginalValue(t *testing.T) {
	var mu sync.Mutex
	var receivedValues []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.URL.Query().Get("host")
		mu.Lock()
		receivedValues = append(receivedValues, val)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	injectURL := srv.URL + "?host=127.0.0.1"
	target := webTarget(srv)
	target.Inventory.Parameters = []*crawler.Parameter{
		{PageURL: srv.URL, Name: "host", Source: "query", InjectURL: injectURL, Method: "GET"},
	}

	ck := &CMDiCheck{TimingThresholdMs: 50}
	ck.Run(context.Background(), target) //nolint:errcheck

	mu.Lock()
	defer mu.Unlock()

	count := 0
	for _, v := range receivedValues {
		if v == "127.0.0.1" {
			count++
		}
	}
	if count < 2 {
		t.Errorf("expected at least 2 baseline probes with original value \"127.0.0.1\", got %d (values: %v)", count, receivedValues)
	}
}

// TestCMDiSlowBaselineSkipped verifies that timing checks are skipped when the
// baseline response time already exceeds threshold/2, indicating the backend is
// too slow for reliable injection detection.
func TestCMDiSlowBaselineSkipped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond) // always slow
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	// threshold=50ms, threshold/2=25ms. Both baselines ≈100ms > 25ms → skip.
	target := webTarget(srv)
	target.Inventory.Parameters = []*crawler.Parameter{
		{PageURL: srv.URL, Name: "host", Source: "query",
			InjectURL: srv.URL + "?host=127.0.0.1", Method: "GET"},
	}

	ck := &CMDiCheck{TimingThresholdMs: 50}
	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when baseline exceeds threshold/2, got %d", len(findings))
	}
}

// TestCMDiTimingDetectsDelayOnConnectionError verifies that a timing finding is
// emitted even when the server closes the TCP connection after the sleep delay
// without sending a response. The old code did `if err != nil { continue }`,
// silently discarding the elapsed measurement. The fix checks elapsed first.
func TestCMDiTimingDetectsDelayOnConnectionError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.URL.Query().Get("host")
		if strings.Contains(strings.ToLower(val), "sleep") {
			time.Sleep(200 * time.Millisecond)
			hj, ok := w.(http.Hijacker)
			if !ok {
				// Hijacking not available: return 500 so retryablehttp retries
				// and total elapsed still exceeds the threshold.
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			conn, _, _ := hj.Hijack()
			conn.Close()
			return
		}
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
	if len(findings) == 0 {
		t.Error("expected CMDi finding even when connection closes after sleep delay")
	}
}

func TestCMDiPathParameterTiming(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.TrimRight(r.URL.Path, "/"), "/")
		raw := parts[len(parts)-1]
		decoded, _ := url.PathUnescape(raw)
		if strings.Contains(strings.ToLower(decoded), "sleep") {
			time.Sleep(100 * time.Millisecond)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ping ok"))
	}))
	defer srv.Close()

	template := srv.URL + "/api/ping/host/{host}"
	target := webTarget(srv)
	target.Inventory.Parameters = []*crawler.Parameter{
		{PageURL: template, Name: "host", Source: "swagger-path", InjectURL: template},
	}

	ck := &CMDiCheck{TimingThresholdMs: 50}
	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected CMDi finding for path-param timing-vulnerable server, got 0")
	}
	if findings[0].CheckID != "web.cmdi" {
		t.Errorf("unexpected check ID %q", findings[0].CheckID)
	}
	if findings[0].Parameter != "host" {
		t.Errorf("expected parameter=host, got %q", findings[0].Parameter)
	}
}

func TestCMDiSwaggerBodyTiming(t *testing.T) {
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
		val := body["host"]
		if strings.Contains(strings.ToLower(val), "sleep") {
			time.Sleep(100 * time.Millisecond)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ping ok"))
	}))
	defer srv.Close()

	endpointURL := srv.URL + "/api/json/ping"
	target := webTarget(srv)
	target.Inventory.Parameters = []*crawler.Parameter{
		{PageURL: endpointURL, Name: "host", Source: "swagger-body", InjectURL: endpointURL},
	}

	ck := &CMDiCheck{TimingThresholdMs: 50}
	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected CMDi finding for JSON-body timing-vulnerable server, got 0")
	}
	if findings[0].CheckID != "web.cmdi" {
		t.Errorf("unexpected check ID %q", findings[0].CheckID)
	}
	if findings[0].Parameter != "host" {
		t.Errorf("expected parameter=host, got %q", findings[0].Parameter)
	}
}
