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

// Package web implements OWASP-style web injection and security header checks.
// All checks source their inputs from the existing crawler inventory; no new
// crawling is performed. HTTP requests go through the scoped internal client.
package web

import (
	_ "embed"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	toml "github.com/pelletier/go-toml/v2"

	"github.com/osintph/suri/internal/crawler"
)

//go:embed payloads.toml
var payloadsRaw []byte

// rawPayload is the TOML wire format for a single catalogue entry.
type rawPayload struct {
	ID                 string `toml:"id"`
	Payload            string `toml:"payload"`
	Category           string `toml:"category"`
	ConfirmationMethod string `toml:"confirmation_method"`
	ExpectedSignal     string `toml:"expected_signal"`
	SleepSecs          int    `toml:"sleep_secs"`
}

type rawCatalogue struct {
	Payloads []rawPayload `toml:"payloads"`
}

// compiledPayload is a parsed and compiled payload entry.
type compiledPayload struct {
	rawPayload
	signal *regexp.Regexp // compiled expected_signal; nil if empty
}

// allPayloads is the catalogue parsed once at package init.
var allPayloads = mustLoadPayloads()

func mustLoadPayloads() []compiledPayload {
	var raw rawCatalogue
	if err := toml.Unmarshal(payloadsRaw, &raw); err != nil {
		panic(fmt.Sprintf("web: corrupted payloads.toml: %v", err))
	}
	result := make([]compiledPayload, 0, len(raw.Payloads))
	for _, p := range raw.Payloads {
		cp := compiledPayload{rawPayload: p}
		if p.ExpectedSignal != "" {
			re, err := regexp.Compile(p.ExpectedSignal)
			if err != nil {
				panic(fmt.Sprintf("web: invalid expected_signal pattern %q in payloads.toml: %v", p.ExpectedSignal, err))
			}
			cp.signal = re
		}
		result = append(result, cp)
	}
	return result
}

// filterPayloads returns payloads for the given category.
func filterPayloads(category string) []compiledPayload {
	var out []compiledPayload
	for _, p := range allPayloads {
		if p.Category == category {
			out = append(out, p)
		}
	}
	return out
}

// applyPlaceholders replaces {canary} and {sleep} in a payload string.
func applyPlaceholders(payload, canary string, sleepSecs int) string {
	s := strings.ReplaceAll(payload, "{canary}", canary)
	s = strings.ReplaceAll(s, "{sleep}", strconv.Itoa(sleepSecs))
	return s
}

// applySignalPlaceholders replaces {canary} in expected_signal strings.
func applySignalPlaceholders(signal, canary string) string {
	return strings.ReplaceAll(signal, "{canary}", canary)
}

// buildQueryProbeReq builds a GET request with the named query parameter set
// to payload. InjectURL must be the URL containing the parameter.
func buildQueryProbeReq(ctx context.Context, injectURL, paramName, payload string) (*http.Request, error) {
	u, err := url.Parse(injectURL)
	if err != nil {
		return nil, fmt.Errorf("parsing inject URL %q: %w", injectURL, err)
	}
	q := u.Query()
	q.Set(paramName, payload)
	u.RawQuery = q.Encode()
	return http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
}

// buildFormProbeReq builds a POST (or method from param) request with only the
// named field set to payload.
func buildFormProbeReq(ctx context.Context, param *crawler.Parameter, payload string) (*http.Request, error) {
	method := strings.ToUpper(param.Method)
	if method == "" {
		method = http.MethodPost
	}
	if method == http.MethodGet {
		// GET form: inject via query parameter
		return buildQueryProbeReq(ctx, param.InjectURL, param.Name, payload)
	}
	// POST form: send as URL-encoded body
	vals := url.Values{param.Name: {payload}}
	body := bytes.NewReader([]byte(vals.Encode()))
	req, err := http.NewRequestWithContext(ctx, method, param.InjectURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req, nil
}

// buildProbeReq builds the appropriate request for a parameter, injecting payload.
func buildProbeReq(ctx context.Context, param *crawler.Parameter, payload string) (*http.Request, error) {
	switch param.Source {
	case "query":
		return buildQueryProbeReq(ctx, param.InjectURL, param.Name, payload)
	case "form":
		return buildFormProbeReq(ctx, param, payload)
	default:
		return nil, fmt.Errorf("unsupported parameter source %q", param.Source)
	}
}

// readBody reads up to limit bytes from r. Ignores read errors (partial reads
// are still useful for pattern matching).
func readBody(r io.Reader, limit int64) []byte {
	b, _ := io.ReadAll(io.LimitReader(r, limit))
	return b
}

// excerpt returns up to n bytes from b.
func excerpt(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[:n]
}
