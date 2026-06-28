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

// Package http provides an HTTP client that enforces engagement scope on every
// request. All scan modules must use this client; direct use of net/http is
// prohibited outside this package.
package http

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"

	retryablehttp "github.com/projectdiscovery/retryablehttp-go"

	"github.com/osintph/suri/internal/scope"
)

// ErrOutOfScope is returned when a request targets a host not permitted by the
// engagement scope. The network call is never made.
type ErrOutOfScope struct {
	Host   string
	Port   int
	Reason string
}

func (e *ErrOutOfScope) Error() string {
	return fmt.Sprintf("request blocked (out of scope): %s port %d: %s", e.Host, e.Port, e.Reason)
}

// Option configures the Client at construction time.
type Option func(*retryablehttp.Options)

// WithTimeout overrides the per-request timeout.
func WithTimeout(d time.Duration) Option {
	return func(o *retryablehttp.Options) {
		o.Timeout = d
	}
}

// WithRetryMax overrides the maximum number of retries.
func WithRetryMax(n int) Option {
	return func(o *retryablehttp.Options) {
		o.RetryMax = n
	}
}

// Client wraps retryablehttp.Client and enforces scope on every request.
type Client struct {
	inner *retryablehttp.Client
	sc    *scope.Scope
}

// New constructs a Client. The scope is checked before every network call.
// Defaults: 10 s timeout, 3 retries with exponential back-off, up to 10
// redirects with scope re-check on each target.
func New(sc *scope.Scope, opts ...Option) *Client {
	c := &Client{sc: sc}

	options := retryablehttp.Options{
		RetryWaitMin:    500 * time.Millisecond,
		RetryWaitMax:    10 * time.Second,
		Timeout:         10 * time.Second,
		RetryMax:        3,
		NoAdjustTimeout: true,
	}
	for _, o := range opts {
		o(&options)
	}

	// Provide a custom http.Client so we can intercept redirects for scope
	// re-checking.
	underlying := &http.Client{
		Timeout:       options.Timeout,
		CheckRedirect: c.checkRedirect,
	}
	options.HttpClient = underlying

	c.inner = retryablehttp.NewClient(options)
	return c
}

// Do performs the request after verifying that the target is in scope.
// If the host is a hostname (not an IP literal) and the scope contains CIDRs,
// the resolved IP is also checked to prevent DNS rebinding attacks.
func (c *Client) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	host, port, err := hostPort(req)
	if err != nil {
		return nil, fmt.Errorf("extracting host/port from request: %w", err)
	}

	if ok, reason := c.sc.Allows(host, port); !ok {
		slog.Warn("out of scope request blocked", "host", host, "port", port, "reason", reason)
		return nil, &ErrOutOfScope{Host: host, Port: port, Reason: reason}
	}

	// DNS rebinding prevention: if the scope has CIDRs, resolve the hostname
	// and verify every returned IP falls within them.
	if net.ParseIP(host) == nil && len(c.sc.CIDRs) > 0 {
		if err := c.verifyResolvedIPs(ctx, host, port); err != nil {
			return nil, err
		}
	}

	rreq, err := retryablehttp.FromRequest(req)
	if err != nil {
		return nil, fmt.Errorf("building retryable request: %w", err)
	}
	*rreq.Request = *req.WithContext(ctx)

	return c.inner.Do(rreq)
}

// checkRedirect is the http.Client.CheckRedirect hook. It re-checks scope on
// every redirect target and enforces a 10-redirect limit.
func (c *Client) checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return fmt.Errorf("too many redirects (limit 10)")
	}
	host, port, err := hostPort(req)
	if err != nil {
		return fmt.Errorf("redirect target: %w", err)
	}
	if ok, reason := c.sc.Allows(host, port); !ok {
		slog.Warn("redirect to out-of-scope target blocked", "host", host, "port", port, "reason", reason)
		return &ErrOutOfScope{Host: host, Port: port, Reason: reason}
	}
	return nil
}

// verifyResolvedIPs resolves host and checks every returned IP against scope
// CIDRs. Returns ErrOutOfScope if any resolved IP is outside all CIDRs.
func (c *Client) verifyResolvedIPs(ctx context.Context, host string, port int) error {
	resolver := net.DefaultResolver
	addrs, err := resolver.LookupHost(ctx, host)
	if err != nil {
		return fmt.Errorf("DNS lookup for %s: %w", host, err)
	}
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		inCIDR := false
		for _, cidr := range c.sc.CIDRs {
			if cidr.Contains(ip) {
				inCIDR = true
				break
			}
		}
		if !inCIDR {
			reason := fmt.Sprintf("resolved IP %s for host %s not in scope CIDRs", addr, host)
			slog.Warn("DNS rebinding prevention triggered", "host", host, "resolved_ip", addr)
			return &ErrOutOfScope{Host: host, Port: port, Reason: reason}
		}
	}
	return nil
}

// hostPort extracts the normalized hostname and port from a request URL.
// Defaults to port 80 for http and 443 for https if no explicit port is given.
func hostPort(req *http.Request) (string, int, error) {
	u := req.URL
	rawHost := u.Host
	if rawHost == "" {
		rawHost = req.Host
	}

	host, portStr, err := net.SplitHostPort(rawHost)
	if err != nil {
		// No port in the host field; derive from scheme.
		host = rawHost
		portStr = defaultPort(u.Scheme)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port %q: %w", portStr, err)
	}
	return host, port, nil
}

func defaultPort(scheme string) string {
	if scheme == "https" {
		return "443"
	}
	return "80"
}
