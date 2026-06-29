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

package cloud

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"

	"github.com/osintph/suri/internal/checks"
)

// s3EndpointNote is the Target.Notes key for overriding the S3 base URL in
// tests. When set, probe URLs are built as {value}/{bucket}?list-type=2
// instead of the real https://{bucket}.s3.amazonaws.com format.
const s3EndpointNote = "_s3_endpoint"

// S3Check probes AWS S3 buckets for anonymous list access.
type S3Check struct{}

func (c *S3Check) ID() string       { return "cloud.s3.public-list" }
func (c *S3Check) Name() string     { return "S3 Bucket Public List" }
func (c *S3Check) Severity() checks.Severity { return checks.SeverityHigh }
func (c *S3Check) Category() checks.Category { return checks.CategoryCloud }

// Run probes candidate S3 buckets. It combines passive extraction from JS
// artifacts already in the inventory with active permutation from the target
// domain. Returns nil, nil without probing if S3 probing is not authorised.
func (c *S3Check) Run(ctx context.Context, target *checks.Target) ([]*checks.Finding, error) {
	if !target.Scope.HasS3Authorisation() {
		slog.Info("cloud.s3: s3 probing not authorised in scope, skipping",
			"hint", "add *.s3.amazonaws.com or similar to cloud_buckets in scope file")
		return nil, nil
	}

	override := ""
	if target.Notes != nil {
		override = target.Notes[s3EndpointNote]
	}

	var candidates []string

	// Passive: JS artifacts of type "s3" extracted during crawl.
	for _, a := range target.Inventory.JSArtifacts {
		if a.Type == "s3" {
			candidates = append(candidates, s3ListURL(a.Value, override))
		}
	}

	// Active: permutation from the engagement domain.
	if target.Domain != "" {
		stem := DomainStem(target.Domain)
		for _, name := range Names(stem) {
			candidates = append(candidates, s3ListURL(s3BucketBase(name, override), override))
		}
	}

	return probeAll(ctx, target, candidates, detectS3PublicList, c.ID())
}

// s3BucketBase returns the base URL for an S3 bucket name, using the override
// endpoint when set (for tests) or the real global S3 endpoint.
func s3BucketBase(bucket, override string) string {
	if override != "" {
		return override + "/" + bucket
	}
	return "https://" + bucket + ".s3.amazonaws.com"
}

// s3ListURL converts a bucket base URL or artifact value to a ListObjectsV2
// URL. For test overrides, the endpoint already contains the path prefix.
func s3ListURL(base, override string) string {
	if override != "" && strings.HasPrefix(base, override) {
		return base + "?list-type=2"
	}
	// Real URL: strip any path from the artifact URL to get the bucket root.
	u := bucketRoot(base)
	return u + "?list-type=2"
}

// detectS3PublicList returns true when the response indicates a publicly
// listable S3 bucket (200 OK with ListBucketResult XML body).
func detectS3PublicList(status int, body []byte) bool {
	return status == http.StatusOK && strings.Contains(string(body), "<ListBucketResult")
}

// S3AcceleratedCheck probes the S3 Transfer Acceleration endpoint.
type S3AcceleratedCheck struct{}

func (c *S3AcceleratedCheck) ID() string       { return "cloud.s3.accelerated-public-list" }
func (c *S3AcceleratedCheck) Name() string     { return "S3 Accelerated Bucket Public List" }
func (c *S3AcceleratedCheck) Severity() checks.Severity { return checks.SeverityHigh }
func (c *S3AcceleratedCheck) Category() checks.Category { return checks.CategoryCloud }

func (c *S3AcceleratedCheck) Run(ctx context.Context, target *checks.Target) ([]*checks.Finding, error) {
	if !target.Scope.HasS3Authorisation() {
		return nil, nil
	}
	override := ""
	if target.Notes != nil {
		override = target.Notes[s3EndpointNote]
	}
	if override != "" {
		// Accelerated endpoint not meaningful in tests; skip.
		return nil, nil
	}
	var candidates []string
	if target.Domain != "" {
		stem := DomainStem(target.Domain)
		for _, name := range Names(stem) {
			candidates = append(candidates,
				"https://"+name+".s3-accelerate.amazonaws.com/?list-type=2")
		}
	}
	return probeAll(ctx, target, candidates, detectS3PublicList, c.ID())
}

// probeAll fires HTTP GET requests to each candidate URL concurrently and
// returns findings for any that match the detect predicate.
func probeAll(
	ctx context.Context,
	target *checks.Target,
	candidates []string,
	detect func(status int, body []byte) bool,
	checkID string,
) ([]*checks.Finding, error) {
	concurrency := target.Concurrency
	if concurrency <= 0 {
		concurrency = 10
	}

	var (
		findings []*checks.Finding
		mu       sync.Mutex
		wg       sync.WaitGroup
	)
	sem := make(chan struct{}, concurrency)

	for _, rawURL := range candidates {
		rawURL := rawURL
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			f, err := probeURL(ctx, target.HTTP, rawURL, detect, checkID)
			if err != nil {
				slog.Debug("cloud probe error", "url", rawURL, "err", err)
				return
			}
			if f != nil {
				mu.Lock()
				findings = append(findings, f)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return findings, nil
}

// probeURL performs a single GET request and returns a Finding if detect
// returns true, otherwise nil.
func probeURL(
	ctx context.Context,
	client interface {
		Do(context.Context, *http.Request) (*http.Response, error)
	},
	rawURL string,
	detect func(int, []byte) bool,
	checkID string,
) (*checks.Finding, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building request for %s: %w", rawURL, err)
	}

	reqBytes := []byte(req.Method + " " + req.URL.RequestURI() + " HTTP/1.1\r\nHost: " + req.URL.Host + "\r\n\r\n")

	start := time.Now()
	resp, err := client.Do(ctx, req)
	elapsed := time.Since(start)
	if err != nil {
		return nil, fmt.Errorf("probing %s: %w", rawURL, err)
	}
	defer resp.Body.Close()

	// Dump response (reads body into buffer and restores resp.Body).
	respBytes, _ := httputil.DumpResponse(resp, true)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body from %s: %w", rawURL, err)
	}

	if !detect(resp.StatusCode, body) {
		return nil, nil
	}

	return &checks.Finding{
		CheckID:     checkID,
		Severity:    checks.SeverityHigh,
		Title:       "Cloud storage bucket publicly accessible",
		Description: fmt.Sprintf("Anonymous GET to %s returned HTTP %d with a listing response.", rawURL, resp.StatusCode),
		URL:         rawURL,
		Confidence:  checks.ConfidenceConfirmed,
		CWE:         "CWE-284",
		OWASP:       "A01:2021",
		Evidence: &checks.Evidence{
			RequestBytes:   reqBytes,
			ResponseBytes:  respBytes,
			ResponseStatus: resp.StatusCode,
			ResponseTimeMs: elapsed.Milliseconds(),
		},
	}, nil
}

// bucketRoot strips any path from a URL, returning scheme + host + "/".
func bucketRoot(rawURL string) string {
	idx := strings.Index(rawURL, "://")
	if idx < 0 {
		// No scheme separator: strip any path component.
		if slash := strings.Index(rawURL, "/"); slash >= 0 {
			return rawURL[:slash] + "/"
		}
		return rawURL + "/"
	}
	scheme := rawURL[:idx]
	after := rawURL[idx+3:] // everything after "://"
	if slash := strings.Index(after, "/"); slash >= 0 {
		return scheme + "://" + after[:slash] + "/"
	}
	return rawURL + "/"
}
