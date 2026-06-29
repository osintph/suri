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

// S3Check probes AWS S3 buckets (or S3-compatible endpoints such as Minio)
// for anonymous list access. When Endpoint is empty, virtual-hosted-style AWS
// URLs are used. When Endpoint is set, path-style URLs against the custom
// endpoint are used and PathStyle must be true.
type S3Check struct {
	Endpoint  string
	PathStyle bool
}

func (c *S3Check) ID() string                { return "cloud.s3.public-list" }
func (c *S3Check) Name() string              { return "S3 Bucket Public List" }
func (c *S3Check) Severity() checks.Severity { return checks.SeverityHigh }
func (c *S3Check) Category() checks.Category { return checks.CategoryCloud }

// Run probes candidate S3 buckets. It combines passive extraction from JS
// artifacts already in the inventory with active permutation from the target
// domain. Returns nil, nil without probing if the endpoint is not authorised.
func (c *S3Check) Run(ctx context.Context, target *checks.Target) ([]*checks.Finding, error) {
	if c.Endpoint != "" {
		if !target.Scope.HasCustomEndpointAuthorisation(c.Endpoint) {
			slog.Info("cloud.s3: custom endpoint not authorised in scope, skipping",
				"endpoint", c.Endpoint,
				"hint", "add the endpoint host to cloud_buckets in scope file")
			return nil, nil
		}
	} else {
		if !target.Scope.HasS3Authorisation() {
			slog.Info("cloud.s3: s3 probing not authorised in scope, skipping",
				"hint", "add *.s3.amazonaws.com or similar to cloud_buckets in scope file")
			return nil, nil
		}
	}

	var candidates []string

	// Passive: JS artifacts of type "s3" extracted during crawl.
	for _, a := range target.Inventory.JSArtifacts {
		if a.Type == "s3" {
			if u := c.artifactListURL(a.Value); u != "" {
				candidates = append(candidates, u)
			}
		}
	}

	// Active: permutation from the engagement domain.
	if target.Domain != "" {
		stem := DomainStem(target.Domain)
		for _, name := range Names(stem) {
			candidates = append(candidates, c.bucketListURL(name))
		}
	}

	return probeAll(ctx, target, candidates, detectS3PublicList, c.ID())
}

// bucketListURL returns the S3 listing URL for a named bucket.
// Virtual-hosted style is used when PathStyle is false (AWS standard);
// path-style is used when PathStyle is true (custom endpoints such as Minio).
func (c *S3Check) bucketListURL(bucket string) string {
	if c.PathStyle {
		return strings.TrimRight(c.Endpoint, "/") + "/" + bucket + "/?list-type=2"
	}
	return "https://" + bucket + ".s3.amazonaws.com/?list-type=2"
}

// artifactListURL converts a passive S3 artifact value to a listing probe URL.
// Path-style: extracts the bucket from the first path segment of the artifact
// URL and builds against the configured endpoint.
// Virtual-hosted: strips the artifact path to get the bucket root.
func (c *S3Check) artifactListURL(artifactValue string) string {
	if c.PathStyle {
		bucket := s3BucketFromPath(artifactValue)
		if bucket == "" {
			return ""
		}
		return strings.TrimRight(c.Endpoint, "/") + "/" + bucket + "/?list-type=2"
	}
	root := bucketRoot(artifactValue)
	if root == "" {
		return ""
	}
	return root + "?list-type=2"
}

// s3BucketFromPath extracts the bucket name from a path-style URL, where the
// bucket is the first path segment after the host (e.g. http://host/bucket/key).
func s3BucketFromPath(rawURL string) string {
	idx := strings.Index(rawURL, "://")
	if idx < 0 {
		return ""
	}
	after := rawURL[idx+3:]
	slash1 := strings.Index(after, "/")
	if slash1 < 0 {
		return ""
	}
	rest := after[slash1+1:]
	if rest == "" {
		return ""
	}
	if slash2 := strings.Index(rest, "/"); slash2 >= 0 {
		return rest[:slash2]
	}
	return rest
}

// detectS3PublicList returns true when the response indicates a publicly
// listable S3 bucket (200 OK with ListBucketResult XML body).
func detectS3PublicList(status int, body []byte) bool {
	return status == http.StatusOK && strings.Contains(string(body), "<ListBucketResult")
}

// S3AcceleratedCheck probes the S3 Transfer Acceleration endpoint.
// This check is AWS-specific and does not support custom endpoints.
type S3AcceleratedCheck struct{}

func (c *S3AcceleratedCheck) ID() string                { return "cloud.s3.accelerated-public-list" }
func (c *S3AcceleratedCheck) Name() string              { return "S3 Accelerated Bucket Public List" }
func (c *S3AcceleratedCheck) Severity() checks.Severity { return checks.SeverityHigh }
func (c *S3AcceleratedCheck) Category() checks.Category { return checks.CategoryCloud }

func (c *S3AcceleratedCheck) Run(ctx context.Context, target *checks.Target) ([]*checks.Finding, error) {
	if !target.Scope.HasS3Authorisation() {
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
