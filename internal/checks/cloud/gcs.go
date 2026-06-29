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
	"log/slog"
	"net/http"
	"strings"

	"github.com/osintph/suri/internal/checks"
)

// GCSCheck probes Google Cloud Storage buckets (or GCS-compatible endpoints)
// for anonymous list access. When Endpoint is empty, the standard GCS endpoint
// is used. When Endpoint is set, path-style addressing against the custom
// endpoint is used.
type GCSCheck struct {
	Endpoint string
}

func (c *GCSCheck) ID() string                { return "cloud.gcs.public-bucket" }
func (c *GCSCheck) Name() string              { return "GCS Bucket Public List" }
func (c *GCSCheck) Severity() checks.Severity { return checks.SeverityHigh }
func (c *GCSCheck) Category() checks.Category { return checks.CategoryCloud }

// Run probes candidate GCS buckets. Passive extraction uses gcs artifacts
// from the crawl inventory; active permutation derives bucket names from the
// engagement domain.
func (c *GCSCheck) Run(ctx context.Context, target *checks.Target) ([]*checks.Finding, error) {
	if c.Endpoint != "" {
		if !target.Scope.HasCustomEndpointAuthorisation(c.Endpoint) {
			slog.Info("cloud.gcs: custom endpoint not authorised in scope, skipping",
				"endpoint", c.Endpoint,
				"hint", "add the endpoint host to cloud_buckets in scope file")
			return nil, nil
		}
	} else {
		if !target.Scope.HasGCSAuthorisation() {
			slog.Info("cloud.gcs: gcs probing not authorised in scope, skipping",
				"hint", "add storage.googleapis.com or *.googleapis.com to cloud_buckets in scope file")
			return nil, nil
		}
	}

	var candidates []string

	// Passive: gcs artifacts from the crawler inventory.
	for _, a := range target.Inventory.JSArtifacts {
		if a.Type == "gcs" {
			bucket := gcsParseBucket(a.Value)
			if bucket != "" {
				candidates = append(candidates, c.listURL(bucket))
			}
		}
	}

	// Active: permutation from the engagement domain.
	if target.Domain != "" {
		stem := DomainStem(target.Domain)
		for _, name := range Names(stem) {
			candidates = append(candidates, c.listURL(name))
		}
	}

	return probeAll(ctx, target, candidates, detectGCSPublicBucket, c.ID())
}

// listURL builds the GCS bucket listing URL. Uses path-style against the
// custom endpoint when set; otherwise uses the standard GCS URL.
func (c *GCSCheck) listURL(bucket string) string {
	const suffix = "?prefix=&max-keys=10"
	if c.Endpoint != "" {
		return strings.TrimRight(c.Endpoint, "/") + "/" + bucket + suffix
	}
	return "https://storage.googleapis.com/" + bucket + suffix
}

// gcsParseBucket extracts the bucket name from a GCS URL such as
// https://storage.googleapis.com/my-bucket/object or gs://my-bucket/object.
func gcsParseBucket(rawURL string) string {
	// gs:// scheme: host is the bucket name.
	if strings.HasPrefix(rawURL, "gs://") {
		after := rawURL[5:]
		if slash := strings.Index(after, "/"); slash >= 0 {
			return after[:slash]
		}
		return after
	}
	// https://storage.googleapis.com/{bucket}/...
	const prefix = "https://storage.googleapis.com/"
	if strings.HasPrefix(rawURL, prefix) {
		path := rawURL[len(prefix):]
		if slash := strings.Index(path, "/"); slash >= 0 {
			return path[:slash]
		}
		return path
	}
	return ""
}

// detectGCSPublicBucket returns true when the response indicates a publicly
// listable GCS bucket. GCS uses the same XML format as the S3 XML API.
func detectGCSPublicBucket(status int, body []byte) bool {
	return status == http.StatusOK && strings.Contains(string(body), "<ListBucketResult")
}
