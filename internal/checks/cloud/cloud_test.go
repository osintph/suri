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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/osintph/suri/internal/checks"
	"github.com/osintph/suri/internal/crawler"
	internalhttp "github.com/osintph/suri/internal/http"
	"github.com/osintph/suri/internal/scope"
)

// testScope builds a scope that authorises all three cloud providers plus
// 127.0.0.1 (for httptest servers). Provider patterns are required so that
// HasS3Authorisation / HasAzureAuthorisation / HasGCSAuthorisation return true.
func testScope() *scope.Scope {
	return &scope.Scope{
		CloudBuckets: []string{
			"*.s3.amazonaws.com",
			"*.blob.core.windows.net",
			"storage.googleapis.com",
			"127.0.0.1",
		},
		IPs: []string{"127.0.0.1"},
	}
}

func testTarget(sc *scope.Scope, srv *httptest.Server, notes map[string]string) *checks.Target {
	return &checks.Target{
		Inventory:   &crawler.Inventory{},
		Scope:       sc,
		HTTP:        internalhttp.New(sc),
		Domain:      "example.com",
		Concurrency: 4,
		Notes:       notes,
	}
}

// S3 tests

func TestS3CheckPublicList(t *testing.T) {
	const s3XML = `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-bucket</Name>
  <IsTruncated>false</IsTruncated>
</ListBucketResult>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(s3XML)) //nolint:errcheck
	}))
	defer srv.Close()

	sc := testScope()
	target := testTarget(sc, srv, nil)
	target.Domain = "example.com"

	findings, err := (&S3Check{Endpoint: srv.URL, PathStyle: true}).Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for publicly listable S3 bucket")
	}
	f := findings[0]
	if f.CheckID != "cloud.s3.public-list" {
		t.Errorf("CheckID: want cloud.s3.public-list, got %s", f.CheckID)
	}
	if f.Severity != checks.SeverityHigh {
		t.Errorf("Severity: want high, got %s", f.Severity)
	}
	if f.Evidence == nil {
		t.Error("Evidence must not be nil")
	} else if f.Evidence.ResponseStatus != http.StatusOK {
		t.Errorf("Evidence.ResponseStatus: want 200, got %d", f.Evidence.ResponseStatus)
	}
}

func TestS3CheckNotPublic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	sc := testScope()
	target := testTarget(sc, srv, nil)

	findings, err := (&S3Check{Endpoint: srv.URL, PathStyle: true}).Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for 403 response, got %d", len(findings))
	}
}

func TestS3CheckNotAuthorised(t *testing.T) {
	// Scope with no S3 authorisation: check must return nil without probing.
	sc := &scope.Scope{Hostnames: []string{"example.com"}}
	target := &checks.Target{
		Inventory:   &crawler.Inventory{},
		Scope:       sc,
		HTTP:        internalhttp.New(sc),
		Domain:      "example.com",
		Concurrency: 2,
	}

	findings, err := (&S3Check{}).Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings when S3 not authorised, got %d", len(findings))
	}
}

func TestS3CheckPassiveArtifact(t *testing.T) {
	const s3XML = `<ListBucketResult><Name>passive-bucket</Name></ListBucketResult>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(s3XML)) //nolint:errcheck
	}))
	defer srv.Close()

	sc := testScope()
	// Passive artifact: value points to the test server (simulates a real S3
	// artifact value that the crawler extracted from JS).
	inv := &crawler.Inventory{
		JSArtifacts: []*crawler.JSArtifact{
			{
				SourceURL: "http://127.0.0.1/app.js",
				Type:      "s3",
				Value:     srv.URL + "/my-passive-bucket/key",
			},
		},
	}
	target := &checks.Target{
		Inventory:   inv,
		Scope:       sc,
		HTTP:        internalhttp.New(sc),
		Concurrency: 2,
	}

	findings, err := (&S3Check{Endpoint: srv.URL, PathStyle: true}).Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding from passive S3 artifact probing")
	}
}

// TestS3BucketListURLs verifies that S3Check generates the correct URL style
// for both the default AWS mode and the custom endpoint path-style mode.
func TestS3BucketListURLs(t *testing.T) {
	// Default (no endpoint): virtual-hosted AWS style.
	c := &S3Check{}
	got := c.bucketListURL("my-app")
	want := "https://my-app.s3.amazonaws.com/?list-type=2"
	if got != want {
		t.Errorf("virtual-hosted URL: got %q, want %q", got, want)
	}

	// Custom endpoint: path-style.
	c2 := &S3Check{Endpoint: "http://localhost:9000", PathStyle: true}
	got2 := c2.bucketListURL("my-app")
	want2 := "http://localhost:9000/my-app/?list-type=2"
	if got2 != want2 {
		t.Errorf("path-style URL: got %q, want %q", got2, want2)
	}
}

// TestS3CheckCustomEndpointNotAuthorised verifies that when a custom endpoint
// host is not listed in cloud_buckets, the check skips without probing.
func TestS3CheckCustomEndpointNotAuthorised(t *testing.T) {
	// Scope authorises AWS S3 but not localhost.
	sc := &scope.Scope{
		CloudBuckets: []string{"*.s3.amazonaws.com"},
	}
	target := &checks.Target{
		Inventory:   &crawler.Inventory{},
		Scope:       sc,
		HTTP:        internalhttp.New(sc),
		Concurrency: 2,
	}
	check := &S3Check{Endpoint: "http://localhost:9000", PathStyle: true}
	findings, err := check.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when endpoint host not in cloud_buckets, got %d", len(findings))
	}
}

// Azure tests

func TestAzureCheckPublicContainer(t *testing.T) {
	const azureXML = `<?xml version="1.0" encoding="UTF-8"?>
<EnumerationResults ServiceEndpoint="https://account.blob.core.windows.net/" ContainerName="public">
  <Blobs></Blobs><NextMarker/>
</EnumerationResults>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(azureXML)) //nolint:errcheck
	}))
	defer srv.Close()

	sc := testScope()
	target := testTarget(sc, srv, nil)

	findings, err := (&AzureCheck{Endpoint: srv.URL}).Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for publicly listable Azure container")
	}
	if findings[0].CheckID != "cloud.azure.public-container" {
		t.Errorf("CheckID: want cloud.azure.public-container, got %s", findings[0].CheckID)
	}
}

func TestAzureCheckNotAuthorised(t *testing.T) {
	sc := &scope.Scope{Hostnames: []string{"example.com"}}
	target := &checks.Target{
		Inventory: &crawler.Inventory{},
		Scope:     sc,
		HTTP:      internalhttp.New(sc),
	}
	findings, err := (&AzureCheck{}).Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings when Azure not authorised, got %d", len(findings))
	}
}

// GCS tests

func TestGCSCheckPublicBucket(t *testing.T) {
	const gcsXML = `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://doc.s3.amazonaws.com/2006-03-01">
  <Name>my-gcs-bucket</Name>
  <IsTruncated>false</IsTruncated>
</ListBucketResult>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(gcsXML)) //nolint:errcheck
	}))
	defer srv.Close()

	sc := testScope()
	target := testTarget(sc, srv, nil)

	findings, err := (&GCSCheck{Endpoint: srv.URL}).Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for publicly listable GCS bucket")
	}
	if findings[0].CheckID != "cloud.gcs.public-bucket" {
		t.Errorf("CheckID: want cloud.gcs.public-bucket, got %s", findings[0].CheckID)
	}
}

func TestGCSCheckNotAuthorised(t *testing.T) {
	sc := &scope.Scope{Hostnames: []string{"example.com"}}
	target := &checks.Target{
		Inventory: &crawler.Inventory{},
		Scope:     sc,
		HTTP:      internalhttp.New(sc),
	}
	findings, err := (&GCSCheck{}).Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings when GCS not authorised, got %d", len(findings))
	}
}

// Permutation tests

func TestBucketNames(t *testing.T) {
	names := Names("acme")
	want := []string{
		"acme", "acme-prod", "acme-dev", "acme-backup",
		"acme-assets", "acme-static", "acme-data", "acme-uploads",
		"acme-tf-state", "acme-logs", "prod-acme", "dev-acme",
	}
	if len(names) != len(want) {
		t.Fatalf("Names count: want %d, got %d: %v", len(want), len(names), names)
	}
	for i, w := range want {
		if names[i] != w {
			t.Errorf("Names[%d]: want %q, got %q", i, w, names[i])
		}
	}
}

func TestDomainStem(t *testing.T) {
	cases := []struct {
		domain string
		want   string
	}{
		{"example.com", "example"},
		{"api.example.com", "example"},
		{"deep.sub.example.co.uk", "co"},
		{"localhost", "localhost"},
	}
	for _, tc := range cases {
		got := DomainStem(tc.domain)
		if got != tc.want {
			t.Errorf("DomainStem(%q) = %q, want %q", tc.domain, got, tc.want)
		}
	}
}

// Helper tests

func TestBucketRoot(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"https://bucket.s3.amazonaws.com/key/path", "https://bucket.s3.amazonaws.com/"},
		{"https://bucket.s3.amazonaws.com/", "https://bucket.s3.amazonaws.com/"},
		{"https://bucket.s3.amazonaws.com", "https://bucket.s3.amazonaws.com/"},
		{"http://127.0.0.1:1234/bucket/key", "http://127.0.0.1:1234/"},
	}
	for _, tc := range cases {
		got := bucketRoot(tc.in)
		if got != tc.want {
			t.Errorf("bucketRoot(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestAzureParseArtifact(t *testing.T) {
	cases := []struct {
		url      string
		wantAcct string
		wantCont string
	}{
		{
			"https://myaccount.blob.core.windows.net/mycontainer/blob",
			"myaccount", "mycontainer",
		},
		{
			"https://myaccount.blob.core.windows.net/mycontainer",
			"myaccount", "mycontainer",
		},
		{"https://no-path.blob.core.windows.net", "", ""},
		{"https://no-dot", "", ""},
	}
	for _, tc := range cases {
		acct, cont := azureParseArtifact(tc.url)
		if acct != tc.wantAcct || cont != tc.wantCont {
			t.Errorf("azureParseArtifact(%q) = (%q, %q), want (%q, %q)",
				tc.url, acct, cont, tc.wantAcct, tc.wantCont)
		}
	}
}

func TestGCSParseBucket(t *testing.T) {
	cases := []struct {
		url  string
		want string
	}{
		{"https://storage.googleapis.com/my-bucket/object", "my-bucket"},
		{"https://storage.googleapis.com/my-bucket", "my-bucket"},
		{"gs://my-bucket/object", "my-bucket"},
		{"gs://my-bucket", "my-bucket"},
		{"https://other.example.com/bucket", ""},
	}
	for _, tc := range cases {
		got := gcsParseBucket(tc.url)
		if got != tc.want {
			t.Errorf("gcsParseBucket(%q) = %q, want %q", tc.url, got, tc.want)
		}
	}
}

// TestPerProviderAuthorisationSkip verifies that when only S3 is authorised in
// the scope, Azure and GCS checks skip while S3 proceeds.
func TestPerProviderAuthorisationSkip(t *testing.T) {
	// Scope with only S3 patterns: Azure and GCS must skip.
	s3OnlyScope := &scope.Scope{
		CloudBuckets: []string{"*.s3.amazonaws.com", "127.0.0.1"},
		IPs:          []string{"127.0.0.1"},
	}

	emptyInv := &crawler.Inventory{}

	azTarget := &checks.Target{
		Inventory:   emptyInv,
		Scope:       s3OnlyScope,
		HTTP:        internalhttp.New(s3OnlyScope),
		Concurrency: 2,
	}
	azFindings, err := (&AzureCheck{}).Run(context.Background(), azTarget)
	if err != nil {
		t.Fatalf("AzureCheck.Run: %v", err)
	}
	if len(azFindings) != 0 {
		t.Errorf("AzureCheck: expected 0 findings when only S3 authorised, got %d", len(azFindings))
	}

	gcsTarget := &checks.Target{
		Inventory:   emptyInv,
		Scope:       s3OnlyScope,
		HTTP:        internalhttp.New(s3OnlyScope),
		Concurrency: 2,
	}
	gcsFindings, err := (&GCSCheck{}).Run(context.Background(), gcsTarget)
	if err != nil {
		t.Fatalf("GCSCheck.Run: %v", err)
	}
	if len(gcsFindings) != 0 {
		t.Errorf("GCSCheck: expected 0 findings when only S3 authorised, got %d", len(gcsFindings))
	}
}
