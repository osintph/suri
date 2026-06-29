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

package crawler

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	internalhttp "github.com/osintph/suri/internal/http"
	"github.com/osintph/suri/internal/scope"
)

// newTestServer builds an httptest.Server that serves the testdata corpus.
// The sitemap.xml and robots.txt have a BASEURL placeholder replaced with
// the server's actual URL so links resolve correctly.
func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var file, ct string
		switch r.URL.Path {
		case "/", "/index.html":
			file, ct = "testdata/crawler/index.html", "text/html; charset=utf-8"
		case "/about":
			file, ct = "testdata/crawler/about.html", "text/html; charset=utf-8"
		case "/app.js":
			file, ct = "testdata/crawler/app.js", "application/javascript"
		case "/sitemap.xml":
			file, ct = "testdata/crawler/sitemap.xml", "text/xml"
		case "/robots.txt":
			file, ct = "testdata/crawler/robots.txt", "text/plain"
		default:
			http.NotFound(w, r)
			return
		}
		data, err := os.ReadFile(file)
		if err != nil {
			http.Error(w, "fixture not found", 500)
			return
		}
		// Replace placeholder so sitemap/robots URLs point at the test server.
		data = []byte(strings.ReplaceAll(string(data), "BASEURL", srv.URL))
		w.Header().Set("Content-Type", ct)
		w.Write(data)
	}))
	return srv
}

// localhostScope builds a Scope permitting any address in 127.0.0.0/8.
func localhostScope() *scope.Scope {
	_, cidr, _ := net.ParseCIDR("127.0.0.0/8")
	return &scope.Scope{CIDRs: []*net.IPNet{cidr}}
}

func TestCrawlDiscoversURLs(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	sc := localhostScope()
	client := internalhttp.New(sc)

	cfg := Config{MaxDepth: 2, MaxURLs: 50, Concurrency: 2, RatePerHost: 100}
	cr := New(sc, client, cfg)

	inv, err := cr.Crawl(context.Background(), []string{srv.URL + "/"})
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}

	if len(inv.URLs) < 2 {
		t.Errorf("URLs: want at least 2, got %d", len(inv.URLs))
	}
}

func TestCrawlDiscoversFormsAndParameters(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	sc := localhostScope()
	client := internalhttp.New(sc)

	cfg := Config{MaxDepth: 1, MaxURLs: 20, Concurrency: 2, RatePerHost: 100}
	cr := New(sc, client, cfg)

	inv, err := cr.Crawl(context.Background(), []string{srv.URL + "/"})
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}

	if len(inv.Forms) == 0 {
		t.Error("Forms: expected at least 1 form from index.html")
	}

	// index.html has a login form with username + password and a search form with q + page.
	fieldNames := make(map[string]bool)
	for _, f := range inv.Forms {
		for _, field := range f.Fields {
			fieldNames[field] = true
		}
	}
	for _, want := range []string{"username", "password", "q"} {
		if !fieldNames[want] {
			t.Errorf("expected form field %q to be discovered", want)
		}
	}

	// /contact?ref=home should yield a query parameter named "ref".
	paramNames := make(map[string]bool)
	for _, p := range inv.Parameters {
		paramNames[p.Name] = true
	}
	if !paramNames["ref"] {
		t.Errorf("expected query parameter %q from /contact?ref=home", "ref")
	}
}

func TestCrawlDiscoversJSArtifacts(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	sc := localhostScope()
	client := internalhttp.New(sc)

	cfg := Config{MaxDepth: 2, MaxURLs: 50, Concurrency: 2, RatePerHost: 100}
	cr := New(sc, client, cfg)

	inv, err := cr.Crawl(context.Background(), []string{srv.URL + "/"})
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}

	if len(inv.JSArtifacts) == 0 {
		t.Error("JSArtifacts: expected at least 1 artifact from app.js")
	}

	typesSeen := make(map[string]bool)
	for _, a := range inv.JSArtifacts {
		typesSeen[a.Type] = true
	}
	for _, want := range []string{"api-path", "s3", "azure-blob", "gcs"} {
		if !typesSeen[want] {
			t.Errorf("expected JS artifact of type %q", want)
		}
	}
}

func TestCrawlRespectsMaxURLs(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	sc := localhostScope()
	client := internalhttp.New(sc)

	cfg := Config{MaxDepth: 5, MaxURLs: 2, Concurrency: 1, RatePerHost: 100}
	cr := New(sc, client, cfg)

	inv, err := cr.Crawl(context.Background(), []string{srv.URL + "/"})
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	if len(inv.URLs) > cfg.MaxURLs {
		t.Errorf("MaxURLs violated: got %d URLs, limit is %d", len(inv.URLs), cfg.MaxURLs)
	}
}

// TestCrawlerRedirectInventoriesBothURLs verifies that when a 302 redirect is
// followed, both the original URL and the redirect target appear in the inventory.
func TestCrawlerRedirectInventoriesBothURLs(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, srv.URL+"/login.php", http.StatusFound)
		case "/login.php":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<!DOCTYPE html><html><body><h1>Login</h1></body></html>`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	sc := localhostScope()
	client := internalhttp.New(sc)
	cfg := Config{MaxDepth: 2, MaxURLs: 50, Concurrency: 2, RatePerHost: 100}
	cr := New(sc, client, cfg)

	inv, err := cr.Crawl(context.Background(), []string{srv.URL + "/"})
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}

	urlSet := make(map[string]bool)
	for _, u := range inv.URLs {
		urlSet[u.URL] = true
	}

	if !urlSet[srv.URL+"/"] {
		t.Errorf("seed URL %s not in inventory", srv.URL+"/")
	}
	if !urlSet[srv.URL+"/login.php"] {
		t.Errorf("redirect target %s/login.php not in inventory", srv.URL)
	}
}

// TestCrawlerRedirectExtractsLinksFromTarget verifies that when a redirect is
// followed, links in the redirect target's body are extracted and crawled.
func TestCrawlerRedirectExtractsLinksFromTarget(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, srv.URL+"/login.php", http.StatusFound)
		case "/login.php":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<!DOCTYPE html><html><body>
<a href="/setup.php">Setup</a>
</body></html>`))
		case "/setup.php":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<!DOCTYPE html><html><body>Setup page</body></html>`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	sc := localhostScope()
	client := internalhttp.New(sc)
	cfg := Config{MaxDepth: 3, MaxURLs: 50, Concurrency: 2, RatePerHost: 100}
	cr := New(sc, client, cfg)

	inv, err := cr.Crawl(context.Background(), []string{srv.URL + "/"})
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}

	urlSet := make(map[string]bool)
	for _, u := range inv.URLs {
		urlSet[u.URL] = true
	}

	if !urlSet[srv.URL+"/setup.php"] {
		t.Errorf("link /setup.php from redirect target was not discovered; inventory: %v", urlSet)
	}
}

func TestCrawlOutOfScopeLinksIgnored(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	sc := localhostScope()
	client := internalhttp.New(sc)

	cfg := Config{MaxDepth: 2, MaxURLs: 50, Concurrency: 2, RatePerHost: 100}
	cr := New(sc, client, cfg)

	inv, err := cr.Crawl(context.Background(), []string{srv.URL + "/"})
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}

	for _, u := range inv.URLs {
		if strings.Contains(u.URL, "external.invalid") {
			t.Errorf("out-of-scope URL was added to inventory: %s", u.URL)
		}
	}
}

// TestCrawlerRedirectExtractsLinks verifies that <a href> and <link href>
// elements in a redirect-target body are extracted and added to the inventory.
func TestCrawlerRedirectExtractsLinks(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, srv.URL+"/landing", http.StatusFound)
		case "/landing":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<!DOCTYPE html><html><head>
<link rel="stylesheet" href="/style.css">
</head><body>
<a href="/about">About</a>
</body></html>`))
		case "/about", "/style.css":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ok"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	sc := localhostScope()
	client := internalhttp.New(sc)
	cfg := Config{MaxDepth: 2, MaxURLs: 50, Concurrency: 2, RatePerHost: 100}
	cr := New(sc, client, cfg)

	inv, err := cr.Crawl(context.Background(), []string{srv.URL + "/"})
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}

	urlSet := make(map[string]bool)
	for _, u := range inv.URLs {
		urlSet[u.URL] = true
	}

	if !urlSet[srv.URL+"/about"] {
		t.Errorf("<a href='/about'> from redirect target not in inventory; got %v", urlSet)
	}
	if !urlSet[srv.URL+"/style.css"] {
		t.Errorf("<link href='/style.css'> from redirect target not in inventory; got %v", urlSet)
	}
}

// TestCrawlerRedirectMinesJS verifies that a <script src> referenced from a
// redirect-target body is fetched and its JS artifacts mined.
func TestCrawlerRedirectMinesJS(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, srv.URL+"/landing", http.StatusFound)
		case "/landing":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<!DOCTYPE html><html><body>
<script src="/static/main.js"></script>
</body></html>`))
		case "/static/main.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`var apiBase = "/api/users";`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	sc := localhostScope()
	client := internalhttp.New(sc)
	cfg := Config{MaxDepth: 3, MaxURLs: 50, Concurrency: 2, RatePerHost: 100}
	cr := New(sc, client, cfg)

	inv, err := cr.Crawl(context.Background(), []string{srv.URL + "/"})
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}

	// The script file itself must appear in the inventory.
	urlSet := make(map[string]bool)
	for _, u := range inv.URLs {
		urlSet[u.URL] = true
	}
	if !urlSet[srv.URL+"/static/main.js"] {
		t.Errorf("<script src='/static/main.js'> from redirect target not in inventory; got %v", urlSet)
	}

	// The JS artifact /api/users must be mined from main.js.
	found := false
	for _, a := range inv.JSArtifacts {
		if a.Value == "/api/users" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("JS artifact /api/users not mined from /static/main.js; artifacts: %v", inv.JSArtifacts)
	}
}

// TestCrawlerRedirectRelativeURLResolution verifies that relative hrefs in a
// redirect-target body resolve against the target URL, not the seed URL.
// The redirect target is at /section/page so that a relative href "about"
// (no leading slash) resolves differently against /section/page than against /.
func TestCrawlerRedirectRelativeURLResolution(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, srv.URL+"/section/page", http.StatusFound)
		case "/section/page":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<!DOCTYPE html><html><body>
<a href="./about">About</a>
</body></html>`))
		case "/section/about":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("about page"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	sc := localhostScope()
	client := internalhttp.New(sc)
	cfg := Config{MaxDepth: 3, MaxURLs: 50, Concurrency: 2, RatePerHost: 100}
	cr := New(sc, client, cfg)

	inv, err := cr.Crawl(context.Background(), []string{srv.URL + "/"})
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}

	urlSet := make(map[string]bool)
	for _, u := range inv.URLs {
		urlSet[u.URL] = true
	}

	// ./about relative to /section/page must resolve to /section/about.
	if !urlSet[srv.URL+"/section/about"] {
		t.Errorf("./about did not resolve to /section/about against redirect-target base; inventory: %v", urlSet)
	}
	// Must NOT resolve to /about (which would happen if seed URL / was used as base).
	if urlSet[srv.URL+"/about"] {
		t.Errorf("./about incorrectly resolved to /about (seed URL used as base instead of redirect target)")
	}
}

// TestCrawlerRedirectFormPageURLAlreadyWorks is a regression test confirming
// that form extraction on redirect-target bodies sets the correct page_url.
func TestCrawlerRedirectFormPageURLAlreadyWorks(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, srv.URL+"/landing", http.StatusFound)
		case "/landing":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<!DOCTYPE html><html><body>
<form action="/submit" method="post">
  <input name="username" type="text">
</form>
</body></html>`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	sc := localhostScope()
	client := internalhttp.New(sc)
	cfg := Config{MaxDepth: 2, MaxURLs: 50, Concurrency: 2, RatePerHost: 100}
	cr := New(sc, client, cfg)

	inv, err := cr.Crawl(context.Background(), []string{srv.URL + "/"})
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}

	if len(inv.Forms) == 0 {
		t.Fatal("expected at least one form from redirect-target body, got none")
	}

	// The form's PageURL must be the redirect target, not the seed URL.
	f := inv.Forms[0]
	if f.PageURL != srv.URL+"/landing" {
		t.Errorf("form PageURL: want %s/landing, got %q", srv.URL, f.PageURL)
	}
	if f.Action != srv.URL+"/submit" {
		t.Errorf("form Action: want %s/submit, got %q", srv.URL, f.Action)
	}
}
