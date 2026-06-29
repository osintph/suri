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

// Package crawler implements the web crawler and JavaScript miner.
package crawler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"

	internalhttp "github.com/osintph/suri/internal/http"
	"github.com/osintph/suri/internal/scope"
)

// Config controls crawl behavior.
type Config struct {
	MaxDepth    int
	MaxURLs     int
	Concurrency int
	RatePerHost float64 // requests per second per host
}

// DefaultConfig returns sensible defaults matching the scan command flags.
func DefaultConfig() Config {
	return Config{
		MaxDepth:    3,
		MaxURLs:     500,
		Concurrency: 10,
		RatePerHost: 10,
	}
}

// Crawler discovers URLs, forms, parameters, and JS artifacts from a seed set.
type Crawler struct {
	cfg    Config
	client *internalhttp.Client
	sc     *scope.Scope
	rl     *hostRateLimiter
}

// New constructs a Crawler.
func New(sc *scope.Scope, client *internalhttp.Client, cfg Config) *Crawler {
	return &Crawler{
		cfg:    cfg,
		client: client,
		sc:     sc,
		rl:     newHostRateLimiter(cfg.RatePerHost),
	}
}

type urlItem struct {
	url    string
	source string
	depth  int
}

// Crawl performs a crawl starting from seedURLs. Workers read from a shared
// queue; dispatch is goroutine-safe and never blocks the caller, so workers
// cannot deadlock on the semaphore pattern. Results are in the returned
// Inventory.
func (c *Crawler) Crawl(ctx context.Context, seedURLs []string) (*Inventory, error) {
	inv := &Inventory{}
	var mu sync.Mutex
	visited := make(map[string]bool)
	urlReg := make(map[string]*DiscoveredURL) // rawURL → pointer for post-fetch metadata

	// Queue capacity bounded by MaxURLs so goroutines spawned in dispatch
	// complete quickly (the queue always has space up to MaxURLs).
	queue := make(chan urlItem, c.cfg.MaxURLs+c.cfg.Concurrency+10)
	var wg sync.WaitGroup

	// dispatch records a URL in the inventory and hands it to the queue.
	// It spawns a tiny goroutine per URL so the caller is never blocked by a
	// full queue (preventing the semaphore-style deadlock in fan-out designs).
	// The wg count ensures wg.Wait() cannot return while these senders run.
	dispatch := func(rawURL, source string, depth int) {
		if depth > c.cfg.MaxDepth {
			return
		}
		mu.Lock()
		if len(inv.URLs) >= c.cfg.MaxURLs || visited[rawURL] {
			mu.Unlock()
			return
		}
		visited[rawURL] = true
		du := &DiscoveredURL{URL: rawURL, Source: source, Depth: depth}
		inv.URLs = append(inv.URLs, du)
		urlReg[rawURL] = du
		mu.Unlock()

		wg.Add(1)
		go func() { queue <- urlItem{url: rawURL, source: source, depth: depth} }()
	}

	// updateMeta is called by process after a successful fetch to record the
	// HTTP status and body hash on the DiscoveredURL created by dispatch.
	updateMeta := func(rawURL string, status int, bodyHash string) {
		mu.Lock()
		if du, ok := urlReg[rawURL]; ok {
			du.ResponseStatus = status
			du.BodyHash = bodyHash
		}
		mu.Unlock()
	}

	// addToInv records a URL in the inventory without enqueuing it for a fetch.
	// It is used for redirect targets that have already been fetched inline.
	// Concurrent-safe: holds mu for the duration.
	addToInv := func(rawURL, source string, depth int) {
		mu.Lock()
		defer mu.Unlock()
		if visited[rawURL] || len(inv.URLs) >= c.cfg.MaxURLs {
			return
		}
		visited[rawURL] = true
		du := &DiscoveredURL{URL: rawURL, Source: source, Depth: depth}
		inv.URLs = append(inv.URLs, du)
		urlReg[rawURL] = du
	}

	// Fixed worker pool: workers read from queue, call process, then wg.Done().
	// This avoids the deadlock that occurs when goroutines holding a semaphore
	// slot try to acquire another slot to dispatch children.
	var workerWg sync.WaitGroup
	for i := 0; i < c.cfg.Concurrency; i++ {
		workerWg.Add(1)
		go func() {
			defer workerWg.Done()
			for item := range queue {
				c.process(ctx, item.url, item.depth, inv, &mu, dispatch, updateMeta, addToInv)
				wg.Done()
			}
		}()
	}

	// Seed the crawl. Also probe robots.txt and sitemap.xml from each base.
	for _, raw := range seedURLs {
		dispatch(raw, "seed", 0)
		if base, err := url.Parse(raw); err == nil && base.Host != "" {
			root := base.Scheme + "://" + base.Host
			dispatch(root+"/robots.txt", "seed", 0)
			dispatch(root+"/sitemap.xml", "seed", 0)
		}
	}

	wg.Wait()
	close(queue)
	workerWg.Wait()

	return inv, ctx.Err()
}

// process fetches a single URL, updates the inventory, and dispatches new URLs.
func (c *Crawler) process(ctx context.Context, rawURL string, depth int, inv *Inventory, mu *sync.Mutex, dispatch func(string, string, int), updateMeta func(string, int, string), addToInv func(string, string, int)) {
	if ctx.Err() != nil {
		return
	}

	base, err := url.Parse(rawURL)
	if err != nil {
		return
	}

	if err := c.rl.wait(ctx, base.Hostname()); err != nil {
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		slog.Debug("bad request URL", "url", rawURL, "err", err)
		return
	}
	req.Header.Set("User-Agent", "Suri/0.1 (VAPT scanner; authorized)")

	resp, err := c.client.Do(ctx, req)
	if err != nil {
		slog.Debug("fetch error", "url", rawURL, "err", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	if err != nil {
		return
	}

	// Determine the effective URL and base after any redirects.
	// Go's HTTP client follows redirects transparently; resp.Request.URL is the
	// final URL the response came from.
	effectiveURL := rawURL
	effectiveBase := base
	if finalURLStr := resp.Request.URL.String(); finalURLStr != rawURL && c.inScope(finalURLStr) {
		// Add the redirect target to the inventory without re-queuing it. We
		// already have its response body so there is no need to fetch it again.
		addToInv(finalURLStr, "redirect-target", depth)
		updateMeta(finalURLStr, resp.StatusCode, computeBodyHash(body))
		effectiveURL = finalURLStr
		effectiveBase = resp.Request.URL
		// rawURL (the redirect source) keeps ResponseStatus == 0 because we
		// never received a direct response for it.
	} else {
		updateMeta(rawURL, resp.StatusCode, computeBodyHash(body))
	}

	ct := resp.Header.Get("Content-Type")
	path := effectiveBase.Path

	switch {
	case isHTML(ct):
		c.processHTML(effectiveURL, effectiveBase, depth, body, inv, mu, dispatch)
	case isJS(ct, path):
		arts := MineJS(effectiveURL, body)
		mu.Lock()
		inv.JSArtifacts = append(inv.JSArtifacts, arts...)
		mu.Unlock()
		for _, a := range arts {
			if abs := jsArtifactURL(effectiveBase, a); abs != "" && c.inScope(abs) {
				dispatch(abs, "js", depth+1)
			}
		}
	case isXML(ct, path):
		res, err := ParseSitemap(body)
		if err != nil {
			slog.Debug("sitemap parse error", "url", effectiveURL, "err", err)
			return
		}
		for _, u := range res.PageURLs {
			if abs := toAbsolute(effectiveBase, u); abs != "" && c.inScope(abs) {
				dispatch(abs, "sitemap", depth+1)
			}
		}
		for _, child := range res.ChildSitemaps {
			if abs := toAbsolute(effectiveBase, child); abs != "" && c.inScope(abs) {
				dispatch(abs, "sitemap", depth)
			}
		}
	case isRobots(path):
		res := ParseRobots(body)
		for _, p := range res.DisallowPaths {
			abs := effectiveBase.Scheme + "://" + effectiveBase.Host + p
			if c.inScope(abs) {
				dispatch(abs, "robots", depth+1)
			}
		}
		for _, sm := range res.SitemapURLs {
			if abs := toAbsolute(effectiveBase, sm); abs != "" && c.inScope(abs) {
				dispatch(abs, "robots", depth)
			}
		}
	}
}

// processHTML parses HTML, extracts links, forms, parameters, and script URLs.
func (c *Crawler) processHTML(pageURL string, base *url.URL, depth int, data []byte, inv *Inventory, mu *sync.Mutex, dispatch func(string, string, int)) {
	doc, err := html.Parse(strings.NewReader(string(data)))
	if err != nil {
		return
	}

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "a":
				if href := attr(n, "href"); href != "" {
					if abs := toAbsolute(base, href); abs != "" && c.inScope(abs) {
						dispatch(abs, "html", depth+1)
						extractQueryParams(pageURL, abs, inv, mu)
					}
				}
			case "link":
				// <link href> for stylesheets and other referenced resources.
				if href := attr(n, "href"); href != "" {
					if abs := toAbsolute(base, href); abs != "" && c.inScope(abs) {
						dispatch(abs, "html", depth+1)
					}
				}
			case "form":
				action := attr(n, "action")
				method := strings.ToUpper(attr(n, "method"))
				if method == "" {
					method = "GET"
				}
				absAction := toAbsolute(base, action)
				f := &Form{PageURL: pageURL, Action: absAction, Method: method}
				collectInputs(n, f, pageURL, inv, mu)
				mu.Lock()
				inv.Forms = append(inv.Forms, f)
				mu.Unlock()
			case "script":
				if src := attr(n, "src"); src != "" {
					if abs := toAbsolute(base, src); abs != "" && c.inScope(abs) {
						dispatch(abs, "html", depth+1)
					}
				} else {
					var sb strings.Builder
					for child := n.FirstChild; child != nil; child = child.NextSibling {
						if child.Type == html.TextNode {
							sb.WriteString(child.Data)
						}
					}
					if sb.Len() > 0 {
						arts := MineJS(pageURL, []byte(sb.String()))
						mu.Lock()
						inv.JSArtifacts = append(inv.JSArtifacts, arts...)
						mu.Unlock()
						for _, a := range arts {
							if abs := jsArtifactURL(base, a); abs != "" && c.inScope(abs) {
								dispatch(abs, "js", depth+1)
							}
						}
					}
				}
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)
}

func collectInputs(formNode *html.Node, f *Form, pageURL string, inv *Inventory, mu *sync.Mutex) {
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "input", "textarea", "select":
				if name := attr(n, "name"); name != "" {
					f.Fields = append(f.Fields, name)
					injectURL := f.Action
					if injectURL == "" {
						injectURL = pageURL
					}
					mu.Lock()
					inv.Parameters = append(inv.Parameters, &Parameter{
						PageURL:   pageURL,
						Name:      name,
						Source:    "form",
						InjectURL: injectURL,
						Method:    f.Method,
					})
					mu.Unlock()
				}
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(formNode)
}

func extractQueryParams(pageURL, targetURL string, inv *Inventory, mu *sync.Mutex) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return
	}
	for name := range u.Query() {
		mu.Lock()
		inv.Parameters = append(inv.Parameters, &Parameter{
			PageURL:   pageURL,
			Name:      name,
			Source:    "query",
			InjectURL: targetURL,
			Method:    "GET",
		})
		mu.Unlock()
	}
}

func (c *Crawler) inScope(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := u.Hostname()
	port := 80
	if ps := u.Port(); ps != "" {
		n := 0
		for _, ch := range ps {
			if ch < '0' || ch > '9' {
				return false
			}
			n = n*10 + int(ch-'0')
		}
		port = n
	} else if u.Scheme == "https" {
		port = 443
	}
	ok, _ := c.sc.Allows(host, port)
	return ok
}

func toAbsolute(base *url.URL, ref string) string {
	if ref == "" || strings.HasPrefix(ref, "#") {
		return ""
	}
	u, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	abs := base.ResolveReference(u)
	if abs.Scheme != "http" && abs.Scheme != "https" {
		return ""
	}
	abs.Fragment = ""
	return abs.String()
}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

// jsArtifactURL resolves an artifact value to an absolute URL when the artifact
// type carries URL-like data. Returns empty string for non-URL types such as
// auth-header, role, and permission. The base URL is used to resolve absolute
// paths and protocol-relative values.
func jsArtifactURL(base *url.URL, a *JSArtifact) string {
	switch a.Type {
	case "api-path", "url-proto-relative":
		return toAbsolute(base, a.Value)
	case "url-full", "s3", "azure-blob", "gcs":
		if strings.HasPrefix(a.Value, "http://") || strings.HasPrefix(a.Value, "https://") {
			return a.Value
		}
		return ""
	default:
		return ""
	}
}

func isHTML(ct string) bool { return strings.Contains(ct, "text/html") }
func isJS(ct, path string) bool {
	return strings.Contains(ct, "javascript") ||
		strings.HasSuffix(path, ".js") ||
		strings.HasSuffix(path, ".mjs")
}
func isXML(ct, path string) bool {
	return strings.Contains(ct, "xml") ||
		strings.HasSuffix(path, ".xml")
}
func isRobots(path string) bool { return path == "/robots.txt" }

// computeBodyHash returns the hex-encoded SHA-256 of the first 32 KB of body.
func computeBodyHash(body []byte) string {
	const limit = 32 * 1024
	if len(body) > limit {
		body = body[:limit]
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

type hostRateLimiter struct {
	mu       sync.Mutex
	lastReq  map[string]time.Time
	interval time.Duration
}

func newHostRateLimiter(ratePerSecond float64) *hostRateLimiter {
	interval := time.Duration(float64(time.Second) / ratePerSecond)
	return &hostRateLimiter{
		lastReq:  make(map[string]time.Time),
		interval: interval,
	}
}

func (h *hostRateLimiter) wait(ctx context.Context, host string) error {
	h.mu.Lock()
	last, ok := h.lastReq[host]
	h.mu.Unlock()
	if ok {
		if remaining := h.interval - time.Since(last); remaining > 0 {
			select {
			case <-time.After(remaining):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	h.mu.Lock()
	h.lastReq[host] = time.Now()
	h.mu.Unlock()
	return nil
}
