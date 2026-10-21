package api

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

// static embeds the web UI's built assets — normally web/dist, copied into
// this directory by the Dockerfile's web-build stage before `go build` runs
// (see Dockerfile). What's checked into the repo at internal/api/static/ is
// just a placeholder index.html so `go build`/`go run` still work without
// Docker (go:embed requires the directory to exist at compile time); a local
// build with only the placeholder still serves correctly, it just doesn't
// have a real UI in it. This is what makes the end product a single
// container (hub binary + Postgres) rather than hub + a separate UI
// container — the consolidation decision recorded in
// DESIGN.md §4.1.1.
//
//go:embed static
var staticFS embed.FS

// handleStatic serves the embedded web UI, with SPA fallback: any GET that
// doesn't match a real embedded file (e.g. a client-side route like
// /clusters, which react-router handles, not this server) gets index.html
// instead of a 404 — the same pattern every SPA host uses. Registered as the
// catch-all "GET /" route in routes(), so it only ever runs for requests that
// didn't match a more specific pattern (every /api/... route, /healthz,
// /readyz all take precedence — net/http's ServeMux matches the most
// specific pattern regardless of registration order).
func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		http.Error(w, "static assets unavailable", http.StatusInternalServerError)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" {
		path = "index.html"
	}

	setCacheHeaders(w, path)

	if f, err := sub.Open(path); err == nil {
		f.Close()
		http.FileServerFS(sub).ServeHTTP(w, r)
		return
	}

	index, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(index) //nolint:errcheck
}

// setCacheHeaders splits the embedded assets into the two classes they actually
// are, because serving them all with no header at all made content hashing
// pointless.
//
// Vite emits every JS/CSS chunk into assets/ with a content hash in its name
// (index-B2s9qMWc.css), so a changed file is a changed URL and the old one is
// never asked for again — those are safe to cache forever. index.html is the
// opposite: its name never changes and it is the only thing that says which
// hashed assets to fetch.
//
// With no Cache-Control on either, a browser applies its own heuristic freshness
// to index.html and keeps requesting the PREVIOUS build's asset names. Observed
// exactly that on 2026-08-25: the hub was serving a rebuilt UI, verified by
// fetching the assets directly, while the browser kept rendering the old one and
// the change looked like it had not deployed. Hard-refreshing worked, which is
// the tell.
//
// "no-cache" is not "no-store": the browser may keep the file, it just has to
// revalidate before using it, and FileServerFS answers with a 304 off the
// ETag/Last-Modified it already sets. So this costs one conditional request per
// page load, not a re-download.
func setCacheHeaders(w http.ResponseWriter, path string) {
	if strings.HasPrefix(path, "assets/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		return
	}
	// index.html and the handful of unhashed files beside it (favicon.svg), plus
	// every SPA-fallback route, which is served index.html's bytes.
	w.Header().Set("Cache-Control", "no-cache")
}
