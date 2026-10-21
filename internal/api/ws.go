// This file implements the hub's live-update WebSocket surface:
// POST /api/v1/ws/ticket (mint a short-lived connect ticket) and
// GET /ws/events (the actual upgrade), per lld/11-ui-design.md §5's
// requirement that IncidentUpdated (and this codebase's sensible
// extension, ClusterUpdated — see internal/events' doc comment) events
// trigger an in-place frontend refetch instead of the polling-only
// approach every page used until now.
//
// AUTHENTICATION: every other route in this codebase authenticates via
// Authorization: Bearer <JWT> (requireAuth, middleware.go). A browser's
// WebSocket API has no way to attach a custom header to the upgrade
// request, so that convention cannot extend to GET /ws/events directly.
// The mechanism chosen here — mint a short-lived, single-use ticket via a
// normal authenticated REST call, then pass ONLY the ticket as a query
// parameter on the immediately-following upgrade request — is documented
// in full on internal/authz.WSTicketIssuer's doc comment, including why a
// long-lived credential in the URL was rejected (query strings end up in
// browser history and server access logs) and why this specific ticket
// shape is safe there regardless (single-use, ~seconds of lifetime).
//
// AUTHORIZATION: see wsEventScope below. Both halves of this surface are
// capability-gated — minting a ticket requires a read capability, and every
// event is filtered against the connecting subscriber's own capabilities
// before it is written to the socket.
package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"argus/internal/authz"
	"argus/internal/data"
	"argus/internal/events"
	"argus/internal/logging"
)

// wsTicketResponse is POST /api/v1/ws/ticket's response body.
type wsTicketResponse struct {
	Ticket    string `json:"ticket"`
	ExpiresAt string `json:"expiresAt"`
}

// wsEventScope is one subscriber's server-side event filter: which of
// internal/events' event kinds this subscriber's capabilities entitle them
// to receive.
//
// BUG FIX (2026-08-21): this whole type, and everything that consults it,
// is new. POST /api/v1/ws/ticket previously required no capability beyond
// being authenticated, and serveWSClient forwarded every event on the
// process-wide bus to every connected socket with no filtering at all — so
// a user with zero grants, who correctly gets 403 from GET /incidents and
// GET /clusters, nonetheless received a live feed of every incident id and
// cluster id in the fleet. This file's own comment claimed the ticket was
// "scoped to whatever your own effective permissions already let you see";
// nothing implemented that, and this is what makes the claim true.
//
// Scope, stated plainly rather than implied: this filters by event KIND
// against capabilities only. It is NOT per-cluster filtering — no route in
// this codebase resolves per-cluster grant scope (every grant the UI can
// create is AllClusters; see internal/api/middleware.go's requireAuth
// comment and internal/events' own doc comment), so there is no narrower
// scope to filter against yet. When cluster-scoped grants become real, this
// is the place that must additionally check the event's ClusterID against
// the subscriber's accessible clusters, and lld/10-api-spec.md §5's
// ScopeNarrowed event becomes meaningful at the same time.
type wsEventScope struct {
	incidents bool
	clusters  bool
}

// wsEventScopeFor derives the filter from a principal's effective grants.
// The capabilities chosen are the same ones that gate the REST reads these
// events point at: IncidentUpdated is a "refetch this incident" hint, so it
// requires incident:read exactly as GET /api/v1/incidents does, and
// ClusterUpdated requires cluster:read.
func wsEventScopeFor(grants []authz.EffectiveGrant) wsEventScope {
	return wsEventScope{
		incidents: authz.HasCapability(grants, authz.CapIncidentRead),
		clusters:  authz.HasCapability(grants, authz.CapClusterRead),
	}
}

// allowsAnything reports whether this scope permits any event kind at all —
// a principal for whom it doesn't has no business holding a connect ticket.
func (sc wsEventScope) allowsAnything() bool { return sc.incidents || sc.clusters }

// allows reports whether one event may be written to this subscriber's
// socket. Fails CLOSED on an unrecognized event type: a new event kind added
// to internal/events must be classified here deliberately, not leak to every
// subscriber by default — that default is exactly how this bug existed.
func (sc wsEventScope) allows(ev events.Event) bool {
	switch ev.Type {
	case events.TypeIncidentUpdated:
		return sc.incidents
	case events.TypeClusterUpdated:
		return sc.clusters
	case events.TypeFindingRecorded:
		// A "refetch the findings list" hint; GET /api/v1/findings is gated on
		// incident:read, so the same capability gates the hint.
		return sc.incidents
	default:
		return false
	}
}

// resolveWSEventScope re-resolves the connecting principal's effective
// permissions from the live grants table at upgrade time, rather than
// trusting anything carried in the ticket. Deliberately its own short,
// read-only transaction that is finished before the long-lived connection
// starts — requireAuth's request-scoped transaction shape doesn't apply to
// GET /ws/events (see handleWSEvents' comment), and holding a transaction
// open for the lifetime of a WebSocket would be indefensible regardless.
//
// Known limitation, stated rather than implied: this is resolved ONCE, at
// connect time. A grant revoked while a socket is open is not noticed until
// that socket reconnects. lld/10-api-spec.md §5's periodic scope
// revalidation sweep is the real answer and belongs with the same change
// that introduces cluster-scoped grants; every event here is a
// non-authoritative "go refetch X" hint whose refetch is itself fully
// authorized (internal/events' doc comment), so the exposure of the gap is
// an id, and only until the connection turns over.
func (s *Server) resolveWSEventScope(ctx context.Context, userID, tenantID string) (wsEventScope, error) {
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return wsEventScope{}, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // read-only; nothing to commit

	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		return wsEventScope{}, fmt.Errorf("set request scope: %w", err)
	}
	grants, err := authz.ResolveEffectivePermissions(ctx, tx, userID)
	if err != nil {
		return wsEventScope{}, fmt.Errorf("resolve effective permissions: %w", err)
	}
	return wsEventScopeFor(grants), nil
}

// handleCreateWSTicket is POST /api/v1/ws/ticket. requireAuth-gated like
// every other route and, since the bug fix described on wsEventScope,
// requireAnyCapability-gated on incident:read OR cluster:read (see routes()
// in server.go): this ticket grants no capability the caller didn't already
// have — it only carries their identity across the WebSocket upgrade — but
// the feed it opens carries incident/cluster ids, so "authenticated as
// yourself" was never a sufficient bar for it. Holding EITHER read
// capability entitles the caller to a connection; which events actually
// reach it is then decided per event, per subscriber (wsEventScope).
func (s *Server) handleCreateWSTicket(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	ticket, expiresAt, err := s.wsTickets.Issue(rc.UserID, rc.TenantID)
	if err != nil {
		logger.ErrorContext(r.Context(), "issuing a WebSocket ticket failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not issue connect ticket", "")
		return
	}
	writeJSON(w, http.StatusCreated, wsTicketResponse{
		Ticket:    ticket,
		ExpiresAt: formatRFC3339(expiresAt),
	})
}

// wsUpgrader configures the gorilla/websocket upgrade. CheckOrigin
// enforces the same same-origin expectation browsers already assume for
// this app (the web UI is served by this exact hub — static.go — with no
// cross-origin API usage anywhere else in this codebase, and no CORS
// headers are ever sent): a request with an Origin header that doesn't
// match the request's own Host is rejected, closing off cross-site
// WebSocket hijacking from a page on some other origin that got a user to
// visit it while an ARGUS tab (or ticket) was live. A request with NO
// Origin header (a non-browser client — argusctl, curl, a test) is
// allowed through; it has no cross-origin threat model to defend against
// in the first place, and the ticket requirement above is still the real
// authentication gate regardless of Origin.
var wsUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true
		}
		originHost := origin
		if i := strings.Index(origin, "://"); i != -1 {
			originHost = origin[i+3:]
		}
		return originHost == r.Host
	},
}

// wsWriteWait bounds how long a single WriteMessage/WriteJSON call is
// allowed to block on a stalled TCP peer before this connection is given
// up on and closed — the same "never let one slow reader hold anything
// open indefinitely" principle internal/events.Bus already applies at the
// fan-out layer; this is the analogous bound at the actual socket-write
// layer.
const wsWriteWait = 10 * time.Second

// wsPongWait/wsPingPeriod implement the server side of a standard
// WebSocket liveness check: if no pong (in response to this server's own
// pings, or any other client traffic) arrives within wsPongWait, the
// connection is presumed dead and closed, which frees this subscriber's
// slot on internal/events.Bus and lets the frontend's own reconnect-with-
// backoff logic (lld/11-ui-design.md §5) take over. wsPingPeriod is set
// well inside wsPongWait so a ping is always sent with room to spare for
// a pong to come back before the deadline would otherwise expire.
//
// wsPingPeriod is also what keeps the connection from ever looking idle to
// whatever sits between the browser and the hub, and that is the tighter
// bound. It used to be 54s (9/10 of wsPongWait); a real on-prem load balancer
// in front of ingress-nginx was measured dropping idle connections at ~50s
// (2026-09-29), and AWS ALB's default is 60s. 25s stays inside both with
// margin, for the cost of one control frame per connection per 25s.
const (
	wsPongWait   = 60 * time.Second
	wsPingPeriod = 25 * time.Second
)

// handleWSEvents is GET /ws/events?ticket=... — deliberately NOT
// registered under /api/v1 (matching this codebase's existing convention
// of keeping non-REST, non-JSON-body surfaces — the agent enrollment
// endpoints, the tunnel listener itself — visually distinct from the
// versioned REST API) and deliberately NOT wrapped with requireAuth: that
// middleware's Authorization-header convention and its per-request-
// transaction-commit-on-2xx shape both assume a normal, short-lived HTTP
// request/response, neither of which describes a long-lived WebSocket
// connection. Authentication here is the ticket minted by
// handleCreateWSTicket above; see this file's package-level comment for
// the full reasoning.
func (s *Server) handleWSEvents(w http.ResponseWriter, r *http.Request) {
	// PROJECT.md B162: refuse a NEW feed once this hub is draining, BEFORE
	// the ticket is redeemed. A connect ticket is single-use (see Redeem
	// below), so checking this later would burn the client's ticket on a hub
	// that is about to close the socket anyway, forcing it to mint another
	// one before it could reconnect — and its reconnect should land on
	// whichever hub replaces this one, not on this one's remaining seconds.
	if s.IsShuttingDown() {
		writeProblem(w, http.StatusServiceUnavailable, "https://argus.io/errors/shutting-down", "Shutting down", "")
		return
	}

	ticket := r.URL.Query().Get("ticket")
	if ticket == "" {
		writeProblem(w, http.StatusUnauthorized, "https://argus.io/errors/missing-ticket", "Missing connect ticket", "")
		return
	}

	// Redeem is single-use regardless of outcome (internal/authz.WSTicketIssuer's
	// own doc comment) — a captured/replayed ticket value is worthless for a
	// second attempt whether or not this specific attempt succeeds.
	userID, tenantID, ok := s.wsTickets.Redeem(ticket)
	if !ok {
		writeProblem(w, http.StatusUnauthorized, "https://argus.io/errors/invalid-ticket", "Invalid or expired connect ticket", "")
		return
	}

	// Capabilities are resolved from the live grants table here, BEFORE the
	// upgrade, so an unauthorized connection is refused with a normal HTTP
	// response instead of being accepted and then silently fed nothing —
	// and so a grant revoked in the seconds between minting the ticket and
	// redeeming it is honoured. See wsEventScope for the bug this fixes.
	scope, err := s.resolveWSEventScope(r.Context(), userID, tenantID)
	if err != nil {
		logger.ErrorContext(r.Context(), "resolving a WebSocket client's event scope failed", logging.ActorID(userID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not resolve effective permissions", "")
		return
	}
	if !scope.allowsAnything() {
		writeProblem(w, http.StatusForbidden, "https://argus.io/errors/scope-denied",
			"Missing required capability",
			fmt.Sprintf("a live-update connection requires at least one of the following capabilities: %s, %s",
				authz.CapIncidentRead, authz.CapClusterRead))
		return
	}

	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		// Upgrade already wrote its own error response to w on failure —
		// nothing further to write here, only log server-side.
		logger.WarnContext(r.Context(), "upgrading a WebSocket connection failed", logging.ActorID(userID), logging.Err(err))
		return
	}

	s.serveWSClient(conn, userID, scope)
}

// serveWSClient owns one live WebSocket connection end to end: subscribe
// to the shared internal/events.Bus, forward every event this subscriber's
// scope permits to this client as JSON, keep the connection alive with
// periodic pings, and clean up (unsubscribe, close) the moment the
// connection goes away in either direction. Blocks until the connection
// ends; callers (handleWSEvents) run it synchronously on the request
// goroutine net/http already gave the upgraded connection, the same way
// internal/gateway.handleConn owns its tunnel connection's goroutine end to
// end.
//
// scope is resolved once, by the caller, from the live grants table
// (resolveWSEventScope) — the bus itself is a process-wide broadcast, so
// this is the only place fan-out is narrowed to what a given subscriber is
// allowed to see. See wsEventScope for the bug that made that necessary.
func (s *Server) serveWSClient(conn *websocket.Conn, userID string, scope wsEventScope) {
	// PROJECT.md B162: this goroutine, and only this goroutine, writes to
	// conn — so the shutdown drain cannot close the socket itself without
	// breaking gorilla/websocket's single-concurrent-writer rule. It
	// registers here instead, and the select loop below sends its own 1001
	// close frame when the drain signal arrives. wsActive is what
	// DrainWebSockets waits on; wsOpen is only for its log line.
	s.wsActive.Add(1)
	s.wsOpen.Add(1)
	defer func() {
		s.wsOpen.Add(-1)
		s.wsActive.Done()
	}()

	ch, unsubscribe := s.events.Subscribe()
	defer unsubscribe()
	defer conn.Close()

	// The drain may have started between handleWSEvents' IsShuttingDown check
	// and this goroutine being scheduled, in which case the select below
	// would be the only thing standing between this connection and an abrupt
	// process exit. It handles that correctly (wsDrain is already closed, so
	// that case is immediately ready) — this early return only avoids the
	// pointless subscribe/ping setup for a connection that is leaving at once.
	if s.wsDrainClosed() {
		_ = conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
		_ = conn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseGoingAway, "hub shutting down"))
		return
	}

	_ = conn.SetReadDeadline(time.Now().Add(wsPongWait))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(wsPongWait))
	})

	// This connection sends events to the browser and pings it for
	// liveness; it never expects any application-level message FROM the
	// browser (there's nothing for the client to subscribe/unsubscribe to —
	// see internal/events' doc comment on why per-connection scoping
	// doesn't exist yet). A dedicated read pump is still needed regardless,
	// for two reasons: gorilla/websocket requires SOMETHING to be reading
	// in order for control frames (pings/pongs/close) to be processed at
	// all, and this is also how a client-initiated close is ever noticed by
	// this goroutine.
	readErr := make(chan struct{})
	go func() {
		defer close(readErr)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	ticker := time.NewTicker(wsPingPeriod)
	defer ticker.Stop()

	wsLog := logger.With(logging.ActorID(userID))
	wsLog.Debug("WebSocket client connected")
	defer wsLog.Debug("WebSocket client disconnected")

	for {
		select {
		case <-readErr:
			return
		case <-s.wsDrain:
			// PROJECT.md B162: a real 1001 "going away" close frame, sent by
			// this connection's own writer goroutine, so the browser sees a
			// clean close and reconnects on its own schedule instead of
			// reporting the 1006 abnormal closure an unannounced process
			// exit produces. nil on a bare &Server{}, where a nil channel in
			// a select simply never fires.
			_ = conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
			_ = conn.WriteMessage(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseGoingAway, "hub shutting down"))
			wsLog.Info("closing a WebSocket client feed for shutdown")
			return
		case ev, open := <-ch:
			if !open {
				// The bus itself doesn't get torn down while the hub is
				// running (see internal/events.Bus — unsubscribe is the
				// only thing that ever closes a subscriber channel, and
				// this goroutine owns its own unsubscribe via the defer
				// above), so this branch is unreachable in practice; kept
				// for the same reason a range-until-closed loop always
				// handles closure explicitly rather than assuming it can't
				// happen.
				return
			}
			if !scope.allows(ev) {
				continue // not this subscriber's to see — see wsEventScope
			}
			_ = conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
			if err := conn.WriteJSON(ev); err != nil {
				wsLog.Warn("writing to a WebSocket client failed", logging.Err(err))
				return
			}
		case <-ticker.C:
			_ = conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}
