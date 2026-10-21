package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"argus/internal/audit"
	"argus/internal/authz"
	"argus/internal/data"
	"argus/internal/logging"
)

// bufferedResponseWriter captures a handler's whole response — status, headers
// and body — instead of streaming it to the client as the handler writes it, so
// that requireAuth can decide what the client actually receives AFTER it knows
// whether the request's transaction committed. It also lets requireAuth decide
// whether to commit or roll back at all, based on what the handler did: a
// handler that wrote a 4xx/5xx must not have its transaction committed, since
// lld/05-data-model.md draws no distinction between "a write happened" and "a
// read happened" as far as transaction hygiene goes; treating both uniformly is
// simpler and never wrong.
//
// BUG FIX (2026-08-21): this replaces the previous statusCapturingWriter, which
// only OBSERVED the status code and passed every write straight through. That
// meant the commit at the bottom of requireAuth ran after the status line and
// body had already gone out on the wire, so a commit failure (a serialization
// failure, a statement timeout, a dropped connection to Postgres, a cancelled
// request context) was merely log.Printf'ed and the caller got a 2xx for a
// transaction that persisted nothing. internal/api/clusters.go's
// handleDecommissionCluster is the sharpest instance: it severs the live tunnel
// (s.gw.Disconnect) and depends on the commit for the Archived cluster row, so
// a failed commit left the cluster disconnected-but-Active and reported
// success. With buffering, that request now honestly returns 500.
//
// Buffering is safe for every route this middleware wraps: they all write one
// complete JSON document through writeJSON/writeProblem, never a stream, so
// this costs one response's worth of memory per in-flight request (the largest
// being a fleet-wide list response, which is sized by the query's result set —
// the same data the handler already materialized to encode it) and buys a
// response that can't contradict what was persisted. The two surfaces that
// could NOT tolerate buffering are deliberately not wrapped with requireAuth in
// the first place — GET /ws/events hijacks the connection for a long-lived
// WebSocket (ws.go's own comment explains why requireAuth's request-shaped
// transaction lifecycle doesn't fit it) and GET / serves the embedded UI
// (static.go); both are registered bare in routes(). This type therefore
// deliberately implements neither http.Hijacker/http.Flusher nor an Unwrap
// method: a future streaming or hijacking route wired through requireAuth
// should fail visibly here rather than quietly bypass the buffer and
// reintroduce this bug.
type bufferedResponseWriter struct {
	header http.Header
	// sentHeader is a snapshot of header taken when the handler called
	// WriteHeader, mirroring net/http's own semantics that headers set after
	// the status line is written are ignored.
	sentHeader  http.Header
	status      int
	wroteHeader bool
	body        bytes.Buffer
}

func newBufferedResponseWriter() *bufferedResponseWriter {
	return &bufferedResponseWriter{header: make(http.Header), status: http.StatusOK}
}

func (w *bufferedResponseWriter) Header() http.Header { return w.header }

func (w *bufferedResponseWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return // net/http ignores a second WriteHeader; so does this
	}
	w.wroteHeader = true
	w.status = code
	w.sentHeader = w.header.Clone()
}

func (w *bufferedResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK) // implicit 200, exactly like net/http
	}
	return w.body.Write(b)
}

// flushTo replays the buffered response onto the real ResponseWriter. Called
// only once the request's transaction has been resolved (see completeRequest).
func (w *bufferedResponseWriter) flushTo(dst http.ResponseWriter) {
	header := w.sentHeader
	if header == nil {
		header = w.header // handler wrote neither a status nor a body
	}
	dstHeader := dst.Header()
	for key, values := range header {
		dstHeader[key] = append([]string(nil), values...)
	}
	dst.WriteHeader(w.status)
	if w.body.Len() > 0 {
		if _, err := dst.Write(w.body.Bytes()); err != nil {
			logger.Error("writing buffered response to the client failed",
				slog.Int("status", w.status), logging.Err(err))
		}
	}
}

// txFinisher is the pgx.Tx surface completeRequest needs, narrowed to an
// interface purely so the commit-failure path is unit-testable without a live
// Postgres (see middleware_test.go — that path is the entire point of the
// buffering above, so it must be covered by a real test). pgx.Tx satisfies this
// as-is.
type txFinisher interface {
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}

// completeRequest resolves the request's transaction and only then sends the
// buffered response — the ordering fix described on bufferedResponseWriter.
//
// The >= 400 branch preserves the pre-existing, deliberate behaviour exactly:
// an error response rolls back. That rollback-on-4xx is also precisely why
// recordCapabilityDenial (below) opens its own separate transaction, so nothing
// here may change it.
func completeRequest(ctx context.Context, dst http.ResponseWriter, buf *bufferedResponseWriter, tx txFinisher, afterCommit func()) {
	if buf.status >= 400 {
		if err := tx.Rollback(ctx); err != nil {
			logger.ErrorContext(ctx, "rolling back the request transaction after an error response failed",
				slog.Int("status", buf.status), logging.Err(err))
		}
		buf.flushTo(dst)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		// The handler's own 2xx is discarded on purpose: nothing it described
		// as having happened actually persisted.
		logger.ErrorContext(ctx, "request transaction commit failed; discarding the handler's response",
			slog.Int("status", buf.status), logging.Err(err))
		writeProblem(dst, http.StatusInternalServerError, "https://argus.io/errors/internal",
			"Could not commit this request",
			"The request was not applied — its transaction failed to commit, so nothing was persisted. It is safe to retry.")
		return
	}
	// Only now that the data is durable: run the irreversible, outside-the-
	// database side effects the handler deferred (see requestContext.OnCommit).
	// Before the response is flushed, so a handler cannot observe a client
	// disconnect and skip them.
	if afterCommit != nil {
		afterCommit()
	}
	buf.flushTo(dst)
}

// requireAuth implements lld/02-authz-spec.md §10.1's middleware layer: every
// wrapped route resolves (actor, capabilities, scope) from the authenticated
// session before the handler runs. A route that needs no capability check at all
// (there are none yet beyond this file's own auth endpoints) simply isn't wrapped
// with this — but every DATA-BEARING route must be, and that discipline is a code
// review rule for now, not yet a compile-time or lint-enforced one (see
// STATUS.md's Phase 0 notes for what's still manual here).
func (s *Server) requireAuth(next func(w http.ResponseWriter, r *http.Request, rc *requestContext)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// PROJECT.md T23's HTTP half. The id is normally already on the
		// context — observability.go's wrapper mints or adopts one for
		// every request that reaches the mux through Server.ServeHTTP —
		// but it is minted here too when it is missing, for two reasons:
		// the board names requireAuth as the minting point, and a large
		// part of this package's test suite drives s.mux directly, so
		// "every authenticated request has a correlation id" must not
		// depend on a wrapper those tests skip.
		//
		// Setting it on w here is what puts it in the RFC 9457 problem
		// body of every error this function itself returns (see
		// writeProblemWithExtras) — including the 401s below, which are
		// returned before any handler or transaction exists.
		requestID := logging.RequestIDFrom(r.Context())
		ctx := r.Context()
		if requestID == "" {
			requestID = logging.NewRequestID()
			ctx = logging.ContextWithRequestID(ctx, requestID)
		}
		w.Header().Set(RequestIDHeader, requestID)

		authHeader := r.Header.Get("Authorization")
		tokenString, ok := strings.CutPrefix(authHeader, "Bearer ")
		if !ok || tokenString == "" {
			writeProblem(w, http.StatusUnauthorized, "https://argus.io/errors/missing-token", "Missing bearer token", "")
			return
		}

		userID, generation, err := s.signer.VerifyAccessToken(tokenString)
		if err != nil {
			// err.Error() wraps golang-jwt's own message (BACKLOG.md G6) —
			// harmless-sounding library text ("token is malformed", "token
			// signature is invalid", ...) still tells an UNAUTHENTICATED
			// caller which specific check their token failed, and this
			// function's own pgx.ErrNoRows branch below already treats an
			// invalid/expired token as one generic outcome rather than a
			// diagnosis. Matched here for the same reason.
			writeProblem(w, http.StatusUnauthorized, "https://argus.io/errors/invalid-token", "Invalid or expired access token", "")
			return
		}

		tx, err := s.db.Pool.Begin(ctx)
		if err != nil {
			writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not start request transaction", "")
			return
		}

		tenantID, err := data.SingleOrganisationID(ctx, tx)
		if err != nil {
			_ = tx.Rollback(ctx)
			writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not resolve organisation scope", "")
			return
		}

		// Tenant scope only, at this point: the grants table has to be readable
		// before the caller's accessible clusters can be known. Narrowed to those
		// clusters immediately after they are resolved — see below.
		if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
			_ = tx.Rollback(ctx)
			writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not set request scope", "")
			return
		}

		// The generation check below is what makes a password change/reset
		// (internal/api/auth.go's handleChangePassword, internal/api/users.go's
		// handleResetPassword) actually end an already-issued, not-yet-expired
		// access token immediately, rather than only at its natural 15-minute
		// expiry — see accessTokenClaims' doc comment (internal/authz/jwt.go).
		// A user row that no longer exists (pgx.ErrNoRows) is treated the same
		// as a generation mismatch: whatever this token claims, it's no longer
		// good for anything.
		var currentGeneration int64
		if err := tx.QueryRow(ctx, `SELECT token_generation FROM users WHERE id = $1 AND deleted_at IS NULL`, userID).Scan(&currentGeneration); err != nil {
			_ = tx.Rollback(ctx)
			if errors.Is(err, pgx.ErrNoRows) {
				writeProblem(w, http.StatusUnauthorized, "https://argus.io/errors/invalid-token", "Invalid or expired access token", "")
				return
			}
			logger.ErrorContext(ctx, "looking up the caller's token generation failed",
				logging.ActorID(userID), logging.Err(err))
			writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not verify session", "")
			return
		}
		if currentGeneration != generation {
			_ = tx.Rollback(ctx)
			writeProblem(w, http.StatusUnauthorized, "https://argus.io/errors/invalid-token", "Access token has been revoked", "")
			return
		}

		grants, err := authz.ResolveEffectivePermissions(ctx, tx, userID)
		if err != nil {
			_ = tx.Rollback(ctx)
			writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not resolve effective permissions", "")
			return
		}

		// BACKLOG S1: narrow RLS to the clusters this principal's grants actually
		// reach, now that the grants are known.
		//
		// Set a SECOND time, deliberately. The first call above establishes tenant
		// scope so the grants table can be read at all; only afterwards is it
		// possible to know which clusters those grants name. `set_config` is
		// transaction-local and idempotent, so re-setting it is the correct way to
		// go from "tenant" to "tenant plus these clusters".
		//
		// The safety property that makes this shippable: every existing
		// installation's grants include AllClusters (internal/authz/bootstrap.go
		// creates one), so unrestricted is true and nil is passed — byte-identical
		// to the previous behaviour. Narrowing only begins when somebody creates a
		// scoped grant, which the UI has always let them do and which nothing has
		// ever enforced.
		accessible, unrestricted, err := authz.AccessibleClusterIDs(ctx, tx, grants)
		if err != nil {
			// An uninterpretable grant fails the request rather than defaulting
			// either way: denying silently would look like missing data, and
			// widening silently would be a privilege escalation.
			_ = tx.Rollback(ctx)
			logger.ErrorContext(ctx, "resolving the caller's accessible clusters failed",
				logging.ActorID(userID), logging.Err(err))
			// Generic detail, logged server-side instead (BACKLOG.md G6) —
			// every other internal-error branch in this function already
			// does this; this one was the exception.
			writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal",
				"Could not resolve the scope of your permissions", "")
			return
		}
		if !unrestricted {
			if err := data.SetRequestScope(ctx, tx, tenantID, accessible); err != nil {
				_ = tx.Rollback(ctx)
				writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not narrow request scope", "")
				return
			}
		}

		rc := &requestContext{Tx: tx, UserID: userID, TenantID: tenantID, Grants: grants, RequestID: requestID}

		// Now that the caller is known, the actor joins the correlation id
		// on the context — so every converted log line under this handler
		// carries both without naming either (internal/logging's context
		// handler). actor_id is the third of T22's four fixed attributes;
		// incident_id and cluster_id are per-handler and narrowed where
		// the handler knows them.
		ctx = logging.ContextWith(ctx, logging.ActorID(userID))

		// The handler writes into a buffer, never straight to the client: the
		// response is only sent once this request's transaction has actually
		// been resolved. See bufferedResponseWriter/completeRequest.
		buf := newBufferedResponseWriter()
		// The buffer has its own header map, so the correlation id has to
		// be put on it as well as on w: writeProblem inside a handler reads
		// the id off the writer it was handed, and flushTo copies these
		// headers onto the real response.
		buf.Header().Set(RequestIDHeader, requestID)
		next(buf, r.WithContext(withRequestContext(ctx, rc)), rc)
		completeRequest(ctx, w, buf, tx, rc.runAfterCommit)
	}
}

// requireCapability composes with requireAuth: it must wrap the INNER handler,
// with requireAuth wrapping the result, e.g.
// `s.requireAuth(s.requireCapability(authz.CapClusterOnboard, s.handleX))`.
// Implements the capability half of lld/02-authz-spec.md §10.1 — scope-specific
// checks (does the grant's scope actually cover the cluster this request touches)
// are a separate, per-route concern for once cluster-scoped routes exist; this is
// the "does the caller hold this capability at all" check.
func (s *Server) requireCapability(capability string, next func(w http.ResponseWriter, r *http.Request, rc *requestContext)) func(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	return func(w http.ResponseWriter, r *http.Request, rc *requestContext) {
		if !authz.HasCapability(rc.Grants, capability) {
			s.recordCapabilityDenial(r.Context(), rc, capability, clientIP(r))
			writeProblem(w, http.StatusForbidden, "https://argus.io/errors/scope-denied",
				"Missing required capability",
				fmt.Sprintf("capability %q is required for this request", capability))
			return
		}
		next(w, r, rc)
	}
}

// requireAnyCapability is requireCapability's OR-shaped sibling: the caller must
// hold AT LEAST ONE of capabilities. Composes identically (wrap the inner
// handler, then wrap the result in requireAuth).
//
// Added for POST /api/v1/ws/ticket (ws.go), whose live feed carries two
// independently-gated event kinds — IncidentUpdated needs incident:read,
// ClusterUpdated needs cluster:read — so holding either is enough to be
// entitled to a connection at all, and the per-event server-side filter
// (wsEventScope) is what decides which of them a given subscriber actually
// receives. Nesting two requireCapability calls, the way GET /api/v1/insights
// legitimately does, would wrongly demand BOTH here.
//
// The audit denial is recorded against capabilities[0]: audit_events.capability
// holds one capability from lld/02-authz-spec.md §4's catalogue, and "the first
// capability that would have allowed this request" is a truthful, catalogue-
// valid value, where a synthesized "a-or-b" string would be neither.
func (s *Server) requireAnyCapability(capabilities []string, next func(w http.ResponseWriter, r *http.Request, rc *requestContext)) func(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	return func(w http.ResponseWriter, r *http.Request, rc *requestContext) {
		for _, capability := range capabilities {
			if authz.HasCapability(rc.Grants, capability) {
				next(w, r, rc)
				return
			}
		}
		s.recordCapabilityDenial(r.Context(), rc, capabilities[0], clientIP(r))
		writeProblem(w, http.StatusForbidden, "https://argus.io/errors/scope-denied",
			"Missing required capability",
			fmt.Sprintf("this request requires at least one of the following capabilities: %s", strings.Join(capabilities, ", ")))
	}
}

// recordCapabilityDenial writes the audit_events row for a failed capability
// check (Outcome: "denied") — the generic denial-logging layer, wired here
// so every requireCapability-gated route gets it for free rather than each
// handler having to remember to log its own denials.
//
// This deliberately opens and commits its OWN small transaction rather than
// reusing rc.Tx: requireAuth (above) rolls back rc.Tx whenever the wrapped
// handler's response status is >= 400 (see completeRequest, and
// bufferedResponseWriter — formerly statusCapturingWriter, the name some other
// files' comments still use) — and a 403 from this exact check is precisely
// that case. By the time requireAuth's wrapper regains control, rc.Tx is
// already destined for rollback regardless of what this function does with
// it, so a denial being durably logged must not depend on the outcome of the
// very transaction whose entire point was to deny something. Best-effort:
// if the audit write itself fails, that's logged server-side, but it must
// never turn an already-decided 403 into a 500, and it must never block the
// denial from being returned to the caller either way.
func (s *Server) recordCapabilityDenial(ctx context.Context, rc *requestContext, capability, sourceIP string) {
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		denialLog := logger.With(logging.ActorID(rc.UserID), slog.String("capability", capability))
		denialLog.ErrorContext(ctx, "recording a capability denial: begin transaction failed", logging.Err(err))
		return
	}
	denialLog := logger.With(logging.ActorID(rc.UserID), slog.String("capability", capability))
	defer tx.Rollback(ctx) //nolint:errcheck

	if err := data.SetRequestScope(ctx, tx, rc.TenantID, nil); err != nil {
		denialLog.ErrorContext(ctx, "recording a capability denial: set request scope failed", logging.Err(err))
		return
	}

	if err := audit.RecordEvent(ctx, tx, audit.Event{
		TenantID:   rc.TenantID,
		ActorID:    &rc.UserID,
		Capability: &capability,
		SourceIP:   sourceIP,
		Outcome:    audit.OutcomeDenied,
	}); err != nil {
		denialLog.ErrorContext(ctx, "recording a capability denial: audit write failed", logging.Err(err))
		return
	}

	if err := tx.Commit(ctx); err != nil {
		denialLog.ErrorContext(ctx, "recording a capability denial: commit failed", logging.Err(err))
	}
}

// clientIP extracts a best-effort caller address from r for audit logging
// (audit.Event.SourceIP) — r.RemoteAddr is normally "host:port"; this strips
// the port. Never blocks or errors the request itself: an address that can't
// be parsed just falls back to the raw value rather than being discarded,
// since this field is explicitly best-effort ("" only when truly unknown).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
