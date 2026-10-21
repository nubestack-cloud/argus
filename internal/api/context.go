package api

import (
	"context"

	"github.com/jackc/pgx/v5"

	"argus/internal/authz"
)

type requestCtxKey struct{}

// requestContext carries per-request state set up by the auth middleware — the
// open scoped transaction (lld/02-authz-spec.md §10.2), the authenticated user,
// and their resolved effective permissions (§6). Handlers read from this rather
// than touching the bare pool, so every query a handler issues runs inside the
// RLS-scoped transaction, never around it.
type requestContext struct {
	Tx       pgx.Tx
	UserID   string
	TenantID string
	Grants   []authz.EffectiveGrant

	// RequestID is this request's correlation id (PROJECT.md T23), minted
	// or adopted before the handler ran. Handlers rarely need it directly —
	// it is already on the request context for logging, already on the
	// response header, and already in any RFC 9457 problem body this
	// request produces — but a handler that PERSISTS something the id
	// should be recoverable from reads it here (see PersistAnalysis and
	// analyses.request_id).
	RequestID string

	// afterCommit holds side effects that must not happen unless the
	// transaction actually commits — irreversible, outside-the-database
	// actions like severing a live agent tunnel.
	//
	// This exists because handleDecommissionCluster used to call
	// gw.Disconnect() inline: a commit failure then left the tunnel severed
	// while the cluster stayed Active in the database, i.e. a cluster that
	// looks healthy and connected but isn't, fixable only by restarting the
	// agent. Ordering the response after the commit (see
	// middleware.completeRequest) made the *response* honest but did nothing
	// about the side effect, which had already fired.
	//
	// Deliberately post-commit rather than post-response: these actions must
	// run whether or not the client is still listening. Errors are logged, not
	// returned — by the time these run the request has already succeeded and
	// been reported as such, so failing it retroactively would be a lie in the
	// other direction.
	afterCommit []func()
}

// OnCommit registers a side effect to run only if this request's transaction
// commits. Handlers should use it for anything irreversible that lives outside
// the database.
func (rc *requestContext) OnCommit(f func()) {
	rc.afterCommit = append(rc.afterCommit, f)
}

// runAfterCommit executes the registered side effects in registration order.
// Called by the middleware immediately after a successful commit, never on the
// rollback path.
func (rc *requestContext) runAfterCommit() {
	for _, f := range rc.afterCommit {
		f()
	}
}

func withRequestContext(ctx context.Context, rc *requestContext) context.Context {
	return context.WithValue(ctx, requestCtxKey{}, rc)
}
