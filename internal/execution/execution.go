// Package execution prepares, rehearses, signs, dispatches, records and undoes
// the changes ARGUS makes to a customer's cluster.
//
// It was lifted out of internal/api (PROJECT.md P23). That package is 70-odd
// files that can all reach every private field of one *Server, so until this
// split there was no compile-time boundary at all between an HTTP handler and
// the code that patches a production cluster: any handler could call
// PreparePlan, skip a guardrail, or construct a PlanPrep by hand. Now the
// safety pipeline has an explicit, deliberately small exported surface, and
// internal/api holds the transport layer that calls it. The precedent is
// internal/orchestrator, which owns the incident state machine the same way —
// package-level logic over caller-supplied, already-RLS-scoped transactions,
// plus narrow interfaces (AppliedValueVerifier there, PlanCorrectionModel and
// EvidenceLister here) for the things it must not import.
//
// # What this package guarantees
//
// Nothing in here mutates a cluster without every one of these, in this order,
// per approved plan:
//
//  1. Resolve the real patch target (resolvePodTemplateTarget: a RestartPod,
//     PatchResourceLimits or RevertContainerImage plan's TargetGVK is usually
//     "v1/Pod" — the actual patch always targets the owning Deployment/
//     StatefulSet/DaemonSet, resolved via the read-only get_owner_chain tool,
//     never guessed).
//  2. Fetch a fresh resourceVersion precondition against that resolved target
//     via the read-only describe_resource tool — never the value from whenever
//     the plan was originally proposed. The same read supplies the live values
//     every per-action bound check compares against, and — for
//     PatchResourceLimits and RevertContainerImage — the live container state
//     (resources, image) that becomes the plan's pre-computed rollback (§10.3),
//     captured before anything is mutated because that is the only moment they
//     are knowable. For RevertContainerImage this step also resolves the TARGET
//     STATE from the cluster, not from the plan: the workload's owned
//     ReplicaSets are its revision history, so the previous revision's image for
//     that container is read here — through the same read-only tools — and
//     signed into the plan content. A plan never names an image and this hub
//     never accepts one from a model; see resolvePreviousImage.
//  3. Rehearse it server-side (attestByDryRun) and refuse on a missing or false
//     dryRun echo — fail-closed, never "the agent probably did it".
//  4. Sign the plan (internal/remediation.Sign) with this cluster's derived key,
//     with a two-minute TTL (signedPlanTTL).
//  5. Commit AwaitingApproval -> Executing, in its own transaction, before ever
//     calling the agent — a durable "we committed to this" record even if the
//     hub crashes before the tunnel call returns.
//  6. Call scale_deployment/restart_pod/patch_resource_limits/
//     revert_container_image over the tunnel.
//  7. Record the outcome (Executing -> Validating or -> Failed) plus a
//     remediation_executions row, in a second, separate transaction.
//
// Steps 1-4 are read-only against the cluster and don't touch incidents.state at
// all — a failure there (cluster disconnected, object not found, a signing
// error) costs nothing to retry: nothing was recorded, nothing changed. Step 5
// is the one moment this becomes irreversible from the caller's point of view,
// which is exactly why it's the row-locked, separately-committed transaction
// that also records the approval decision itself — the two are the same atomic
// "we're doing this now" fact, not two separate facts that could end up
// disagreeing.
//
// # RLS
//
// Every entry point that reads or writes on behalf of a request takes a Scope:
// an already-scoped pgx.Tx plus the tenant it is scoped to. This package never
// opens an unscoped transaction — the two functions that do open their own
// (recordExecutingTransition and recordExecutionOutcome, which must commit
// separately from the request's transaction) call data.SetRequestScope on it
// themselves, and the background reconciler goes through data.InScope /
// data.InFleetScope, which never hand out an unscoped one.
// internal/data/scope_structural_test.go enforces both properties against this
// package by path.
package execution

import (
	"context"

	"github.com/jackc/pgx/v5"

	"argus/internal/authz"
	"argus/internal/data"
	"argus/internal/events"
	"argus/internal/gateway"
	"argus/internal/llm"
	"argus/internal/logging"
)

// logger is this package's package-local slog logger, matching internal/api's
// own convention (PROJECT.md T22). Named "execution" rather than "api" now that
// this code no longer lives there, so a log line about a cluster mutation is
// attributable to the thing that made it rather than to whichever HTTP handler
// happened to be on the stack.
var logger = logging.For("execution")

// Scope is one caller's already-RLS-scoped database transaction and the tenant
// it is scoped to — what internal/api's requestContext carries, narrowed to the
// two fields this package actually reads.
//
// It is deliberately NOT an interface and deliberately carries no way to open a
// transaction: a caller can only hand this package a transaction that something
// upstream already called data.SetRequestScope on (a request's, via
// requireAuth; a sweep's, via data.InScope/InFleetScope). Under FORCE ROW LEVEL
// SECURITY an unscoped transaction does not fail, it silently matches no rows —
// PROJECT.md B175 — so "you cannot pass me an unscoped one" is worth more here
// than any amount of remembering.
type Scope struct {
	// Tx is the open, already-scoped transaction. Everything this package reads
	// or writes on the caller's behalf runs inside it, never around it.
	Tx pgx.Tx
	// TenantID is the organisation that transaction is scoped to. Used both as
	// a column value on the rows written here and to re-scope the two
	// separately-committed transactions this package opens for itself.
	TenantID string
}

// EvidenceLister reads back the MCP tool calls the hub itself recorded for one
// investigation, so a CreateResource plan's own parameter values can be checked
// against what the cluster actually said (PROJECT.md B161 — see PreparePlan's
// call site for exactly what that comparison is and is not).
//
// A function rather than a direct call into internal/api.ListMCPToolCalls,
// because internal/api imports THIS package and the dependency must not point
// back. cmd/hub already wires the same function into internal/llm for the same
// reason; api.NewServer wires this one.
//
// Nil is allowed and means "no evidence available": PreparePlan then proceeds
// unchecked, exactly as it already does when the read fails or when the
// investigation ran on the api backend (which records no tool-call content at
// all). This is a deliberate best-effort check — an unavailable ledger must
// never be the reason a safe remediation is refused.
type EvidenceLister func(ctx context.Context, clusterID, incidentID string) ([]llm.RecordedToolCall, error)

// Executor is everything this package needs from the outside world, and the
// receiver for the whole prepare/execute/record/undo pipeline.
//
// The field names are deliberately the same as the *Server fields these methods
// used to read, so the move is readable as a move. All of them may be nil in a
// unit test that does not reach them — this package's own tests build a bare
// &Executor{...} with only what the case under test needs, the same convention
// internal/api's tests use for &Server{}.
type Executor struct {
	db *data.DB
	// gw is the mTLS tunnel to the cluster agents: every read this package
	// makes about live cluster state, and every mutating tool call, goes
	// through it. The SAME *gateway.Gateway cmd/hub starts the tunnel listener
	// on, never a second instance.
	gw     *gateway.Gateway
	events *events.Bus
	// planSigningRootKey is internal/remediation's root key. A per-cluster key
	// is derived from it per execution (remediation.DeriveClusterSigningKey);
	// the root itself never leaves this hub.
	planSigningRootKey []byte
	// guardrailTokens redeems the single-use confirmation tokens a guardrail's
	// own refusal minted, so "the operator set confirmScaleFromZero" and "the
	// operator was actually shown the refusal" stay distinguishable (WORKLOG
	// §97 G5).
	guardrailTokens *authz.GuardrailConfirmationIssuer
	// planCorrector may be nil (a test build, or a deployment with no AI
	// provider), in which case preparePlanWithCorrection's correct() closure
	// reports "no AI provider configured" and the retry loop surfaces the
	// ORIGINAL dry-run rejection unchanged, exactly as if the feature did not
	// exist.
	planCorrector PlanCorrectionModel
	// evidence may be nil; see EvidenceLister.
	evidence EvidenceLister
}

// New builds the Executor. Every dependency is passed in rather than read from
// the environment, matching internal/api's own rule that configuration arrives
// from cmd/hub.
func New(db *data.DB, gw *gateway.Gateway, bus *events.Bus, planSigningRootKey []byte,
	guardrailTokens *authz.GuardrailConfirmationIssuer, planCorrector PlanCorrectionModel,
	evidence EvidenceLister,
) *Executor {
	return &Executor{
		db:                 db,
		gw:                 gw,
		events:             bus,
		planSigningRootKey: planSigningRootKey,
		guardrailTokens:    guardrailTokens,
		planCorrector:      planCorrector,
		evidence:           evidence,
	}
}

// Result is what one execution or undo leaves behind: where the incident ended
// up and the sentence an operator reads about it. The HTTP response shapes
// (approveRejectResponse, rollbackResponse) are built from this by
// internal/api — this package has no opinion about JSON.
type Result struct {
	// IncidentState is the state the outcome transaction committed. Empty means
	// the bookkeeping write itself failed: the cluster change happened (or
	// didn't), the attempt row is still open, and the execution reconciler will
	// settle it. Callers must not render an empty value as if it were a state.
	IncidentState string
	// Message is the operator-facing sentence for this outcome.
	Message string
}

// nullIfEmpty returns what goes into a nullable text column: a real SQL NULL
// for the empty string, never a sentinel.
//
// A local copy rather than an import, the same way internal/orchestrator's
// db.go keeps its own: this package must not depend on internal/api, and a
// three-line helper is not worth a shared package of its own.
func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// deref is the read side of nullIfEmpty. Local copy, same reasoning.
func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
