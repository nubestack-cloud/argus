package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/authz"
	"argus/internal/gateway"
	"argus/internal/logging"
	"argus/internal/orchestrator"
	"argus/internal/resolution"
	"argus/internal/scm"
	"argus/internal/tunnel"
)

// ResolveIncidentRoute is lld/08-remediation-contracts.md §12's
// pre-investigation step, shared by internal/api/analyze.go's
// handleAnalyzeIncident and internal/autoanalyze's investigateOne so the two
// call sites can never diverge on how a route gets computed — mirrors
// orchestrator.ApplyAnalysisResult's own "one function, two callers"
// rationale.
//
// Fetches ownership LIVE, and BEFORE the investigation runs — a real
// restructuring, not just a new call: cacheIncidentOwnership used to make
// this same get_gitops_ownership call AFTER Investigate returned, because
// nothing needed the answer any earlier. §12.5 does: the route has to be
// known before the system prompt is built. incidents.ownership is still
// written here exactly as that function wrote it, so the ownership panel and
// checkGitOpsPrecedence's cache-first read keep working unchanged; this
// function is what replaces cacheIncidentOwnership's call site, not its
// effect. (BACKLOG.md 80 — the auto-analysis path never called
// cacheIncidentOwnership at all — is closed as a side effect: this step now
// runs unconditionally from both callers.)
//
// grants is nil for autoanalyze's unattended caller: there is no human actor
// to hold a capability, so the capability half of ExecutionAllowed is
// skipped (defaults to true) rather than checked against nobody. The
// cluster-RBAC half of ExecutionAllowed (BACKLOG B4's ClusterRemediation,
// tunnel/protocol.go) is a real, agent-reported signal that nothing hub-side
// stores yet — a genuine, documented gap, not a silent one: ExecutionAllowed
// here is capability-only. Getting this wrong in the permissive direction
// costs a plan that fails its own RBAC check at execution time (a worse UX,
// already caught by existing execution-time checks) — not a void pull
// request, which is the failure mode this package's Applier handling exists
// to prevent, and does.
func ResolveIncidentRoute(ctx context.Context, tx pgx.Tx, gw *gateway.Gateway, scmStore *scm.Store, incidentID, clusterID string, grants []authz.EffectiveGrant) (orchestrator.RouteDecision, error) {
	var state string
	var prNumber *int
	var storedRoute, storedReason, storedApplier *string
	if err := tx.QueryRow(ctx,
		`SELECT state, pr_number, route, route_reason, applier FROM incidents WHERE id = $1`, incidentID,
	).Scan(&state, &prNumber, &storedRoute, &storedReason, &storedApplier); err != nil {
		return orchestrator.RouteDecision{}, err
	}

	// §12.9 decision B point 3: a plan in flight keeps its route — recomputed
	// below for visibility (logged), but not applied. Executing is not
	// checked: MarkInvestigating already refuses to start an analysis from
	// that state (internal/orchestrator/state.go), so it can never be the
	// incident's state at this point.
	inFlight := state == orchestrator.StateAwaitingMerge && prNumber != nil

	facts := gatherOwnershipFacts(ctx, tx, gw, scmStore, incidentID, clusterID)
	executionAllowed := true
	if grants != nil {
		var err error
		executionAllowed, err = authz.HasCapabilityForCluster(ctx, tx, grants, authz.CapRemediationExecInplace, clusterID)
		if err != nil {
			return orchestrator.RouteDecision{}, err
		}
	}
	fresh, applier := orchestrator.ResolveRoute(facts, executionAllowed)

	if inFlight {
		logger.InfoContext(ctx, "incident has a plan in flight: the recomputed route will not be applied, using the stored one for this investigation",
			logging.IncidentID(incidentID), slog.Int("pull_request", *prNumber),
			slog.String("recomputed_route", string(fresh.Route)), slog.String("recomputed_reason", fresh.Reason),
			slog.String("stored_route", deref(storedRoute)))
		return orchestrator.RouteDecision{
			Route:   resolution.Route(deref(storedRoute)),
			Reason:  deref(storedReason),
			Applier: resolution.Applier(deref(storedApplier)),
			Apply:   false,
		}, nil
	}
	return orchestrator.RouteDecision{Route: fresh.Route, Reason: fresh.Reason, Applier: applier, Apply: true}, nil
}

// ClusterDryRunAvailable resolves BACKLOG.md C4's gate for the dry_run_patch
// investigation tool: whether THIS cluster's agent has reported holding the
// opt-in argus-dryrun grant, read from cluster_facts — the same table
// handleGetCluster (clusters.go) already joins by clusterID, and the same
// "ask the cluster, never infer from a chart value" discipline
// ResolveIncidentRoute's own doc comment already applies to
// ClusterRemediation's cousin, ExecutionAllowed.
//
// Shared by both callers of ResolveIncidentRoute (handleAnalyzeIncident and
// autoanalyze's investigateOne) so the two can never diverge on how this is
// computed — the same "one function, two callers" rationale that function's
// own doc comment gives for itself.
//
// Fails closed on every error path: a facts row that does not exist yet, a
// blob that fails to unmarshal, a nil DryRun field, or Checked=false all
// return false. Never advertising the tool is always the safe direction —
// the cost of getting this wrong toward false is a missed investigation
// shortcut; the cost of getting it wrong toward true is offering a tool call
// that fails server-side (an ordinary, already-handled tool error), so
// there is no reason to fail permissive here.
func ClusterDryRunAvailable(ctx context.Context, tx pgx.Tx, clusterID string) bool {
	var raw json.RawMessage
	if err := tx.QueryRow(ctx, `SELECT facts FROM cluster_facts WHERE cluster_id = $1`, clusterID).Scan(&raw); err != nil {
		// pgx.ErrNoRows (no inventory sync yet) and any other read failure
		// are both "unknown" here — logged only for the latter, since the
		// former is the ordinary state of a freshly enrolled cluster.
		if err != pgx.ErrNoRows {
			logger.ErrorContext(ctx, "reading cluster_facts for the dry-run check failed", logging.ClusterID(clusterID), logging.Err(err))
		}
		return false
	}
	return dryRunAvailableFromFacts(raw)
}

// dryRunAvailableFromFacts is ClusterDryRunAvailable's pure half — the part
// that needs no database, split out the same way parseOwnershipFacts is
// split from gatherOwnershipFacts just above, so the actual decision logic
// has a real unit test (routing_test.go) rather than only an
// integration-level one.
func dryRunAvailableFromFacts(raw json.RawMessage) bool {
	var facts tunnel.ClusterFacts
	if err := json.Unmarshal(raw, &facts); err != nil {
		logger.Warn("cluster_facts does not parse; treating dry-run as unavailable", logging.Err(err))
		return false
	}
	return facts.DryRun != nil && facts.DryRun.Checked && facts.DryRun.Allowed
}

// ClusterMetricsAvailable resolves BACKLOG.md C4's gate for the query_metrics
// investigation tool: whether THIS cluster's agent has reported holding the
// RBAC grant a configured metrics.prometheusService needs, read from
// cluster_facts — the exact same "ask the cluster, never infer from a chart
// value" discipline ClusterDryRunAvailable above already applies to
// dry_run_patch, applied here to query_metrics.
//
// Shared by both callers of ResolveIncidentRoute (handleAnalyzeIncident and
// autoanalyze's investigateOne), same as ClusterDryRunAvailable, so the two
// can never diverge on how this is computed.
//
// Fails closed on every error path, for the identical reason
// ClusterDryRunAvailable does: never advertising the tool is always the safe
// direction.
func ClusterMetricsAvailable(ctx context.Context, tx pgx.Tx, clusterID string) bool {
	var raw json.RawMessage
	if err := tx.QueryRow(ctx, `SELECT facts FROM cluster_facts WHERE cluster_id = $1`, clusterID).Scan(&raw); err != nil {
		if err != pgx.ErrNoRows {
			logger.ErrorContext(ctx, "reading cluster_facts for the metrics check failed", logging.ClusterID(clusterID), logging.Err(err))
		}
		return false
	}
	return metricsAvailableFromFacts(raw)
}

// metricsAvailableFromFacts is ClusterMetricsAvailable's pure half, the same
// split dryRunAvailableFromFacts above uses and for the same reason: the
// actual decision logic gets a real unit test (routing_test.go) with no
// database involved.
func metricsAvailableFromFacts(raw json.RawMessage) bool {
	var facts tunnel.ClusterFacts
	if err := json.Unmarshal(raw, &facts); err != nil {
		logger.Warn("cluster_facts does not parse; treating metrics as unavailable", logging.Err(err))
		return false
	}
	return facts.Metrics != nil && facts.Metrics.Checked && facts.Metrics.Allowed
}

// gatherOwnershipFacts asks the cluster live who owns this incident's object
// (get_gitops_ownership) and persists the raw answer onto incidents.ownership
// — the same tool call and the same write cacheIncidentOwnership used to make
// after an investigation. Every failure path returns
// orchestrator.OwnershipFacts{Determined: false} rather than an error:
// resolution.RouteFor already turns an undetermined ownership into guidance
// (HLD §11.2 step 6's "give up honestly"), which is the correct outcome for
// "the cluster is unreachable" every bit as much as for "no object to ask
// about" — this function does not need a second way to say the same thing.
//
// BACKLOG.md F19 mechanism 1: when the agent's own answer is "helm" or
// "none" with no repo of its own, this also checks the tenant's
// repository_bindings for an operator-declared objectMappings match — see
// matchObjectMapping below. The agent cannot do this itself: repository_
// bindings is a hub-DB table the cluster agent has no access to at all.
//
// BUGS.md 118/124: when the incident's own object comes back genuinely
// unmanaged AND the incident carries a populated related_workload_key —
// checkOrphanedPVC's own field, naming the StatefulSet an orphaned
// volumeClaimTemplate PVC was made FOR, which never itself carries Argo's
// tracking annotation — this re-runs the identical ownership check against
// THAT related object instead. A fix belonging to the related workload's
// source becomes reachable through the incident this way, rather than
// dead-ending on the incident's own object's unmanaged status when a real,
// reachable owner exists one hop away. The actual fallback now lives in
// resolveLiveOwnership below, shared with repoScopeForMCP
// (internal/api/repo_tools.go) — see that function's doc comment for why
// sharing it, rather than each caller keeping its own copy, is the point:
// BUGS.md 124 is exactly the two copies having already drifted apart once.
func gatherOwnershipFacts(ctx context.Context, tx pgx.Tx, gw *gateway.Gateway, scmStore *scm.Store, incidentID, clusterID string) orchestrator.OwnershipFacts {
	raw, facts, sourceKey, err := resolveLiveOwnership(ctx, tx, gw, scmStore, clusterID, incidentID)
	if err != nil {
		logger.WarnContext(ctx, "get_gitops_ownership failed; routing from what is already known",
			logging.IncidentID(incidentID), slog.String("source_key", sourceKey), logging.Err(err))
		return orchestrator.OwnershipFacts{Determined: false}
	}
	if sourceKey == "" {
		return orchestrator.OwnershipFacts{Determined: false}
	}

	if _, err := tx.Exec(ctx, `UPDATE incidents SET ownership = $2 WHERE id = $1`, incidentID, raw); err != nil {
		// Best-effort, matching cacheIncidentOwnership: a failed cache write
		// must not lose an already-fetched, real answer this call still has
		// in hand and can still route on.
		logger.ErrorContext(ctx, "storing the incident's ownership facts failed", logging.IncidentID(incidentID), logging.Err(err))
	}
	return facts
}

// resolveLiveOwnership is gatherOwnershipFacts's and repoScopeForMCP's
// shared "ask the cluster live who owns this incident's object, falling
// back to its related workload when the object's own answer is genuinely
// unmanaged" step.
//
// BUGS.md 124: before this extraction, gatherOwnershipFacts (routing.go, for
// `route`/`route_reason`) and repoScopeForMCP (repo_tools.go, for whether
// list_repo_files/read_repo_file are even offered) each resolved ownership
// live with their own copy of this logic, and only the former ever received
// BUGS.md 118's related_workload_key fallback — so a cold first analysis on
// an incident whose own object resolves unmanaged but whose related
// workload has a real GitOps source could see `route: "pullRequest"` while
// the SAME call's `list_repo_files` failed outright with "no repository is
// known". Both callers now go through this one implementation instead of
// each carrying a copy that can drift again.
//
// Returns sourceKey == "" (with a nil error) when the incident has no
// usable object_key/workload_key at all — the same "nothing to ask" shape
// ownershipQueryTarget already uses; callers that need to distinguish "no
// key" from "a live tool error" can do so via err.
func resolveLiveOwnership(ctx context.Context, tx pgx.Tx, gw *gateway.Gateway, scmStore *scm.Store, clusterID, incidentID string) (raw json.RawMessage, facts orchestrator.OwnershipFacts, sourceKey string, err error) {
	gvk, namespace, name, sourceKey, err := ownershipQueryTarget(ctx, tx, incidentID)
	if err != nil {
		return nil, orchestrator.OwnershipFacts{}, "", err
	}
	if sourceKey == "" {
		return nil, orchestrator.OwnershipFacts{}, "", nil
	}

	raw, facts, err = queryGitOpsOwnership(ctx, tx, gw, scmStore, clusterID, gvk, namespace, name)
	if err != nil {
		return nil, orchestrator.OwnershipFacts{}, sourceKey, err
	}

	raw, facts = applyRelatedWorkloadFallback(ctx, tx, incidentID, raw, facts, func(relatedGVK, relatedNamespace, relatedName string) (json.RawMessage, orchestrator.OwnershipFacts, error) {
		return queryGitOpsOwnership(ctx, tx, gw, scmStore, clusterID, relatedGVK, relatedNamespace, relatedName)
	})
	return raw, facts, sourceKey, nil
}

// applyRelatedWorkloadFallback is resolveLiveOwnership's BUGS.md 118/124
// fallback step, split out behind an injectable `ask` (rather than calling
// queryGitOpsOwnership itself) so it can be exercised directly in a
// database-backed test against a fake tool call instead of a live tunnel —
// see routing_related_workload_fallback_db_test.go. Production callers pass
// a closure over queryGitOpsOwnership, same as before this split.
//
// The incident's own object is genuinely unmanaged (not a repo-registered
// mapping either) — see if a related workload is known and, if so, whether
// IT resolves to something reachable. Only ever replaces raw/facts when the
// related lookup is a real improvement; a related object that is itself
// unmanaged, or that fails to resolve at all, leaves the incident's own
// (still correct) "unmanaged" answer in place rather than regressing it.
func applyRelatedWorkloadFallback(ctx context.Context, tx pgx.Tx, incidentID string, raw json.RawMessage, facts orchestrator.OwnershipFacts, ask func(gvk, namespace, name string) (json.RawMessage, orchestrator.OwnershipFacts, error)) (json.RawMessage, orchestrator.OwnershipFacts) {
	if facts.ManagedBy != "none" || facts.RepoKnown {
		return raw, facts
	}
	relatedGVK, relatedNamespace, relatedName, ok := relatedWorkloadQueryTarget(ctx, tx, incidentID)
	if !ok {
		return raw, facts
	}
	relatedRaw, relatedFacts, relatedErr := ask(relatedGVK, relatedNamespace, relatedName)
	if relatedErr != nil {
		logger.WarnContext(ctx, "get_gitops_ownership for the related workload failed",
			logging.IncidentID(incidentID), slog.String("related_gvk", relatedGVK),
			slog.String("related_namespace", relatedNamespace), slog.String("related_name", relatedName), logging.Err(relatedErr))
		return raw, facts
	}
	if relatedFacts.ManagedBy == "none" && !relatedFacts.RepoKnown {
		return raw, facts
	}
	logger.InfoContext(ctx, "the incident's own object is unmanaged but its related workload is; routing from the related workload instead",
		logging.IncidentID(incidentID), slog.String("related_gvk", relatedGVK),
		slog.String("related_namespace", relatedNamespace), slog.String("related_name", relatedName),
		slog.String("managed_by", relatedFacts.ManagedBy), slog.Bool("repo_known", relatedFacts.RepoKnown))
	return relatedRaw, relatedFacts
}

// queryGitOpsOwnership calls get_gitops_ownership for one gvk/namespace/name
// tuple and applies BACKLOG.md F19 mechanism 1's objectMappings enrichment —
// the part of gatherOwnershipFacts that is identical whether the object in
// question is the incident's own object or, per BUGS.md 118, a related
// workload gatherOwnershipFacts falls back to. Split out so that fallback
// can reuse it rather than duplicate it.
func queryGitOpsOwnership(ctx context.Context, tx pgx.Tx, gw *gateway.Gateway, scmStore *scm.Store, clusterID, gvk, namespace, name string) (json.RawMessage, orchestrator.OwnershipFacts, error) {
	args, err := json.Marshal(map[string]string{"gvk": gvk, "namespace": namespace, "name": name})
	if err != nil {
		return nil, orchestrator.OwnershipFacts{}, fmt.Errorf("build args: %w", err)
	}
	// Detached from the request context the same way cacheIncidentOwnership's
	// own call was, and for the same reason (that function's doc comment) —
	// this call now happens BEFORE the investigation rather than after, but a
	// slow tunnel round trip is exactly as real either way.
	//
	// CallToolWithRetry, not plain CallTool: get_gitops_ownership is
	// read-only, so a resend on a transient stall is safe here in a way it
	// is not for the mutating call sites CallToolWithGrace exists for
	// (BACKLOG.md C8, BUGS.md 104) — see that function's doc comment. A
	// single unretried 15s timeout used to permanently lock this whole
	// analysis's route to guidance-only even when the model's own subsequent
	// tool-calling loop re-established the identical ownership fact seconds
	// later (BUGS.md 115).
	//
	// Deliberately NOT wrapped in its own context.WithTimeout(ownershipLookup
	// Timeout) the way the old single-attempt call was, and the way
	// cacheIncidentOwnership's still-unretried call below still is: that
	// bound was sized for exactly one attempt. CallToolWithRetry's first
	// attempt can itself legitimately run for up to gateway's own
	// toolCallTimeout+resultGraceWindow before it even knows it needs to
	// retry, and callToolAttemptWithGrace checks ctx.Err() as the very first
	// thing on the retry attempt (internal/gateway/tools.go) — so an outer
	// 15s deadline would already have expired by the time the retry runs,
	// silently turning the "fix" into a same-shaped call that still only
	// ever tries once. Bounding this by gateway's own worst case (which is
	// what actually determines how long any CallTool*/attempt can take)
	// rather than re-guessing a second, smaller number here is what keeps
	// the retry real. This narrows the failure window; it does not close it
	// — a genuinely down cluster still can't be retried into ownership, and
	// that is the correct, unchanged outcome.
	callCtx := context.WithoutCancel(ctx)
	raw, err := gw.CallToolWithRetry(callCtx, clusterID, "get_gitops_ownership", args)
	if err != nil {
		return nil, orchestrator.OwnershipFacts{}, err
	}

	facts := parseOwnershipFacts(raw)
	if !facts.RepoKnown && (facts.ManagedBy == "helm" || facts.ManagedBy == "none") {
		if enrichedRaw, enrichedFacts, ok := matchObjectMapping(ctx, tx, scmStore, clusterID, raw); ok {
			raw, facts = enrichedRaw, enrichedFacts
		}
	}
	return raw, facts, nil
}

// relatedWorkloadQueryTarget reads incidents.related_workload_key and splits
// it the same "<gvk>|<namespace>|<name>" way pickOwnershipQueryTuple splits
// object_key/workload_key — see internal/gateway/finding.go's
// relatedWorkloadCorrelationKey for the write side (checkOrphanedPVC's own
// field, populated specifically to carry "the StatefulSet this claim was
// made FOR"). Returns ok=false when nothing is stored or it does not parse
// into all three non-empty parts.
func relatedWorkloadQueryTarget(ctx context.Context, tx pgx.Tx, incidentID string) (gvk, namespace, name string, ok bool) {
	var relatedKey *string
	if err := tx.QueryRow(ctx, `SELECT related_workload_key FROM incidents WHERE id = $1`, incidentID).Scan(&relatedKey); err != nil {
		logger.ErrorContext(ctx, "reading the incident's related_workload_key failed", logging.IncidentID(incidentID), logging.Err(err))
		return "", "", "", false
	}
	if relatedKey == nil || *relatedKey == "" {
		return "", "", "", false
	}
	parts := strings.SplitN(*relatedKey, "|", 3)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

// ownershipWire is get_gitops_ownership's full wire shape — every field this
// package's routing needs, decoded without the "no repo means discard
// ManagedBy too" behaviour parseRepoTarget deliberately has for its own,
// different caller (loadRepoTargetWithFallback: "no usable repo" already
// means "refuse" there, so ManagedBy is moot). Routing needs ManagedBy even
// when there is no repo — that is exactly what tells OwnershipUnmanaged
// apart from OwnershipHelmNoRepo — so this is a second, narrower decode
// rather than a change to parseRepoTarget's existing contract.
//
// AppRef and Labels (BACKLOG.md F19) are read only by matchObjectMapping
// below, never by ResolveRoute's classification itself.
type ownershipWire struct {
	ManagedBy string `json:"managed_by"`
	AppRef    *struct {
		Kind      string `json:"kind"`
		Namespace string `json:"namespace,omitempty"`
		Name      string `json:"name"`
	} `json:"app_ref,omitempty"`
	Labels map[string]string `json:"labels,omitempty"`
	Repo   *struct {
		RepoURL        string `json:"repo_url"`
		Applier        string `json:"applier"`
		SourceEditable *bool  `json:"source_editable"`
	} `json:"repo"`
}

func parseOwnershipFacts(raw []byte) orchestrator.OwnershipFacts {
	if len(raw) == 0 {
		return orchestrator.OwnershipFacts{Determined: false}
	}
	var wire ownershipWire
	if err := json.Unmarshal(raw, &wire); err != nil {
		logger.Warn("stored ownership facts do not parse; treating the object as unowned", logging.Err(err))
		return orchestrator.OwnershipFacts{Determined: false}
	}
	facts := orchestrator.OwnershipFacts{Determined: true, ManagedBy: wire.ManagedBy}
	if wire.Repo != nil && wire.Repo.RepoURL != "" {
		facts.RepoKnown = true
		facts.ApplierRaw = wire.Repo.Applier
		facts.SourceEditable = wire.Repo.SourceEditable
	}
	return facts
}

// objectMappingResolveTimeout bounds matchObjectMapping's live calls to the
// matched binding's Git provider (resolving its default branch to a commit)
// — separate from ownershipLookupTimeout because this is a different kind of
// round trip (an HTTPS call to GitHub/GitLab, not the cluster tunnel) that
// must not be allowed to stall an analysis indefinitely just because a
// registered token has gone bad or a provider is slow.
const objectMappingResolveTimeout = 10 * time.Second

// matchObjectMapping is BACKLOG.md F19 mechanism 1's hub-side half. Called
// only when the agent's own answer already says there is no repo (ManagedBy
// "helm" or "none") — never overrides a real GitOps-controller-resolved repo.
//
// raw is the agent's wire bytes, decoded here (again, narrowly) for exactly
// the two pieces of identity F19's two mapping forms need: a Helm release's
// name+namespace (from app_ref, only meaningful when ManagedBy == "helm"),
// and the object's own labels (populated for every ManagedBy value since
// internal/agent/tools.go's F19 widening).
//
// On a match, this ALSO resolves a real commit SHA for the mapping's
// Binding (via its DEFAULT BRANCH, since no GitOps controller exists here to
// report a synced revision) — required because internal/api/
// repository_change.go's loadRepoTarget refuses to open a pull request
// against an unpinned revision (lld/09 §4/§5: never HEAD implicitly, always
// a resolved commit), and there is no controller status to read one from for
// this path. Resolving the DEFAULT branch's current head is the right
// analogue here, not a shortcut: unlike a GitOps-managed object, nothing
// continuously reconciles this one, so there is no "commit actually running"
// for a live SHA read to get stale against — the only question is which
// commit ARGUS's proposed diff is computed against, and the branch tip is
// the obvious answer.
//
// Any failure along the way (no such binding usable, the branch cannot be
// resolved, the provider is unreachable) is logged and treated as "no
// match" — the caller falls through to whatever facts it already had,
// exactly F19's own "give up honestly" framing, never a hard failure of the
// whole analysis.
func matchObjectMapping(ctx context.Context, tx pgx.Tx, scmStore *scm.Store, clusterID string, raw []byte) ([]byte, orchestrator.OwnershipFacts, bool) {
	var wire ownershipWire
	if err := json.Unmarshal(raw, &wire); err != nil {
		return nil, orchestrator.OwnershipFacts{}, false
	}

	var releaseName, releaseNamespace string
	if wire.ManagedBy == "helm" && wire.AppRef != nil {
		releaseName, releaseNamespace = wire.AppRef.Name, wire.AppRef.Namespace
	}
	if releaseName == "" && len(wire.Labels) == 0 {
		return nil, orchestrator.OwnershipFacts{}, false
	}

	matched, found, err := scm.FindObjectMapping(ctx, tx, clusterID, releaseName, releaseNamespace, wire.Labels)
	if err != nil {
		logger.ErrorContext(ctx, "looking for an object mapping failed", logging.ClusterID(clusterID), logging.Err(err))
		return nil, orchestrator.OwnershipFacts{}, false
	}
	if !found {
		return nil, orchestrator.OwnershipFacts{}, false
	}

	resolveCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), objectMappingResolveTimeout)
	defer cancel()
	provider, repoRef, binding, err := scmStore.ProviderFor(resolveCtx, tx, matched.Binding.URL)
	if err != nil {
		logger.WarnContext(ctx, "an object mapping matched but its binding could not be used",
			slog.String("repo_url", matched.Binding.URL), logging.Err(err))
		return nil, orchestrator.OwnershipFacts{}, false
	}
	branch := binding.DefaultBranch
	if branch == "" {
		branch, err = provider.DefaultBranch(resolveCtx, repoRef)
		if err != nil {
			logger.WarnContext(ctx, "an object mapping matched but its default branch could not be resolved",
				slog.String("repo_url", matched.Binding.URL), logging.Err(err))
			return nil, orchestrator.OwnershipFacts{}, false
		}
	}
	sha, err := provider.ResolveRef(resolveCtx, repoRef, branch)
	if err != nil {
		logger.WarnContext(ctx, "an object mapping matched but its branch could not be resolved to a commit",
			slog.String("repo_url", matched.Binding.URL), slog.String("branch", branch), logging.Err(err))
		return nil, orchestrator.OwnershipFacts{}, false
	}

	// Preserve managed_by/app_ref/labels exactly as the agent reported them
	// — only "repo" is ours to add — by decoding into a generic map rather
	// than a fully-typed mirror of gitOpsOwnershipResult, so a future field
	// on that shape survives round-tripping through here without this
	// function having to know about it.
	var generic map[string]json.RawMessage
	if err := json.Unmarshal(raw, &generic); err != nil {
		generic = map[string]json.RawMessage{}
	}
	// Every source a binding maps is editable: a repository change is a set of
	// whole files, so a templated file is no longer refused for its shape. The
	// real gates are per-file path confinement and the denylist in
	// gitops.prepareChanges, then the human reading the diff.
	editable := true
	repoBlob, err := json.Marshal(map[string]any{
		"repo_url":        matched.Binding.URL,
		"path":            matched.Mapping.Path,
		"branch":          branch,
		"revision":        sha,
		"revision_pinned": true,
		"applier":         "none",
		"source_editable": &editable,
		"resolved_from":   objectMappingResolvedFrom(matched, releaseName, releaseNamespace),
	})
	if err != nil {
		return nil, orchestrator.OwnershipFacts{}, false
	}
	generic["repo"] = repoBlob
	enrichedRaw, err := json.Marshal(generic)
	if err != nil {
		return nil, orchestrator.OwnershipFacts{}, false
	}

	facts := orchestrator.OwnershipFacts{
		Determined:     true,
		ManagedBy:      wire.ManagedBy,
		RepoKnown:      true,
		ApplierRaw:     "none",
		SourceEditable: &editable,
	}
	return enrichedRaw, facts, true
}

// objectMappingResolvedFrom is incidentRepoTarget.ResolvedFrom's value for a
// mapping-resolved target — named the same way every other ResolvedFrom
// string in this codebase is (object + field), so a human reading it can
// tell this apart from a live GitOps controller read at a glance.
func objectMappingResolvedFrom(matched scm.MatchedObjectMapping, releaseName, releaseNamespace string) string {
	if releaseName != "" {
		return fmt.Sprintf("repository_bindings %s: operator-declared object mapping for Helm release %s/%s", matched.Binding.URL, releaseNamespace, releaseName)
	}
	return fmt.Sprintf("repository_bindings %s: operator-declared object mapping matched by label selector", matched.Binding.URL)
}
