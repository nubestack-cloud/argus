package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"argus/internal/data"
	"argus/internal/orchestrator"
	"argus/internal/scm"
)

// CheckPullRequestMerged implements orchestrator.PullRequestMergeChecker —
// see that interface's own doc comment for why this lives here rather than
// in internal/orchestrator (it needs the scm provider and a live tunnel
// call, and internal/gateway already imports internal/orchestrator, so that
// package cannot import either back).
//
// Read-only start to finish. Nothing here writes anything — MergeSweeper's
// own sweep is what records pr_merged_at and moves the incident to
// Validating, once this reports Merged && Synced.
func (s *Server) CheckPullRequestMerged(ctx context.Context, incidentID string) (orchestrator.PullRequestOutcome, error) {
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return orchestrator.PullRequestOutcome{}, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		return orchestrator.PullRequestOutcome{}, fmt.Errorf("resolve organisation: %w", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		return orchestrator.PullRequestOutcome{}, fmt.Errorf("set request scope: %w", err)
	}

	var clusterID string
	var prNumber *int
	err = tx.QueryRow(ctx, `SELECT cluster_id, pr_number FROM incidents WHERE id = $1`, incidentID).Scan(&clusterID, &prNumber)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return orchestrator.PullRequestOutcome{}, fmt.Errorf("incident %s not found", incidentID)
	case err != nil:
		return orchestrator.PullRequestOutcome{}, fmt.Errorf("read incident %s: %w", incidentID, err)
	case prNumber == nil:
		return orchestrator.PullRequestOutcome{}, fmt.Errorf("incident %s has no recorded pull request number", incidentID)
	}

	target, err := loadRepoTarget(ctx, tx, incidentID)
	if err != nil {
		return orchestrator.PullRequestOutcome{}, fmt.Errorf("read incident %s's GitOps ownership: %w", incidentID, err)
	}
	if target == nil || target.RepoURL == "" {
		return orchestrator.PullRequestOutcome{}, fmt.Errorf("incident %s has no recorded repository", incidentID)
	}

	provider, repo, _, err := s.scmStore.ProviderFor(ctx, tx, target.RepoURL)
	if err != nil {
		return orchestrator.PullRequestOutcome{}, fmt.Errorf("resolve provider for %s: %w", target.RepoURL, err)
	}

	// The same workload_key-over-object_key preference loadRepoTargetWithFallback
	// uses, and for the same reason: re-checking sync means asking the cluster
	// about this object again, and the incident's own object_key is frequently a
	// long-gone Pod by the time a PR has merged.
	gvk, namespace, name, sourceKey, err := ownershipQueryTarget(ctx, tx, incidentID)
	if err != nil {
		return orchestrator.PullRequestOutcome{}, fmt.Errorf("resolve object to re-check sync for incident %s: %w", incidentID, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return orchestrator.PullRequestOutcome{}, fmt.Errorf("commit: %w", err)
	}

	// Everything past here is a network call (provider API, tunnel), so it runs
	// outside the transaction above — the same shape rollback.go's
	// VerifyAppliedValue uses for the same reason.
	status, err := provider.PullRequestStatus(ctx, repo, *prNumber)
	if err != nil {
		return orchestrator.PullRequestOutcome{}, fmt.Errorf("check pull request #%d: %w", *prNumber, err)
	}
	if !status.Merged {
		// BUGS.md 82: State is the provider's own word for whether this PR is
		// still under review ("open") or was rejected ("closed" without ever
		// merging) — MergeSweeper needs that distinction to stop waiting on a
		// merge that already isn't coming. CreatedAt rides along so the
		// still-open case can be checked for staleness without a second call.
		return orchestrator.PullRequestOutcome{Closed: status.State == "closed", CreatedAt: status.CreatedAt}, nil
	}

	if sourceKey == "" {
		// Merged, but there is no object left to ask the cluster about.
		// Treated as unconfirmed rather than assumed synced — this
		// checker's contract is that an error leaves the incident exactly
		// where it was, retried next tick, not advanced on ignorance.
		return orchestrator.PullRequestOutcome{}, fmt.Errorf("incident %s's pull request #%d merged, but the incident has no object left to confirm sync against", incidentID, *prNumber)
	}
	if !s.gw.IsConnected(clusterID) {
		return orchestrator.PullRequestOutcome{}, fmt.Errorf("cluster %s is not connected — cannot confirm the merge synced yet", clusterID)
	}
	args, err := json.Marshal(map[string]string{"gvk": gvk, "namespace": namespace, "name": name})
	if err != nil {
		return orchestrator.PullRequestOutcome{}, fmt.Errorf("build ownership args: %w", err)
	}
	raw, err := s.gw.CallTool(ctx, clusterID, "get_gitops_ownership", args)
	if err != nil {
		return orchestrator.PullRequestOutcome{}, fmt.Errorf("re-check GitOps ownership for incident %s (%s): %w", incidentID, sourceKey, err)
	}
	live := parseRepoTarget(ctx, raw, incidentID)
	synced, err := syncedPastMergeCommit(ctx, provider, repo, status.MergeCommitSHA, live)
	if err != nil {
		// BUGS.md 81's own constraint: an ancestry check that could not be
		// made (unreachable provider, an unknown SHA) is a failed CHECK, not
		// a verdict — it must read the same as any other error from this
		// function, leaving the incident in AwaitingMerge to be retried next
		// tick, never as "not synced".
		return orchestrator.PullRequestOutcome{}, fmt.Errorf("check whether incident %s's synced revision has caught up to merge commit %s: %w", incidentID, status.MergeCommitSHA, err)
	}
	return orchestrator.PullRequestOutcome{Merged: true, MergedAt: status.MergedAt, Synced: synced}, nil
}

// syncedPastMergeCommit answers whether the GitOps controller's reported
// revision has caught up to a merge commit — BUGS.md 81: exact SHA equality
// alone under-reports this, because any later commit landing on the base
// branch before the next sync makes the controller's reported revision a
// DESCENDANT of the merge commit rather than equal to it, and the fix this PR
// carried is present in that descendant just as much as in the merge commit
// itself. On a repository where more than one pull request merges per sync
// interval, the exact-equality check never fires again after the first.
//
// The exact-equality comparison stays as the fast path — true for the
// overwhelmingly common case of nothing else landing in between, and free —
// so IsAncestor's extra network call is only paid when that comparison is
// false, not on every tick.
func syncedPastMergeCommit(ctx context.Context, provider scm.Provider, repo scm.Repo, mergeCommitSHA string, live *incidentRepoTarget) (bool, error) {
	if live == nil || live.Revision == "" {
		return false, nil
	}
	if live.Revision == mergeCommitSHA {
		return true, nil
	}
	return provider.IsAncestor(ctx, repo, mergeCommitSHA, live.Revision)
}
