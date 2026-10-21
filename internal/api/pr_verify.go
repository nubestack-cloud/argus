package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"argus/internal/data"
	"argus/internal/scm"
)

// VerifyMergedPullRequest implements orchestrator.AppliedValueVerifier's
// pull-request half — lld/08-remediation-contracts.md §12.8, closing
// BUGS.md 77.
//
// # Why this exists alongside VerifyAppliedValue
//
// The pull-request route mutates a repository, not a cluster, so it never
// writes a remediation_executions row — VerifyAppliedValue has nothing to key
// on. This dispatches to whichever of two assertions incident's recorded pull
// request supports, in order of preference:
//
//  1. verifyMergedPullRequestField — the single-field grammar's own re-check
//     (incidents.pr_field_path/pr_expected_value, migration 000059). Nothing
//     writes those columns any more (2026-08-28): the whole-file grammar has
//     no single field to re-assert. This branch survives ONLY for pull
//     requests opened by earlier builds, whose columns are still populated —
//     see BACKLOG.md F23's regression requirement, and the test with the
//     same name.
//  2. verifyMergedPullRequestFiles — BACKLOG.md F23's whole-file successor
//     (incidents.pr_proposed_files, migration 000075): re-read every file
//     the pull request changed, at the revision the GitOps controller
//     currently reports synced, and compare it byte-for-byte against what
//     was proposed. This is what every pull request opened since the
//     whole-file grammar landed uses.
//
// Neither recorded (a pull request opened between the two migrations, or one
// whose bookkeeping write failed) falls all the way back to
// ValidationSweeper's quiet-grace-period behaviour — the honest degradation,
// not a manufactured recurrence.
//
// # What an error means, and why that is not "the change is gone"
//
// Same contract as VerifyAppliedValue, in both branches: every "cannot tell"
// path returns an error rather than held=false. An unreachable cluster or
// provider falls back to ValidationSweeper's quiet-grace-period behaviour
// rather than being manufactured into a recurrence.
func (s *Server) VerifyMergedPullRequest(ctx context.Context, incidentID string) (bool, string, error) {
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return false, "", fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		return false, "", fmt.Errorf("resolve organisation: %w", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		return false, "", fmt.Errorf("set request scope: %w", err)
	}

	var clusterID string
	var fieldPath, expectedValue *string
	var proposedFilesRaw []byte
	if err := tx.QueryRow(ctx,
		`SELECT cluster_id, pr_field_path, pr_expected_value, pr_proposed_files FROM incidents WHERE id = $1`, incidentID,
	).Scan(&clusterID, &fieldPath, &expectedValue, &proposedFilesRaw); err != nil {
		return false, "", fmt.Errorf("load incident %s: %w", incidentID, err)
	}

	// The legacy single-field grammar takes precedence when both happen to be
	// recorded — that should not occur in practice (the two columns are
	// mutually exclusive by construction, see recordOpenedPullRequest and
	// approveByOpeningPullRequest), but preferring it keeps this branch's
	// behaviour EXACTLY what it was before migration 000075 for any pull
	// request that predates the whole-file grammar, which is the regression
	// guard BACKLOG.md F23 asks for.
	if fieldPath != nil && expectedValue != nil {
		return s.verifyMergedPullRequestField(ctx, tx, incidentID, clusterID, *fieldPath, *expectedValue)
	}

	if len(proposedFilesRaw) == 0 {
		return false, "", fmt.Errorf("incident %s has no recorded field path/value or proposed file content to re-check — its pull request predates migration 000059/000075, or opened through a path that recorded neither", incidentID)
	}
	var proposed []prProposedFile
	if err := json.Unmarshal(proposedFilesRaw, &proposed); err != nil {
		return false, "", fmt.Errorf("incident %s has recorded proposed file content that does not parse: %w", incidentID, err)
	}
	if len(proposed) == 0 {
		return false, "", fmt.Errorf("incident %s recorded a pull request with no changed files to re-check", incidentID)
	}
	return s.verifyMergedPullRequestFiles(ctx, tx, incidentID, clusterID, proposed)
}

// verifyMergedPullRequestField is the single-field grammar's own post-merge
// assertion, unchanged in behaviour from before migration 000075: re-read the
// field a merged, synced pull request changed and compare it against what was
// recorded when it opened. Kept only for pull requests opened before
// 2026-08-28, whose incidents.pr_field_path/pr_expected_value are still
// populated — see VerifyMergedPullRequest's own doc comment.
func (s *Server) verifyMergedPullRequestField(ctx context.Context, tx pgx.Tx, incidentID, clusterID, fieldPath, expectedValue string) (bool, string, error) {
	gvk, namespace, name, sourceKey, err := ownershipQueryTarget(ctx, tx, incidentID)
	if err != nil {
		return false, "", fmt.Errorf("resolve object for incident %s: %w", incidentID, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, "", fmt.Errorf("commit: %w", err)
	}
	if sourceKey == "" {
		return false, "", fmt.Errorf("incident %s has no object recorded to re-check the merged change against", incidentID)
	}
	if !s.gw.IsConnected(clusterID) {
		return false, "", fmt.Errorf("cluster %s is not connected", clusterID)
	}

	// Everything past here is a network call (tunnel), so it runs outside the
	// transaction above — the same shape rollback.VerifyAppliedValue and
	// mergecheck.CheckPullRequestMerged use for the same reason.
	_, _, live, err := s.exec().FetchPreconditionWithObject(ctx, clusterID, gvk, namespace, name)
	if err != nil {
		return false, "", fmt.Errorf("read %s %s/%s: %w", gvk, namespace, name, err)
	}
	var obj map[string]any
	if err := json.Unmarshal(live, &obj); err != nil {
		return false, "", fmt.Errorf("decode live object: %w", err)
	}

	segments := splitLiveFieldPath(fieldPath)
	current, found, err := nestedFieldAtPath(obj, segments)
	if err != nil {
		return false, "", fmt.Errorf("cannot address %s on the live object: %w", fieldPath, err)
	}
	if !found {
		return false, fmt.Sprintf("%s is no longer set on %s %s/%s", fieldPath, gvk, namespace, name), nil
	}
	currentStr := stringifyLiveValue(current)
	if currentStr == expectedValue {
		return true, fmt.Sprintf("%s is still %q", fieldPath, currentStr), nil
	}
	return false, fmt.Sprintf("%s: the merged pull request set it to %q and it is now %q", fieldPath, expectedValue, currentStr), nil
}

// verifyMergedPullRequestFiles is BACKLOG.md F23's whole-file post-merge
// assertion: re-read each file this pull request changed, at the revision the
// GitOps controller CURRENTLY reports synced, and compare it byte-for-byte
// against what was proposed (incidents.pr_proposed_files, migration 000075 —
// captured from the same gitops.ChangeVerification the pull request body and
// audit record already quote, so this compares against what actually landed).
//
// # Why the currently synced revision, not the merge commit or the stored one
//
// incidents.ownership is written once, at analysis time, and is never
// refreshed by a later merge — using its stored Revision here would compare
// against a commit from BEFORE this incident's own fix landed. The correct
// revision is a LIVE re-check of get_gitops_ownership, the exact call
// mergecheck.CheckPullRequestMerged already makes to confirm a merge synced
// (internal/api/mergecheck.go's syncedPastMergeCommit) — reusing it here
// rather than trusting the merge commit itself matters because a later,
// unrelated commit can revert or conflict with this one AFTER the sync that
// promoted the incident to Validating; re-reading at whatever is synced NOW
// is what actually answers "does the file still carry what was merged".
//
// # What this does and does not establish
//
// This answers "did the file content survive" — not "did the cluster object's
// health improve", which BACKLOG.md F23 draws as a deliberately separate
// question. That second half is ValidationSweeper's own
// AppliedValueVerifier.RuleStillFires (the E9 rule re-run) plus its
// siblingStillFailing/grace-period logic in validation.go's sweep, all of
// which run independently of and in addition to this — see that function's
// own doc comments for the scope boundary already drawn there (it only
// re-runs a check for an incident whose opening finding came from a known
// declarative rule).
func (s *Server) verifyMergedPullRequestFiles(ctx context.Context, tx pgx.Tx, incidentID, clusterID string, proposed []prProposedFile) (bool, string, error) {
	target, err := loadRepoTarget(ctx, tx, incidentID)
	if err != nil {
		return false, "", fmt.Errorf("read incident %s's GitOps ownership: %w", incidentID, err)
	}
	if target == nil || target.RepoURL == "" {
		return false, "", fmt.Errorf("incident %s has no recorded repository to re-check its merged files against", incidentID)
	}
	provider, repo, _, err := s.scmStore.ProviderFor(ctx, tx, target.RepoURL)
	if err != nil {
		return false, "", fmt.Errorf("resolve provider for %s: %w", target.RepoURL, err)
	}

	gvk, namespace, name, sourceKey, err := ownershipQueryTarget(ctx, tx, incidentID)
	if err != nil {
		return false, "", fmt.Errorf("resolve object for incident %s: %w", incidentID, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, "", fmt.Errorf("commit: %w", err)
	}
	if sourceKey == "" {
		return false, "", fmt.Errorf("incident %s has no object recorded to re-check the currently synced revision against", incidentID)
	}
	if !s.gw.IsConnected(clusterID) {
		return false, "", fmt.Errorf("cluster %s is not connected", clusterID)
	}

	// Everything past here is a network call (tunnel, provider API), so it
	// runs outside the transaction above — the same shape
	// verifyMergedPullRequestField and mergecheck.CheckPullRequestMerged use
	// for the same reason.
	args, err := json.Marshal(map[string]string{"gvk": gvk, "namespace": namespace, "name": name})
	if err != nil {
		return false, "", fmt.Errorf("build ownership args: %w", err)
	}
	raw, err := s.gw.CallTool(ctx, clusterID, "get_gitops_ownership", args)
	if err != nil {
		return false, "", fmt.Errorf("re-check GitOps ownership for incident %s: %w", incidentID, err)
	}
	live := parseRepoTarget(ctx, raw, incidentID)
	if live == nil || strings.TrimSpace(live.Revision) == "" {
		return false, "", fmt.Errorf("incident %s's GitOps controller reports no synced revision to re-check the merged files against", incidentID)
	}

	return compareProposedFilesAtRevision(ctx, provider, repo, live.Revision, proposed)
}

// compareProposedFilesAtRevision is the actual byte-for-byte assertion,
// pulled out of verifyMergedPullRequestFiles so it is testable against a
// fake scm.Provider with no database or live tunnel involved — the same
// separation mergecheck.go's syncedPastMergeCommit already draws for the
// ancestry check it makes, and for the same reason: everything ABOVE this
// (resolving the incident's repository, asking the cluster what it currently
// has synced) needs real infrastructure this package's tests don't stand up;
// everything in this function is pure given its inputs.
//
// revision is the commit to read at — the caller's job is making sure that is
// the CURRENTLY synced one, not this function's.
func compareProposedFilesAtRevision(ctx context.Context, provider scm.Provider, repo scm.Repo, revision string, proposed []prProposedFile) (bool, string, error) {
	for _, f := range proposed {
		content, readErr := provider.ReadFile(ctx, repo, revision, f.Path)
		if f.Deleted {
			// The comparison a deletion needs is the INVERSE of a write's:
			// the file must still be ABSENT at the currently synced
			// revision. Its continued absence is what a merged delete
			// looks like surviving, not a failure to re-read it.
			switch {
			case errors.Is(readErr, scm.ErrNotFound):
				continue
			case readErr != nil:
				return false, "", fmt.Errorf("re-read %s at %s: %w", f.Path, revision, readErr)
			default:
				return false, fmt.Sprintf("%s exists again at the synced revision %s — this pull request deleted it, but something has since re-added it", f.Path, shortRevision(revision)), nil
			}
		}
		switch {
		case errors.Is(readErr, scm.ErrNotFound):
			return false, fmt.Sprintf("%s no longer exists at the synced revision %s — it existed when this pull request merged", f.Path, shortRevision(revision)), nil
		case readErr != nil:
			return false, "", fmt.Errorf("re-read %s at %s: %w", f.Path, revision, readErr)
		}
		if string(content) != f.Content {
			return false, fmt.Sprintf("%s at the synced revision %s no longer matches what this pull request merged — something changed it afterward", f.Path, shortRevision(revision)), nil
		}
	}
	return true, fmt.Sprintf("%d file(s) at the synced revision %s still match what this pull request merged", len(proposed), shortRevision(revision)), nil
}

// splitLiveFieldPath normalises bracket/dot/slash notation into segments,
// matching remediation.normaliseFieldPath — the same notation the model and
// the PatchField allowlist both already split on. Duplicated locally rather than exported from either
// package: internal/agent's own patchfield.go carries this exact duplication
// for the same reason (see its normalisePath doc comment) — this reads a live
// object over the tunnel, which is a different shape of data than either
// package's own input.
func splitLiveFieldPath(p string) []string {
	p = strings.ReplaceAll(p, "[", ".")
	p = strings.ReplaceAll(p, "]", "")
	p = strings.ReplaceAll(p, "/", ".")
	segments := make([]string, 0, 8)
	for _, seg := range strings.Split(p, ".") {
		if strings.TrimSpace(seg) != "" {
			segments = append(segments, seg)
		}
	}
	return segments
}

// nestedFieldAtPath walks a decoded live object, handling both map keys and
// list indices — the read-side counterpart of internal/agent/patchfield.go's
// nestedFieldAt, operating on a plain describe_resource result instead of an
// unstructured.Unstructured, since this runs hub-side and has no client-go
// object to walk.
func nestedFieldAtPath(obj map[string]any, segments []string) (any, bool, error) {
	var cur any = obj
	for i, seg := range segments {
		switch node := cur.(type) {
		case map[string]any:
			v, ok := node[seg]
			if !ok {
				return nil, false, nil
			}
			cur = v
		case []any:
			idx, err := strconv.Atoi(seg)
			if err != nil {
				return nil, false, fmt.Errorf("%q is a list, so %q must be an index", strings.Join(segments[:i], "."), seg)
			}
			if idx < 0 || idx >= len(node) {
				return nil, false, nil
			}
			cur = node[idx]
		default:
			return nil, false, fmt.Errorf("%q is a single value, so %q cannot be read from it", strings.Join(segments[:i], "."), seg)
		}
	}
	return cur, true, nil
}

// stringifyLiveValue renders a decoded JSON value as the literal string form
// every plan/params/verification value elsewhere in this codebase uses — the
// same "compare as strings" convention rollback.go's undo comparison and
// remediation.PatchFieldParams use.
//
// float64 gets special handling because encoding/json decodes every JSON
// number into one, and a whole-number field (replicas, a port) must compare
// equal to the plain integer string ProposeFieldChange recorded, not to a
// %v rendering that happens to differ (e.g. exponent form on a large value).
func stringifyLiveValue(v any) string {
	if f, ok := v.(float64); ok && f == float64(int64(f)) {
		return strconv.FormatInt(int64(f), 10)
	}
	return fmt.Sprintf("%v", v)
}
