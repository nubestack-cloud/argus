package api

import (
	"context"
	"encoding/json"
	"fmt"

	"argus/internal/data"
)

// RuleStillFires implements orchestrator.AppliedValueVerifier's third leg —
// BACKLOG.md V3's synthetic post-fix health check. Unlike VerifyAppliedValue/
// VerifyMergedPullRequest (rollback.go, pr_verify.go), which both re-read a
// field ARGUS itself changed, this re-runs the ORIGINAL CHECK that flagged
// the problem — the thing this codebase could not do before BACKLOG.md E9
// gave a declarative rule an addressable identity to re-run.
//
// # Why incidents.opening_rule_id, not Reason
//
// tunnel.Finding.RuleID (and the opening_rule_id column migration 000071
// adds) is what makes this possible at all — see that field's own doc
// comment for why Reason was rejected as a substitute identifier (not
// guaranteed unique across rules, never designed to be a lookup key).
//
// # Scope boundary
//
// evaluated is false — not an error — whenever this incident's own
// opening_rule_id is NULL/empty: an incident opened by one of the 13
// hand-written Go checkers, one of the two watch-based detectors, or a rule
// ID the agent no longer has loaded.
//
// Since BUGS.md 94 that column means "no finding correlated into this
// incident has ever named a rule", not "the first finding to arrive named
// none" — internal/gateway/finding.go's correlation branch fills it from a
// later rule-bearing finding when it is still empty. That widened what this
// check can act on: an incident whose rule genuinely fired but lost the
// arrival race to a warning-event detector on the same object used to be
// out of scope here for a reason that had nothing to do with the rule. See
// orchestrator.AppliedValueVerifier.RuleStillFires's own doc comment for the
// full reasoning; ValidationSweeper.sweep is the caller that acts on this.
func (s *Server) RuleStillFires(ctx context.Context, incidentID string) (evaluated, fires bool, detail string, err error) {
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return false, false, "", fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		return false, false, "", fmt.Errorf("resolve organisation: %w", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		return false, false, "", fmt.Errorf("set request scope: %w", err)
	}

	var clusterID string
	var ruleID *string
	if err := tx.QueryRow(ctx, `SELECT cluster_id, opening_rule_id FROM incidents WHERE id = $1`, incidentID).Scan(&clusterID, &ruleID); err != nil {
		return false, false, "", fmt.Errorf("load incident %s: %w", incidentID, err)
	}
	if ruleID == nil || *ruleID == "" {
		// Scope boundary, not a failure — see doc comment above.
		return false, false, "", nil
	}

	// ownershipQueryTarget prefers workload_key over object_key, but every
	// rule-addressable kind (PodDisruptionBudget, NetworkPolicy,
	// ResourceQuota, cert-manager Certificate, per BACKLOG.md E9) is never a
	// Pod's owning workload in the sense workload_key means, so this always
	// falls through to object_key for a rule-originated incident — the same
	// resolver VerifyMergedPullRequest already trusts, not a second one.
	gvk, namespace, name, sourceKey, err := ownershipQueryTarget(ctx, tx, incidentID)
	if err != nil {
		return false, false, "", fmt.Errorf("resolve object for incident %s: %w", incidentID, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, false, "", fmt.Errorf("commit: %w", err)
	}
	if sourceKey == "" {
		return false, false, "", fmt.Errorf("incident %s has no object recorded to re-check rule %s against", incidentID, *ruleID)
	}
	if !s.gw.IsConnected(clusterID) {
		return false, false, "", fmt.Errorf("cluster %s is not connected", clusterID)
	}

	argsJSON, err := json.Marshal(map[string]any{"ruleId": *ruleID, "namespace": namespace, "name": name})
	if err != nil {
		return false, false, "", fmt.Errorf("build reevaluate_rule args: %w", err)
	}
	raw, err := s.gw.CallTool(ctx, clusterID, "reevaluate_rule", argsJSON)
	if err != nil {
		return false, false, "", fmt.Errorf("re-check rule %s on %s %s/%s: %w", *ruleID, gvk, namespace, name, err)
	}

	var result struct {
		Found   bool   `json:"found"`
		Fires   bool   `json:"fires"`
		Message string `json:"message,omitempty"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return false, false, "", fmt.Errorf("decode reevaluate_rule result for rule %s: %w", *ruleID, err)
	}

	if !result.Found {
		// The object itself is gone — a legitimately different sentence from
		// "the condition cleared on a live object" (see
		// reevaluateRuleResult.Found's own doc comment, internal/agent/tools.go).
		return true, false, fmt.Sprintf("%s %s/%s no longer exists", gvk, namespace, name), nil
	}
	if result.Fires {
		msg := result.Message
		if msg == "" {
			return true, true, fmt.Sprintf("rule %s still fires on %s %s/%s", *ruleID, gvk, namespace, name), nil
		}
		return true, true, fmt.Sprintf("rule %s still fires on %s %s/%s: %s", *ruleID, gvk, namespace, name, msg), nil
	}
	return true, false, fmt.Sprintf("rule %s no longer fires on %s %s/%s", *ruleID, gvk, namespace, name), nil
}
