package execution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"argus/internal/logging"
	"argus/internal/objdiff"
)

const GuardrailGitOpsManaged = "gitOpsManaged"

// ErrGitOpsManagedRefused is the sentinel for a refusal to patch an object whose
// spec is owned elsewhere. Its own error type, like ErrScaleFromZeroRefused, so
// handleApproveIncident can map it to a distinct problem type and the UI can
// offer the matching confirmation instead of matching on message text.
var ErrGitOpsManagedRefused = errors.New("refusing to patch a GitOps-managed object without explicit confirmation")

// checkGitOpsPrecedence refuses an in-place patch when a Helm release or an
// Argo CD/Flux controller owns the target's spec — DESIGN.md
// §10.1's precedence rule, previously unimplemented for every action type.
//
// The problem it solves is not hypothetical on a real fleet: the cluster this is
// tested against runs its applications from a Helm release, so an in-place patch
// there is undone by the next `helm upgrade` and the incident reopens. ARGUS
// already TOLD the operator that (the ownership caveat on the incident page);
// nothing stopped it from doing it anyway, which meant recording a "successful"
// remediation that quietly disappears.
//
// Ownership comes from incidents.ownership (migration 000038 — determined by the
// hub at analysis time), and falls back to asking the cluster live when that is
// absent. The live fallback matters: an incident analysed before that migration,
// or one whose ownership call failed, would otherwise read as "unowned" and slip
// through the guardrail entirely. Approval is exactly the right moment to pay
// for one extra tunnel call — it already makes several.
//
// FAILS CLOSED. If ownership cannot be determined at all, the patch is refused
// rather than allowed: an unreadable answer is not evidence of absence, and the
// cost of being wrong in the permissive direction is a fix that silently
// evaporates. The operator can still proceed by stating the intent explicitly,
// which is the same shape as the scale-from-zero guardrail.
func (s *Executor) checkGitOpsPrecedence(ctx context.Context, scope Scope,
	incidentID, clusterID, gvk, namespace, name string, confirmed bool,
	liveObject json.RawMessage, plannedPaths []string) error {
	if confirmed {
		// The operator has stated they know this is a stop-gap. Recorded in the
		// audit details either way (see recordExecutingTransition), so a
		// confirmed override is never silent.
		return nil
	}

	managedBy, source := s.resolveOwnership(ctx, scope, incidentID, clusterID, gvk, namespace, name)
	switch managedBy {
	case "":
		return fmt.Errorf("%w: ARGUS could not determine whether a Helm release or a GitOps controller owns %s %s/%s, so it cannot rule out that this patch would be reverted on the next reconcile. If you have checked and want to proceed anyway, approve again with \"confirmGitOpsManaged\": true", ErrGitOpsManagedRefused, gvk, namespace, name)
	case "none":
		return nil
	}

	// A named source makes the message actionable — an operator can go and change
	// the right chart or manifest instead of guessing which one.
	where := managedBy
	if source != "" {
		where = managedBy + " (" + source + ")"
	}

	// DESIGN.md §11.2 rung 4, BACKLOG F16 item 1: which controller owns the
	// SPECIFIC field this patch writes. A different question from "who owns the
	// object", and the one that decides whether the patch survives.
	//
	// It sharpens the message in both directions but deliberately does NOT change
	// the verdict, and that restraint is the decision worth recording. §11.2 calls
	// managedFields a "weaker signal" and it is right: whether an *unmanaged* field
	// survives a sync depends on the controller's apply strategy — a server-side
	// apply leaves unowned fields alone, while a client-side apply or a replace can
	// rewrite the whole spec — and ARGUS cannot see which is configured. So an
	// uncontended field is reported as probably-durable rather than waved through.
	// Auto-allowing on a signal the design calls weak would trade a false refusal
	// for a silently reverted fix, which is the worse failure.
	if detail := fieldContentionDetail(liveObject, plannedPaths); detail != "" {
		return fmt.Errorf("%w: %s %s/%s is managed by %s. %s If you want the symptom gone now and will fix the source afterwards, approve again with \"confirmGitOpsManaged\": true; the confirmation is recorded in the audit trail",
			ErrGitOpsManagedRefused, gvk, namespace, name, where, detail)
	}
	return fmt.Errorf("%w: %s %s/%s is managed by %s, so this in-place change is a stop-gap — the next reconcile or upgrade rewrites that object from its source and the problem returns. Make the same change at the source. If you want the symptom gone now and will fix the source afterwards, approve again with \"confirmGitOpsManaged\": true; the confirmation is recorded in the audit trail", ErrGitOpsManagedRefused, gvk, namespace, name, where)
}

// ErrDeleteResourcePVCManagedRefused is the sentinel for DeleteResource's own
// PersistentVolumeClaim-specific ownership re-check below. Its own error
// type, matching ErrGitOpsManagedRefused/ErrNamespaceProtectedRefused, so a
// caller can distinguish this refusal from either of those rather than
// matching on message text.
//
// NO CONFIRMATION EVER WAIVES IT — unlike ErrGitOpsManagedRefused, which
// checkGitOpsPrecedence lets an operator waive with confirmGitOpsManaged:true
// for every OTHER action type. That override exists because a patch that
// turns out to be reverted next reconcile is recoverable: the operator finds
// out, the object goes back to what the source declares, nothing is lost.
// A DeleteResource plan against a PersistentVolumeClaim has no such
// recovery — DESIGN.md §10.5 states plainly that deletion is "effectively
// irreversible," and internal/remediation/deleteresource.go's own allowlist
// entry narrows this action's reach to exactly the case where nothing
// declares the claim at all. Letting an operator confirm past THAT specific
// combination — irreversible, and the one precondition the allowlist row
// exists to enforce — would recreate exactly the flat "delete a PVC" hazard
// DESIGN.md §9.3's forbidden tier exists to rule out, just with an extra
// click in front of it. So this check runs unconditionally, ignoring
// whatever the request's overrides carry, matching
// ErrNamespaceProtectedRefused's "no confirmation ever waives it" posture
// rather than ErrGitOpsManagedRefused's confirmable one.
var ErrDeleteResourcePVCManagedRefused = errors.New("refusing to delete a PersistentVolumeClaim that is not genuinely orphaned")

// checkDeleteResourcePVCOwnership is the ownership half of the
// PersistentVolumeClaim precondition internal/remediation/deleteresource.go's
// allowlist entry and internal/agent/deleteresource.go's header comment both
// describe — the liveness half (no Pod references the claim) is that
// agent-side tool's own job, re-checked live immediately before the DELETE
// call; this is the OTHER live re-check, ahead of signing.
//
// FAILS CLOSED exactly like checkGitOpsPrecedence: an unreadable answer
// ("") is refused, not treated as "probably fine." Unlike
// checkGitOpsPrecedence, there is no confirmed bool parameter at all —
// see ErrDeleteResourcePVCManagedRefused's own doc comment for why this
// specific combination gets no override, ever.
//
// DELIBERATELY calls liveGitOpsOwnership directly, never resolveOwnership —
// see liveGitOpsOwnership's own doc comment for why the incidents.ownership
// cache is exactly the wrong thing to trust here: for THIS incident shape
// (checkOrphanedPVC's own object_key IS the PVC a DeleteResource plan
// targets), resolveOwnership's cache-hit path would return whatever
// gatherOwnershipFacts adopted for ROUTING (BUGS.md 118 part (a) —
// correctly the related StatefulSet's "argocd", when that StatefulSet is
// GitOps-managed), not the PVC's own literal, correct "none". Trusting that
// cached, adopted value here would refuse the exact case this mechanism
// exists for.
func (s *Executor) checkDeleteResourcePVCOwnership(ctx context.Context, clusterID, gvk, namespace, name string) error {
	managedBy, source := s.liveGitOpsOwnership(ctx, clusterID, gvk, namespace, name)
	if managedBy == "none" {
		return nil
	}
	if managedBy == "" {
		return fmt.Errorf("%w: ARGUS could not determine whether anything owns %s %s/%s, and this action type has no confirmation override — re-analyze this incident once ownership can be resolved",
			ErrDeleteResourcePVCManagedRefused, gvk, namespace, name)
	}
	where := managedBy
	if source != "" {
		where = managedBy + " (" + source + ")"
	}
	return fmt.Errorf("%w: %s %s/%s is managed by %s — this is not the orphaned/unmanaged case internal/remediation/deleteresource.go's allowlist entry permits, and there is no confirmation that waives this check for a delete",
		ErrDeleteResourcePVCManagedRefused, gvk, namespace, name, where)
}

// fieldContentionDetail turns the live object's managedFields into one sentence
// about the field(s) this patch writes, or "" when there is nothing specific to
// say.
//
// Empty covers three genuinely different situations, and collapsing them is
// correct here: no live object (a preflight that could not read one), an action
// type with no known paths, or a field nothing contends. In all three the caller
// falls back to the object-level message, which is the honest thing to say when
// no field-level claim can be made.
func fieldContentionDetail(liveObject json.RawMessage, plannedPaths []string) string {
	if len(liveObject) == 0 || len(plannedPaths) == 0 {
		return ""
	}
	var obj map[string]any
	if err := json.Unmarshal(liveObject, &obj); err != nil {
		return ""
	}

	var contended []string
	var uncontended []string
	for _, path := range plannedPaths {
		owners := objdiff.OwnersOf(obj, path)
		if msg := objdiff.DescribeContention(path, owners, argusFieldManager); msg != "" {
			contended = append(contended, msg)
			continue
		}
		uncontended = append(uncontended, path)
	}

	switch {
	case len(contended) > 0:
		// The precise version of the warning F16 item 1 asked for: not "this
		// object is GitOps-managed" but which field and which manager. The
		// reversion claim is made HERE rather than in objdiff, because it follows
		// from the caller already knowing a reconciling controller owns the object
		// — not from the field-management operation, which live data showed does
		// not predict it (see objdiff.DescribeContention).
		return strings.Join(contended, "; ") + " — the controller that owns this object reasserts that field on its next reconcile, so this patch is reverted rather than kept."
	case len(uncontended) > 0:
		// The other direction, and the more common one on a chart that does not
		// set every field it could. Stated as a probability rather than a promise,
		// for the reason the caller's comment gives.
		return fmt.Sprintf("No controller currently manages %s, so this patch will probably survive the next sync — but that depends on the controller's apply strategy, which ARGUS cannot see, so it is not a guarantee.",
			strings.Join(uncontended, " or "))
	}
	return ""
}

// resolveOwnership returns (managedBy, sourceDescription). managedBy is "" when
// it genuinely could not be determined, "none" when nothing owns the object, and
// otherwise the controller/release kind. Stored value first, live call second —
// see checkGitOpsPrecedence for why both.
func (s *Executor) resolveOwnership(ctx context.Context, scope Scope,
	incidentID, clusterID, gvk, namespace, name string) (managedBy, source string) {
	var raw []byte
	var storedKey *string
	if err := scope.Tx.QueryRow(ctx,
		`SELECT ownership, object_key FROM incidents WHERE id = $1`, incidentID).Scan(&raw, &storedKey); err != nil {
		logger.ErrorContext(ctx, "reading the incident's stored GitOps ownership failed",
			logging.IncidentID(incidentID), logging.Err(err))
	}

	// The cached answer is only usable if it is about the object we are ABOUT TO
	// PATCH. It is not always: cacheIncidentOwnership asks about the incident's
	// own object (incidents.object_key), and for the most common findings —
	// OOMKilled, CrashLoopBackOff — that object is the POD, while the patch
	// target is the Deployment its owner chain resolves to.
	//
	// Using it anyway is not a mild inaccuracy, it inverts the guardrail.
	// Helm's meta.helm.sh/release-name is written on the Deployment and NOT on
	// its pods (verified on a live Helm-managed workload: the Deployment carries
	// the release annotation, the pod carries nothing); Argo's instance label
	// and tracking-id land on the Deployment too, since pods only inherit
	// pod-TEMPLATE labels. So a Pod-scoped lookup returns "none", and "none" is
	// the one answer that means "go ahead" — the guardrail would confidently
	// permit precisely the Helm-managed patch it exists to stop.
	//
	// A stale-but-correct-object answer is fine (ownership does not churn); a
	// fresh answer about the wrong object is not. So the cache is used only on
	// an exact tuple match, and every other case pays for a live lookup against
	// the resolved target.
	if len(raw) > 0 && (storedKey == nil || *storedKey != gvk+"|"+namespace+"|"+name) {
		raw = nil
	}

	if len(raw) == 0 {
		return s.liveGitOpsOwnership(ctx, clusterID, gvk, namespace, name)
	}
	return parseOwnershipResult(raw)
}

// liveGitOpsOwnership calls get_gitops_ownership fresh, over the tunnel,
// against exactly the (gvk, namespace, name) given — no cache, no
// incidents.ownership read, ever. Extracted from resolveOwnership's own live
// branch so checkDeleteResourcePVCOwnership can call it directly: that
// check's whole point is to never trust anything cached about this
// incident, because incidents.ownership can legitimately hold an ADOPTED
// answer about a DIFFERENT object (routing.go's gatherOwnershipFacts falls
// back to the related workload's ownership — BUGS.md 118 part (a) — and
// writes THAT into incidents.ownership for routing purposes, which is
// correct for deciding pullRequest vs inPlace but would be exactly the
// wrong answer to "is the object this plan actually deletes itself
// unmanaged" for the one incident shape this mechanism exists for: an
// orphaned StatefulSet PVC, whose own object_key IS the DeleteResource
// plan's target, so resolveOwnership's ordinary cache-hit path would
// otherwise silently substitute the StatefulSet's "argocd" for the PVC's
// own, correct, "none".
func (s *Executor) liveGitOpsOwnership(ctx context.Context, clusterID, gvk, namespace, name string) (managedBy, source string) {
	args, err := json.Marshal(map[string]string{"gvk": gvk, "namespace": namespace, "name": name})
	if err != nil {
		return "", ""
	}
	live, err := s.gw.CallTool(ctx, clusterID, "get_gitops_ownership", args)
	if err != nil {
		logger.WarnContext(ctx, "the live GitOps-ownership lookup failed",
			logging.ClusterID(clusterID), slog.String("gvk", gvk),
			slog.String("namespace", namespace), slog.String("name", name), logging.Err(err))
		return "", ""
	}
	return parseOwnershipResult(live)
}

// parseOwnershipResult decodes a get_gitops_ownership tool result — the
// shared parsing resolveOwnership's cache-hit and live-lookup branches, and
// liveGitOpsOwnership, all need identically.
func parseOwnershipResult(raw []byte) (managedBy, source string) {
	var parsed struct {
		ManagedBy string `json:"managed_by"`
		AppRef    *struct {
			Kind      string `json:"kind"`
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"app_ref"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", ""
	}
	if parsed.AppRef != nil && parsed.AppRef.Name != "" {
		source = parsed.AppRef.Kind + " " + parsed.AppRef.Name
	}
	return parsed.ManagedBy, source
}
