package orchestrator

import (
	"log/slog"

	"argus/internal/llm"
	"argus/internal/remediation"
	"argus/internal/resolution"
)

// OwnershipFacts is what a caller (internal/api) has already fetched live
// from the cluster before ResolveRoute classifies it — the I/O half of
// lld/08-remediation-contracts.md §12.2's RouteInputs, gathered outside this
// package so ResolveRoute itself stays a plain function of already-known
// facts, matching resolution.RouteFor's own purity.
type OwnershipFacts struct {
	// Determined is false when the get_gitops_ownership check itself could
	// not be made at all (no object left to ask about, an unreachable
	// cluster) — resolution.OwnershipUnknown, HLD §11.2 step 6's "give up
	// honestly." False makes every other field below meaningless.
	Determined bool
	// ManagedBy is get_gitops_ownership's raw answer: "argocd" | "flux" |
	// "fleet" | "helm" | "none".
	ManagedBy string
	// RepoKnown is whether a repository was independently resolved for this
	// object despite get_gitops_ownership itself finding no controller
	// (ManagedBy == "none") — or, since BACKLOG.md F19 mechanism 1
	// (2026-08-25), despite ManagedBy == "helm" either: an operator-declared
	// repository_bindings.spec.objectMappings entry, matched hub-side in
	// internal/api/routing.go's gatherOwnershipFacts because the cluster
	// agent has no access to that hub-DB table at all. Before F19 this was
	// permanently false in every real code path — resolution.
	// OwnershipRepoRegistered's own doc comment used to call it
	// "genuinely unreachable" for exactly that reason; F19 is what makes it
	// reachable for the first time.
	RepoKnown bool
	// ApplierRaw is internal/agent/tools.go's gitOpsRepoTarget.Applier verbatim
	// — "gitopsController" | "none" | "" (empty: no check exists for this
	// controller kind in this cut, e.g. Fleet — must classify as
	// resolution.ApplierUnknown, never resolution.ApplierNone).
	ApplierRaw string
	// SourceEditable is gitOpsRepoTarget.SourceEditable verbatim — nil when
	// no signal exists (Flux, Fleet, or no controller at all).
	SourceEditable *bool
}

// ResolveRoute classifies already-fetched ownership facts into
// resolution.RouteInputs and calls resolution.RouteFor — the ONE place both
// internal/api/analyze.go and internal/autoanalyze build a route, so the two
// call sites can never silently diverge (mirrors ApplyAnalysisResult's own
// "one function, two callers" rationale, db.go). The classified Applier is
// returned alongside the route so the caller can persist incidents.applier
// without reclassifying facts.ApplierRaw a second time.
func ResolveRoute(facts OwnershipFacts, executionAllowed bool) (resolution.RouteResult, resolution.Applier) {
	if !facts.Determined {
		return resolution.RouteFor(resolution.RouteInputs{Ownership: resolution.OwnershipUnknown}), resolution.ApplierUnknown
	}

	// SourceEditable is now unconditionally TRUE, and facts.SourceEditable is
	// deliberately not read (2026-08-28).
	//
	// It used to carry Argo's own status.sourceType verdict — "Directory" meant
	// plain manifests and so editable, "Helm"/"Kustomize" meant a rendered
	// source and so NOT editable — because internal/gitops could only express a
	// change as one scalar in one plain-YAML file, and refused a templated file
	// by name. That refusal is gone: a repository change is now a set of whole
	// files, and a whole-file edit works against a chart template, a values
	// file, a Kustomize overlay or a plain manifest alike (internal/gitops/
	// files.go). A Helm-sourced application is no longer a reason to route an
	// incident to guidance, and routing it there would keep the old cap in
	// place while the mechanism that justified it no longer exists.
	//
	// The dimension is kept on RouteInputs rather than deleted because "ARGUS
	// cannot express a change in this source" is still a coherent thing for a
	// future input to say (a binary source, a source ARGUS may not read at
	// all). Nothing says it today.
	in := resolution.RouteInputs{ExecutionAllowed: executionAllowed, SourceEditable: true}

	switch facts.ManagedBy {
	case "argocd", "flux", "fleet":
		in.Ownership = resolution.OwnershipGitOpsController
	case "helm":
		// F19 mechanism 1: a Helm release with no repo trace of its own can
		// still have a repository INDEPENDENTLY known for it, via an
		// operator-declared objectMappings entry (RepoKnown, set hub-side —
		// see OwnershipFacts.RepoKnown's doc comment). That is exactly
		// OwnershipRepoRegistered's own definition ("no controller governs
		// this object, but a repository is known for it regardless"), so a
		// match takes this OUT of HelmNoRepo rather than leaving it there;
		// with no match, HelmNoRepo is unchanged from before F19.
		if facts.RepoKnown {
			in.Ownership = resolution.OwnershipRepoRegistered
		} else {
			in.Ownership = resolution.OwnershipHelmNoRepo
		}
	default: // "none", or anything this classifier does not recognize
		if facts.RepoKnown {
			in.Ownership = resolution.OwnershipRepoRegistered
		} else {
			in.Ownership = resolution.OwnershipUnmanaged
		}
	}

	switch {
	case in.Ownership == resolution.OwnershipRepoRegistered:
		// §12.3's own definition of ApplierNone is "repo registered, neither
		// [a GitOps controller] nor [deploy-on-merge CI]" — and Ownership
		// only classifies as RepoRegistered when get_gitops_ownership found
		// no AUTO-APPLYING controller: either ManagedBy == "none" (no
		// controller at all), or, since F19, ManagedBy == "helm" with an
		// operator-declared mapping (a Helm release is not itself something
		// that reconciles a Git repo back onto the cluster). Either way "no
		// controller applies this repo" is a fact this classifier already
		// has, not a check that could separately fail — so this is
		// ApplierNone by construction, never ApplierUnknown, regardless of
		// what facts.ApplierRaw carries (tools.go never populates Applier
		// for either of those two ManagedBy values, since resolveRepoTarget
		// returns nil for "none" and never reaches Applier-setting code for
		// "helm" either).
		in.Applier = resolution.ApplierNone
	case facts.ApplierRaw == "gitopsController":
		in.Applier = resolution.ApplierGitOpsController
	case facts.ApplierRaw == "none":
		in.Applier = resolution.ApplierNone
	default:
		// Empty, or an unrecognized value — Fleet's case today (§12.9
		// decision A: no automated-sync check exists for it in this cut),
		// and the safe default for anything future code sends that this
		// classifier does not yet know about. RouteFor only reads Applier
		// when Ownership needs it, so this is a no-op for HelmNoRepo/
		// Unmanaged.
		in.Applier = resolution.ApplierUnknown
	}

	return resolution.RouteFor(in), in.Applier
}

// EnforceRoute is lld/08 §12.5's fail-closed check: a proposed plan whose
// ActionType is outside route's permitted set is refused HERE, before
// Advance ever sees it — the same shape as isOfferedTool
// (internal/llm/toolloop.go refuses a tool name the loop never advertised;
// this refuses an action shape the route never advertised). Applies
// uniformly to both Investigator backends (api, cli) because it runs on the
// already-parsed llm.Investigation result, after Investigate returns,
// rather than inside either backend's own parsing.
//
// Refusal drops the plan (nil) rather than failing the investigation: a
// wrong-shaped proposal is not evidence the root cause is wrong, and
// Advance's existing "no proposed plan" handling already gives that case an
// honest state (NeedsHumanInvestigation, or Diagnosed for a guidance route)
// — matching this codebase's own repeated position that a wrong or
// overreaching proposedPlan is worse than none.
func EnforceRoute(result llm.Investigation, route resolution.Route) llm.Investigation {
	permitted := resolution.PermittedActionTypes(route)
	result.ProposedPlan = refuseIfNotPermitted(result.ProposedPlan, permitted, route, "proposedPlan")
	result.ProposedPairedPlan = refuseIfNotPermitted(result.ProposedPairedPlan, permitted, route, "proposedPairedPlan")

	if route != resolution.RoutePaired {
		// Not a paired route — a second plan has nothing to pair with, even
		// if its own ActionType happened to be individually permitted.
		if result.ProposedPairedPlan != nil {
			logger.Warn("refused a proposed paired plan: this route does not offer one",
				slog.String("action_type", string(result.ProposedPairedPlan.ActionType)), slog.String("route", string(route)))
			result.ProposedPairedPlan = nil
		}
		return result
	}

	// Paired route (§12.5: "the model proposes one of each"). Reassign by
	// ACTUAL ActionType rather than trusting which wire field the model used
	// — a model that puts OpenPR under proposedPlan and the in-place action
	// under proposedPairedPlan still produced a complete, correct pairing.
	// A duplicate (both OpenPR, or both in-place) is genuinely ambiguous
	// about which the model meant as primary, so the first survives and the
	// second is refused rather than guessed at; a PARTIAL pairing (only one
	// half proposed at all) is left as-is — it still fixes what it fixes,
	// and discarding a valid proposal because its sibling is missing would
	// be exactly the "wrong or overreaching plan is worse than none"
	// mistake in the other direction.
	isOpenPR := func(p *remediation.RemediationPlan) bool { return p != nil && p.ActionType == remediation.ActionOpenPR }
	switch {
	case isOpenPR(result.ProposedPlan) && result.ProposedPairedPlan != nil && !isOpenPR(result.ProposedPairedPlan):
		result.ProposedPlan, result.ProposedPairedPlan = result.ProposedPairedPlan, result.ProposedPlan
	case isOpenPR(result.ProposedPlan) && isOpenPR(result.ProposedPairedPlan):
		logger.Warn("paired route proposed OpenPR twice: keeping the first, refusing the duplicate")
		result.ProposedPairedPlan = nil
	case result.ProposedPlan != nil && !isOpenPR(result.ProposedPlan) && result.ProposedPairedPlan != nil && !isOpenPR(result.ProposedPairedPlan):
		logger.Warn("paired route proposed two in-place actions and no OpenPR: keeping the first, refusing the duplicate")
		result.ProposedPairedPlan = nil
	}
	return result
}

func refuseIfNotPermitted(plan *remediation.RemediationPlan, permitted []string, route resolution.Route, field string) *remediation.RemediationPlan {
	if plan == nil {
		return nil
	}
	for _, at := range permitted {
		if at == string(plan.ActionType) {
			return plan
		}
	}
	logger.Warn("refused a proposed action: not in this route's permitted set",
		slog.String("field", field), slog.String("action_type", string(plan.ActionType)),
		slog.String("route", string(route)), slog.Any("permitted", permitted))
	return nil
}
