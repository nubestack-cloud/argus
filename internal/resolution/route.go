// Package resolution implements lld/08-remediation-contracts.md §12's
// RouteFor — the decision ADR-18 accepted: a resolution Route is computed by
// non-AI code, before the model proposes anything, and constrains which
// action shapes the per-incident system prompt offers. Closes BACKLOG.md
// F17.
//
// Pure by design: no I/O, no clock, no model. Every input is gathered by the
// caller (internal/orchestrator's routing.go classifies raw ownership facts
// into the Ownership/Applier values this package consumes; internal/api
// fetches those facts live from the cluster) — RouteFor itself is a plain
// function of its inputs, which is what makes it exhaustively table-testable
// against §12.4's routing table.
package resolution

// Ownership is who declares this object's desired state — a classification
// one level above the raw "argocd"/"flux"/"fleet"/"helm"/"none" managed-by
// value get_gitops_ownership reports (internal/agent/tools.go), because
// routing also needs to know whether a repository is independently known
// for an object no controller governs. The classification itself is
// internal/orchestrator's job (routing.go), not this package's.
type Ownership string

const (
	// OwnershipGitOpsController: a real Argo CD Application, Flux
	// Kustomization or Fleet Bundle governs this object's desired state,
	// found via get_gitops_ownership's owner-chain walk.
	OwnershipGitOpsController Ownership = "gitopsController"
	// OwnershipRepoRegistered: no controller governs this object, but a
	// repository is known for it regardless (lld/08 §12.4 rows 4-6).
	// Reachable since BACKLOG.md F19 mechanism 1 (2026-08-25): an operator
	// declares "Helm release X in namespace Y" or "objects carrying these
	// labels" -> a registered repository + path
	// (repository_bindings.spec.objectMappings), matched hub-side
	// (internal/api/routing.go's gatherOwnershipFacts) whenever
	// get_gitops_ownership itself reports "helm" or "none" with no repo of
	// its own. Before F19 this was genuinely unreachable via any automatic
	// discovery in this build — get_gitops_ownership's "none"/"helm"
	// branches never populated a repo, and there was no per-object manual
	// registration mechanism at all (internal/agent/tools.go's
	// resolveRepoTarget: "Deliberately not attempted for helm... that gap is
	// what repository_bindings exists to fill by human configuration",
	// REMEDIATION_ROADMAP.md milestone 2.1). Modelled and routed correctly
	// either way, because RouteFor's job is to be correct for every input it
	// could receive, not only the ones a caller could produce at the time.
	OwnershipRepoRegistered Ownership = "repoRegistered"
	// OwnershipHelmNoRepo: a Helm release owns this object (the
	// meta.helm.sh/release-name annotation), and no repo trace exists —
	// resolveRepoTarget never attempts one for Helm, by design.
	OwnershipHelmNoRepo Ownership = "helmNoRepo"
	// OwnershipUnmanaged: no controller, no release, no repo — kubectl-applied
	// or created by something ARGUS cannot see.
	OwnershipUnmanaged Ownership = "unmanaged"
	// OwnershipUnknown: the ownership check itself could not be made (no
	// object left to ask about, an unreachable/disconnected cluster). lld/08
	// §12.4 row 11: "Cannot determine -> guidance", HLD §11.2 step 6's "give
	// up honestly."
	OwnershipUnknown Ownership = "unknown"
)

// Applier is whether anything actually acts on the declared desired state —
// a separate question from Ownership, and the one HLD §10.1 calls "a
// required input to channel selection, not an optimisation" (lld/08 §12.3).
type Applier string

const (
	// ApplierGitOpsController: the owning Argo Application has
	// spec.syncPolicy.automated set, or the owning Flux Kustomization is not
	// suspended (internal/agent/tools.go).
	ApplierGitOpsController Applier = "gitopsController"
	// ApplierNone: nothing currently applies the declared state. Two real
	// cases collapse into this value, deliberately: a registered repo with
	// no controller at all (lld/08 §12.3's own definition), AND a GitOps
	// controller object that exists but has automated sync switched off —
	// DESIGN.md §10.2 states plainly that in-place remediation of an
	// Argo-managed resource is safe precisely when "no automated" holds, so
	// treating that case as "nothing will revert an in-place fix" is
	// DESIGN.md's own stated position, not a guess filling a silence. §12.4's
	// table only spells out Ownership=GitOpsController paired with
	// Applier=GitOpsController (rows 1-3); this is the documented rule for
	// the combination it leaves unwritten.
	ApplierNone Applier = "none"
	// ApplierUnknown: the check could not be made — provider unreachable,
	// RBAC denied, or (this cut) a controller kind this build has no
	// automated-sync check for at all (Fleet: §12.9 decision A ships exactly
	// two appliers, "a GitOps controller with sync enabled, and nothing";
	// Fleet Bundles get neither check, so they read as Unknown, not as
	// silently automated). MUST NEVER be treated as ApplierNone — conflating
	// them is how a pull request gets opened into a void (lld/08 §12.3).
	ApplierUnknown Applier = "unknown"
	// ApplierDeployOnMerge does NOT ship in this cut (§12.9 decision A) —
	// listed here only so a future cut has the name reserved, matching
	// lld/08 §12.3's own table. Nothing in this package ever produces it.
	ApplierDeployOnMerge Applier = "deployOnMerge"
)

// Route is one of DESIGN.md §10.1's four resolution channels.
type Route string

const (
	RoutePullRequest Route = "pullRequest"
	RouteInPlace     Route = "inPlace"
	// RoutePaired is HLD §10.1's fourth row: durable (PR) and immediate
	// (in-place), together, because neither alone is sufficient when a repo
	// is known but nothing applies it automatically.
	RoutePaired Route = "pullRequest+inPlace"
	// RouteGuidance: ARGUS explains and proposes nothing executable. A
	// destination in its own right (lld/08 §12.4's own stated property),
	// never a fallthrough — see internal/orchestrator's StateDiagnosed.
	RouteGuidance Route = "guidance"
)

// RouteInputs is RouteFor's complete input — lld/08 §12.2's contract.
type RouteInputs struct {
	Ownership Ownership
	// Applier is read only when Ownership == OwnershipGitOpsController or
	// OwnershipRepoRegistered — RouteFor ignores it otherwise (HelmNoRepo,
	// Unmanaged and Unknown have no Applier dimension in §12.4's table,
	// marked "—").
	Applier Applier
	// SourceEditable answers "can ARGUS express a change in this source at
	// all". Ignored when no repo is known (OwnershipUnmanaged,
	// OwnershipUnknown).
	//
	// **Every caller passes true today** (orchestrator.ResolveRoute, 2026-08-28,
	// which has the full reasoning). It used to carry Argo's status.sourceType
	// verdict, because internal/gitops could only edit one scalar in one
	// plain-YAML file and refused a Helm or Kustomize source outright. A
	// repository change is now a set of whole files, which works against a
	// chart template, a values file and an overlay just as well as a manifest,
	// so no source ARGUS can read is un-editable any more.
	//
	// Kept as a dimension rather than deleted because "ARGUS cannot express a
	// change in this source" remains a coherent thing for a future input to
	// say — a binary source, or one the binding forbids reading. Rows 2-3 below
	// are what it would select, and they are correct if it ever does.
	SourceEditable bool
	// ExecutionAllowed: per-cluster remediate.enabled RBAC plus the acting
	// capability grant — whether an in-place action could even be attempted.
	ExecutionAllowed bool
}

// RouteResult is RouteFor's output: the chosen Route, and the reason a human
// operator reads on the incident (persisted as incidents.route_reason,
// migration 000062).
type RouteResult struct {
	Route  Route
	Reason string
}

func result(route Route, reason string) RouteResult { return RouteResult{Route: route, Reason: reason} }

// RouteFor is lld/08 §12.2's pure decision function. Every branch below cites
// the §12.4 table row it implements; branches with no row number fill a
// combination the table leaves unwritten, and each of those carries its own
// citation for why the chosen answer is the correct one rather than a guess.
func RouteFor(in RouteInputs) RouteResult {
	switch in.Ownership {
	case OwnershipUnknown:
		// Row 11: "Cannot determine -> guidance."
		return result(RouteGuidance, "ownership could not be determined for this object — ARGUS will not guess between a live patch and a pull request it cannot confirm applies")

	case OwnershipGitOpsController:
		switch in.Applier {
		case ApplierGitOpsController:
			if in.SourceEditable {
				// Row 1.
				return result(RoutePullRequest, "a GitOps controller applies this object's manifest with automated sync enabled — an in-place patch has a few-second half-life under selfHeal, since the controller reconciles it straight back; the durable fix is a pull request")
			}
			// Rows 2-3 (both guidance, regardless of ExecutionAllowed).
			return result(RouteGuidance, "a GitOps controller applies this object's manifest, but ARGUS cannot express the change at source (a templated/rendered file) — a live patch would be reverted and no pull request can be opened against it; say both in the analysis")
		case ApplierUnknown:
			// No table row names this combination; §12.3's own rule for
			// ApplierUnknown ("must never be treated as ApplierNone... never
			// open a PR you cannot say will be applied") is stated as a
			// general principle, not scoped to one Ownership value, so it
			// governs here exactly as it governs row 7.
			return result(RouteGuidance, "a GitOps controller governs this object, but whether it is actually applying (automated sync / not suspended) could not be checked — fail closed rather than open a pull request that might merge into a void")
		default: // ApplierNone (or ApplierDeployOnMerge, unreachable this cut)
			// Not a table row: §12.4 only shows Ownership=GitOpsController
			// paired with Applier=GitOpsController. DESIGN.md §10.2 is
			// explicit that an Argo-managed resource with no automated sync
			// is one of the narrow cases where in-place remediation is
			// correct, not futile — so this combination is routed exactly
			// like OwnershipRepoRegistered (rows 4-6): a repo is known, and
			// nothing is currently reconciling it back.
			return routeForKnownRepoNoApplier(in.SourceEditable, in.ExecutionAllowed, "a GitOps controller object exists for this object, but automated sync is not enabled — nothing is reconciling it back, so this is treated the same as no applier at all")
		}

	case OwnershipRepoRegistered:
		switch in.Applier {
		case ApplierUnknown:
			// Row 7, verbatim.
			return result(RouteGuidance, "a repository is known for this object, but whether anything applies it could not be checked — fail closed rather than open a pull request that might merge into a void")
		default: // ApplierNone
			return routeForKnownRepoNoApplier(in.SourceEditable, in.ExecutionAllowed, "a repository is known for this object and nothing applies it automatically")
		}

	case OwnershipHelmNoRepo:
		if !in.ExecutionAllowed {
			// Not itself a table row (row 8 only shows ExecutionAllowed=yes),
			// but rows 9/10's own pattern — no durable channel exists
			// (resolveRepoTarget never attempts a repo for Helm), so refusing
			// execution leaves nothing to route to.
			return result(RouteGuidance, "a Helm release owns this object and no repository is known for it, and in-place execution is not available on this cluster — there is no channel left to route to")
		}
		// Row 8.
		return result(RouteInPlace, "a Helm release owns this object and no repository is known for it — an in-place fix is the only available channel, with the caveat that the next helm upgrade may reintroduce the problem")

	case OwnershipUnmanaged:
		if !in.ExecutionAllowed {
			// Row 10.
			return result(RouteGuidance, "nothing manages this object and in-place execution is not available on this cluster")
		}
		// Row 9.
		return result(RouteInPlace, "nothing manages this object — an in-place fix is durable because nothing reconciles it back")

	default:
		// An Ownership value this function does not recognise (a future
		// addition, or a caller's bug) is exactly "cannot determine" —
		// failing closed rather than falling through to a channel that might
		// execute against an object this function never actually reasoned
		// about.
		return result(RouteGuidance, "unrecognized ownership classification — treated as undetermined")
	}
}

// routeForKnownRepoNoApplier is rows 4-6's shared logic: a repository is
// known, and nothing currently applies it. Reachable from two different
// Ownership values (see RouteFor) with slightly different reasons, so the
// reason each row's message needs is passed in rather than hardcoded here.
func routeForKnownRepoNoApplier(sourceEditable, executionAllowed bool, why string) RouteResult {
	switch {
	case sourceEditable && executionAllowed:
		// Row 4: the paired route.
		return result(RoutePaired, why+" — in-place stops the outage now, the pull request stops the next deploy reintroducing it")
	case sourceEditable && !executionAllowed:
		// Row 5.
		return result(RoutePullRequest, why+", and in-place execution is not available on this cluster — the durable half only; the incident stays open until the pull request merges")
	case !sourceEditable && executionAllowed:
		// Row 6.
		return result(RouteInPlace, why+", but ARGUS cannot express the change at this source (a templated/rendered file) — in-place only, with the caveat that the next deploy may reintroduce it")
	default:
		// Not a table row: neither channel is available (no editable
		// source, no execution) — there is nothing left to route to.
		return result(RouteGuidance, why+", but ARGUS can neither express the change at source nor execute in-place on this cluster")
	}
}

// PermittedActionTypes returns the remediation.ActionType wire strings route
// permits — lld/08 §12.5's table, restated as data so both the prompt
// builder (internal/llm) and the fail-closed parse-time check
// (internal/orchestrator.EnforceRoute) read the same list rather than two
// hand-maintained ones. Returned as plain strings, not remediation.ActionType,
// so this package takes no dependency on internal/remediation — it has no
// other reason to know that package exists.
//
// PatchField is never included — but NOT because internal/api lacks an
// execution case for it. That was BUGS.md 78's claim, and it is fixed and
// removed: internal/execution's ActionPatchField case executes
// it end to end, and four real executions have succeeded live. The actual
// reason is BACKLOG.md F11, a deliberately parked decision: asked
// directly whether to make this mechanism model-reachable, the owner's
// answer (2026-08-26) was that the real ask was file editing, not several
// field/value boxes — that shipped as OpenPR/B4 instead, and F11's own
// safety machinery was left built but dormant pending a fresh, separate
// decision to wire it into either backend's prompt or tool dispatch. F11 may
// be reopened on its own merits later; until then PatchField stays off this
// list on that parked decision's authority, not because offering it would
// let the fail-closed check pass a plan nothing can act on.
//
// DeleteResource (added 2026-09-01, BUGS.md 118 part (b)) is offered on
// EVERY executable route, including RoutePullRequest — deliberately NOT
// folded into inPlace's conditional the way the other four are, and this
// needs its own explanation because it looks like it should follow the
// same rule as its siblings and does not.
//
// Every other in-place action type shares its TARGET's ownership chain with
// whatever route computed: a live patch to the same object (or one directly
// in its GitOps lineage) that a pullRequest route says is durably fixed via
// Git would indeed be pointless or actively wrong, so gating those four to
// non-pullRequest routes is a real safety property, not an arbitrary
// restriction. DeleteResource's narrowly-permitted PersistentVolumeClaim
// case is different in exactly the way that matters here: the object it
// targets (an orphaned volumeClaimTemplate PVC) is BY DEFINITION never
// itself GitOps-tracked — that is the whole reason BUGS.md 118 exists — so
// whatever route the INCIDENT resolves to is answering a question about a
// DIFFERENT object (typically the owning StatefulSet, once
// BUGS.md 118 part (a)'s related-workload ownership fallback adopts that
// object's ownership for ROUTING purposes). A StatefulSet routed to
// pullRequest because Argo CD durably owns ITS manifest says nothing about
// whether the orphaned PVC beside it is safe to delete — that question is
// independently, freshly re-verified by internal/execution's
// checkDeleteResourcePVCOwnership (which deliberately calls
// liveGitOpsOwnership directly rather than trusting incidents.ownership,
// for exactly this reason — see that function's own doc comment) and
// internal/agent/deleteresource.go's liveness precondition, regardless of
// what route this function returned. Restricting DeleteResource to
// non-pullRequest routes would make it unreachable for the primary case it
// exists for — an orphaned PVC beside a GitOps-managed StatefulSet is
// exactly the shape that resolves to pullRequest today — defeating the
// point of offering a fallback for when the model declines to author that
// pull request (BUGS.md 118's own still-open finding on that half).
//
// This is not offered on RouteGuidance, which is unaffected by any of the
// above: several of ITS causes are "execution is not available on this
// cluster at all" (RouteFor's rows 5/10), for which there is no
// argus-remediate identity to run DeleteResource — or anything else —
// through regardless of any object's individual ownership.
//
// One known, accepted gap: row 1 (Ownership=GitOpsController,
// Applier=GitOpsController, SourceEditable) returns RoutePullRequest
// without consulting ExecutionAllowed at all — exactly like OpenPR itself,
// which needs no in-cluster execution to open a PR. So a cluster with
// execution genuinely disabled could still see DeleteResource OFFERED on
// this route. This degrades safely, not dangerously: an execution attempt
// against a cluster with no argus-remediate identity fails cleanly at
// dispatch (no tool registered / no RBAC), surfaced to the human approver
// as a failed execution rather than a silent hazard — the same "offered,
// then cleanly refused downstream" shape this file's own DeleteResource
// note above already relies on for the narrower ownership/liveness case.
// Worth tightening if it turns out to cost real wasted approval cycles in
// practice; not tightened here because doing so needs ExecutionAllowed
// threaded through PermittedActionTypes' signature and every caller
// (internal/llm.SystemPrompt, internal/orchestrator.EnforceRoute), a wider
// change than this fix's own scope.
// AnnotateResource/LabelResource/CreateResource (PROJECT.md B130/F9,
// exposed 2026-09-06) join inPlace, not RoutePullRequest — decided per
// verb, not assumed from the existing four's pattern:
//
// AnnotateResource/LabelResource share the existing four's exact reasoning.
// Both patch an existing object's own metadata (an enumerated,
// narrowly-reviewed annotation/label key — internal/remediation/
// annotatelabel.go's allowlist), and metadata IS part of what a GitOps
// controller's own diff considers — Argo CD's default sync reverts or
// fights an out-of-band annotation/label change on a synced object exactly
// as it would a live patch to spec.replicas. There is no equivalent to
// DeleteResource's "the target is independently, structurally never
// GitOps-tracked" exception (an orphaned volumeClaimTemplate PVC): these
// two target the SAME object the incident's own route was computed for, so
// gating them to non-pullRequest routes is the same real safety property
// gating the other four, not an arbitrary restriction.
//
// CreateResource does NOT join RoutePullRequest, and this needs its own
// paragraph because the reasoning is not "it would be unsafe" — it is that
// nothing today can actually use it there.
//
// The shape this action exists for (internal/remediation/createresource.go's
// own header: a Deployment references a ConfigMap that was never created)
// on a repo-managed namespace is, by this file's own GitOps-first direction,
// a new file arriving via OpenPR — NOT a live create of something Git is
// about to consider its own. That would be exactly the anti-pattern the
// other four's gating protects against, just for an object that does not
// exist yet instead of one that already does.
//
// But OpenPR cannot currently do this: internal/llm's SystemPrompt already
// tells the model a file that does not exist is "created" by naming it, and
// that claim is false today. internal/api/repo_tools.go's
// RefuseUnreadRepositoryProposals (BACKLOG.md F28 finding 1) refuses any
// OpenPR plan naming a path this investigation's ReadLog has no recorded
// read for, with no exemption for a path confirmed absent — and
// read_repo_file only ever calls ReadLog.record on its SUCCESS path
// (internal/repotools/repotools.go's readFile), so a nonexistent path can
// structurally never be "read" at all. A model proposing a genuinely new
// file is refused exactly like one that invented content for a path it
// never opened, which is the wrong reason to refuse it. This is a real,
// separate defect, not a reason to route around it here — filed as its own
// item rather than worked around by, say, adding CreateResource to
// RoutePullRequest as an in-place stand-in for what OpenPR cannot yet do
// (which would reintroduce the exact live-create-of-a-Git-owned-object
// anti-pattern this paragraph opened by rejecting).
//
// So: CreateResource is in inPlace only, reachable for a missing ConfigMap
// on an unmanaged namespace (RouteInPlace, and RoutePaired's in-place half
// where both channels are otherwise legitimately available) — exactly
// createresource.go's own worked example — and reaches nothing on
// RoutePullRequest until the OpenPR gap above is closed.
func PermittedActionTypes(route Route) []string {
	// CordonNode/DrainNode (PROJECT.md PG15) are in-place only: no GitOps
	// controller owns a Node, and Validate refuses them for any other kind.
	inPlace := []string{"ScaleDeployment", "RestartPod", "PatchResourceLimits", "RevertContainerImage", "DeleteResource", "AnnotateResource", "LabelResource", "CreateResource", "CordonNode", "DrainNode"}
	switch route {
	case RoutePullRequest:
		return []string{"OpenPR", "DeleteResource"}
	case RouteInPlace:
		return inPlace
	case RoutePaired:
		return append(append([]string{}, inPlace...), "OpenPR")
	default: // RouteGuidance, or anything unrecognized
		return nil
	}
}
