package api

// BACKLOG.md F22 piece 1, hub side: resolving which repository an incident's
// investigation may read, and dispatching the two repository tools.
//
// # The dispatch seam
//
// internal/llm.ToolCallback is a plain function, and until now both call sites
// that supply one (handleAnalyzeIncident here, and internal/autoanalyze) hard-
// coded gateway.CallToolWithRetry — every tool went over the tunnel to the
// cluster agent. The repository tools are the first that do not, because the
// repository is fetched hub-side and always has been: the credential lives in
// repository_bindings, and repository_locate.go already clones sparsely at the
// pinned revision. So the callback dispatches on the tool NAME
// (repotools.IsRepoTool) and the loop itself is unchanged.
//
// # Resolved before the model says anything
//
// IncidentRepoScope runs before Investigate is called, from the incident's own
// stored GitOps ownership and its registered binding. Nothing in the resulting
// scope can be influenced by model output — there is no argument on either tool
// that names a repository, a revision or a directory. That is non-negotiable 3
// ("never trust scope claimed by the model") enforced by construction rather
// than by validation.
//
// # An unpinned revision is no repository
//
// A branch name is refused here exactly as handleOpenRepositoryChange refuses
// it, and for the identical reason (DESIGN.md §11.4's "pin the SHA"): reading
// a moving branch would show the model content the cluster has never applied,
// and every inference drawn from it would be about a different deployment than
// the one that is broken. An incident whose controller has never synced simply
// has no readable repository, which is a normal answer.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"gopkg.in/yaml.v3"

	"argus/internal/data"
	"argus/internal/gitops"
	"argus/internal/llm"
	"argus/internal/logging"
	"argus/internal/remediation"
	"argus/internal/repotools"
	"argus/internal/scm"
)

// IncidentRepoScope resolves the repository one incident's investigation may
// read, or a zero Scope when there is none.
//
// A zero Scope is a normal outcome, not an error — most incidents are about
// objects nobody deploys from Git — so the only errors returned are ones a
// caller could act on. Everything else is logged and reported as "no
// repository", the same honest degradation loadRepoTargetWithFallback already
// applies to an unreachable agent.
//
// Exported because internal/autoanalyze needs the identical resolution: an
// unattended analysis and a human-triggered one must offer the model exactly
// the same tool surface, or the two paths silently produce different-quality
// investigations of the same incident.
func IncidentRepoScope(ctx context.Context, tx pgx.Tx, scmStore *scm.Store, incidentID string) repotools.Scope {
	target, err := loadRepoTarget(ctx, tx, incidentID)
	if err != nil {
		logger.ErrorContext(ctx, "reading the incident's ownership for the repository scope failed", logging.IncidentID(incidentID), logging.Err(err))
		return repotools.Scope{}
	}
	return scopeForTarget(ctx, tx, scmStore, incidentID, target)
}

// scopeForTarget turns one resolved ownership target into a Scope, or a zero
// Scope. Split out from IncidentRepoScope so the live-lookup fallback below can
// reach it with a target it did not read from the database.
func scopeForTarget(ctx context.Context, tx pgx.Tx, scmStore *scm.Store, incidentID string, target *incidentRepoTarget) repotools.Scope {
	if target == nil || target.RepoURL == "" {
		return repotools.Scope{}
	}
	if !target.RevisionPinned || strings.TrimSpace(target.Revision) == "" {
		// See this file's header: a branch is not a revision whose content is
		// known to be what is running.
		return repotools.Scope{}
	}

	provider, _, binding, err := scmStore.ProviderFor(ctx, tx, target.RepoURL)
	if err != nil {
		// ErrNoBinding is the ordinary case — the object names a repository
		// ARGUS was never told about. Not logged at all, because it would log
		// on every incident in a fleet that has registered no repositories.
		if !errors.Is(err, scm.ErrNoBinding) {
			logger.ErrorContext(ctx, "resolving the repository provider failed",
				logging.IncidentID(incidentID), slog.String("repo_url", target.RepoURL), logging.Err(err))
		}
		return repotools.Scope{}
	}
	cred, ok := provider.(scm.CloneCredentialer)
	if !ok {
		// The same refusal locateObjectFile makes, for the same reason: a
		// provider that will not hand over a fetch credential cannot be read.
		return repotools.Scope{}
	}
	return repotools.Scope{
		RepoURL:   target.RepoURL,
		Revision:  target.Revision,
		SourceDir: target.Path,
		Host:      binding.Host,
		Token:     cred.CloneToken(),
		// The binding's own extra denylist, on top of scm's non-overridable
		// builtin one. Applied to READS here, not only to writes — see
		// internal/repotools' package comment for why that is the right
		// default rather than an over-restriction.
		ForbiddenPaths: binding.WriteScope.ForbiddenPaths,
	}
}

// RepoToolCallback builds the dispatching ToolCallback: repository tools to
// reader, everything else over the tunnel to the cluster agent.
//
// reader may be nil (this incident has no repository), in which case a
// repository tool is refused with a real explanation rather than dispatched to
// an agent that has never heard of it. In practice the model is never offered
// one in that case — llm.Target.RepoReadable gates the surface — so this is the
// belt to that braces, and it exists because "the model was not offered it" is
// not enforcement (the same lesson isOfferedTool was added for).
func RepoToolCallback(reader *repotools.Reader, cluster func(ctx context.Context, tool string, args json.RawMessage) (json.RawMessage, error)) func(context.Context, string, json.RawMessage) (json.RawMessage, error) {
	return func(ctx context.Context, tool string, args json.RawMessage) (json.RawMessage, error) {
		if repotools.IsRepoTool(tool) {
			if reader == nil {
				return nil, repotools.ErrNoRepository
			}
			return reader.Call(ctx, tool, args)
		}
		return cluster(ctx, tool, args)
	}
}

// CallRepoTool serves one repository tool for the cli backend, which reaches
// tools over MCP rather than through a Go closure and so has no callback to
// dispatch through.
//
// It opens its own short, RLS-scoped transaction, the same shape
// RecordMCPToolCall uses and for the same reason: the MCP server holds no
// request context and no pgx.Tx, only a grant. The grant's incident and cluster
// are what scope this — never anything from the tool arguments, which is
// internal/mcp's own SR-24 rule carried through to the one tool it does not
// dispatch to a cluster.
func (s *Server) CallRepoTool(ctx context.Context, clusterID, incidentID, tool string, args json.RawMessage) (json.RawMessage, error) {
	if incidentID == "" {
		// A grant with no incident cannot scope a repository read to anything,
		// and a fleet-wide repository read is exactly the "different and much
		// worse feature" F22 warns against.
		return nil, errors.New("refusing a repository tool call with no incident id")
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), repoToolTimeout)
	defer cancel()

	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		return nil, fmt.Errorf("resolve organisation: %w", err)
	}
	var clusters []string
	if clusterID != "" {
		clusters = []string{clusterID}
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, clusters); err != nil {
		return nil, fmt.Errorf("set request scope: %w", err)
	}

	scope := s.repoScopeForMCP(ctx, tx, clusterID, incidentID)
	if !scope.Valid() {
		return nil, repotools.ErrNoRepository
	}
	// Read-only throughout; the transaction is closed before the fetch so a
	// slow clone never holds a database connection open.
	if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		logger.ErrorContext(ctx, "closing the repository-tool read transaction failed", logging.IncidentID(incidentID), logging.Err(err))
	}

	reader := repotools.NewReader(scope, s.checkouts)
	// BACKLOG.md F28 finding 1: attach whatever ReadLog this incident's own
	// investigation registered (internal/api/analyze.go or
	// internal/autoanalyze, via s.readLogs.Begin), if any. This is the ONLY
	// way a cli-backend investigation's real read_repo_file calls — which
	// arrive here, never through the in-process Reader analyze.go built —
	// become visible to RefuseTruncatedRepositoryProposals/
	// RefuseUnreadRepositoryProposals at all. s.readLogs.Get returns nil for
	// a nil registry, an incident with no investigation currently in
	// flight, or a manual out-of-band call (e.g. a test), in which case
	// SetReadLog(nil) is the same no-op it always was.
	reader.SetReadLog(s.readLogs.Get(incidentID))
	return reader.Call(ctx, tool, args)
}

// repoToolTimeout bounds one repository tool call end to end, including a cold
// clone. Longer than internal/gateway's 30s tool-call timeout because a git
// fetch of a real repository is genuinely slower than an API read against a
// cluster, and short enough that a hung fetch cannot consume an investigation's
// whole time budget on its own.
const repoToolTimeout = 60 * time.Second

// repoScopeForMCP is IncidentRepoScope plus a live fallback, and the fallback is
// not an optimisation — without it the cli backend can never read a repository
// on an incident's FIRST analysis.
//
// Why: `incidents.ownership` is resolved and cached by ResolveIncidentRoute,
// which runs inside handleAnalyzeIncident's own long-lived investigation
// transaction and does not commit until the investigation finishes. The api
// backend is unaffected — its tool callback reads through that same transaction.
// The cli backend is not: the CLI calls back into the hub over MCP, this handler
// opens its OWN transaction, and a separate transaction cannot see an uncommitted
// write. So every first analysis of an Argo-managed object got "no repository is
// known" from a tool the model had correctly been granted. Observed live on
// `inc_01m14qgq3ybkf89h33jfm88439` (the hub log's own
// "list_repo_files ... FAILED: no repository is known for this incident"), after
// a first attempt at this had already fixed the simpler ordering half of it.
//
// The fallback is the same one loadRepoTargetWithFallback already makes for the
// pull-request path, for the same column and the same reason: ask the cluster
// live, one tool call against a connected agent — and, per BUGS.md 124, the
// exact same resolveLiveOwnership (routing.go) gatherOwnershipFacts calls for
// `route`/`route_reason`, related-workload fallback included, rather than a
// second copy of that fallback that can drift from the first one again.
//
// It deliberately does NOT persist what it learns. The analysis transaction
// holds a row lock on this very incident row (it wrote ownership), so an UPDATE
// from here would block until the investigation finished — turning a repository
// read into a stall for the length of the analysis. The in-memory answer is
// enough: the analysis transaction will commit the identical value moments later.
func (s *Server) repoScopeForMCP(ctx context.Context, tx pgx.Tx, clusterID, incidentID string) repotools.Scope {
	if scope := IncidentRepoScope(ctx, tx, s.scmStore, incidentID); scope.Valid() {
		return scope
	}
	if clusterID == "" || s.gw == nil {
		return repotools.Scope{}
	}
	raw, _, sourceKey, err := resolveLiveOwnership(ctx, tx, s.gw, s.scmStore, clusterID, incidentID)
	if sourceKey == "" {
		return repotools.Scope{}
	}
	if err != nil {
		// Logged, not returned: an unreachable agent means ownership is
		// unknown, which is the same answer as "nothing stored" and produces
		// the same honest ErrNoRepository.
		logger.WarnContext(ctx, "live get_gitops_ownership failed while scoping the MCP repository tools",
			logging.IncidentID(incidentID), slog.String("source_key", sourceKey), logging.Err(err))
		return repotools.Scope{}
	}
	return scopeForTarget(ctx, tx, s.scmStore, incidentID, parseRepoTarget(ctx, raw, incidentID))
}

// RefuseTruncatedRepositoryProposals is BACKLOG.md F25's enforcement point:
// for each of result's OpenPR plans (ProposedPlan and ProposedPairedPlan),
// refuse it outright — the exact same "replace with nil" shape
// orchestrator.EnforceRoute already uses to refuse a plan the incident's
// route disallows — if it proposes new content for ANY path whose most
// recent read in THIS investigation was truncated (log, built alongside the
// Reader the investigation actually read through — see
// internal/repotools.ReadLog's own doc comment for why one log belongs to
// one investigation).
//
// Exported and called from both internal/api/analyze.go (the manual path)
// and internal/autoanalyze.go (the unattended path) — the same "one function,
// two callers" shape as IncidentRepoScope/RepoToolCallback/ResolveIncidentRoute
// above, for the identical reason: a human-triggered analysis and an
// unattended one must apply exactly the same safety guard to exactly the
// same proposal shape, or the two paths silently diverge in how safe they
// are.
//
// Called with a nil log (no repository scope was resolved, or a Reader was
// never attached to one) is a complete no-op — repotools.ReadLog.CheckPaths
// already tolerates a nil receiver, and a plan that names files but was never
// read against at all is exactly the different, out-of-scope question this
// guard does not answer (see CheckPaths' own doc comment).
//
// A refusal is logged here, not surfaced through any new API/timeline
// surface: this mirrors EnforceRoute's own existing precedent for a
// plan silently refused before a human ever sees it, and a refused OpenPR
// plan is not silently lost information — the incident simply proceeds with
// no proposedPlan/proposedPairedPlan for that half, exactly as it would for
// any other honest "no clean automatable fix" outcome, and the reason is one
// hub log line away for whoever is debugging it.
func RefuseTruncatedRepositoryProposals(result llm.Investigation, sourceDir string, log_ *repotools.ReadLog) llm.Investigation {
	result.ProposedPlan = refuseTruncatedPlan(result.ProposedPlan, sourceDir, log_, "proposedPlan")
	result.ProposedPairedPlan = refuseTruncatedPlan(result.ProposedPairedPlan, sourceDir, log_, "proposedPairedPlan")
	return result
}

// RefuseUnreadRepositoryProposals is BACKLOG.md F28 finding 1's enforcement
// point: for each of result's OpenPR plans, refuse it outright — the same
// "replace with nil" shape RefuseTruncatedRepositoryProposals just above
// already uses — if it proposes new content for any path this investigation's
// ReadLog has NO record of at all, truncated or otherwise.
//
// This is the guard F25 itself named and declined to build: "a path the
// model never read at all is deliberately NOT refused by this guard — a
// real, different, unenforced gap this entry did not expand into." The
// measured reason it needs building now: of 253 real OpenPR proposals in
// this system's own history (remediation_recommendations, action_type =
// 'OpenPR'), only 13 incidents have ANY read_repo_file call recorded against
// them at all — the model is routinely proposing a complete replacement file
// it never opened, not merely one it read part of.
//
// Deliberately a SEPARATE function from RefuseTruncatedRepositoryProposals,
// not a parameter added to it: the two guards answer genuinely different
// questions (repotools.ReadLog.Unread's own doc comment), a plan can be
// refused by one, the other, both, or neither, and keeping them separate
// keeps each one's own test suite pinned to exactly the scenario it covers
// rather than a combined truth table.
//
// Called immediately after RefuseTruncatedRepositoryProposals in both
// internal/api/analyze.go and internal/autoanalyze.go — same placement
// discipline (before route enforcement, correction, or persistence), same
// two callers, same reasoning: a human-triggered and an unattended analysis
// must be held to the identical safety guard or the two paths silently
// diverge in how safe they are.
//
// log_ now typically comes from a repotools.ReadLogRegistry
// (s.readLogs.Begin/autoanalyze's own registry) rather than a bare
// NewReadLog(), which is what lets it see reads the cli backend made
// through internal/api.CallRepoTool — a completely different call path from
// the one that built it — see ReadLogRegistry's own doc comment. Everything
// below is unaffected by where the log came from; it only ever reads it.
func RefuseUnreadRepositoryProposals(result llm.Investigation, sourceDir string, log_ *repotools.ReadLog) llm.Investigation {
	result.ProposedPlan = refuseUnreadPlan(result.ProposedPlan, sourceDir, log_, "proposedPlan")
	result.ProposedPairedPlan = refuseUnreadPlan(result.ProposedPairedPlan, sourceDir, log_, "proposedPairedPlan")
	return result
}

// RefuseOrphanedRecreatedResourceProposals is BUGS.md 117's fix: a whole-file
// OpenPR plan can recreate a manifest deleted from Git (with honest
// placeholder content — the model cannot know the real deleted content)
// WHILE, in the SAME plan, removing the only reference to that object from a
// sibling file — directly contradicting the plan's own stated intent to
// restore the missing object (its rootCause said the fix was "add the
// missing ConfigMap manifest"; the diff it proposed also deletes the one
// place that referenced it). Neither change is individually wrong — a
// created file and a field removal are each an ordinary, safe edit — but
// together they ship a stub object nothing in the plan's own diff
// references, which never fixes anything and silently defeats the reason
// the file was recreated in the first place.
//
// A narrow, mechanically-checkable version of GC-007's specific shape, not a
// general "does this plan make sense" check. Flags exactly when ALL of:
//
//   - one of this plan's proposed files is CREATED — it does not exist at
//     the pinned synced revision this investigation read from — and its
//     content defines a ConfigMap or Secret (by kind + metadata.name) whose
//     data/stringData/binaryData payload is empty (namedStubObjects below);
//     that is the specific "honest placeholder, not real content" shape a
//     model produces when it cannot know what was actually deleted;
//   - that exact object name appears (a plain substring match — see below)
//     in at least one of this SAME plan's OTHER changed, non-deleted files'
//     PRE-CHANGE content, at the same pinned revision; and
//   - after this plan's own edits, that name appears in NONE of the plan's
//     other changed files' PROPOSED content any more — the created object
//     ends up referenced by nothing else the plan itself touches.
//
// Reference detection is a plain, kind-blind substring match against the
// bare object name, deliberately: it does not understand which specific
// field construct (envFrom, a volume, a Secret reference, a Helm values
// lookup) constitutes a "reference," it only knows whether the literal name
// text is still present. That is a real limitation — a name that happens to
// collide with an unrelated string trips this needlessly, and a reference
// spelled through indirection (e.g. built from a values-file substitution)
// would not be seen at all — but it errs in the SAFE direction for a check
// whose only job is "refuse rather than silently ship a contradiction":
// false positives cost a human an extra review of a plan that turns out to
// be fine, never a missed real contradiction being let through.
//
// Same "refuse by nilling, log why" shape as RefuseTruncatedRepositoryProposals
// (BACKLOG.md F25) just above — deliberately the more conservative of the
// two options BUGS.md 117 itself left open (refuse outright vs. a milder,
// UI-surfaced "extra scrutiny" flag). This entry is explicit that a human PR
// reviewer catching this kind of self-contradiction is also a real, working
// safety net — PR #66's own diff was small enough a reviewer could have
// caught it — so choosing to refuse instead is a judgment call, not the
// only defensible one; BACKLOG.md's entry for this records that
// explicitly rather than presenting refusal as obviously correct. Refusing
// costs nothing safety-relevant (the incident falls back to
// NeedsHumanInvestigation, exactly F25's own failure mode for the identical
// reason) and keeps this file's one existing precedent — refuse a known-bad
// shape here rather than let a human's first signal be a self-contradictory
// merged diff.
//
// Called from both internal/api/analyze.go and internal/autoanalyze.go,
// immediately after RefuseTruncatedRepositoryProposals and before
// orchestrator.EnforceRoute — the same "one function, two callers, before
// route enforcement/persistence" placement F25's own guard uses, for the
// identical reason. repoReader may be nil (no repository scope for this
// incident) — a complete no-op in that case, matching every other repo-tool
// guard's convention for "no repository, nothing to check."
func RefuseOrphanedRecreatedResourceProposals(ctx context.Context, result llm.Investigation, repoReader *repotools.Reader, sourceDir string) llm.Investigation {
	result.ProposedPlan = refuseOrphanedRecreatedResourcePlan(ctx, result.ProposedPlan, repoReader, sourceDir, "proposedPlan")
	result.ProposedPairedPlan = refuseOrphanedRecreatedResourcePlan(ctx, result.ProposedPairedPlan, repoReader, sourceDir, "proposedPairedPlan")
	return result
}

// namedStubObject is one ConfigMap/Secret namedStubObjects found defined in a
// proposed file's content, with an empty data payload.
type namedStubObject struct {
	kind string
	name string
}

// namedStubObjects parses every YAML document in content (the same
// multi-document, "---"-separated convention internal/gitops/locate.go's
// readDocuments already parses real repository files with) and returns one
// namedStubObject for every ConfigMap or Secret document whose
// data/stringData/binaryData mapping has no real entries — empty, absent, or
// containing only comments (a YAML comment is never a mapping entry, so
// `data: {}` plus a commented-out example key parses identically to no data
// key at all). A malformed document, or one with no metadata.name, is
// skipped rather than treated as an error — this check only ever adds a
// refusal on top of an otherwise-valid plan; it must never itself be the
// reason a plan fails to parse.
func namedStubObjects(content string) []namedStubObject {
	var out []namedStubObject
	dec := yaml.NewDecoder(strings.NewReader(content))
	for {
		var doc yaml.Node
		if err := dec.Decode(&doc); err != nil {
			break
		}
		node := &doc
		if node.Kind == yaml.DocumentNode && len(node.Content) == 1 {
			node = node.Content[0]
		}
		if node.Kind != yaml.MappingNode {
			continue
		}
		kind := repoToolsScalarAt(node, "kind")
		if kind != "ConfigMap" && kind != "Secret" {
			continue
		}
		meta := repoToolsMappingValue(node, "metadata")
		name := repoToolsScalarAt(meta, "name")
		if name == "" {
			continue
		}
		if !stubDataPayload(node) {
			continue
		}
		out = append(out, namedStubObject{kind: kind, name: name})
	}
	return out
}

// stubDataPayload reports whether obj's data/stringData/binaryData mapping
// (whichever it has) is empty — the placeholder shape this check exists to
// name, distinct from a recreated manifest that genuinely restates real
// content the model was shown elsewhere in the investigation (which this
// check has no way to verify either way, and does not try to).
func stubDataPayload(obj *yaml.Node) bool {
	for _, key := range []string{"data", "stringData", "binaryData"} {
		if v := repoToolsMappingValue(obj, key); v != nil && v.Kind == yaml.MappingNode && len(v.Content) > 0 {
			return false
		}
	}
	return true
}

// repoToolsScalarAt and repoToolsMappingValue mirror internal/gitops/
// locate.go's unexported scalarAt/mappingValue exactly (same yaml.v3 node
// shape, same "mapping content alternates key, value" walk) — kept as a
// small, deliberate duplication rather than exporting gitops' internals,
// since this package's use (walking a proposed plan's in-memory content) and
// gitops' (walking a real repository file on disk) are different enough
// callers that sharing the exported surface was not worth widening
// internal/gitops' API for.
func repoToolsScalarAt(mapping *yaml.Node, key string) string {
	v := repoToolsMappingValue(mapping, key)
	if v == nil || v.Kind != yaml.ScalarNode {
		return ""
	}
	return v.Value
}

func repoToolsMappingValue(mapping *yaml.Node, key string) *yaml.Node {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			return mapping.Content[i+1]
		}
	}
	return nil
}

func refuseOrphanedRecreatedResourcePlan(ctx context.Context, plan *remediation.RemediationPlan, repoReader *repotools.Reader, sourceDir, field string) *remediation.RemediationPlan {
	if plan == nil || plan.ActionType != remediation.ActionOpenPR || repoReader == nil {
		return plan
	}
	params, ok := plan.Params.(remediation.OpenPRParams)
	if !ok || len(params.Files) < 2 {
		// Needs at least one created file plus at least one other changed
		// file for there to be anything to contradict.
		return plan
	}

	type createdCandidate struct {
		path string
		obj  namedStubObject
	}
	var created []createdCandidate
	// referencedBefore/referencedAfter are keyed by object name: whether ANY
	// of the plan's OTHER files' pre-change / proposed content contains that
	// name. Populated for every candidate name found, regardless of which
	// file it came from, since the check is "referenced by nothing else in
	// the plan," not "referenced by any one specific file."
	referencedBefore := map[string]bool{}
	referencedAfter := map[string]bool{}

	err := repoReader.WithCheckout(ctx, func(dir string) error {
		// Pass 1: find every newly-created ConfigMap/Secret stub. A file
		// "exists" at this revision iff gitops.ReadCheckoutFile can read it —
		// the identical existence check ApplyFileEdit's own Created path
		// uses.
		for _, f := range params.Files {
			if f.Delete {
				continue
			}
			if _, readErr := gitops.ReadCheckoutFile(dir, sourceDir, f.Path); readErr == nil {
				continue // existed before -> an edit, not a creation
			}
			for _, obj := range namedStubObjects(f.Content) {
				created = append(created, createdCandidate{path: f.Path, obj: obj})
			}
		}
		if len(created) == 0 {
			return nil // nothing to cross-check; skip reading every other file for nothing
		}
		// Pass 2: for every OTHER file in the plan (never the created file
		// itself — a ConfigMap does not "reference" its own name), check
		// whether each created name appears in that file's pre-change and
		// post-change content.
		for _, f := range params.Files {
			isTheCreatedFile := false
			for _, c := range created {
				if c.path == f.Path {
					isTheCreatedFile = true
					break
				}
			}
			if isTheCreatedFile {
				continue
			}
			var before string
			if existing, readErr := gitops.ReadCheckoutFile(dir, sourceDir, f.Path); readErr == nil {
				before = string(existing.Content)
			}
			after := f.Content // "" for a deleted file — deleting it removes every reference it ever held
			for _, c := range created {
				name := c.obj.name
				if strings.Contains(before, name) {
					referencedBefore[name] = true
				}
				if !f.Delete && strings.Contains(after, name) {
					referencedAfter[name] = true
				}
			}
		}
		return nil
	})
	if err != nil {
		// The same checkout this investigation's own repository tools
		// already used successfully — a failure here means something
		// changed underneath (the checkout cache evicted, the pinned
		// revision vanished). Fail OPEN: this guard has nothing to add on
		// top of an error it cannot make sense of, and refusing an
		// otherwise-valid plan because ITS OWN safety check could not run is
		// a worse outcome than letting route enforcement and human review
		// see it.
		logger.WarnContext(ctx, "checking out the repository for the orphaned-recreation check failed; skipping that check for this plan",
			slog.String("field", field), logging.Err(err))
		return plan
	}

	var contradictions []string
	for _, c := range created {
		name := c.obj.name
		if referencedBefore[name] && !referencedAfter[name] {
			contradictions = append(contradictions, fmt.Sprintf("%s %q (recreated as a stub in %s, referenced before this plan but by nothing this plan leaves behind)", c.obj.kind, name, c.path))
		}
	}
	if len(contradictions) == 0 {
		return plan
	}
	logger.WarnContext(ctx, "refused an OpenPR plan: it recreates resource(s) as placeholder content while the same plan removes every other reference to them, contradicting its own stated intent to restore what was deleted",
		slog.String("field", field), slog.Int("contradictions", len(contradictions)),
		slog.String("detail", strings.Join(contradictions, "; ")))
	return nil
}

func refuseTruncatedPlan(plan *remediation.RemediationPlan, sourceDir string, log_ *repotools.ReadLog, field string) *remediation.RemediationPlan {
	if plan == nil || plan.ActionType != remediation.ActionOpenPR {
		return plan
	}
	params, ok := plan.Params.(remediation.OpenPRParams)
	if !ok {
		// Params didn't even parse into the OpenPR shape — nothing this guard
		// can check a path against, and remediation.RemediationPlan.Validate()
		// (called downstream by internal/remediation.Evaluate) already Blocks
		// this for the real reason (missing/invalid params), unrelated to F25.
		return plan
	}
	paths := make([]string, 0, len(params.Files))
	for _, f := range params.Files {
		if f.Delete {
			// F25's guard exists because a content-replace proposal built on
			// a partial read silently discards every line the model did not
			// see — a risk that is specific to CONTENT. A delete proposes no
			// content at all, so a truncated read of this same path earlier
			// in the investigation is irrelevant to it: what a delete needs
			// confirmed is that the file currently EXISTS and is the right
			// one, which list_repo_files or any read (truncated or not)
			// already establishes far more cheaply than a full read would.
			// gitops.prepareChanges separately refuses a delete of a path
			// that turns out not to exist at the synced commit — that is
			// this proposal's actual correctness check, not this guard.
			continue
		}
		paths = append(paths, f.Path)
	}
	bad := log_.CheckPaths(sourceDir, paths)
	if len(bad) == 0 {
		return plan
	}
	details := make([]string, 0, len(bad))
	for _, b := range bad {
		details = append(details, fmt.Sprintf("%s (only lines %d-%d of %d were read)", b.Path, b.StartLine, b.EndLine, b.TotalLines))
	}
	logger.Warn("refused an OpenPR plan: it proposes new content for file(s) this investigation only partially read. A proposal built on a partial read silently discards everything outside the window that was read",
		slog.String("field", field), slog.Int("files", len(bad)), slog.String("details", strings.Join(details, "; ")))
	return nil
}

// refuseUnreadPlan is RefuseUnreadRepositoryProposals' per-plan/per-field
// worker — same shape and same delete-exemption reasoning as
// refuseTruncatedPlan just above, checking repotools.ReadLog.Unread instead
// of CheckPaths.
func refuseUnreadPlan(plan *remediation.RemediationPlan, sourceDir string, log_ *repotools.ReadLog, field string) *remediation.RemediationPlan {
	if plan == nil || plan.ActionType != remediation.ActionOpenPR {
		return plan
	}
	params, ok := plan.Params.(remediation.OpenPRParams)
	if !ok {
		// Left for remediation.RemediationPlan.Validate() to Block, exactly as
		// refuseTruncatedPlan leaves it — unrelated to this guard.
		return plan
	}
	paths := make([]string, 0, len(params.Files))
	for _, f := range params.Files {
		if f.Delete {
			// Identical reasoning to refuseTruncatedPlan's own delete
			// exemption: a delete proposes no CONTENT, so whether this exact
			// path was ever read for its content is not what a delete needs
			// established. What it does need — that the file currently
			// exists and is the right one — a list_repo_files call already
			// establishes, and gitops.prepareChanges separately refuses a
			// delete of a path that does not exist at the synced commit.
			continue
		}
		paths = append(paths, f.Path)
	}
	bad := log_.Unread(sourceDir, paths)
	if len(bad) == 0 {
		return plan
	}
	logger.Warn("refused an OpenPR plan: it proposes new content for file(s) that read_repo_file never opened this investigation. A whole-file proposal for a path the model never read is content it invented, not content it observed",
		slog.String("field", field), slog.Int("files", len(bad)), slog.String("paths", strings.Join(bad, ", ")))
	return nil
}

// RefuseSchemaInvalidRepositoryProposals is PROJECT.md B147's mechanism-level
// fix. Found live 2026-09-06 (breadth-campaign CHG-001 fixture): a plan
// correcting a Deployment's drifted image field also wrote syncPolicy — an
// Argo CD Application-level field — as a top-level sibling of the
// Deployment's own spec. Kubernetes silently drops the unrecognized key on
// apply, but Argo's diff engine keeps it in the desired manifest forever,
// permanently defeating the fix.
//
// # Why schema validation, not a per-kind field list
//
// Enumerating "fields that belong to a Deployment" (or the inverse, "fields
// that do not") caps the check at whatever someone wrote down and drifts the
// moment the API adds a field — the identical per-kind enumeration problem
// this codebase's kind-agnostic detection predicates already exist to avoid,
// applied to plan review instead of detection. The cluster's own OpenAPI v3
// document is the authoritative, always-current field list for every kind it
// knows; internal/agent/resourceschema.go's get_resource_schema tool is
// exactly this document, agent-side, fetched fresh (no schema embedded or
// guessed hub-side).
//
// # Why this needs a live cluster call, unlike this file's other guards
//
// Every other guard in this file is a pure function over the investigation's
// own ReadLog — the read-repository tools already ran hub-side during the
// investigation itself, so nothing further is needed. A schema is a fact
// about the LIVE CLUSTER, not the repository, and the only path to it is the
// same tunnel every in-place precondition/dry-run already uses
// (gateway.Gateway.CallTool) — hence the schemaFetcher parameter this
// function's siblings do not need.
//
// # Fail OPEN, deliberately, and only at TOP-LEVEL fields
//
// If the cluster is unreachable, the kind is unrecognized (no CRD installed,
// or a typo ARGUS cannot resolve either), or a specific file's content is not
// a plain, directly-parseable manifest (most commonly a Helm/Kustomize
// TEMPLATE, whose `{{ }}` syntax is not valid YAML at all) — this check is
// skipped for that object, not refused. This is deliberately the opposite
// direction from RefuseUnreadRepositoryProposals' own fail-closed posture:
// that guard protects against CONTENT the model invented, where "we could
// not check" must mean "refuse" (the model's own claim to have read the file
// is unverifiable otherwise); this one is an ADDITIONAL safety net, still
// building on repository content the model actually read, and a live-cluster
// hiccup must not make the whole remediation pipeline start refusing plans
// it would have accepted before this check existed. Only TOP-LEVEL fields
// are checked, not a recursive walk into spec/status: a full JSON-schema
// validator would need to correctly handle Kubernetes' own OpenAPI quirks
// (x-kubernetes-int-or-string, x-kubernetes-preserve-unknown-fields,
// oneOf/anyOf polymorphism) to avoid false-flagging legitimate content, which
// is separately-scoped, higher-risk work; the observed defect (a field with
// no home anywhere on its kind) is fully caught by confirming an object's own
// top-level keys are a subset of its schema's own top-level properties. A
// wrong value nested several levels into an existing field is a known,
// un-covered limitation, not silently overclaimed.
func RefuseSchemaInvalidRepositoryProposals(ctx context.Context, gw schemaFetcher, clusterID string, result llm.Investigation) llm.Investigation {
	result.ProposedPlan = refuseSchemaInvalidPlan(ctx, gw, clusterID, result.ProposedPlan, "proposedPlan")
	result.ProposedPairedPlan = refuseSchemaInvalidPlan(ctx, gw, clusterID, result.ProposedPairedPlan, "proposedPairedPlan")
	return result
}

// schemaFetcher is the minimal live-cluster capability this guard needs —
// narrower than *gateway.Gateway so a test can supply a fake without
// building a whole Gateway (which needs a live tunnel listener). Satisfied
// by *gateway.Gateway's own CallTool/IsConnected, already used exactly this
// way by every in-place precondition check in internal/api.
type schemaFetcher interface {
	IsConnected(clusterID string) bool
	CallTool(ctx context.Context, clusterID, tool string, args json.RawMessage) (json.RawMessage, error)
}

func refuseSchemaInvalidPlan(ctx context.Context, gw schemaFetcher, clusterID string, plan *remediation.RemediationPlan, field string) *remediation.RemediationPlan {
	if plan == nil || plan.ActionType != remediation.ActionOpenPR {
		return plan
	}
	params, ok := plan.Params.(remediation.OpenPRParams)
	if !ok {
		// Left for remediation.RemediationPlan.Validate() to Block, exactly
		// as every sibling guard in this file leaves it.
		return plan
	}
	if gw == nil || !gw.IsConnected(clusterID) {
		return plan
	}
	for _, f := range params.Files {
		if f.Delete {
			continue // no content to validate
		}
		for _, obj := range parseYAMLMappingsTolerant(f.Content) {
			apiVersion := repoToolsScalarAt(obj, "apiVersion")
			kind := repoToolsScalarAt(obj, "kind")
			if apiVersion == "" || kind == "" {
				// Not a plain, directly-identifiable manifest — most likely
				// a Helm/Kustomize template. Honest skip, not a refusal.
				continue
			}
			schemaFields, found := fetchResourceSchemaFields(ctx, gw, clusterID, apiVersion+"/"+kind)
			if !found {
				continue
			}
			allowed := make(map[string]bool, len(schemaFields))
			for _, sf := range schemaFields {
				allowed[sf] = true
			}
			for _, key := range repoToolsMappingKeys(obj) {
				if allowed[key] {
					continue
				}
				logger.WarnContext(ctx, "refused an OpenPR plan: it proposes an object with a top-level field that does not exist anywhere in this cluster's own schema for that kind. A field belonging to a different kind is silently dropped by Kubernetes on apply but can permanently defeat a GitOps controller's sync status",
					slog.String("field", field), slog.String("path", f.Path), slog.String("offending_field", key),
					slog.String("api_version", apiVersion), slog.String("kind", kind))
				return nil
			}
		}
	}
	return plan
}

// parseYAMLMappingsTolerant parses every document in content (the same
// "---"-separated, decode-until-first-failure convention
// namedStubObjects above already uses) and returns every one that decodes
// to a plain YAML mapping — silently skipping anything that fails to parse
// at all (a Helm/Kustomize template's `{{ }}` syntax is not valid YAML) or
// that parses to something other than a mapping. This check only ever adds
// a refusal on top of an otherwise-valid plan; it must never itself be the
// reason a plan fails to parse.
func parseYAMLMappingsTolerant(content string) []*yaml.Node {
	var out []*yaml.Node
	dec := yaml.NewDecoder(strings.NewReader(content))
	for {
		var doc yaml.Node
		if err := dec.Decode(&doc); err != nil {
			break
		}
		node := &doc
		if node.Kind == yaml.DocumentNode && len(node.Content) == 1 {
			node = node.Content[0]
		}
		if node.Kind != yaml.MappingNode {
			continue
		}
		out = append(out, node)
	}
	return out
}

// repoToolsMappingKeys returns every top-level key of a YAML mapping node —
// mapping.Content alternates key, value, key, value, so keys are the
// even-indexed entries' own scalar values.
func repoToolsMappingKeys(mapping *yaml.Node) []string {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil
	}
	keys := make([]string, 0, len(mapping.Content)/2)
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		keys = append(keys, mapping.Content[i].Value)
	}
	return keys
}

// resourceSchemaToolResult mirrors internal/agent/resourceschema.go's
// resourceSchemaResult wire shape exactly — kept as a second, hub-side
// struct rather than a shared import, the same "two ends of one tunnel call,
// two independent struct definitions" precedent every other tool
// request/response pair in this codebase already follows (describe_resource,
// get_gitops_ownership, etc. — internal/agent is never imported by
// internal/api, since one runs on the hub and the other in cluster-side
// binaries).
type resourceSchemaToolResult struct {
	Found          bool     `json:"found"`
	TopLevelFields []string `json:"topLevelFields"`
}

// fetchResourceSchemaFields calls get_resource_schema for gvkString ("[group/]version/Kind",
// the same wire convention describe_resource's own gvk argument uses) and
// returns its top-level field list. found is false for every failure mode
// alike — tool error, malformed response, or the tool's own honest
// Found:false — since refuseSchemaInvalidPlan's only correct response to any
// of them is the same: skip validation for this object rather than guess.
func fetchResourceSchemaFields(ctx context.Context, gw schemaFetcher, clusterID, gvkString string) (fields []string, found bool) {
	argsJSON, err := json.Marshal(map[string]any{"gvk": gvkString})
	if err != nil {
		return nil, false
	}
	raw, err := gw.CallTool(ctx, clusterID, "get_resource_schema", argsJSON)
	if err != nil {
		return nil, false
	}
	var result resourceSchemaToolResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, false
	}
	if !result.Found {
		return nil, false
	}
	return result.TopLevelFields, true
}
