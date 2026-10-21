package api

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"argus/internal/gitops"
	"argus/internal/logging"
	"argus/internal/render"
	"argus/internal/repotools"
)

// renderEvaluationTimeout bounds the whole render-and-diff step — a caller
// wiring this into a pull-request-opening path must never wait
// indefinitely for it (this task's own instruction: a render
// failure/unavailability degrades, it never gates). lld/09 §2's own
// per-pod wall clock is 2 minutes; this budgets for the checkout PLUS two
// sandboxed renders PLUS the comparison, so it is wider than one pod's own
// timeout, not narrower.
const renderEvaluationTimeout = 3 * time.Minute

// helmMissingValueFilesReason is quoted verbatim into RenderEvidence.Degraded
// — and from there into a customer-facing pull-request body/trailer, the
// preview response, and the audit record — so it is written for that
// reader, not as an internal log line.
const helmMissingValueFilesReason = "no Helm values-file list is available for this chart (ARGUS has no Argo CD API connection registered yet to discover spec.source.helm.valueFiles), so a render could only use the chart's built-in defaults — never a real deployment's actual configuration. A defaults-only render cannot confirm whether a real values file would make this edit effective, so no verdict from it — including one that happens to say \"no effective change\" — is treated as authoritative here"

// helmMissingValueFileDiscovery is BACKLOG.md F28 finding 2's own
// predicate, pulled out of evaluateRenderEffect as a small pure function so
// it can be unit-tested directly (render_evidence_test.go) without needing
// a real render sandbox: kind == KindHelm and valueFiles is empty. See
// evaluateRenderEffect's own inline comment, right where this is called,
// for the full reasoning — this function only names the condition.
func helmMissingValueFileDiscovery(kind render.Kind, valueFiles []string) bool {
	return kind == render.KindHelm && len(valueFiles) == 0
}

// evaluateRenderEffect is BACKLOG.md F26's wiring point: given exactly the
// input a caller is about to hand to gitops.ProposeChanges/PreviewChanges
// (the resolved repository scope and the model's own proposed edit set), try
// to compute a *gitops.RenderEvidence BEFORE that call, so the caller can
// set it on ProposalInput.RenderEvidence and have it land in the pull
// request body, its trailers, and the audit/timeline record — all from one
// evaluation, computed once.
//
// # The three outcomes, and why none of them is an error return
//
// This method's signature has no error return on purpose. Every failure
// mode is encoded IN the result:
//
//   - nil: never attempted. No render sandbox is configured on this hub, the
//     repository scope is empty (no known ownership), or the checked-out
//     tree is not a Helm chart or Kustomize overlay at all (plain YAML,
//     where a diff already IS the cluster effect and this package has
//     nothing to add). This is exactly today's status quo — the same
//     "unproven and stated as unproven" posture the pull request already
//     carries without F26.
//   - *gitops.RenderEvidence{Attempted: true, Degraded: "..."}: rendering
//     was tried and could not produce a usable answer (checkout failed, the
//     sandbox timed out, the renderer errored). Treated identically to nil
//     by the pull-request body (see gitops.renderedDeltaSection) — the
//     point of encoding it explicitly rather than silently returning nil
//     too is so an operator reading logs/audit can tell "never tried" apart
//     from "tried and the sandbox is unhealthy", without that distinction
//     ever reaching the reviewer as a reason to distrust the PR.
//   - *gitops.RenderEvidence{Attempted: true, Effective: ...}: a real
//     answer.
//
// valueFiles is the Helm values-file precedence list (lld/09 §5.1 step 3) —
// see render.RenderParams' doc comment for why this package cannot resolve
// it automatically yet (no Argo CD API connection is registered with
// ARGUS) and must be supplied by the caller when known.
func (s *Server) evaluateRenderEffect(ctx context.Context, scope repotools.Scope, edits []gitops.FileEdit, valueFiles []string) *gitops.RenderEvidence {
	if s.renderSandbox == nil {
		return nil
	}
	if !scope.Valid() {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), renderEvaluationTimeout)
	defer cancel()

	repoDir, release, err := s.checkouts.Checkout(ctx, scope)
	if err != nil {
		logger.WarnContext(ctx, "checking out the repository for render evidence failed",
			slog.String("repo_url", scope.RepoURL), slog.String("revision", shortRevision(scope.Revision)), logging.Err(err))
		return &gitops.RenderEvidence{Attempted: true, Degraded: "could not read the repository content to render it (see hub logs for detail)"}
	}
	defer release()

	sourceDir := repoDir
	if clean := strings.Trim(strings.TrimSpace(scope.SourceDir), "/"); clean != "" && clean != "." {
		sourceDir = filepath.Join(repoDir, clean)
	}

	tree, err := readSourceTree(sourceDir)
	if err != nil {
		logger.WarnContext(ctx, "reading the checked-out tree for render evidence failed", slog.String("source_dir", sourceDir), logging.Err(err))
		return &gitops.RenderEvidence{Attempted: true, Degraded: "could not read the checked-out source tree (see hub logs for detail)"}
	}

	kind := render.DetectKind(tree)
	if kind == render.KindUnsupported {
		// Not a rendering gap — there is nothing to render. A plain-YAML
		// source's diff already IS the cluster effect, so "never attempted"
		// here is the honest answer, not a degraded one.
		return nil
	}

	// BACKLOG.md F28 finding 2's honesty fix: a Helm render with no
	// values-file list is not a weaker-but-still-true answer, it is a
	// DIFFERENT question answered instead of the one being asked. Until the
	// values-file list is discovered from the Argo Application (no Argo CD
	// API connection is registered with ARGUS today — see RenderParams' own
	// doc comment in internal/render/evaluate.go), every caller of this
	// function passes valueFiles as nil/empty, which means EVERY Helm render
	// this hub has ever produced was against chart defaults only. A
	// defaults-only render can genuinely agree with the real deployed
	// manifests by chance, or it can silently miss the one values file that
	// makes an edit effective (or ineffective) — this function has no way
	// to tell which, because it never looked at the file that would tell it.
	// Reporting "no effective change" from that basis is exactly the false
	// confidence non-negotiable 8 forbids: a guess presented as a checked
	// fact. So this is refused BEFORE the render ever runs — a render whose
	// answer would be discarded regardless of what it found is a render not
	// worth the sandbox pod's three-minute budget — and reported as
	// Degraded, never as a confident Effective:false, even though a
	// downstream renderer might well have agreed with that guess.
	//
	// Kustomize is unaffected: ValueFiles has no meaning for it (this
	// package's own RenderParams doc comment — "Ignored for Kustomize"), so
	// an empty list there is not a missing input, it is simply not an input
	// at all.
	if helmMissingValueFileDiscovery(kind, valueFiles) {
		return &gitops.RenderEvidence{
			Attempted: true,
			Degraded:  helmMissingValueFilesReason,
		}
	}

	editMap := make(map[string][]byte, len(edits))
	deleteMap := make(map[string]bool, len(edits))
	for _, e := range edits {
		path := relativeToSourceDir(e.Path, scope.SourceDir)
		if e.Delete {
			deleteMap[path] = true
			continue
		}
		editMap[path] = e.Content
	}
	proposedTree := render.ApplyEdits(tree, editMap, deleteMap)

	result, err := render.EvaluateProposal(ctx, s.renderSandbox.RenderFunc(), kind, tree, proposedTree, render.RenderParams{ValueFiles: valueFiles})
	if err != nil {
		// The FULL error (which may include the renderer's stderr — e.g. a
		// Helm error that echoes a line of a values file) is logged
		// server-side only. RenderEvidence.Degraded is quoted verbatim into
		// a customer-facing pull request body and the audit record
		// (renderedDeltaSection, renderEvidenceAuditFields) — a short,
		// generic classification there, never the raw renderer output, is
		// the same "don't put repository content where it wasn't already
		// going" discipline propose.go's own PR body keeps (evidence links,
		// never inlined raw content).
		logger.WarnContext(ctx, "rendering the repository for render evidence failed",
			slog.String("repo_url", scope.RepoURL), slog.String("revision", shortRevision(scope.Revision)), logging.Err(err))
		return &gitops.RenderEvidence{Attempted: true, Degraded: "the renderer reported an error (see hub logs for detail)"}
	}

	changed := make([]string, 0, len(result.Changed))
	for _, d := range result.Changed {
		changed = append(changed, d.Object)
	}
	return &gitops.RenderEvidence{
		Attempted:       true,
		RendererKind:    result.RendererKind,
		Effective:       result.Effective,
		ObjectsCompared: result.ObjectsTotal,
		ObjectsChanged:  changed,
		Summary:         result.Summary,
	}
}

// renderEvidenceAuditFields turns a *gitops.RenderEvidence (nil included)
// into the map[string]any shape audit.Event.Details and timeline.Event.Detail
// already use everywhere else in this package — always present as a key
// (matching the "advisories" precedent right above its own call site), never
// omitted just because rendering was never attempted.
func renderEvidenceAuditFields(re *gitops.RenderEvidence) map[string]any {
	if re == nil {
		return map[string]any{"attempted": false}
	}
	out := map[string]any{"attempted": re.Attempted}
	if re.Degraded != "" {
		out["degraded"] = re.Degraded
		return out
	}
	out["rendererKind"] = re.RendererKind
	out["effective"] = re.Effective
	out["objectsCompared"] = re.ObjectsCompared
	out["objectsChanged"] = re.ObjectsChanged
	out["summary"] = re.Summary
	return out
}

// relativeToSourceDir turns a FileEdit's repository-root-relative path into a
// path relative to the SOURCE DIR tree readSourceTree reads — the same
// SourceDir prefix ProposalInput's own paths are already confined to
// (propose.go's prepareChanges checks this before any edit reaches here), so
// stripping it is safe rather than assumed.
func relativeToSourceDir(path, sourceDir string) string {
	clean := strings.Trim(strings.TrimSpace(sourceDir), "/")
	if clean == "" || clean == "." {
		return path
	}
	prefix := clean + "/"
	if strings.HasPrefix(path, prefix) {
		return strings.TrimPrefix(path, prefix)
	}
	return path
}

// readSourceTree walks a checked-out directory into the path->content map
// render.BuildTarGz packages — skipping .git entirely, since gitops.Clone's
// checkout is a real working tree (not the API-based reads propose.go uses
// for writes) and a chart/overlay render has no use for git's own internal
// object store.
func readSourceTree(root string) (map[string][]byte, error) {
	tree := map[string][]byte{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		if info.IsDir() {
			if rel == ".git" || strings.HasPrefix(rel, ".git"+string(filepath.Separator)) {
				return filepath.SkipDir
			}
			return nil
		}
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		tree[filepath.ToSlash(rel)] = content
		return nil
	})
	if err != nil {
		return nil, err
	}
	return tree, nil
}
