package api

// BACKLOG.md F30, pieces 1 and 2: replace a hand-typed release/namespace/path
// ObjectMapping with a DISCOVERED and RENDER-PROVEN one.
//
// Argo CD and Flux give ARGUS a repo/path/revision for free, straight off
// their own Application/Kustomization CR. A plain Helm release has nothing
// equivalent anywhere in the cluster (non-negotiable #9 also rules out the
// one place that DOES know — the release Secret), so this file's job is to
// answer, without ANY operator-supplied configuration, "which registered
// repository, and which path in it, actually renders this exact live
// object" — and to say so only when a real render proves it, never as a
// guess.
//
// Every registered repository is already fetchable
// (internal/repotools.Checkouts, the same clone cache the investigation
// loop's repo tools use). Every chart is already renderable in the sandbox
// (internal/render, internal/render/sandbox). This file's only genuinely
// new code is deciding WHICH chart, at WHICH values-file combination, to
// try — everything after that is a call to something F26/F28/F19 already
// built and proved.
import (
	"context"
	"fmt"
	"log/slog"
	"path"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"gopkg.in/yaml.v3"

	"argus/internal/logging"
	"argus/internal/render"
	"argus/internal/repotools"
	"argus/internal/scm"
)

// LinkCandidate is one (repository, path) pair a render has either proven or
// is still ambiguous about. ValuesFile is "" when the chart's own defaults
// alone already produce the live object — the common case for a chart with
// no per-environment split at all.
type LinkCandidate struct {
	BindingID  string `json:"bindingId"`
	RepoURL    string `json:"repoUrl"`
	ChartPath  string `json:"chartPath"`
	ValuesFile string `json:"valuesFile,omitempty"`
}

// LinkDiscoveryResult is discoverRepositoryLink's whole answer. Status is
// exactly one of:
//
//   - "proven": len(Candidates) == 1. The one candidate is what the
//     incident-flow UI pre-fills, and Scope's own default (Cluster) is what
//     it proposes.
//   - "ambiguous": len(Candidates) > 1. Two or more registered repositories
//     (or two chart paths) genuinely render the SAME live object — a
//     monorepo and a split repo, a fork, or dev/prod overlays that both
//     happen to match. F30's own rule: present every one, pick none.
//   - "none": no candidate rendered the live object, and every render that
//     was attempted completed without error. A real, honest negative — what
//     a third-party chart ARGUS has no repository for (cert-manager,
//     ingress-nginx) looks like.
//   - "degraded": rendering could not be attempted at all (no sandbox
//     configured) or every attempt that was made failed to run to
//     completion. Never conflated with "none": a chart that could not be
//     rendered has told ARGUS nothing about whether it produces the object.
type LinkDiscoveryResult struct {
	Status     string
	Candidates []LinkCandidate
	Degraded   string
}

// discoverRepositoryLink is F30's whole discover-then-prove step for one
// blocked incident's Helm release (or, via labels, one plain kubectl-applied
// object). Called only when an incident actually needs a link — never on a
// timer, never for every release in the fleet up front — which is what
// keeps a render sandbox's per-pod budget from ever being spent on a link
// nobody is waiting on.
//
// gvk is this codebase's own "apiVersion/Kind" wire form (e.g.
// "apps/v1/Deployment"), matching render.Object's own APIVersion+"/"+Kind —
// the same identity ObjectOwnership.ObjectGVK already carries on the wire.
func (s *Server) discoverRepositoryLink(ctx context.Context, tx pgx.Tx, releaseName, releaseNamespace, targetGVK, targetNamespace, targetName string) LinkDiscoveryResult {
	if s.renderSandbox == nil {
		// Not a misconfiguration — see this file's own header and
		// render_evidence.go's identical nil-check. Every caller of THIS
		// function must degrade exactly the way evaluateRenderEffect's
		// callers already do.
		return LinkDiscoveryResult{Status: "degraded", Degraded: "no render sandbox is configured on this hub, so a link cannot be proven by rendering"}
	}

	bindings, err := s.scmStore.ListBindings(ctx, tx)
	if err != nil {
		logger.ErrorContext(ctx, "listing the repository bindings for link discovery failed", logging.Err(err))
		return LinkDiscoveryResult{Status: "degraded", Degraded: "could not list registered repositories (see hub logs for detail)"}
	}
	if len(bindings) == 0 {
		return LinkDiscoveryResult{Status: "none"}
	}

	var proven []LinkCandidate
	anyRenderAttempted := false
	anyRenderSucceeded := false
	anyRenderFailed := false

	for _, b := range bindings {
		charts, valuesFiles, fullTree, ok := s.checkoutAndFindCharts(ctx, tx, b)
		if !ok {
			continue
		}
		orderChartsByNameAlignment(charts, releaseName)

		for _, chart := range charts {
			// Chart defaults alone, first — the common case (no
			// per-environment split at all) needs no values file.
			for _, vf := range append([]string{""}, valuesFiles...) {
				anyRenderAttempted = true
				objs, err := s.renderChartCached(ctx, b.ID, chart.commit, fullTree, chart.dir, vf)
				if err != nil {
					logger.WarnContext(ctx, "rendering a chart during repository-link discovery failed",
						slog.String("repo_url", b.URL), slog.String("commit", shortRevision(chart.commit)),
						slog.String("chart_dir", chart.dir), slog.String("values_file", vf), logging.Err(err))
					anyRenderFailed = true
					continue
				}
				anyRenderSucceeded = true
				if objectAppearsIn(objs, targetGVK, targetNamespace, targetName) {
					proven = append(proven, LinkCandidate{BindingID: b.ID, RepoURL: b.URL, ChartPath: chart.dir, ValuesFile: vf})
					break // one proof is enough to count this chart as a candidate — no need to try more values files for it
				}
			}
		}
	}

	status, degraded := classifyDiscovery(len(proven), anyRenderAttempted, anyRenderSucceeded, anyRenderFailed)
	return LinkDiscoveryResult{Status: status, Candidates: proven, Degraded: degraded}
}

// classifyDiscovery is discoverRepositoryLink's status decision, pulled out
// as a pure function so the boundary between "none" and "degraded" — the
// one this feature's whole honesty guarantee rests on — is unit-testable
// without a database, a checkout or a render sandbox.
//
// "none" requires EVERY attempted render to have completed without error —
// LinkDiscoveryResult's own doc comment says so in as many words. The bug
// this fixes: an earlier version returned "none" as soon as ANY render
// anywhere succeeded, so one registered repository's genuinely broken chart
// (a live example: a duplicate YAML mapping key in an Ingress template,
// caught 2026-09-09 against the real shop-apps-helm repository) was silently
// absorbed into "none" whenever some OTHER, unrelated repository's chart
// happened to render cleanly elsewhere — reporting "ARGUS checked and this
// isn't here" when the honest answer was "the repository that actually
// might match could not be rendered at all". A render failure on any
// candidate means the sweep did not fully complete, so the correct answer
// is "degraded", never "none", regardless of what else succeeded.
func classifyDiscovery(provenCount int, anyRenderAttempted, anyRenderSucceeded, anyRenderFailed bool) (status, degraded string) {
	switch {
	case provenCount == 1:
		return "proven", ""
	case provenCount > 1:
		return "ambiguous", ""
	case !anyRenderAttempted:
		return "degraded", "no registered repository contains a Helm chart or Kustomize overlay to render"
	case !anyRenderSucceeded:
		return "degraded", "every render attempt failed (see hub logs for detail) — not the same as a chart that rendered cleanly and did not produce the object"
	case anyRenderFailed:
		return "degraded", "at least one render attempt failed (see hub logs for detail) — not the same as every chart rendering cleanly and none producing the object"
	default:
		return "none", ""
	}
}

// chartCandidate is one Chart.yaml found inside a binding's checked-out
// tree — dir and commit are enough to re-derive everything else (the
// chart's own subtree, and where a values file sits relative to it) against
// the fullTree the caller already holds, so nothing here duplicates it.
type chartCandidate struct {
	dir    string // repo-root-relative directory the Chart.yaml was found in ("" for the repo root)
	name   string // Chart.yaml's own `name:` field, "" if absent/unreadable
	commit string
}

// checkoutAndFindCharts resolves one binding to a real commit, checks it
// out in FULL (no sparse path restriction — discovery does not know the
// chart's location yet; that is the thing being discovered), and returns
// every Chart.yaml found, every values-file-shaped path anywhere in the
// checkout, and the full repo-root-relative tree itself (needed later to
// re-root each chart's own subtree and to look up a values file wherever it
// actually lives). ok is false when the binding could not be used at all
// (no usable credential, no resolvable branch, a clone failure) — logged,
// and treated by the caller as "this repository contributed nothing", never
// as a hard failure of the whole discovery.
func (s *Server) checkoutAndFindCharts(ctx context.Context, tx pgx.Tx, b scm.Binding) ([]chartCandidate, []string, map[string][]byte, bool) {
	provider, repo, binding, err := s.scmStore.ProviderFor(ctx, tx, b.URL)
	if err != nil {
		logger.WarnContext(ctx, "resolving the repository provider failed", slog.String("repo_url", b.URL), logging.Err(err))
		return nil, nil, nil, false
	}
	cred, ok := provider.(scm.CloneCredentialer)
	if !ok {
		return nil, nil, nil, false
	}

	// Same "stored branch first, provider auto-detect only as a fallback"
	// order matchObjectMapping and handleCheckRepositoryBinding both already
	// use — a repository whose own default-branch auto-detection is broken
	// (this session's own live GitLab finding) must not also be unusable
	// here for the identical reason.
	branch := binding.DefaultBranch
	if branch == "" {
		branch, err = provider.DefaultBranch(ctx, repo)
		if err != nil {
			logger.WarnContext(ctx, "resolving the repository's default branch failed", slog.String("repo_url", b.URL), logging.Err(err))
			return nil, nil, nil, false
		}
	}
	commit, err := provider.ResolveRef(ctx, repo, branch)
	if err != nil {
		logger.WarnContext(ctx, "resolving the repository branch to a commit failed",
			slog.String("repo_url", b.URL), slog.String("branch", branch), logging.Err(err))
		return nil, nil, nil, false
	}

	dir, release, err := s.checkouts.Checkout(ctx, repotools.Scope{
		RepoURL: b.URL, Revision: commit, Host: binding.Host, Token: cred.CloneToken(),
	})
	if err != nil {
		logger.WarnContext(ctx, "checking out the repository failed",
			slog.String("repo_url", b.URL), slog.String("commit", shortRevision(commit)), logging.Err(err))
		return nil, nil, nil, false
	}
	defer release()

	tree, err := readSourceTree(dir)
	if err != nil {
		logger.WarnContext(ctx, "reading the checked-out tree failed",
			slog.String("repo_url", b.URL), slog.String("commit", shortRevision(commit)), logging.Err(err))
		return nil, nil, nil, false
	}

	var charts []chartCandidate
	var valuesFiles []string
	for p := range tree {
		base := path.Base(p)
		if base == "Chart.yaml" {
			charts = append(charts, chartCandidate{
				dir:    strings.TrimSuffix(strings.TrimSuffix(p, "Chart.yaml"), "/"),
				name:   chartNameFrom(tree[p]),
				commit: commit,
			})
			continue
		}
		if looksLikeValuesFile(base) {
			valuesFiles = append(valuesFiles, p)
		}
	}
	sort.Slice(charts, func(i, j int) bool { return charts[i].dir < charts[j].dir })
	sort.Strings(valuesFiles)
	return charts, valuesFiles, tree, true
}

// looksLikeValuesFile is F30's own bounded heuristic for "a Helm values
// override file that isn't the chart's own bundled values.yaml" —
// deliberately narrow (a name starting with "values" and ending .yaml/.yml)
// rather than an attempt to recognise every possible repository convention.
// F30's own example is exactly this shape (values-prod.yaml disambiguating
// from values-dev.yaml); a convention this does not recognise simply
// produces no candidate, which surfaces as "none" or stays "ambiguous"
// rather than becoming a wrong guess.
func looksLikeValuesFile(base string) bool {
	return strings.HasPrefix(base, "values") && (strings.HasSuffix(base, ".yaml") || strings.HasSuffix(base, ".yml"))
}

// chartNameFrom reads Chart.yaml's own `name:` field for the name-alignment
// ordering step (F30 piece 2: "name alignment orders candidates, it never
// asserts a link"). An unreadable or nameless Chart.yaml is not an error
// here — it just never sorts first, and is still tried.
func chartNameFrom(raw []byte) string {
	var doc struct {
		Name string `yaml:"name"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return ""
	}
	return doc.Name
}

// orderChartsByNameAlignment sorts chart candidates already found so the
// render loop tries the most plausible chart first — purely a cost
// ordering; every candidate is still tried regardless, so this never
// removes one. "name alignment orders candidates, it never asserts a link."
func orderChartsByNameAlignment(charts []chartCandidate, releaseName string) {
	aligned := func(c chartCandidate) bool {
		return c.name == releaseName || path.Base(c.dir) == releaseName
	}
	sort.SliceStable(charts, func(i, j int) bool {
		ai, aj := aligned(charts[i]), aligned(charts[j])
		return ai && !aj
	})
}

// subtree returns the entries of tree whose path is under prefix, with
// prefix stripped — what a Helm render needs at its tar root
// (render.BuildTarGz packages exactly the map it is given, unaware of
// anything above it). prefix == "" returns a copy of the whole tree (the
// chart lives at the repository root).
func subtree(tree map[string][]byte, prefix string) map[string][]byte {
	out := make(map[string][]byte)
	if prefix == "" {
		for k, v := range tree {
			out[k] = v
		}
		return out
	}
	withSlash := prefix + "/"
	for p, content := range tree {
		if rel, ok := strings.CutPrefix(p, withSlash); ok && rel != "" {
			out[rel] = content
		}
	}
	return out
}

// renderChartCached renders one chart (identified by its repo-root-relative
// directory within fullTree), optionally with one values file — which may
// live INSIDE the chart's own directory (the ordinary case, already part of
// its subtree once re-rooted) or OUTSIDE it (a per-environment values file
// living alongside, not under, the chart — copied in under a synthetic name
// so RenderParams.ValueFiles, which is chart-tree-relative, can reference
// it regardless of where in the repository it actually lives).
//
// Memoised by exactly what was rendered — see Server.linkDiscoveryCache's
// own doc comment for why an unbounded process-lifetime cache is the right
// size of "bound the cost" here.
func (s *Server) renderChartCached(ctx context.Context, bindingID, commit string, fullTree map[string][]byte, chartDir, valuesFile string) ([]render.Object, error) {
	key := bindingID + "@" + commit + "#" + chartDir + "?" + valuesFile
	if cached, ok := s.linkDiscoveryCache.Load(key); ok {
		entry := cached.(renderCacheEntry)
		return entry.objs, entry.err
	}

	chartTree := subtree(fullTree, chartDir)
	params := render.RenderParams{ReleaseName: "argus-discovery"}
	if valuesFile != "" {
		content, ok := fullTree[valuesFile]
		if !ok {
			return nil, fmt.Errorf("render: values file %q not found in the checked-out tree", valuesFile)
		}
		if rel, inside := strings.CutPrefix(valuesFile, chartDir+"/"); chartDir != "" && inside {
			// Already part of chartTree once re-rooted — reference its own
			// relative path, no copy needed.
			params.ValueFiles = []string{rel}
		} else if chartDir == "" {
			// The chart IS the repo root, so every repo-root-relative path
			// is already chart-tree-relative too.
			params.ValueFiles = []string{valuesFile}
		} else {
			synthetic := "_argus_discovery_values_" + path.Base(valuesFile)
			chartTree = withExtraFile(chartTree, synthetic, content)
			params.ValueFiles = []string{synthetic}
		}
	}

	objs, err := render.RenderTree(ctx, s.renderSandbox.RenderFunc(), render.DetectKind(chartTree), chartTree, params)
	s.linkDiscoveryCache.Store(key, renderCacheEntry{objs: objs, err: err})
	return objs, err
}

type renderCacheEntry struct {
	objs []render.Object
	err  error
}

// withExtraFile returns a shallow copy of tree with one additional entry —
// tree itself is never mutated, matching render.ApplyEdits' own contract.
func withExtraFile(tree map[string][]byte, path string, content []byte) map[string][]byte {
	out := make(map[string][]byte, len(tree)+1)
	for k, v := range tree {
		out[k] = v
	}
	out[path] = content
	return out
}

// objectAppearsIn is the actual "proof" step: does the live object, by
// kind+namespace+name, appear anywhere in a chart's rendered output. gvk
// comparison is exact-string ("apps/v1/Deployment" form) — no fuzzy
// matching, because a render that produced a DIFFERENT kind at the same
// name is not evidence of anything.
func objectAppearsIn(objs []render.Object, targetGVK, targetNamespace, targetName string) bool {
	for _, o := range objs {
		if o.APIVersion+"/"+o.Kind == targetGVK && o.Namespace == targetNamespace && o.Name == targetName {
			return true
		}
	}
	return false
}
