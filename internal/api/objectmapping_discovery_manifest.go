package api

// BACKLOG.md F30 owner decision 2026-09-09: "non-Helm objects are matched
// the same way, by rendering, with no label selectors [typed by an
// operator]." objectmapping_discovery.go's discoverRepositoryLink answers
// this for a Helm release (candidate charts, rendered in the sandbox,
// checked against the live object). This file answers the sibling
// question for a PLAIN-MANIFEST object — no Helm release annotation, no
// Argo CD/Flux controller — where there is no chart to render at all: the
// object's own YAML, wherever it lives in a registered repository, IS the
// manifest (internal/render's own KindUnsupported doc comment says so in as
// many words: "rendering is a no-op distinction... this package has
// nothing useful to add"). So "render" here means parsing that file
// directly with render.ParseManifests — no sandbox call, no Helm/Kustomize
// invocation — and checking whether the live object appears in it, exactly
// the same proof discoverRepositoryLink uses (objectAppearsIn).
//
// Deliberately excludes anything inside a directory this binding's own
// Helm charts occupy (checkoutAndFindCharts already found them) — a
// chart's own template files are not plain manifests, they are Go-template
// text that happens to have a .yaml extension, and trying to parse them
// here would either error (a false "degraded") or occasionally decode into
// something that never runs live at all. That exclusion is a scope limit,
// not silent guessing: a plain-manifest object that happens to sit in the
// same repository as a chart is still found, as long as it is not under
// the chart's own directory.
import (
	"context"
	"log/slog"
	"path"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"

	"argus/internal/logging"
	"argus/internal/render"
)

// looksLikeManifestPath reports whether p is a YAML file this scan should
// try to parse as a standalone manifest — a .yaml/.yml file that is not
// Chart.yaml, not a Kustomize entrypoint (kustomize rendering is F30's
// explicitly out-of-scope sibling — see this file's own header), and not a
// Helm values override (looksLikeValuesFile, reused from
// objectmapping_discovery.go: a values file never carries a rendered
// object on its own, Helm or not).
func looksLikeManifestPath(p string) bool {
	base := path.Base(p)
	if !strings.HasSuffix(base, ".yaml") && !strings.HasSuffix(base, ".yml") {
		return false
	}
	if base == "Chart.yaml" || base == "kustomization.yaml" || base == "kustomization.yml" {
		return false
	}
	return !looksLikeValuesFile(base)
}

// underAnyChartDir reports whether p sits inside (or, for a chart rooted at
// the repository root, anywhere in) one of charts' own directories — see
// this file's header for why that content is excluded from a plain-manifest
// scan rather than attempted and reported as a parse failure.
func underAnyChartDir(p string, charts []chartCandidate) bool {
	for _, c := range charts {
		if c.dir == "" {
			return true // the chart IS the repository root — nothing here is "outside" it
		}
		if strings.HasPrefix(p, c.dir+"/") {
			return true
		}
	}
	return false
}

// discoverManifestLink is discoverRepositoryLink's plain-manifest sibling —
// same candidate/proof shape (LinkCandidate, LinkDiscoveryResult), same
// "present every proof, guess at none" rule, but proving by directly parsing
// a repository-tracked YAML file rather than invoking a renderer, since a
// plain manifest has no template step to run. Never gated on
// s.renderSandbox being configured: parsing needs no sandbox at all, so a
// hub with no render sandbox wired up can still discover this case even
// though it cannot discover the Helm one.
func (s *Server) discoverManifestLink(ctx context.Context, tx pgx.Tx, targetGVK, targetNamespace, targetName string) LinkDiscoveryResult {
	bindings, err := s.scmStore.ListBindings(ctx, tx)
	if err != nil {
		logger.ErrorContext(ctx, "listing the repository bindings for manifest link discovery failed", logging.Err(err))
		return LinkDiscoveryResult{Status: "degraded", Degraded: "could not list registered repositories (see hub logs for detail)"}
	}
	if len(bindings) == 0 {
		return LinkDiscoveryResult{Status: "none"}
	}

	var proven []LinkCandidate
	anyAttempted, anySucceeded, anyFailed := false, false, false

	for _, b := range bindings {
		charts, _, fullTree, ok := s.checkoutAndFindCharts(ctx, tx, b)
		if !ok {
			continue
		}

		paths := make([]string, 0, len(fullTree))
		for p := range fullTree {
			paths = append(paths, p)
		}
		sort.Strings(paths)

		for _, p := range paths {
			if !looksLikeManifestPath(p) || underAnyChartDir(p, charts) {
				continue
			}
			anyAttempted = true
			objs, err := render.ParseManifests(fullTree[p])
			if err != nil {
				logger.WarnContext(ctx, "parsing a manifest during link discovery failed",
					slog.String("path", p), slog.String("repo_url", b.URL), logging.Err(err))
				anyFailed = true
				continue
			}
			anySucceeded = true
			if objectAppearsIn(objs, targetGVK, targetNamespace, targetName) {
				// The candidate's own file IS the exact edit target — no
				// values file, no chart subdirectory, matching
				// candidatePath's '.chartPath || .valuesFile || "."'
				// contract on the frontend.
				proven = append(proven, LinkCandidate{BindingID: b.ID, RepoURL: b.URL, ChartPath: p})
			}
		}
	}

	status, degraded := classifyManifestDiscovery(len(proven), anyAttempted, anySucceeded, anyFailed)
	return LinkDiscoveryResult{Status: status, Candidates: proven, Degraded: degraded}
}

// classifyManifestDiscovery mirrors classifyDiscovery's status decision
// (same "a real failure must never collapse into 'none'" rule — see that
// function's own doc comment for the live bug this shape fixes) with
// messages that describe parsing a file rather than rendering a chart, so
// "Could not verify" never reads as though a render sandbox was involved
// when it was not.
func classifyManifestDiscovery(provenCount int, anyAttempted, anySucceeded, anyFailed bool) (status, degraded string) {
	switch {
	case provenCount == 1:
		return "proven", ""
	case provenCount > 1:
		return "ambiguous", ""
	case !anyAttempted:
		return "degraded", "no registered repository contains a plain manifest file for this object outside a Helm chart"
	case !anySucceeded:
		return "degraded", "every manifest file that was checked failed to parse (see hub logs for detail) — not the same as a file that parsed cleanly and did not produce the object"
	case anyFailed:
		return "degraded", "at least one manifest file could not be parsed (see hub logs for detail) — not the same as every file parsing cleanly and none producing the object"
	default:
		return "none", ""
	}
}
