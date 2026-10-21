package api

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"k8s.io/client-go/tools/clientcmd"

	"argus/internal/gitops"
	"argus/internal/render/sandbox"
	"argus/internal/repotools"
	"argus/internal/scm"
)

// Live proof of BACKLOG.md F26's WIRING — evaluateRenderEffect, the exact
// function handleOpenRepositoryChange and proposeFromApprovedPlan call —
// against the real GitOps test repository and the real render sandbox on
// the real rke2 cluster. Skipped unless ARGUS_RENDER_WIRING_LIVE=1, mirroring
// internal/gitops/live_test.go's ARGUS_GITOPS_LIVE and
// internal/render/sandbox/runner_live_test.go's ARGUS_RENDER_SANDBOX_LIVE.
//
// Fixture: `charts/cache` in the repository ARGUS_GITOPS_REPO names
// (see MEMORY.md's project-gitops-test-infra) — values.yaml (chart default,
// replicaCount: 1) plus values-prod.yaml (added for F26, replicaCount: 3),
// wired into the argus-gitops-cache Argo Application via
// spec.source.helm.valueFiles: [values-prod.yaml]. Confirmed live on rke2
// BEFORE this test existed: after that wiring, the real Deployment's
// replicas went from 1 to 3 — proof the precedence chain is real, not just
// modeled in a fixture chart under testdata/.
//
// Run:
//
//	ARGUS_RENDER_WIRING_LIVE=1 ARGUS_GITOPS_TOKEN="$(cat ~/argus-test-token)" \
//	KUBECONFIG=<kubeconfig> \
//	  go test ./internal/api/ -run TestLiveRenderEvidence -v
func TestLiveRenderEvidence_ValuesFilePrecedence(t *testing.T) {
	if os.Getenv("ARGUS_RENDER_WIRING_LIVE") != "1" {
		t.Skip("set ARGUS_RENDER_WIRING_LIVE=1 (ARGUS_GITOPS_TOKEN, KUBECONFIG) to run this live wiring proof")
	}
	token := os.Getenv("ARGUS_GITOPS_TOKEN")
	if token == "" {
		t.Fatal("ARGUS_GITOPS_TOKEN is required")
	}
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		t.Fatal("KUBECONFIG is required")
	}
	restCfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		t.Fatalf("building rest.Config: %v", err)
	}
	runner, err := sandbox.NewRunner(restCfg, sandbox.Config{
		Namespace:  "argus-render-sandbox-test",
		PodTimeout: 90 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}

	s := &Server{
		checkouts:     repotools.NewCheckouts(),
		renderSandbox: runner,
	}

	// The live-synced revision, resolved by hand once against the real
	// Application (kubectl -n argocd get applications.argoproj.io
	// argus-gitops-cache -o jsonpath='{.status.sync.revision}') after
	// pushing values-prod.yaml and wiring valueFiles — never a branch name,
	// matching lld/09 §5.1's own "pin the SHA" rule this whole mechanism is
	// built to respect.
	const syncedRevision = "94ceabe7e4efef1c9ff090252e96014e2cc5ef1f"

	scope := repotools.Scope{
		RepoURL:   liveRepoURL(t) + ".git",
		Revision:  syncedRevision,
		SourceDir: "charts/cache",
		Host:      "github.com",
		Token:     token,
	}
	if !scope.Valid() {
		t.Fatalf("scope is not valid: %+v", scope)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// Case 1: edit the OVERRIDDEN file (values.yaml, chart default) — must
	// show no effective change, because values-prod.yaml still wins.
	overridden := s.evaluateRenderEffect(ctx, scope, []gitops.FileEdit{
		{Path: "charts/cache/values.yaml", Content: []byte("# F26 live wiring proof — overridden edit\nreplicaCount: 99\nimage:\n  repository: busybox\n  tag: \"1.36\"\n")},
	}, []string{"values-prod.yaml"})
	if overridden == nil || !overridden.Attempted {
		t.Fatalf("expected an attempted render, got %+v", overridden)
	}
	if overridden.Degraded != "" {
		t.Fatalf("render degraded: %s", overridden.Degraded)
	}
	if overridden.Effective {
		t.Fatalf("editing the OVERRIDDEN values file must show NO effective change against the real repo/cluster, got %+v", overridden)
	}
	t.Logf("overridden-edit result: %+v", overridden)

	// Case 2: edit the WINNING file (values-prod.yaml) — must show a real,
	// effective change.
	winning := s.evaluateRenderEffect(ctx, scope, []gitops.FileEdit{
		{Path: "charts/cache/values-prod.yaml", Content: []byte("# F26 live wiring proof — winning edit\nreplicaCount: 7\n")},
	}, []string{"values-prod.yaml"})
	if winning == nil || !winning.Attempted {
		t.Fatalf("expected an attempted render, got %+v", winning)
	}
	if winning.Degraded != "" {
		t.Fatalf("render degraded: %s", winning.Degraded)
	}
	if !winning.Effective {
		t.Fatalf("editing the WINNING values file must show an effective change against the real repo/cluster, got %+v", winning)
	}
	found := false
	for _, o := range winning.ObjectsChanged {
		if strings.Contains(o, "Deployment") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the changed Deployment to be named, got %v", winning.ObjectsChanged)
	}
	t.Logf("winning-edit result: %+v", winning)
}

// TestLiveRenderEvidence_HelmWithNoValueFilesIsDegraded is BACKLOG.md F28
// finding 2's own live-verification instruction: against the SAME real
// repository/revision/chart the test above uses — the one real fixture
// that already has a second Helm values file wired into the real Argo
// Application — call evaluateRenderEffect the way every real caller in
// this codebase does TODAY (valueFiles nil; no Argo CD API connection is
// registered to discover spec.source.helm.valueFiles), and confirm the
// result is Degraded, never a confident Effective:false — even for an edit
// (case 1 above, editing the OVERRIDDEN values.yaml) whose real answer
// against the actual deployed configuration genuinely IS "no effective
// change".
//
// Deliberately does not spin up a render sandbox pod: the fix this proves
// is a short-circuit BEFORE render.EvaluateProposal is ever called (see
// evaluateRenderEffect's own comment), so this test exercises the real
// checkout/DetectKind path against the real repository over the network,
// then confirms the sandbox is never reached — cheaper and lower-risk than
// the sandbox test above, and a genuinely different code path (the new
// check) rather than a re-run of it.
//
// Run:
//
//	ARGUS_RENDER_WIRING_LIVE=1 ARGUS_GITOPS_TOKEN="$(cat ~/argus-test-token)" \
//	  go test ./internal/api/ -run TestLiveRenderEvidence_HelmWithNoValueFilesIsDegraded -v
func TestLiveRenderEvidence_HelmWithNoValueFilesIsDegraded(t *testing.T) {
	if os.Getenv("ARGUS_RENDER_WIRING_LIVE") != "1" {
		t.Skip("set ARGUS_RENDER_WIRING_LIVE=1 (ARGUS_GITOPS_TOKEN) to run this live wiring proof")
	}
	token := os.Getenv("ARGUS_GITOPS_TOKEN")
	if token == "" {
		t.Fatal("ARGUS_GITOPS_TOKEN is required")
	}

	// No renderSandbox at all: the point of this test is that it is never
	// reached. If the fix regressed (the short-circuit stopped firing
	// before the sandbox call), this would panic on a nil
	// s.renderSandbox... except evaluateRenderEffect's OWN, earlier,
	// unrelated "no sandbox configured" guard would swallow that into a
	// silent nil return instead — which is exactly why the assertions
	// below check for Degraded explicitly rather than merely "did not
	// panic": a nil renderSandbox and a genuinely fixed, correctly-firing
	// short-circuit must not be confusable from this test's own output.
	s := &Server{checkouts: repotools.NewCheckouts(), renderSandbox: liveDegradedTestSandbox(t)}

	const syncedRevision = "94ceabe7e4efef1c9ff090252e96014e2cc5ef1f"
	scope := repotools.Scope{
		RepoURL:   liveRepoURL(t) + ".git",
		Revision:  syncedRevision,
		SourceDir: "charts/cache",
		Host:      "github.com",
		Token:     token,
	}
	if !scope.Valid() {
		t.Fatalf("scope is not valid: %+v", scope)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	got := s.evaluateRenderEffect(ctx, scope, []gitops.FileEdit{
		{Path: "charts/cache/values.yaml", Content: []byte("# F28 finding 2 live proof — the OVERRIDDEN file\nreplicaCount: 99\n")},
	}, nil) // the exact shape every real caller passes today — no values-file list

	if got == nil || !got.Attempted {
		t.Fatalf("expected an attempted-but-degraded result against the real repository, got %+v", got)
	}
	if got.Degraded == "" {
		t.Fatalf("expected Degraded — a Helm chart with no values-file list must never report a confident verdict, got %+v", got)
	}
	if got.Effective {
		t.Fatalf("Effective must not be true on a degraded result, got %+v", got)
	}
	t.Logf("real repository, real revision, no values-file list — degraded as required: %+v", got)
}

// liveDegradedTestSandbox exists only so this test still reads as
// exercising the real production type (*sandbox.Runner) rather than
// standing in a nil — but the whole point of the test above is that
// nothing on it is ever called, so a bare non-nil zero value is enough;
// see the comment at its one call site.
func liveDegradedTestSandbox(t *testing.T) *sandbox.Runner {
	t.Helper()
	return &sandbox.Runner{}
}

// TestLiveRenderEvidence_OpensARealPullRequestWithRenderedDelta is the
// "propose a real edit through the normal analysis/plan flow" half of F26's
// own live-verification instruction: not just evaluateRenderEffect's return
// value, but a REAL pull request, opened through gitops.ProposeChanges
// exactly the way handleOpenRepositoryChange calls it, carrying the
// RenderEvidence computed above in its "## Rendered delta" section and
// commit trailer where a human reviewer would actually read it.
//
// Opens a real, throwaway branch/PR against the same GitOps test
// repository every other live GitOps test in this codebase uses
// (internal/gitops/live_test.go's TestStageB_LiveEndToEnd and the
// TestAdditionLivePullRequest referenced in MEMORY.md) — same convention,
// same repo, same gating discipline. Never merged by this test.
func TestLiveRenderEvidence_OpensARealPullRequestWithRenderedDelta(t *testing.T) {
	if os.Getenv("ARGUS_RENDER_WIRING_LIVE") != "1" {
		t.Skip("set ARGUS_RENDER_WIRING_LIVE=1 (ARGUS_GITOPS_TOKEN, KUBECONFIG) to run this live wiring proof")
	}
	token := os.Getenv("ARGUS_GITOPS_TOKEN")
	if token == "" {
		t.Fatal("ARGUS_GITOPS_TOKEN is required")
	}
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		t.Fatal("KUBECONFIG is required")
	}
	restCfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		t.Fatalf("building rest.Config: %v", err)
	}
	runner, err := sandbox.NewRunner(restCfg, sandbox.Config{
		Namespace:  "argus-render-sandbox-test",
		PodTimeout: 90 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	s := &Server{checkouts: repotools.NewCheckouts(), renderSandbox: runner}

	const syncedRevision = "94ceabe7e4efef1c9ff090252e96014e2cc5ef1f"
	scope := repotools.Scope{
		RepoURL:   liveRepoURL(t) + ".git",
		Revision:  syncedRevision,
		SourceDir: "charts/cache",
		Host:      "github.com",
		Token:     token,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	edit := gitops.FileEdit{Path: "charts/cache/values-prod.yaml", Content: []byte("# F26 live pull-request proof — winning edit\nreplicaCount: 7\n")}
	evidence := s.evaluateRenderEffect(ctx, scope, []gitops.FileEdit{edit}, []string{"values-prod.yaml"})
	if evidence == nil || !evidence.Attempted || evidence.Degraded != "" || !evidence.Effective {
		t.Fatalf("expected an attempted, effective render before opening the PR, got %+v", evidence)
	}

	provider := &scm.GitHub{Token: token, UserAgent: "argus-f26-live-test"}
	repo := liveRepo(t)
	branch := "argus/f26-render-evidence-proof"

	proposal, err := gitops.ProposeChanges(ctx, provider, repo, gitops.ProposalInput{
		Object:         gitops.ObjectRef{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "argus-gitops-rke2", Name: "cache"},
		Files:          []gitops.FileEdit{edit},
		SyncedRevision: syncedRevision,
		SourceDir:      "charts/cache",
		Branch:         branch,
		RenderEvidence: evidence,
		Provenance: gitops.Provenance{
			IncidentID:   "f26-live-verification",
			ApprovedBy:   "f26-live-test",
			RootCause:    "BACKLOG.md F26 live verification — not a real incident.",
			ResolvedFrom: "manual live test, internal/api/render_evidence_live_test.go",
			Author:       scm.Identity{Name: "ARGUS", Email: "argus@localhost"},
		},
	})
	if err != nil {
		t.Fatalf("ProposeChanges: %v", err)
	}
	t.Logf("opened %s — inspect its body for the Rendered delta section, then close it without merging", proposal.PullRequest.URL)
}
