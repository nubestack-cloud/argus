package api

// Tests for BACKLOG.md F28 finding 2's honesty fix: evaluateRenderEffect
// must never report a confident "no effective change" from a Helm render
// that only had chart defaults to work with.
//
// TestEvaluateRenderEffect_HelmWithNoValueFilesIsDegraded exercises the real
// method end to end — safe to do without a live cluster because the fix is
// a short-circuit BEFORE the sandbox is ever invoked, so
// s.renderSandbox.RenderFunc() is never called on this path and a
// zero-value *sandbox.Runner is a harmless placeholder. The two negative
// cases (a Helm chart WITH a values-file list, and a Kustomize overlay)
// would have to reach the real sandbox to prove anything about
// evaluateRenderEffect directly — which needs a live cluster and is already
// covered by render_evidence_live_test.go — so those are proven instead
// against helmMissingValueFileDiscovery, the small pure predicate
// evaluateRenderEffect's own new check is built from.

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"argus/internal/gitops"
	"argus/internal/render"
	"argus/internal/render/sandbox"
	"argus/internal/repotools"
)

// TestEvaluateRenderEffect_HelmWithNoValueFilesIsDegraded is finding 2's
// central claim: a Helm chart rendered with an empty ValueFiles list must
// come back Degraded, not a confident Effective:false — even though (as
// the doc comment explains) the render's own arithmetic might well have
// agreed with a real deployment purely by chance.
func TestEvaluateRenderEffect_HelmWithNoValueFilesIsDegraded(t *testing.T) {
	scope := repotools.Scope{
		RepoURL:   "https://github.com/example/apps",
		Revision:  "0123456789abcdef0123456789abcdef01234567",
		SourceDir: "charts/web",
		Host:      "github.com",
	}
	tree := map[string]string{
		"charts/web/Chart.yaml":                "name: web\nversion: 0.1.0\n",
		"charts/web/values.yaml":               "replicaCount: 1\n",
		"charts/web/templates/deployment.yaml": "replicas: {{ .Values.replicaCount }}\n",
	}
	checkouts := repotools.NewCheckoutsForTest(t.TempDir(), func(_ context.Context, opts gitops.CloneOptions) error {
		for p, content := range tree {
			full := filepath.Join(opts.Dir, filepath.FromSlash(p))
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
				return err
			}
		}
		return nil
	})
	// A non-nil placeholder, never actually invoked: evaluateRenderEffect's
	// new check returns before render.EvaluateProposal (and therefore
	// s.renderSandbox.RenderFunc()) is ever called for this input, so a
	// zero-value Runner with no real clientset is safe here — only its
	// non-nilness matters, to get past the EARLIER, unrelated "no sandbox
	// configured at all" guard.
	s := &Server{checkouts: checkouts, renderSandbox: &sandbox.Runner{}}

	got := s.evaluateRenderEffect(context.Background(), scope, []gitops.FileEdit{
		{Path: "charts/web/values.yaml", Content: []byte("replicaCount: 2\n")},
	}, nil) // no values-file list — the exact shape every real caller passes today

	if got == nil {
		t.Fatal("expected an attempted-but-degraded result, got nil (never attempted)")
	}
	if !got.Attempted {
		t.Error("Attempted must be true — this is a degraded result, not a never-tried one")
	}
	if got.Degraded == "" {
		t.Fatal("expected Degraded to be set for a Helm chart with no values-file list — got a confident result instead")
	}
	if got.Effective {
		t.Error("Effective must not be true on a degraded result")
	}
}

// TestHelmMissingValueFileDiscovery pins the pure predicate
// evaluateRenderEffect's new check is built from — see that function's own
// doc comment for why the two "must NOT trip this" cases are proven here
// rather than by driving evaluateRenderEffect all the way to a real
// (unavailable-in-this-test-environment) sandbox render.
func TestHelmMissingValueFileDiscovery(t *testing.T) {
	cases := []struct {
		name       string
		kind       render.Kind
		valueFiles []string
		want       bool
	}{
		{"Helm, no value files — finding 2's own case", render.KindHelm, nil, true},
		{"Helm, empty (non-nil) value files slice", render.KindHelm, []string{}, true},
		{"Helm, WITH a value-file list — must not trip", render.KindHelm, []string{"values-prod.yaml"}, false},
		{"Kustomize, no value files — ValueFiles is meaningless for it", render.KindKustomize, nil, false},
		{"Kustomize, WITH a value-file list (ignored, but still not this case)", render.KindKustomize, []string{"values-prod.yaml"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := helmMissingValueFileDiscovery(c.kind, c.valueFiles); got != c.want {
				t.Errorf("helmMissingValueFileDiscovery(%v, %v) = %v, want %v", c.kind, c.valueFiles, got, c.want)
			}
		})
	}
}
