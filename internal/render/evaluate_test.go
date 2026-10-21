package render

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This file proves the values-file-precedence case BACKLOG.md F26 names as
// its concrete test: a real, multi-values-file Helm chart where an edit to
// the chart-default values file is invisible in the final render because a
// later values file overrides the same key, versus a genuine edit to the
// file that actually wins.
//
// It exercises the real `helm template` binary directly (present on a
// developer/CI machine — `which helm`), NOT sandbox.Runner's Kubernetes-pod
// path, which is tested separately (sandbox/runner_live_test.go) against the
// real isolation mechanism. This split matches evaluate.go's RenderFunc
// comment: this is exactly the kind of direct-exec RenderFunc that must
// never be wired into the hub server itself.

func requireHelm(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm not found on PATH — skipping the real-render fixture test")
	}
	return path
}

// localHelmRender is a test-only RenderFunc: unpack the tree to a scratch
// dir and run `helm template` against it, layering on whatever ValueFiles
// the caller's RenderParams names — mirroring an Argo Application's
// spec.source.helm.valueFiles — in the order given, then return stdout.
func localHelmRender(helmPath string) RenderFunc {
	return func(ctx context.Context, kind Kind, treeTarGz []byte, params RenderParams) ([]byte, error) {
		dir := ""
		{
			d, err := os.MkdirTemp("", "argus-render-fixture-*")
			if err != nil {
				return nil, err
			}
			dir = d
		}
		defer os.RemoveAll(dir)

		if err := ExtractTarGz(treeTarGz, func(name string) (io.WriteCloser, error) {
			full := filepath.Join(dir, name)
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				return nil, err
			}
			return os.Create(full)
		}); err != nil {
			return nil, err
		}

		releaseName := params.ReleaseName
		if releaseName == "" {
			releaseName = "precedence-fixture"
		}
		args := []string{"template", releaseName, dir}
		for _, vf := range params.ValueFiles {
			args = append(args, "-f", filepath.Join(dir, vf))
		}
		cmd := exec.CommandContext(ctx, helmPath, args...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return nil, &execError{err: err, stderr: stderr.String()}
		}
		return stdout.Bytes(), nil
	}
}

type execError struct {
	err    error
	stderr string
}

func (e *execError) Error() string { return e.err.Error() + ": " + e.stderr }

func readChartTree(t *testing.T) map[string][]byte {
	t.Helper()
	root := "testdata/precedence-chart"
	tree := map[string][]byte{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		tree[rel] = content
		return nil
	})
	if err != nil {
		t.Fatalf("reading fixture chart: %v", err)
	}
	return tree
}

// TestEvaluateProposal_ValuesFilePrecedence_OverriddenEditIsNotEffective is
// the concrete proof: editing values.yaml's replicaCount (chart default)
// while values-prod.yaml still sets its own replicaCount produces IDENTICAL
// rendered Deployments, because the later file wins either way. This is
// exactly the trap BACKLOG.md F26 names — "an edit can land in a file that is
// genuinely real, genuinely related, and genuinely overridden — changing
// nothing" — and the assertion below is that render-diff catches it rather
// than reporting a false "effective change" just because a source file's
// bytes moved.
func TestEvaluateProposal_ValuesFilePrecedence_OverriddenEditIsNotEffective(t *testing.T) {
	helmPath := requireHelm(t)
	original := readChartTree(t)

	proposed := ApplyEdits(original, map[string][]byte{
		"values.yaml": []byte("replicaCount: 99\nimage:\n  repository: busybox\n  tag: \"1.36\"\n"),
	}, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := EvaluateProposal(ctx, localHelmRender(helmPath), KindHelm, original, proposed, RenderParams{ValueFiles: []string{"values-prod.yaml"}})
	if err != nil {
		t.Fatalf("EvaluateProposal: %v", err)
	}
	if res.Effective {
		t.Fatalf("editing the OVERRIDDEN values file must render as no effective change, got %+v", res)
	}
	if res.ObjectsTotal == 0 {
		t.Fatalf("expected at least one object rendered")
	}
}

// stubRenderFunc is RenderTree's own unit-test double — unlike
// localHelmRender above, it never shells out to a real renderer, because
// RenderTree's job (build the tar, call render, parse the result) needs
// nothing about Helm/Kustomize specifically to prove: BuildTarGz and
// ParseManifests each already have their own tests.
func stubRenderFunc(output []byte, err error) RenderFunc {
	return func(ctx context.Context, kind Kind, treeTarGz []byte, params RenderParams) ([]byte, error) {
		return output, err
	}
}

// RenderTree is BACKLOG.md F30's render-proof primitive: EvaluateProposal's
// own "render one tree, get its objects" step, exposed directly for a
// caller with no edit to diff against — only "does this chart produce
// object X" to answer from a single tree.
func TestRenderTree_ReturnsParsedObjects(t *testing.T) {
	rendered := []byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: shop-apps-api\n  namespace: shop\n")
	objs, err := RenderTree(context.Background(), stubRenderFunc(rendered, nil), KindHelm, map[string][]byte{"Chart.yaml": nil}, RenderParams{})
	if err != nil {
		t.Fatalf("RenderTree: %v", err)
	}
	if len(objs) != 1 || objs[0].Kind != "Deployment" || objs[0].Name != "shop-apps-api" || objs[0].Namespace != "shop" {
		t.Fatalf("objs = %+v, want one Deployment shop/shop-apps-api", objs)
	}
}

func TestRenderTree_PropagatesARenderError(t *testing.T) {
	renderErr := errors.New("sandbox pod failed")
	_, err := RenderTree(context.Background(), stubRenderFunc(nil, renderErr), KindHelm, map[string][]byte{"Chart.yaml": nil}, RenderParams{})
	if err == nil || !strings.Contains(err.Error(), "sandbox pod failed") {
		t.Fatalf("err = %v, want it to wrap the renderer's own error", err)
	}
}

func TestRenderTree_RefusesUnsupportedKindBeforeRendering(t *testing.T) {
	called := false
	render := func(ctx context.Context, kind Kind, treeTarGz []byte, params RenderParams) ([]byte, error) {
		called = true
		return nil, nil
	}
	_, err := RenderTree(context.Background(), render, KindUnsupported, map[string][]byte{"README.md": nil}, RenderParams{})
	if err == nil {
		t.Fatal("RenderTree(KindUnsupported) returned no error")
	}
	if called {
		t.Fatal("RenderTree called the RenderFunc for a tree with no recognised chart/overlay — it should have refused before ever rendering")
	}
}

// TestEvaluateProposal_ValuesFilePrecedence_WinningFileEditIsEffective is the
// contrast case the entry also asks for: an edit to the file that actually
// WINS the precedence chain (values-prod.yaml) must show up as a real,
// effective change.
func TestEvaluateProposal_ValuesFilePrecedence_WinningFileEditIsEffective(t *testing.T) {
	helmPath := requireHelm(t)
	original := readChartTree(t)

	proposed := ApplyEdits(original, map[string][]byte{
		"values-prod.yaml": []byte("replicaCount: 7\n"),
	}, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := EvaluateProposal(ctx, localHelmRender(helmPath), KindHelm, original, proposed, RenderParams{ValueFiles: []string{"values-prod.yaml"}})
	if err != nil {
		t.Fatalf("EvaluateProposal: %v", err)
	}
	if !res.Effective {
		t.Fatalf("editing the WINNING values file must render as an effective change, got %+v", res)
	}
	if len(res.Changed) != 1 || len(res.Changed[0].FieldDiffs) == 0 {
		t.Fatalf("expected one changed object with a replicas field diff, got %+v", res.Changed)
	}
	found := false
	for _, f := range res.Changed[0].FieldDiffs {
		if f == "spec.replicas: 3 -> 7" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a 'spec.replicas: 3 -> 7' field diff, got %v", res.Changed[0].FieldDiffs)
	}
}
