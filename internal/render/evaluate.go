package render

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"sort"
	"time"
)

// Kind is which renderer a source tree needs.
type Kind string

const (
	KindHelm      Kind = "helm"
	KindKustomize Kind = "kustomize"
	// KindUnsupported means neither a Chart.yaml nor a kustomization file was
	// found at the tree's root — e.g. plain YAML with no renderer at all, for
	// which rendering is a no-op distinction (the file IS the manifest) and
	// this package has nothing useful to add. Evaluate reports this as
	// Unavailable rather than an error: it is an honest "not applicable", not
	// a failure.
	KindUnsupported Kind = ""
)

// DetectKind looks at a source tree's top-level file names (as ARGUS's own
// repository tools already see them — path -> content) and decides which
// renderer, if any, applies. Only the tree ROOT is checked: a subchart's own
// Chart.yaml several directories down does not make the top-level tree a
// Helm chart on its own, and get_gitops_ownership already resolves the
// GitOps controller's own source path down to the directory that matters
// before any of this runs.
func DetectKind(tree map[string][]byte) Kind {
	if _, ok := tree["Chart.yaml"]; ok {
		return KindHelm
	}
	if _, ok := tree["kustomization.yaml"]; ok {
		return KindKustomize
	}
	if _, ok := tree["kustomization.yml"]; ok {
		return KindKustomize
	}
	return KindUnsupported
}

// RenderFunc runs one renderer invocation against one source tree, packaged
// as a gzipped tar (BuildTar), and returns the rendered multi-document YAML.
//
// This is the seam between the pure logic in this package (which never
// executes anything) and the one place execution against untrusted content
// actually happens. In production that is sandbox.Runner.RenderFunc — a
// single-use, network-disabled, no-host-mount Kubernetes pod (see that
// package's comment). Tests may supply a RenderFunc that shells out to a
// local `helm`/`kubectl` binary directly, which is fine for a test process
// running on a developer or CI machine but MUST NEVER be wired into the hub
// server: the hub's own container image is distroless (no shell, no helm, no
// kubectl — internal/gitops/clone.go's header explains why), so a
// direct-exec RenderFunc could not run there even by accident.
type RenderFunc func(ctx context.Context, kind Kind, treeTarGz []byte, params RenderParams) ([]byte, error)

// RenderParams is the render-time information EvaluateProposal cannot infer
// from the tree alone — the whole reason DetectKind stops at "which
// renderer" rather than "how to invoke it".
//
// # Why this exists, and its one real limitation
//
// The Helm values-file-precedence chain (lld/09 §5.1 step 3) is chart
// defaults -> each values file in order -> the Argo Application's own Helm
// parameters. This package resolves that chain correctly GIVEN the list —
// TestLiveRenderFunc_ValuesFilePrecedence (sandbox/runner_live_test.go)
// proves it does — but it does not discover the list itself. A caller must
// supply it, resolved from wherever the binding/Application records it
// (e.g. an Argo Application's spec.source.helm.valueFiles). No Argo CD API
// connection is registered with ARGUS today (lld/09 §5.2), so
// internal/api/render_evidence.go's wiring cannot resolve this
// automatically yet either — an explicit, disclosed gap, not a silent one.
// An empty ValueFiles renders the chart against its own defaults only. That
// is still an honest description of what THIS PACKAGE did — the render
// itself is not wrong — but BACKLOG.md F28 finding 2 is explicit that a
// caller must not treat its ANSWER (in particular a false "no effective
// change") as authoritative on that basis: a defaults-only render has not
// seen whatever real values file a live deployment actually applies, so it
// cannot rule out that file changing the verdict. internal/api/render_evidence.go's
// evaluateRenderEffect is where that caller-side discipline lives — it
// refuses to run this render at all when kind is Helm and valueFiles is
// empty, reporting RenderEvidence.Degraded instead of ever calling in here
// with nothing to render against but defaults.
type RenderParams struct {
	// ValueFiles are additional Helm values file paths (relative to the
	// tree root), applied in order AFTER the chart's own values.yaml — the
	// same order Helm itself applies -f flags in, so the LAST entry here
	// wins ties, matching lld/09 §5.1 step 3's "search... for the last file
	// that sets it". Ignored for Kustomize.
	ValueFiles []string
	// ReleaseName is the Helm release name substituted for
	// {{ .Release.Name }} etc. Empty uses a fixed placeholder
	// ("argus-render") — deliberately NOT the real release name Argo/Helm
	// use live, because this package only ever compares two renders against
	// EACH OTHER, never against a real cluster's actual state, so the exact
	// name is unobservable in the result as long as both renders use the
	// same one.
	ReleaseName string
}

// EvaluateProposal is the top-level operation: render the ORIGINAL tree and
// the PROPOSED tree (same content with the edit set applied) through render,
// and compare. Returns Result.Effective/Changed — the answer to "does this
// edit change what the cluster would run" — plus the raw rendered bytes for
// a caller that wants to keep them (e.g. attaching the proposed render to the
// pull request alongside the diff).
//
// Bounded by ctx: a caller wiring this into a PR-opening path should always
// pass a context with a short timeout (lld/09 §2's 2-minute wall clock is the
// per-render figure; two renders plus the diff should fit inside something
// like double that), because a render step must never be allowed to make an
// otherwise-valid pull request wait indefinitely — see this package's
// evaluate_test.go and internal/api/render_evidence.go for how a caller
// degrades rather than blocks when render either times out or errors.
func EvaluateProposal(ctx context.Context, render RenderFunc, kind Kind, originalTree, proposedTree map[string][]byte, params RenderParams) (Result, error) {
	origOut, err := renderOneTree(ctx, render, kind, originalTree, params, "ORIGINAL")
	if err != nil {
		return Result{}, err
	}
	propOut, err := renderOneTree(ctx, render, kind, proposedTree, params, "PROPOSED")
	if err != nil {
		return Result{}, err
	}
	return CompareManifests(string(kind), origOut, propOut)
}

// RenderTree renders ONE source tree and returns its parsed object set —
// the same package/render/parse steps EvaluateProposal runs twice (via
// renderOneTree below) to build the two sides of its diff, exposed directly
// for BACKLOG.md F30's render-proof: "does this chart produce object X" has
// no edit to compare against, only one tree to check, so the diff half of
// EvaluateProposal is machinery it has no use for.
func RenderTree(ctx context.Context, render RenderFunc, kind Kind, tree map[string][]byte, params RenderParams) ([]Object, error) {
	rendered, err := renderOneTree(ctx, render, kind, tree, params, "")
	if err != nil {
		return nil, err
	}
	return ParseManifests(rendered)
}

// renderOneTree is the package/render step both EvaluateProposal and
// RenderTree need — building the tar, invoking the sandboxed RenderFunc, and
// wrapping any error with which SIDE failed when label is non-empty (kept
// exactly as informative as EvaluateProposal's own two inline calls used to
// be, for the caller that has two sides to tell apart).
func renderOneTree(ctx context.Context, render RenderFunc, kind Kind, tree map[string][]byte, params RenderParams, label string) ([]byte, error) {
	if kind == KindUnsupported {
		return nil, fmt.Errorf("render: no Helm chart or Kustomize overlay was found at the tree root")
	}
	tar, err := BuildTarGz(tree)
	if err != nil {
		if label != "" {
			return nil, fmt.Errorf("render: packaging the %s tree: %w", label, err)
		}
		return nil, fmt.Errorf("render: packaging the tree: %w", err)
	}
	out, err := render(ctx, kind, tar, params)
	if err != nil {
		if label != "" {
			return nil, fmt.Errorf("render: rendering the %s content: %w", label, err)
		}
		return nil, fmt.Errorf("render: %w", err)
	}
	return out, nil
}

// ApplyEdits returns a copy of tree with each edit's path set to its content
// (or removed, for a delete edit). tree itself is never mutated — the caller
// still has the original for the "before" render.
func ApplyEdits(tree map[string][]byte, edits map[string][]byte, deletes map[string]bool) map[string][]byte {
	out := make(map[string][]byte, len(tree)+len(edits))
	for k, v := range tree {
		out[k] = v
	}
	for path := range deletes {
		delete(out, path)
	}
	for path, content := range edits {
		if deletes[path] {
			continue
		}
		out[path] = content
	}
	return out
}

// BuildTarGz packages a path->content tree into a gzipped tar, deterministically
// (sorted path order, fixed mtimes) so two packagings of identical content
// produce byte-identical archives — not load-bearing for correctness (the
// renderer only reads the content) but keeps evaluate_test.go's fixtures
// reproducible.
func BuildTarGz(tree map[string][]byte) ([]byte, error) {
	paths := make([]string, 0, len(tree))
	for p := range tree {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	epoch := time.Unix(0, 0)
	for _, p := range paths {
		content := tree[p]
		hdr := &tar.Header{
			Name:    p,
			Mode:    0o644,
			Size:    int64(len(content)),
			ModTime: epoch,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(content); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ExtractTarGz is BuildTarGz's inverse — used on the receiving side of the
// sandbox (or by a test standing in for it) to materialise a tree of files on
// disk from the bytes a RenderFunc was handed.
func ExtractTarGz(data []byte, destDir func(name string) (io.WriteCloser, error)) error {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("render: not a gzip stream: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("render: reading tar entry: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		w, err := destDir(hdr.Name)
		if err != nil {
			return err
		}
		if _, err := io.Copy(w, tr); err != nil {
			w.Close()
			return fmt.Errorf("render: writing %s: %w", hdr.Name, err)
		}
		if err := w.Close(); err != nil {
			return err
		}
	}
}
