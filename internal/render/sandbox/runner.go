package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"

	"argus/internal/domain"
	"argus/internal/render"
)

// domainRunID mints a fresh, k8s-object-name-safe identifier for one render
// pod/NetworkPolicy pair — internal/domain.NewID's usual prefixed-ULID
// convention (lld/05-data-model.md §2), with its "_" separator swapped for
// "-" because Kubernetes object names are RFC1123 labels and reject
// underscores.
func domainRunID() string {
	return strings.ReplaceAll(domain.NewID("r"), "_", "-")
}

// Runner drives one render sandbox against a Kubernetes cluster the HUB
// administers for this purpose — deliberately NOT a customer cluster, and
// NOT reached through internal/gateway's per-cluster tunnel or the
// read-only agent. Rendering a chart has nothing to do with any customer's
// live cluster, so it must never go anywhere near the credential or the
// path that does (DESIGN.md non-negotiable #1: a compromised investigation
// path must never gain write access by itself — routing render pods through
// the agent's connection would put exactly that path in the way of
// something that creates and execs into pods).
//
// A production deployment points Runner at infrastructure the hub itself
// owns — its own cluster, or a dedicated namespace within one. For this
// task's live verification, the only cluster actually reachable is the
// shared rke2 dev cluster (<kubeconfig>); Runner is pointed at a
// dedicated namespace on it (never argus-e2e-rke2/argus-gitops-rke2, which
// other GitOps test work already uses) specifically to avoid mixing
// "infrastructure the render sandbox owns" with "a customer's simulated
// cluster" even in this dev environment.
type Runner struct {
	clientset *kubernetes.Clientset
	restCfg   *rest.Config
	cfg       Config
}

// NewRunner builds a Runner from a *rest.Config (out-of-cluster kubeconfig
// or in-cluster config — the caller's choice; this package has no opinion).
func NewRunner(restCfg *rest.Config, cfg Config) (*Runner, error) {
	if cfg.Namespace == "" {
		return nil, fmt.Errorf("sandbox: Config.Namespace is required")
	}
	cs, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("sandbox: building clientset: %w", err)
	}
	return &Runner{clientset: cs, restCfg: restCfg, cfg: cfg.withDefaults()}, nil
}

// EnsureNamespace creates the render namespace if it doesn't already exist.
// Idempotent — safe to call before every run.
func (rn *Runner) EnsureNamespace(ctx context.Context) error {
	_, err := rn.clientset.CoreV1().Namespaces().Get(ctx, rn.cfg.Namespace, metav1.GetOptions{})
	if err == nil {
		return nil
	}
	if !apierrors.IsNotFound(err) {
		return fmt.Errorf("sandbox: checking namespace %s: %w", rn.cfg.Namespace, err)
	}
	_, err = rn.clientset.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: rn.cfg.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "argus",
				"argus.io/purpose":             "render-sandbox",
			},
		},
	}, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("sandbox: creating namespace %s: %w", rn.cfg.Namespace, err)
	}
	return nil
}

// RenderFunc returns a render.RenderFunc backed by this Runner. Every call
// creates a BRAND NEW pod (and its own NetworkPolicy), execs the render, and
// tears both down before returning — "single-use" per lld/09 §2 means one
// pod per render, not one pod reused across the two renders one
// EvaluateProposal call needs (original vs proposed), and not across two
// different proposals.
func (rn *Runner) RenderFunc() render.RenderFunc {
	return func(ctx context.Context, kind render.Kind, treeTarGz []byte, params render.RenderParams) ([]byte, error) {
		return rn.renderOnce(ctx, kind, treeTarGz, params)
	}
}

func (rn *Runner) renderOnce(ctx context.Context, kind render.Kind, treeTarGz []byte, params render.RenderParams) ([]byte, error) {
	runID := domainRunID()

	if err := rn.EnsureNamespace(ctx); err != nil {
		return nil, err
	}

	// The NetworkPolicy is created BEFORE the pod, and selects the pod's
	// run-label, so there is never a window between the pod existing and
	// being network-restricted.
	np := BuildNetworkPolicy(rn.cfg, runID)
	if _, err := rn.clientset.NetworkingV1().NetworkPolicies(rn.cfg.Namespace).Create(ctx, np, metav1.CreateOptions{}); err != nil {
		return nil, fmt.Errorf("sandbox: creating NetworkPolicy: %w", err)
	}
	defer func() {
		_ = rn.clientset.NetworkingV1().NetworkPolicies(rn.cfg.Namespace).Delete(context.Background(), np.Name, metav1.DeleteOptions{})
	}()

	pod, err := BuildPod(rn.cfg, runID)
	if err != nil {
		return nil, err
	}
	if _, err := rn.clientset.CoreV1().Pods(rn.cfg.Namespace).Create(ctx, pod, metav1.CreateOptions{}); err != nil {
		return nil, fmt.Errorf("sandbox: creating pod: %w", err)
	}
	defer func() {
		// Single-use: torn down immediately after this one render,
		// regardless of outcome. A background context so a caller's own
		// ctx timing out does not also abandon cleanup.
		grace := int64(0)
		_ = rn.clientset.CoreV1().Pods(rn.cfg.Namespace).Delete(context.Background(), pod.Name, metav1.DeleteOptions{GracePeriodSeconds: &grace})
	}()

	if err := rn.waitRunning(ctx, pod.Name); err != nil {
		return nil, fmt.Errorf("sandbox: waiting for render pod to start: %w", err)
	}

	if err := rn.injectTree(ctx, pod.Name, treeTarGz); err != nil {
		return nil, fmt.Errorf("sandbox: injecting the source tree: %w", err)
	}

	return rn.runRenderCommand(ctx, pod.Name, kind, params)
}

func (rn *Runner) waitRunning(ctx context.Context, podName string) error {
	return wait.PollUntilContextTimeout(ctx, 500*time.Millisecond, rn.cfg.PodTimeout, true, func(ctx context.Context) (bool, error) {
		p, err := rn.clientset.CoreV1().Pods(rn.cfg.Namespace).Get(ctx, podName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		switch p.Status.Phase {
		case corev1.PodRunning:
			return true, nil
		case corev1.PodFailed, corev1.PodSucceeded:
			return false, fmt.Errorf("render pod entered phase %s before becoming Running", p.Status.Phase)
		default:
			return false, nil
		}
	})
}

// injectTree writes the gzipped tar into the pod's tmpfs scratch volume via
// exec-with-stdin — never a Kubernetes volume (a ConfigMap/Secret would work
// for a small chart but silently truncates at etcd's object size limit for a
// larger one) and never a host-mounted path (there isn't one). This is also
// why the pod's own NetworkPolicy doesn't need to special-case anything:
// exec traffic is carried over the API server's connection to the kubelet,
// not through the pod's own network namespace, so it is unaffected by a
// deny-all-egress policy on that pod (see BuildPod's doc comment).
func (rn *Runner) injectTree(ctx context.Context, podName string, treeTarGz []byte) error {
	stdout, stderr, err := rn.exec(ctx, podName, []string{"sh", "-c", "mkdir -p /scratch/src && tar -xzf - -C /scratch/src"}, bytes.NewReader(treeTarGz))
	if err != nil {
		return fmt.Errorf("%w (stderr: %s)", err, stderr.String())
	}
	_ = stdout
	return nil
}

// runRenderCommand execs the actual renderer. `--no-hooks` on the Helm path
// is deliberate and permanent — lld/09 §2's "no execution of
// repository-provided scripts... unless the specific RepositoryBinding has
// explicitly enabled it", and this package has no opt-in mechanism for that
// yet, so hooks are refused outright rather than defaulted on.
//
// # Why ReleaseName/ValueFiles are validated here, not trusted as given
//
// Neither is model-facing in this codebase today — internal/api's callers
// pass nil/empty for both — but RenderParams is this package's PUBLIC
// contract, and the render command is built as one argv slice (never a
// shell string, so no quoting escape is possible), which closes command
// injection but NOT argument/flag injection: an element that starts with
// "-" is a flag to helm/kubectl's own parser regardless of which struct
// field it arrived through. A future caller that resolves ValueFiles from
// something less trusted than a fixed RepositoryBinding config (an Argo
// Application's own Helm parameters, say — exactly what lld/09 §5.1 step 3
// would need) must not be able to smuggle an extra flag in this way. Refuse
// outright rather than sanitise-and-continue: a value that fails this check
// is a caller bug, not a chart that should render with something silently
// dropped.
func (rn *Runner) runRenderCommand(ctx context.Context, podName string, kind render.Kind, params render.RenderParams) ([]byte, error) {
	var cmd []string
	switch kind {
	case render.KindHelm:
		releaseName := params.ReleaseName
		if releaseName == "" {
			releaseName = "argus-render"
		}
		if err := validateArgvElement("ReleaseName", releaseName); err != nil {
			return nil, err
		}
		cmd = []string{"helm", "template", releaseName, "/scratch/src", "--no-hooks"}
		for _, vf := range params.ValueFiles {
			if err := validateValueFilePath(vf); err != nil {
				return nil, err
			}
			// -f flags apply in the order given, LATER wins ties — the same
			// order lld/09 §5.1 step 3 specifies, so ValueFiles must already
			// be in that order (chart default is implicit and always first;
			// these are what's layered on top of it).
			cmd = append(cmd, "-f", "/scratch/src/"+vf)
		}
	case render.KindKustomize:
		cmd = []string{"kubectl", "kustomize", "/scratch/src"}
	default:
		return nil, fmt.Errorf("sandbox: unsupported renderer kind %q", kind)
	}
	stdout, stderr, err := rn.exec(ctx, podName, cmd, nil)
	if err != nil {
		return nil, fmt.Errorf("%w (stderr: %s)", err, stderr.String())
	}
	return stdout.Bytes(), nil
}

func (rn *Runner) exec(ctx context.Context, podName string, cmd []string, stdin *bytes.Reader) (stdout, stderr bytes.Buffer, err error) {
	req := rn.clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Namespace(rn.cfg.Namespace).
		Name(podName).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: "render",
			Command:   cmd,
			Stdin:     stdin != nil,
			Stdout:    true,
			Stderr:    true,
			TTY:       false,
		}, scheme.ParameterCodec)

	executor, execErr := remotecommand.NewSPDYExecutor(rn.restCfg, "POST", req.URL())
	if execErr != nil {
		return stdout, stderr, fmt.Errorf("sandbox: building exec executor: %w", execErr)
	}

	streamOpts := remotecommand.StreamOptions{Stdout: &stdout, Stderr: &stderr}
	if stdin != nil {
		streamOpts.Stdin = stdin
	}
	if err := executor.StreamWithContext(ctx, streamOpts); err != nil {
		return stdout, stderr, fmt.Errorf("sandbox: exec %v: %w", cmd, err)
	}
	return stdout, stderr, nil
}

// validateArgvElement refuses anything that would be interpreted as a flag
// rather than a value by helm/kubectl's own argument parser.
func validateArgvElement(field, v string) error {
	if v == "" {
		return nil
	}
	if strings.HasPrefix(v, "-") {
		return fmt.Errorf("sandbox: refusing %s %q — it looks like a command-line flag, not a value", field, v)
	}
	return nil
}

// validateValueFilePath refuses a flag-like value AND path traversal —
// ValueFiles entries are joined onto "/scratch/src/" verbatim (runRenderCommand),
// so "../" would ask helm to read outside the extracted tree, and an
// absolute path would bypass the join entirely.
func validateValueFilePath(v string) error {
	if err := validateArgvElement("ValueFiles entry", v); err != nil {
		return err
	}
	if v == "" {
		return fmt.Errorf("sandbox: a ValueFiles entry is empty")
	}
	if filepath.IsAbs(v) {
		return fmt.Errorf("sandbox: refusing absolute ValueFiles path %q", v)
	}
	clean := filepath.Clean(v)
	if clean != v || clean == ".." || strings.HasPrefix(clean, "../") {
		return fmt.Errorf("sandbox: refusing ValueFiles path %q — must be a clean, relative path inside the source tree", v)
	}
	return nil
}

// Teardown removes the render namespace's NetworkPolicies/Pods this package
// created, for a caller (or a test) that wants an explicit sweep rather than
// relying on each run's own deferred cleanup — e.g. after a context
// cancellation aborted a run before its own defers could run to completion
// on a background context that itself got interrupted.
func (rn *Runner) Teardown(ctx context.Context) error {
	sel := "app.kubernetes.io/managed-by=argus"
	if err := rn.clientset.CoreV1().Pods(rn.cfg.Namespace).DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{LabelSelector: sel}); err != nil {
		return err
	}
	return rn.clientset.NetworkingV1().NetworkPolicies(rn.cfg.Namespace).DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{LabelSelector: sel})
}
