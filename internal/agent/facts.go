package agent

import (
	"context"
	"log/slog"

	"argus/internal/logging"
	"os"
	"sort"
	"strings"
	"time"

	"argus/internal/tunnel"

	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// nodeMetricsGVR identifies metrics.k8s.io's NodeMetrics resource —
// argus-investigate's ClusterRole already grants get/list on it (see
// deploy/helm/argus-agent/templates/clusterrole.yaml), but nothing installs
// the metrics.k8s.io API itself: that's metrics-server, a separate,
// optional in-cluster component. Listing this resource against a cluster
// that doesn't run metrics-server fails with "the server could not find the
// requested resource" — expected, not an error worth alarming over.
var nodeMetricsGVR = schema.GroupVersionResource{Group: "metrics.k8s.io", Version: "v1beta1", Resource: "nodes"}

// factsTimeout bounds every discovery/list call made while gathering facts or
// deriving the cluster fingerprint, so a half-reachable API server (TCP
// connects, then hangs) can never block this process indefinitely.
const factsTimeout = 5 * time.Second

func newClientset() (*kubernetes.Clientset, error) {
	cfg, err := loadKubeConfig()
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(cfg)
}

// nodeUsage is one node's metrics.k8s.io reading, kept as the raw Quantity
// strings the API returned — no unit conversion, matching NodeStatus' own
// doc comment on why these are reported verbatim.
type nodeUsage struct {
	cpu    string
	memory string
}

// gatherNodeUsage lists metrics.k8s.io's NodeMetrics via a dynamic client
// (no new RBAC beyond what argus-investigate's ClusterRole already grants —
// get/list on metrics.k8s.io pods/nodes). Returns nil whenever that API
// isn't available, which is the normal case for any cluster that doesn't
// run metrics-server: callers must treat a nil map as "omit usage fields,"
// never as an error to surface or a reason to fail the whole facts payload.
func gatherNodeUsage(ctx context.Context, cfg *rest.Config) map[string]nodeUsage {
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		logger.Warn("could not build dynamic client for node metrics — node usage omitted", logging.Err(err))
		return nil
	}

	list, err := dyn.Resource(nodeMetricsGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.Warn("metrics.k8s.io nodes unavailable, likely no metrics-server installed — node usage omitted", logging.Err(err))
		return nil
	}

	usage := make(map[string]nodeUsage, len(list.Items))
	for _, item := range list.Items {
		name, _, _ := unstructured.NestedString(item.Object, "metadata", "name")
		if name == "" {
			continue
		}
		cpu, _, _ := unstructured.NestedString(item.Object, "usage", "cpu")
		mem, _, _ := unstructured.NestedString(item.Object, "usage", "memory")
		usage[name] = nodeUsage{cpu: cpu, memory: mem}
	}
	return usage
}

// buildNodeStatuses assembles tunnel.NodeStatus entries from the Node
// objects GatherFacts already listed plus gatherNodeUsage's best-effort
// usage map (nil is handled the same as "this node has no entry").
func buildNodeStatuses(nodes []corev1.Node, usage map[string]nodeUsage) []tunnel.NodeStatus {
	statuses := make([]tunnel.NodeStatus, 0, len(nodes))
	for _, n := range nodes {
		ns := tunnel.NodeStatus{Name: n.Name}

		for _, cond := range n.Status.Conditions {
			if cond.Type == corev1.NodeReady {
				ns.Ready = cond.Status == corev1.ConditionTrue
				break
			}
		}

		if cpu, ok := n.Status.Allocatable[corev1.ResourceCPU]; ok {
			ns.CPUAllocatable = cpu.String()
		}
		if mem, ok := n.Status.Allocatable[corev1.ResourceMemory]; ok {
			ns.MemoryAllocatable = mem.String()
		}

		if u, ok := usage[n.Name]; ok {
			if u.cpu != "" {
				cpu := u.cpu
				ns.CPUUsed = &cpu
			}
			if u.memory != "" {
				mem := u.memory
				ns.MemoryUsed = &mem
			}
		}

		statuses = append(statuses, ns)
	}
	return statuses
}

// GatherFacts is best-effort, never-panics, never-blocks-indefinitely cluster
// fact collection per lld/03-agent-protocol.md §8's ClusterFacts (this
// increment's subset lives in internal/tunnel.ClusterFacts). Any failure at
// any step — no kubeconfig, unreachable API server, RBAC denial — results in
// Reachable: false and nothing else populated. That's logged at a low
// verbosity, not treated as an error worth alarming an operator over: an
// agent with no reachable target cluster is a normal way to exercise the
// enrollment/tunnel flow standalone.
func GatherFacts() tunnel.ClusterFacts {
	cfg, err := loadKubeConfig()
	if err != nil {
		logger.Warn("no reachable cluster config — reporting Reachable: false", logging.Err(err))
		return tunnel.ClusterFacts{Nodes: []tunnel.NodeStatus{}, Reachable: false}
	}

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		logger.Warn("no reachable cluster config — reporting Reachable: false", logging.Err(err))
		return tunnel.ClusterFacts{Nodes: []tunnel.NodeStatus{}, Reachable: false}
	}

	ctx, cancel := context.WithTimeout(context.Background(), factsTimeout)
	defer cancel()

	version, err := clientset.Discovery().ServerVersion()
	if err != nil {
		logger.Warn("cluster config present but ServerVersion failed — reporting Reachable: false", logging.Err(err))
		return tunnel.ClusterFacts{Nodes: []tunnel.NodeStatus{}, Reachable: false}
	}

	nodes, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.Warn("cluster config present but node list failed — reporting Reachable: false", logging.Err(err))
		return tunnel.ClusterFacts{Nodes: []tunnel.NodeStatus{}, Reachable: false}
	}

	// Best-effort only: gatherNodeUsage returning nil (no metrics-server,
	// RBAC denial, or any other failure to reach metrics.k8s.io) must never
	// fail this whole facts payload — it just means every node's usage
	// fields come back omitted below.
	usage := gatherNodeUsage(ctx, cfg)

	return tunnel.ClusterFacts{
		KubernetesVersion: version.String(),
		NodeCount:         len(nodes.Items),
		Nodes:             buildNodeStatuses(nodes.Items, usage),
		Reachable:         true,
		Remediation:       gatherRemediationAuthority(ctx, clientset),
	}
}

// GatherOwnRemediationAuthority is gatherRemediationAuthority for the
// remediation process (tunnel.RoleRemediate), which gathers no other facts.
// Its answer travels on the heartbeat and replaces the investigation agent's,
// which describes the read-only identity.
func GatherOwnRemediationAuthority() *tunnel.ClusterRemediation {
	cfg, err := loadKubeConfig()
	if err != nil {
		return &tunnel.ClusterRemediation{Checked: false, Error: err.Error(), Reporter: tunnel.RoleRemediate}
	}
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return &tunnel.ClusterRemediation{Checked: false, Error: err.Error(), Reporter: tunnel.RoleRemediate}
	}
	ctx, cancel := context.WithTimeout(context.Background(), factsTimeout)
	defer cancel()
	out := gatherRemediationAuthority(ctx, clientset)
	out.Reporter = tunnel.RoleRemediate
	return out
}

// remediationChecks are the three grants that decide whether an approved plan can
// actually be carried out on this cluster, each named for what an operator would
// recognise rather than for its API group.
//
// Kept as data rather than three inline calls so the set that is CHECKED and the
// set that is REPORTED cannot drift apart — adding an action type means adding one
// row here, and a row with no field to write into fails to compile. Two setters per
// row for the same reason, applied to the two shapes (fleet-wide vs. one namespace)
// that ask this exact same question: if a new action type gets a cluster-wide
// setter but not a namespaced one (or vice versa), that row fails to compile too.
var remediationChecks = []struct {
	name          string
	verb          string
	group         string
	resource      string
	set           func(*tunnel.ClusterRemediation, bool)
	setNamespaced func(*tunnel.NamespaceRemediation, bool)
}{
	{"scale/restart a Deployment", "patch", "apps", "deployments",
		func(r *tunnel.ClusterRemediation, ok bool) { r.CanPatchDeployments = ok },
		func(r *tunnel.NamespaceRemediation, ok bool) { r.CanPatchDeployments = ok }},
	{"scale/restart a StatefulSet", "patch", "apps", "statefulsets",
		func(r *tunnel.ClusterRemediation, ok bool) { r.CanPatchStatefulSets = ok },
		func(r *tunnel.NamespaceRemediation, ok bool) { r.CanPatchStatefulSets = ok }},
	{"restart a Pod", "delete", "", "pods",
		func(r *tunnel.ClusterRemediation, ok bool) { r.CanDeletePods = ok },
		func(r *tunnel.NamespaceRemediation, ok bool) { r.CanDeletePods = ok }},
}

// maxNamespaceRemediationChecks bounds how many namespaces
// gatherNamespacedRemediationAuthority probes with a real SelfSubjectAccessReview
// on every facts refresh (a connected agent re-gathers facts every
// client.go's factsRefreshInterval, so this number of extra API-server round
// trips repeats on that cadence — it is the dominant term in what a refresh
// costs, and the reason that cadence is minutes rather than seconds). Namespace-scoped remediation is meant to be a short, deliberately
// chosen allowlist (values.yaml's own comment: "prefer listing the namespaces you
// actually run workloads in"), so 20 is generous headroom over the expected case
// while still bounding a cluster some operator granted an unexpectedly long list
// to at 60 extra reviews (3 checks * 20 namespaces) rather than an unbounded
// 3-per-namespace scan of however many were granted. Namespaces beyond this many
// are simply not checked this pass — NamespacesTruncated says so — rather than
// silently dropped with no signal.
const maxNamespaceRemediationChecks = 20

// remediateRoleName is the fixed name
// deploy/helm/argus-agent/templates/remediate-role.yaml gives the namespace-scoped
// Role it renders once per entry in remediate.namespaces — not configurable
// per-namespace, and (per that chart's own values.yaml comments on
// remediate.serviceAccount.name) part of the same "don't rename without updating
// the other hardcoded references" convention this repo already relies on
// elsewhere (the ValidatingAdmissionPolicy's matchConditions, the RoleBinding's
// roleRef). Used below only to narrow which namespaces get a real
// SelfSubjectAccessReview — a cluster whose RBAC was hand-rolled under a
// different Role name is not discovered by this filter and simply gets no
// per-namespace breakdown, never a wrong one: the fleet-wide, cluster-scoped
// check in gatherRemediationAuthority is unaffected by this filter either way,
// and stays the safe-direction fallback answer for exactly that case.
const remediateRoleName = "argus-remediate"

// candidateRemediationNamespaces lists every namespace where this cluster's own
// RBAC objects (not the Helm value that was meant to produce them) show a
// namespace-scoped "argus-remediate" Role — a single List call, so this stays
// cheap regardless of how many namespaces the operator granted, unlike checking
// namespace-scoped authority for every namespace in the cluster would be.
// Sorted so the namespaces actually probed (maxNamespaceRemediationChecks may
// truncate this list) are deterministic across refreshes rather than depending
// on the API server's own listing order.
func candidateRemediationNamespaces(ctx context.Context, clientset kubernetes.Interface) ([]string, error) {
	roles, err := clientset.RbacV1().Roles("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	for _, role := range roles.Items {
		if role.Name == remediateRoleName {
			seen[role.Namespace] = true
		}
	}
	namespaces := make([]string, 0, len(seen))
	for ns := range seen {
		namespaces = append(namespaces, ns)
	}
	sort.Strings(namespaces)
	return namespaces, nil
}

// runRemediationChecks issues the SelfSubjectAccessReviews remediationChecks
// describes, scoped to namespace (empty meaning cluster-wide, matching the
// pre-existing fleet-wide behaviour exactly), and returns each result in the
// same order as remediationChecks. Shared by the fleet-wide check and the
// per-namespace loop below so the "three checks" list is walked, and can fail,
// exactly the same way from both call sites.
func runRemediationChecks(ctx context.Context, clientset kubernetes.Interface, namespace string) ([]bool, error) {
	results := make([]bool, len(remediationChecks))
	for i, c := range remediationChecks {
		review := &authorizationv1.SelfSubjectAccessReview{
			Spec: authorizationv1.SelfSubjectAccessReviewSpec{
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: namespace,
					Verb:      c.verb,
					Group:     c.group,
					Resource:  c.resource,
				},
			},
		}
		res, err := clientset.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, review, metav1.CreateOptions{})
		if err != nil {
			return nil, err
		}
		results[i] = res.Status.Allowed
	}
	return results, nil
}

// gatherNamespacedRemediationAuthority is gatherRemediationAuthority's per-
// namespace supplement (see ClusterRemediation.Namespaces' doc comment for why
// this exists rather than reworking the fleet-wide fields). Best-effort at two
// levels, neither of which may fail the fleet-wide answer this is attached to:
// a failure to even list candidate namespaces omits the whole breakdown (nil,
// false), and a failure on one namespace's own reviews omits just that
// namespace rather than aborting the rest.
func gatherNamespacedRemediationAuthority(ctx context.Context, clientset kubernetes.Interface) ([]tunnel.NamespaceRemediation, bool) {
	var candidates []string
	var err error
	if listed := os.Getenv("ARGUS_REMEDIATE_NAMESPACES"); listed == "" {
		candidates, err = candidateRemediationNamespaces(ctx, clientset)
	} else {
		// The remediation identity may not list Roles; its chart says which
		// namespaces it was granted, and each is still checked below.
		for _, ns := range strings.Split(listed, ",") {
			if ns = strings.TrimSpace(ns); ns != "" {
				candidates = append(candidates, ns)
			}
		}
		sort.Strings(candidates)
	}
	if err != nil {
		logger.Warn("could not list namespace-scoped Roles — per-namespace remediation breakdown omitted", slog.String("role", remediateRoleName), logging.Err(err))
		return nil, false
	}

	truncated := false
	if len(candidates) > maxNamespaceRemediationChecks {
		truncated = true
		candidates = candidates[:maxNamespaceRemediationChecks]
	}

	out := make([]tunnel.NamespaceRemediation, 0, len(candidates))
	for _, ns := range candidates {
		results, err := runRemediationChecks(ctx, clientset, ns)
		if err != nil {
			logger.Warn("could not ask remediation authority for a namespace — omitting it from the per-namespace breakdown", slog.String("namespace", ns), logging.Err(err))
			continue
		}
		nr := tunnel.NamespaceRemediation{Namespace: ns}
		for i, c := range remediationChecks {
			c.setNamespaced(&nr, results[i])
		}
		out = append(out, nr)
	}
	return out, truncated
}

// gatherRemediationAuthority asks the API server what this agent may change
// (BACKLOG B4), rather than reporting the Helm value that was meant to grant it.
//
// SelfSubjectAccessReview needs no special RBAC: the built-in system:basic-user
// ClusterRole grants create on it to system:authenticated, so this works on every
// cluster including one where remediation was never enabled — which is exactly the
// cluster whose answer matters most.
//
// The review is deliberately cluster-scoped (no namespace), so a true here means
// the authority holds fleet-wide on this cluster. A namespace-scoped grant answers
// false, which understates it — the safe direction. That used to be the whole
// story ("G1 is where per-namespace scoping gets represented properly" — this is
// G1): gatherNamespacedRemediationAuthority below now supplements these three
// fields with a real per-namespace answer, asked the identical way, for exactly
// the case that understates — a namespaced grant on the chart's own recommended,
// least-privilege remediate.namespaces install. It supplements rather than
// replaces: these three fields stay the fleet-wide fallback, unaffected by
// whether the per-namespace supplement below found anything.
//
// Any failure returns Checked=false with the reason rather than three falses: an
// unreachable authorization endpoint is not a denial, and reporting it as one would
// tell an operator remediation is unavailable when nobody actually asked.
func gatherRemediationAuthority(ctx context.Context, clientset kubernetes.Interface) *tunnel.ClusterRemediation {
	clusterResults, err := runRemediationChecks(ctx, clientset, "")
	if err != nil {
		logger.Warn("could not ask whether this agent may remediate cluster-wide — reporting remediation authority as unknown, not as denied", logging.Err(err))
		return &tunnel.ClusterRemediation{Checked: false, Error: err.Error()}
	}

	out := &tunnel.ClusterRemediation{Checked: true}
	for i, c := range remediationChecks {
		c.set(out, clusterResults[i])
	}
	logger.Info("remediation authority as reported by the API server",
		slog.Bool("patch_deployments", out.CanPatchDeployments), slog.Bool("patch_statefulsets", out.CanPatchStatefulSets), slog.Bool("delete_pods", out.CanDeletePods))

	out.Namespaces, out.NamespacesTruncated = gatherNamespacedRemediationAuthority(ctx, clientset)
	if len(out.Namespaces) > 0 {
		logger.Info("namespace-scoped remediation authority found", slog.Int("namespaces", len(out.Namespaces)), slog.Bool("truncated", out.NamespacesTruncated))
	}
	return out
}

// KubeSystemUID attempts to read the target cluster's own kube-system
// namespace UID — the "real" cluster fingerprint input per
// lld/03-agent-protocol.md §5's note ("a hash of the target cluster's own
// kube-system namespace UID"). Returns ok=false on any error (no reachable
// cluster, RBAC denial, etc.), mirroring GatherFacts' best-effort posture —
// callers fall back to a persisted random fingerprint in that case.
func KubeSystemUID(ctx context.Context) (uid string, ok bool) {
	clientset, err := newClientset()
	if err != nil {
		return "", false
	}

	ctx, cancel := context.WithTimeout(ctx, factsTimeout)
	defer cancel()

	ns, err := clientset.CoreV1().Namespaces().Get(ctx, "kube-system", metav1.GetOptions{})
	if err != nil {
		return "", false
	}
	return string(ns.UID), true
}

// runningAgentImage is the image this agent's own Pod runs, read from the Pod
// spec. ARGUS_AGENT_IMAGE is what the chart rendered, and an upgrade from the
// hub (upgrade_agent) changes only the container image, so after one the
// variable still names the old image. Falls back to the variable when the Pod
// cannot be read.
func runningAgentImage() string {
	fallback := os.Getenv("ARGUS_AGENT_IMAGE")
	name, ns := os.Getenv("ARGUS_POD_NAME"), os.Getenv("ARGUS_POD_NAMESPACE")
	if name == "" || ns == "" {
		return fallback
	}
	restCfg, err := loadKubeConfig()
	if err != nil {
		return fallback
	}
	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return fallback
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pod, err := clientset.CoreV1().Pods(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fallback
	}
	for _, c := range pod.Spec.Containers {
		if c.Name == "agent" {
			return c.Image
		}
	}
	return fallback
}
