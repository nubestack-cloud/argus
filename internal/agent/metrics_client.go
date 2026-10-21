package agent

// metrics_client.go builds BACKLOG.md C4's query_metrics half: the narrow
// abstraction that tool submits its one HTTP GET through, and the live
// authority check that decides whether to offer the tool at all.
//
// WHY THIS IS DIFFERENT FROM dry_run_patch/open_execution_window
//
// dryrun_client.go and policywindow_client.go each build a SECOND,
// independently-authenticated Kubernetes client, because the ValidatingAdmissionPolicy
// that restricts their identity is scoped by exact username and RBAC is
// additive (see dryrun_client.go's package doc comment for the full
// reasoning). query_metrics needs none of that: it never writes anything, so
// there is no admission policy to keep separate from another identity's
// grants, and the RBAC it needs (get on one named Service's proxy
// subresource — deploy/helm/argus-agent/templates/metrics.yaml) is safe to
// add directly to argus-investigate, the SAME identity every other read-only
// tool in this package already runs as. So query_metrics reaches Prometheus
// through this agent's ordinary typed client, not a second credential.
//
// WHY THE PROXY CALL IS ABSTRACTED BEHIND AN INTERFACE ANYWAY
//
// k8sfake's CoreV1().RESTClient() — the fake clientset every other tool's
// test in this package is verified against — returns a nil *rest.RESTClient
// wrapped as rest.Interface (see kubernetes/typed/core/v1/fake's
// generated RESTClient() method); calling anything on it panics. There is no
// way to make the fake clientset actually serve a services/proxy subresource
// response, so this file's real HTTP call is behind metricsProxyClient, and
// tests — including redact_egress_test.go's canary drive, which needs a real
// Execute call to produce real output to check — substitute a fake
// implementation instead. query_metrics_test.go's own tests drive that fake
// through an actual httptest.Server, exercising the same endpoint/params
// wire shape restMetricsProxyClient builds in production.
//
// HOW THE PROXY PATH ITSELF WORKS
//
// The Kubernetes API server exposes a `services/proxy` subresource:
// GET /api/{version}/namespaces/{ns}/services/{name}:{port}/proxy/{path}
// forwards {path} (with its query string) to that Service's endpoint and
// returns the response verbatim — no new network route from this agent's pod
// to Prometheus is needed, only RBAC on the subresource, because the API
// server itself does the dialing. Confirmed against a real cluster (rke2,
// rancher-monitoring-prometheus in cattle-monitoring-system) before this
// tool was built — see BACKLOG.md C4.
import (
	"context"
	"fmt"
	"log/slog"

	"argus/internal/logging"

	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"argus/internal/tunnel"
)

// metricsProxyClient is the abstraction query_metrics submits its one HTTP GET
// through. endpoint is a Prometheus HTTP API path relative to the service
// root (e.g. "api/v1/query" or "api/v1/query_range"); params are that
// request's query-string values. Returns the raw response body — parsing and
// bounding happen in the caller (query_metrics.go).
type metricsProxyClient interface {
	Get(ctx context.Context, endpoint string, params map[string]string) ([]byte, error)
}

// restMetricsProxyClient is the production implementation: this agent's own
// typed client's RESTClient, aimed at one configured Service's proxy
// subresource. Built once, at newToolExecutor construction time, from the
// SAME rest.Config every other tool in this package uses — never a second
// credential.
type restMetricsProxyClient struct {
	rest      rest.Interface
	namespace string
	service   string
	port      int
}

func (c *restMetricsProxyClient) Get(ctx context.Context, endpoint string, params map[string]string) ([]byte, error) {
	req := c.rest.Get().
		Namespace(c.namespace).
		Resource("services").
		SubResource("proxy").
		Name(fmt.Sprintf("%s:%d", c.service, c.port)).
		Suffix(endpoint)
	for k, v := range params {
		req = req.Param(k, v)
	}
	return req.DoRaw(ctx)
}

// newMetricsProxyClient builds query_metrics' proxy client from this agent's
// already-built typed clientset, or returns nil when metrics.prometheusService
// was never configured (namespace/service empty, or port non-positive) — the
// ordinary, default state for any cluster that has not opted into BACKLOG.md
// C4's query_metrics half. A nil return is not an error: newToolExecutor
// treats it exactly like newDryRunDynamicClient's nil "pack not enabled"
// case, and queryMetrics reports errMetricsNotConfigured rather than an
// internal failure.
func newMetricsProxyClient(typed kubernetes.Interface, namespace, service string, port int) metricsProxyClient {
	if namespace == "" || service == "" || port <= 0 {
		return nil
	}
	return &restMetricsProxyClient{
		rest:      typed.CoreV1().RESTClient(),
		namespace: namespace,
		service:   service,
		port:      port,
	}
}

// metricsCheckVerb/metricsCheckResource/metricsCheckSubresource name the one
// RBAC question gatherClusterMetricsAuthority asks — the exact verb+resource+
// subresource deploy/helm/argus-agent/templates/metrics.yaml grants, narrowed
// by resourceNames to the one configured Service.
const (
	metricsCheckVerb        = "get"
	metricsCheckResource    = "services"
	metricsCheckSubresource = "proxy"
)

// gatherClusterMetricsAuthority asks whether THIS cluster's agent identity
// actually holds `get` on the configured Service's `proxy` subresource, using
// the SAME discipline gatherClusterDryRunAuthority already established for
// BACKLOG.md C4's other half: ask the API server directly, report
// Checked=false (never a confident "denied") on anything short of a definite
// answer, and never trust the values.yaml toggle that was supposed to grant
// it.
//
// Unlike gatherClusterDryRunAuthority, this asks with the agent's PRIMARY
// identity's own clientset (typed, already built by newToolExecutor) — there
// is no second credential here to ask with instead, per this file's own
// package doc comment.
func gatherClusterMetricsAuthority(ctx context.Context, typed kubernetes.Interface, namespace, service string, port int) *tunnel.ClusterMetrics {
	if namespace == "" || service == "" || port <= 0 {
		// The ordinary, default case: this cluster never configured
		// metrics.prometheusService. Checked=false with no Error — not a
		// failure, just "not asked because there is nothing to ask".
		return &tunnel.ClusterMetrics{Checked: false}
	}
	if typed == nil {
		// No reachable cluster config at all (newToolExecutor itself failed)
		// — the same "unknown, not denied" posture as any other check this
		// agent cannot actually perform right now.
		return &tunnel.ClusterMetrics{Checked: false, Error: "no reachable cluster config"}
	}

	review := &authorizationv1.SelfSubjectAccessReview{
		Spec: authorizationv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Verb:        metricsCheckVerb,
				Group:       "",
				Resource:    metricsCheckResource,
				Subresource: metricsCheckSubresource,
				Namespace:   namespace,
				// The exact name the proxy request uses (restMetricsProxyClient:
				// "service:port"). RBAC compares resourceNames to that whole
				// string, so asking about the bare Service name answered
				// "allowed" while every real query was refused.
				Name: fmt.Sprintf("%s:%d", service, port),
			},
		},
	}
	res, err := typed.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, review, metav1.CreateOptions{})
	if err != nil {
		logger.Warn("could not ask whether this identity may perform the given verb/resource — reporting metrics authority as unknown, not as denied",
			slog.String("verb", metricsCheckVerb), slog.String("resource", metricsCheckResource), slog.String("service", service),
			slog.String("subresource", metricsCheckSubresource), slog.String("namespace", namespace), logging.Err(err))
		return &tunnel.ClusterMetrics{Checked: false, Error: err.Error()}
	}
	logger.Info("metrics authority as reported by the API server",
		slog.String("namespace", namespace), slog.String("service", service), slog.Int("port", port),
		slog.Bool("allowed", res.Status.Allowed))
	return &tunnel.ClusterMetrics{Checked: true, Allowed: res.Status.Allowed}
}

// gatherClusterMetricsAuthorityFromConfig is factsWithDetection's entry
// point: it builds its own typed clientset from loadKubeConfig() rather than
// requiring an already-built one, mirroring gatherClusterDryRunAuthority's
// own self-contained shape. factsWithDetection can run before Run has built a
// ToolExecutor at all (client.go's Facts is computed independently), so this
// must not depend on one existing.
func gatherClusterMetricsAuthorityFromConfig(ctx context.Context, namespace, service string, port int) *tunnel.ClusterMetrics {
	if namespace == "" || service == "" || port <= 0 {
		return &tunnel.ClusterMetrics{Checked: false}
	}
	cfg, err := loadKubeConfig()
	if err != nil {
		return &tunnel.ClusterMetrics{Checked: false, Error: err.Error()}
	}
	typed, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return &tunnel.ClusterMetrics{Checked: false, Error: err.Error()}
	}
	return gatherClusterMetricsAuthority(ctx, typed, namespace, service, port)
}
