package agent

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"argus/internal/redact"
	"argus/internal/tunnel"
)

// This file is the enforcement half of BACKLOG.md G8. internal/redact has its
// own unit tests for what the filter drops; these tests are about the thing
// that actually failed in BUGS.md 84 — not a filter being wrong, but there
// being no filter on a path somebody added later.
//
// The guarantee is deliberately structural rather than a matter of review
// discipline. ToolExecutor.Execute wraps executeTool's dispatch, so a new tool
// is redacted before its author has an opinion about redaction; these tests
// exist to make sure that wrapping cannot be quietly undone or bypassed.

// egressCanary is planted in every field class a tool could return. One
// distinctive value, so any leak is unambiguous and greppable.
const egressCanary = "CANARY-b7f3e1-must-never-egress"

// toolRedactionCoverage is the authoritative classification of every tool in
// executeTool's dispatch.
//
// readOnly tools are driven against a canary-stuffed fake cluster below.
// mutating tools are excluded from that drive only because standing one up
// requires a signed remediation plan and a live resourceVersion precondition —
// NOT because their output is exempt: they return through the same
// Execute chokepoint as everything else, which
// TestExecuteIsTheRedactionChokepoint pins directly.
//
// TestEveryToolIsClassifiedForRedaction fails if a tool exists in the dispatch
// and is missing here, which is what makes "add a tool, get redaction" true by
// construction rather than by memory.
var toolRedactionCoverage = map[string]string{
	"get_events":                "readOnly",
	"get_logs":                  "readOnly",
	"describe_resource":         "readOnly",
	"list_resources":            "readOnly",
	"get_owner_chain":           "readOnly",
	"get_gitops_ownership":      "readOnly",
	"get_resource_schema":       "readOnly",
	"list_nodeport_allocations": "readOnly",
	"reevaluate_rule":           "readOnly",
	"query_metrics":             "readOnly",

	// Cluster-insight tools (docs/CLUSTER_INSIGHT_SPECS.md): read from the
	// object cache, which hashes env and ConfigMap values at capture; their
	// output still returns through Execute like every other tool.
	"evaluate_network_policy": "readOnly",
	"get_subject_permissions": "readOnly",
	"diagnose_autoscaler":     "readOnly",
	"diagnose_rollout":        "readOnly",
	"get_policy_findings":     "readOnly",
	"explain_scheduling":      "readOnly",
	"get_drain_impact":        "readOnly",
	"get_karpenter_capacity":  "readOnly",
	"get_rightsizing":         "readOnly",
	"get_gitops_insight":      "readOnly",
	"get_traffic":             "readOnly",
	"get_cost_summary":        "readOnly",
	"search_objects":          "readOnly",
	"trace_service_path":      "readOnly",
	"get_neighborhood":        "readOnly",
	"get_posture_findings":    "readOnly",
	"get_upgrade_readiness":   "readOnly",
	"list_certificates":       "readOnly",
	"get_helm_release_status": "readOnly",
	"list_helm_releases":      "readOnly",
	"list_gitops_apps":        "readOnly",
	"get_namespace_topology":  "readOnly",
	"get_network_policy_map":  "readOnly",

	"scale_deployment":       "mutating",
	"upgrade_agent":          "mutating",
	"cordon_node":            "mutating",
	"drain_node":             "mutating",
	"restart_pod":            "mutating",
	"patch_resource_limits":  "mutating",
	"revert_container_image": "mutating",
	"patch_field":            "mutating",
	"annotate_resource":      "mutating",
	"label_resource":         "mutating",
	"delete_resource":        "mutating",
	"create_resource":        "mutating",
	"dry_run_patch":          "mutating",

	// BACKLOG.md F14: these write the argus.io/v1 ExecutionWindow CRD, not
	// any workload — no secret-shaped field ever passes through them (the
	// CRD carries only plan IDs, GVK/UID/field-path strings this hub itself
	// already sent), but "mutating" is still the correct classification: they
	// are a real write path, excluded from the readOnly canary drive below
	// for the same reason scale_deployment etc. are (standing one up needs a
	// signed context this test doesn't build), not because their output is
	// exempt from Execute's redaction wrapper.
	"open_execution_window":  "mutating",
	"close_execution_window": "mutating",
}

// dispatchedToolNames parses tools.go and returns the tool names executeTool's
// switch actually handles.
//
// Reading the source rather than a registry is the point: the switch IS the
// dispatch, so a name can never be in the code and absent from this list. A
// hand-maintained registry would drift in exactly the direction that produced
// BUGS.md 84 — the code grows a path, the safety list does not.
func dispatchedToolNames(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "tools.go", nil, 0)
	if err != nil {
		t.Fatalf("parse tools.go: %v", err)
	}

	var names []string
	var found bool
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "executeTool" {
			return true
		}
		found = true
		ast.Inspect(fn.Body, func(inner ast.Node) bool {
			clause, ok := inner.(*ast.CaseClause)
			if !ok {
				return true
			}
			for _, expr := range clause.List {
				lit, ok := expr.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				name, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatalf("unquote case value %s: %v", lit.Value, err)
				}
				names = append(names, name)
			}
			return true
		})
		return false
	})
	if !found {
		t.Fatal("could not find executeTool in tools.go — if it was renamed, " +
			"update this test rather than deleting it: it is what keeps a new " +
			"tool from shipping without capture-time redaction (BACKLOG.md G8)")
	}
	sort.Strings(names)
	return names
}

// TestEveryToolIsClassifiedForRedaction is the tripwire. Add a case to
// executeTool and this fails until the tool is classified above — at which
// point, if it is read-only, the canary drive below starts exercising it.
func TestEveryToolIsClassifiedForRedaction(t *testing.T) {
	dispatched := dispatchedToolNames(t)
	if len(dispatched) == 0 {
		t.Fatal("parsed zero tool names out of executeTool's switch")
	}
	for _, name := range dispatched {
		if _, ok := toolRedactionCoverage[name]; !ok {
			t.Errorf("tool %q is dispatched by executeTool but not classified in "+
				"toolRedactionCoverage.\nEvery tool's output crosses the tunnel and is "+
				"persisted into analyses.causal_chain (BUGS.md 84). Classify it "+
				"\"readOnly\" (and it will be canary-tested) or \"mutating\", and make "+
				"sure it returns through Execute rather than executeTool.", name)
		}
	}
	for name := range toolRedactionCoverage {
		if !slicesContains(dispatched, name) {
			t.Errorf("tool %q is classified in toolRedactionCoverage but no longer "+
				"dispatched by executeTool — remove the stale entry", name)
		}
	}
}

func slicesContains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// canaryCluster builds a fake cluster where every field class BUGS.md 84 names
// carries the canary: a plaintext env value, a container arg, a
// last-applied-configuration annotation, a log line, and event text.
func canaryCluster(t *testing.T) *ToolExecutor {
	t.Helper()

	lastApplied, err := json.Marshal(map[string]any{
		"spec": map[string]any{"containers": []any{map[string]any{
			"env": []any{map[string]any{"name": "DB_PASSWORD", "value": egressCanary}},
		}}},
	})
	if err != nil {
		t.Fatalf("build last-applied fixture: %v", err)
	}

	// A typed *corev1.Pod rather than an unstructured one, deliberately. The
	// dynamic fake converts a typed object into unstructured for describe's Get
	// AND for list_resources' List; seeded as unstructured it serves the Get
	// fine and then fails the List with "can't assign or convert
	// unstructured.Unstructured into v1.Pod", which made the list_resources
	// canary case SKIP rather than fail — a hole in exactly the coverage this
	// file exists to provide.
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "payments-abc123",
			Namespace: "prod",
			UID:       "11111111-1111-1111-1111-111111111111",
			Annotations: map[string]string{
				"kubectl.kubernetes.io/last-applied-configuration": string(lastApplied),
				// A plain (non-dotted) key, deliberately: RuleCondition.Field
				// splits on ".", so an annotation key containing literal dots
				// (like the one above) cannot be addressed by a rule at all.
				// This is the canary the reevaluate_rule test case below
				// reads, shaped as a bearer credential so the freeform
				// pattern layer (the layer that actually protects a rule's
				// rendered Message — see rules.go's ruleTemplateData doc
				// comment) has something recognisable to catch.
				"canary-token": "bearer " + egressCanary,
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "registry.io/payments:1.4.2",
				Args:  []string{"--db-password=" + egressCanary},
				Env: []corev1.EnvVar{
					{Name: "DB_PASSWORD", Value: egressCanary},
					{Name: "FROM_SECRET", ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{Name: "db-creds"},
							Key:                  "password",
						},
					}},
				},
			}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}

	exec, typed := newTestExecutor(pod)
	attachCanaryObjectCache(t, exec, typed, pod)

	// query_metrics never touches the typed/dynamic fakes above at all — its
	// output comes entirely from metricsProxy (metrics_client.go's package
	// doc comment explains why: k8sfake's RESTClient() is a nil client and
	// cannot serve a proxy subresource). Wired here with a canary-carrying
	// Prometheus response so this tool's redaction gets the same real,
	// non-vacuous Execute-level check as every other read-only tool in this
	// file.
	exec.metricsProxy = canaryMetricsProxyClient{}

	installEventsReactor(typed, []corev1.Event{{
		ObjectMeta: metav1.ObjectMeta{Name: "payments-abc123.1", Namespace: "prod"},
		InvolvedObject: corev1.ObjectReference{
			Kind: "Pod", Name: "payments-abc123", Namespace: "prod",
		},
		Reason:  "Failed",
		Message: "container failed to start: connection refused for postgres://app:" + egressCanary + "@db:5432/payments",
		Type:    "Warning",
		Count:   3,
	}})

	installPodLogs(typed, "starting up\nfatal: auth rejected, token="+egressCanary+"\n")

	// A rule targeting the scalar "canary-token" annotation above — the same
	// shape the four shipped default rules use (Field addresses one scalar,
	// never a whole map), so this is a realistic rule, not an adversarial
	// one. Its rendered Message carries whatever that field holds via
	// evaluateCondition's data.Value := formatFieldValue(fieldVal) — rules.go's
	// ruleTemplateData doc comment is explicit that THIS path's protection is
	// the freeform pattern layer (internal/redact's Text, run again here by
	// Object), not structural per-key redaction: a rule's Field is a
	// caller-chosen path into arbitrary object data, so there is no field
	// NAME for a structural rule to key on the way "env" or
	// "last-applied-configuration" can. Comparator "ne" against a value that
	// can never match guarantees this fires and Message actually renders.
	exec.SetRules([]Rule{{
		ID:       "canary-rule",
		GVK:      "v1/Pod",
		Reason:   "canary-reason",
		Severity: "high",
		Message:  "canary-token observed: {{.Value}}",
		Condition: RuleCondition{
			Field:      "metadata.annotations.canary-token",
			Comparator: "ne",
			Value:      "this-can-never-equal-the-real-annotation-value",
		},
	}})
	return exec
}

// canaryMetricsProxyClient is query_metrics' canary fixture: a Prometheus
// instant-query response carrying the canary in a label value, shaped as a
// bearer credential — the same recognisable-pattern shape
// reevaluate_rule's own canary-token fixture above uses. query_metrics'
// output has no structural field classes for redact.Object's PRIMARY layer to
// key on (there is no "env" or "data" key in a Prometheus response), so what
// this test actually exercises is the SECONDARY, pattern-based layer — the
// one internal/redact's own package doc comment calls "a bounded backstop,
// not the primary control" and explicitly does not claim to catch every
// unrecognisable-format secret. Shaping the canary as a value the pattern
// layer DOES recognise is what makes this a meaningful proof that Execute's
// redaction wrapper still runs on this tool's output, rather than a
// mismatched fixture that would fail regardless of whether the wrapper ran.
type canaryMetricsProxyClient struct{}

func (canaryMetricsProxyClient) Get(context.Context, string, map[string]string) ([]byte, error) {
	return json.Marshal(map[string]any{
		"status": "success",
		"data": map[string]any{
			"resultType": "vector",
			"result": []any{map[string]any{
				"metric": map[string]any{"__name__": "up", "leaked_header": "bearer " + egressCanary},
				"value":  []any{1700000000, "1"},
			}},
		},
	})
}

// installPodLogs makes the fake clientset serve body for any pods/log GET,
// mirroring the reactor shape TestGetLogs_TailLimitedAndParsed already uses
// (the fake has no pod-log support of its own).
func installPodLogs(typed *k8sfake.Clientset, body string) {
	typed.PrependReactor("get", "pods/log", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, &runtime.Unknown{Raw: []byte(body)}, nil
	})
}

// TestEveryReadOnlyToolRedactsItsOutput drives each read-only tool against the
// canary cluster through Execute — the same entry point client.go's
// executeToolRequest uses — and fails if the canary survives anywhere in the
// returned bytes.
func TestEveryReadOnlyToolRedactsItsOutput(t *testing.T) {
	args := map[string]any{
		"get_events":                map[string]any{"namespace": "prod"},
		"get_logs":                  map[string]any{"namespace": "prod", "pod": "payments-abc123"},
		"describe_resource":         map[string]any{"gvk": "v1/Pod", "namespace": "prod", "name": "payments-abc123"},
		"list_resources":            map[string]any{"kind": "Pod", "namespace": "prod"},
		"get_owner_chain":           map[string]any{"gvk": "v1/Pod", "namespace": "prod", "name": "payments-abc123", "direction": "up"},
		"get_gitops_ownership":      map[string]any{"gvk": "v1/Pod", "namespace": "prod", "name": "payments-abc123"},
		"get_resource_schema":       map[string]any{"gvk": "v1/Pod"},
		"list_nodeport_allocations": map[string]any{},
		"reevaluate_rule":           map[string]any{"ruleId": "canary-rule", "namespace": "prod", "name": "payments-abc123"},
		"query_metrics":             map[string]any{"promql": "up"},
		"evaluate_network_policy": map[string]any{
			"source":      map[string]any{"external": true},
			"destination": map[string]any{"kind": "Service", "namespace": "prod", "name": "payments"},
			"port":        80,
		},
		"get_subject_permissions": map[string]any{"kind": "ServiceAccount", "namespace": "prod", "name": "payments"},
		"diagnose_autoscaler":     map[string]any{"namespace": "prod", "name": "payments"},
		"diagnose_rollout":        map[string]any{"namespace": "prod", "name": "payments"},
		"get_policy_findings":     map[string]any{"kind": "Pod", "namespace": "prod", "name": "payments-abc123"},
		"explain_scheduling":      map[string]any{"namespace": "prod", "pod": "payments-abc123"},
		"get_drain_impact":        map[string]any{"node": "worker-1"},
		"get_karpenter_capacity":  map[string]any{},
		"get_rightsizing":         map[string]any{"namespace": "prod"},
		"get_gitops_insight":      map[string]any{"group": "apps", "kind": "Deployment", "namespace": "prod", "name": "payments"},
		"get_traffic":             map[string]any{"namespace": "prod"},
		"get_cost_summary":        map[string]any{"namespace": "prod"},
		"search_objects":          map[string]any{"query": "payments"},
		"trace_service_path":      map[string]any{"kind": "Service", "namespace": "prod", "name": "payments"},
		"get_neighborhood":        map[string]any{"kind": "Deployment", "apiGroup": "apps", "namespace": "prod", "name": "payments"},
		"get_posture_findings":    map[string]any{},
		"get_upgrade_readiness":   map[string]any{"targetVersion": "1.37"},
		"list_certificates":       map[string]any{},
		"get_helm_release_status": map[string]any{"namespace": "prod", "name": "payments"},
		"list_helm_releases":      map[string]any{},
		"list_gitops_apps":        map[string]any{},
		"get_namespace_topology":  map[string]any{"namespace": "prod"},
		"get_network_policy_map":  map[string]any{"namespace": "prod"},
	}

	// One canary cluster for every case: the tools only read it, and building
	// one (with its object-cache sync) per tool made this the slowest test in
	// the repository for no extra coverage.
	exec := canaryCluster(t)
	for name, class := range toolRedactionCoverage {
		if class != "readOnly" {
			continue
		}
		raw, ok := args[name]
		if !ok {
			t.Errorf("read-only tool %q has no argument fixture in this test — add one "+
				"so its output is actually canary-checked", name)
			continue
		}
		t.Run(name, func(t *testing.T) {
			encoded, err := json.Marshal(raw)
			if err != nil {
				t.Fatalf("marshal args: %v", err)
			}
			data, _, err := exec.Execute(context.Background(), name, encoded)
			if err != nil {
				// Deliberately a failure, not a skip. A tool that errors here
				// produced no output to inspect, so its canary check silently
				// proved nothing — and a green-but-vacuous case is the failure
				// mode this whole file exists to prevent. list_resources sat
				// SKIPped exactly this way while looking fine in the summary.
				// If a tool genuinely cannot be driven against the fake
				// cluster, fix the fixture or reclassify it — do not let it
				// pass unexamined.
				t.Fatalf("read-only tool %q errored against the canary cluster, so its "+
					"output was never checked: %v", name, err)
			}
			if strings.Contains(string(data), egressCanary) {
				t.Errorf("tool %q leaked the canary through Execute.\n"+
					"This is BUGS.md 84: whatever this tool returns reaches the model, is "+
					"persisted into analyses.causal_chain and is rendered in the browser.\n"+
					"output: %s", name, data)
			}
		})
	}
}

// TestExecuteIsTheRedactionChokepoint states the guarantee in the crispest form
// available: the raw dispatch leaks, and the exported entry point does not.
//
// If someone "simplifies" Execute by folding executeTool back into it and drops
// the redact.Object call, or adds a tool that returns early from Execute
// without going through the wrapper, this fails. That is the whole reason the
// two functions are split, and this test is the reason the split cannot be
// undone by accident.
func TestExecuteIsTheRedactionChokepoint(t *testing.T) {
	ctx := context.Background()
	args, err := json.Marshal(map[string]any{
		"gvk": "v1/Pod", "namespace": "prod", "name": "payments-abc123",
	})
	if err != nil {
		t.Fatalf("marshal args: %v", err)
	}

	exec := canaryCluster(t)
	rawData, _, err := exec.executeTool(ctx, "describe_resource", args)
	if err != nil {
		t.Fatalf("executeTool: %v", err)
	}
	// Not an aspiration about executeTool — a statement that the fixture
	// really does carry secret material, so the assertion below means
	// something. If this ever stops holding, the canary cluster stopped
	// planting secrets and the test below became vacuous.
	if !strings.Contains(string(rawData), egressCanary) {
		t.Fatal("the unwrapped dispatch did NOT contain the canary — the fixture is " +
			"no longer planting secret material, so this test proves nothing. Fix the " +
			"fixture rather than deleting the test.")
	}

	redactedData, _, err := exec.Execute(ctx, "describe_resource", args)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if strings.Contains(string(redactedData), egressCanary) {
		t.Fatalf("Execute did not redact — the chokepoint is gone.\noutput: %s", redactedData)
	}
	if !redact.ContainsMarker(string(redactedData)) {
		t.Errorf("expected a redaction marker in Execute's output, got: %s", redactedData)
	}
	// The shape must survive, or the fix has traded a leak for a blind spot.
	for _, want := range []string{"DB_PASSWORD", "secretKeyRef", "db-creds", "registry.io/payments:1.4.2"} {
		if !strings.Contains(string(redactedData), want) {
			t.Errorf("expected diagnostic detail %q to survive redaction, output: %s", want, redactedData)
		}
	}
}

// TestFindingMessageIsRedactedBeforeEgress covers the detection path, which is
// the half of BUGS.md 84 that does not go through the tool executor at all:
// every detector copies verbatim event and condition text into Finding.Message.
//
// Asserted against redact.Text directly, matching what client.go's writer loop
// applies to f.Message immediately before enc.Encode. A detector-level test
// would prove less: the filter deliberately does not live in the detectors,
// precisely so a new detector cannot forget it.
func TestFindingMessageIsRedactedBeforeEgress(t *testing.T) {
	f := tunnel.Finding{
		DetectorID: "k8s-warning-events",
		Reason:     "Failed",
		Namespace:  "prod",
		ObjectName: "payments-abc123",
		Message: "Error: failed to connect to postgres://app:" + egressCanary +
			"@db:5432/payments (token=" + egressCanary + ")",
		Severity: "high",
	}

	f.Message = redact.Text(f.Message)

	if strings.Contains(f.Message, egressCanary) {
		t.Errorf("Finding.Message still carries the canary: %s", f.Message)
	}
	// Correlation-bearing fields must be untouched: the hub joins and indexes
	// on these, and corrupting one would silently break incident grouping.
	if f.ObjectName != "payments-abc123" || f.Namespace != "prod" ||
		f.Reason != "Failed" || f.DetectorID != "k8s-warning-events" {
		t.Error("redaction must not touch identifier fields — the hub correlates on them")
	}
	// The diagnostic sentence around the credential has to survive, or the
	// finding stops being readable to the on-call engineer it is for.
	if !strings.Contains(f.Message, "failed to connect to") {
		t.Errorf("surrounding diagnostic text was lost: %s", f.Message)
	}
}
