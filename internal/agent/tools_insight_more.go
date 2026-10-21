package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	"argus/internal/agent/clustersummary"
	"argus/internal/agent/cost"
	"argus/internal/agent/karpenter"
	"argus/internal/agent/objcache"
	"argus/internal/agent/objsearch"
	"argus/internal/agent/policyreports"
	"argus/internal/agent/schedexplain"
	"argus/internal/agent/traffic"
	"argus/internal/gitopsinsight"
	"argus/internal/redact"
	"argus/internal/tunnel"
)

// ---------------------------------------------------------------- last-applied drift store

// driftStore keeps, per object UID, the drift between an object's
// last-applied configuration and its live state, computed by the object
// cache's transform before the annotation (and plaintext env values) are
// dropped (docs/CLUSTER_INSIGHT_SPECS.md CI-S7). Values on secret-bearing
// paths are replaced before storage, so nothing sensitive is retained.
type driftStore struct {
	mu sync.RWMutex
	m  map[types.UID]gitopsinsight.Drift
}

var lastAppliedDrift = &driftStore{m: map[types.UID]gitopsinsight.Drift{}}

const maxDriftStoreEntries = 20000

// sensitiveDriftPath matches drift paths whose values must never be kept:
// container env values and ConfigMap/Secret-shaped data maps.
var sensitiveDriftPath = regexp.MustCompile(`(\.env\.\[\d+\]\.value$)|(^(data|stringData|binaryData)\.)`)

func (d *driftStore) record(obj *unstructured.Unstructured) {
	entries, truncated, err := gitopsinsight.LastAppliedDrift(obj)
	if err != nil {
		return
	}
	for i := range entries {
		if sensitiveDriftPath.MatchString(entries[i].Path) {
			if entries[i].Desired != "" {
				entries[i].Desired = redact.Marker
			}
			if entries[i].Live != "" {
				entries[i].Live = redact.Marker
			}
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(entries) == 0 {
		delete(d.m, obj.GetUID())
		return
	}
	if _, exists := d.m[obj.GetUID()]; !exists && len(d.m) >= maxDriftStoreEntries {
		return
	}
	d.m[obj.GetUID()] = gitopsinsight.Drift{Source: gitopsinsight.DriftSource("lastApplied"), Entries: entries, Truncated: truncated}
}

func (d *driftStore) get(uid types.UID) (gitopsinsight.Drift, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	v, ok := d.m[uid]
	return v, ok
}

// gitOpsManaged is the cheap metadata check that limits drift computation
// to objects a GitOps controller manages.
func gitOpsManaged(o metav1.Object) bool {
	for k := range o.GetAnnotations() {
		if k == "argocd.argoproj.io/tracking-id" {
			return true
		}
	}
	for k := range o.GetLabels() {
		if strings.HasPrefix(k, "kustomize.toolkit.fluxcd.io/") || strings.HasPrefix(k, "helm.toolkit.fluxcd.io/") ||
			k == "argocd.argoproj.io/instance" || strings.HasPrefix(k, "objectset.rio.cattle.io/") {
			return true
		}
	}
	return false
}

// argoSyncFor reads Argo CD's own verdict on one managed object from its
// Application's status.resources (CI-P9 b). Nil when the object is not
// tracked by an Application the cache holds, or the Application does not
// list it.
func argoSyncFor(c *objcache.Cache, mo metav1.Object, group, kind string) *gitopsinsight.ControllerSync {
	ref := parseArgoTrackingID(mo.GetAnnotations()["argocd.argoproj.io/tracking-id"])
	if ref == nil {
		if name := mo.GetLabels()["argocd.argoproj.io/instance"]; name != "" {
			ref = &gitOpsAppRef{Kind: "Application", Name: name}
		}
	}
	if ref == nil {
		return nil
	}
	apps, err := c.Dynamic("argoproj.io", "Application", ref.Namespace)
	if err != nil {
		return nil
	}
	for _, app := range apps {
		if app.GetName() != ref.Name {
			continue
		}
		if cs, ok := gitopsinsight.ArgoResourceSync(app.Object, group, kind, mo.GetNamespace(), mo.GetName()); ok {
			return &cs
		}
	}
	return nil
}

func defaultObjcacheHook() objcacheHook {
	return objcacheHook{lastApplied: func(_, _ string, obj *unstructured.Unstructured, _ string) {
		lastAppliedDrift.record(obj)
	}}
}

// ---------------------------------------------------------------- cluster summary (facts)

// clusterSummaryJSON computes the cluster summary from the object cache for
// ClusterFacts.Summary (CI-S11). Nil when the cache is not running.
func clusterSummaryJSON() json.RawMessage {
	c := activeObjectCache.Load()
	if c == nil {
		return nil
	}
	return clusterSummaryFrom(c)
}

// Summary cache states. "syncing" means the object cache has not finished
// its first list of every kind, so the summary carries no figures at all:
// a kind still mid-list would otherwise be filed under `unavailable` and read
// as "not visible to the agent", which on a just-restarted agent is false.
const (
	summaryCacheSyncing = "syncing"
	summaryCacheSynced  = "synced"
)

// syncingSummary is the figure-free summary sent while the cache's first
// sync is still running: when it started, so the reader can say how long the
// agent has been reading, and nothing that could be mistaken for a count.
type syncingSummary struct {
	CacheState     string    `json:"cacheState"`
	CacheStartedAt time.Time `json:"cacheStartedAt"`
	ComputedAt     time.Time `json:"computedAt"`
}

func clusterSummaryFrom(c *objcache.Cache) json.RawMessage {
	if c.SyncedAt().IsZero() {
		b, err := json.Marshal(syncingSummary{CacheState: summaryCacheSyncing, CacheStartedAt: c.StartedAt().UTC(), ComputedAt: time.Now().UTC()})
		if err != nil {
			return nil
		}
		return b
	}
	var unavailable []string
	note := func(kind string, err error) {
		if err != nil {
			unavailable = append(unavailable, kind)
		}
	}
	in := clustersummary.CountsInput{}
	var err error
	in.Pods, err = c.Pods("")
	note(clustersummary.KindPods, err)
	in.Deployments, err = c.Deployments("")
	note(clustersummary.KindDeployments, err)
	in.StatefulSets, err = c.StatefulSets("")
	note(clustersummary.KindStatefulSets, err)
	in.DaemonSets, err = c.DaemonSets("")
	note(clustersummary.KindDaemonSets, err)
	in.Services, err = c.Services("")
	note(clustersummary.KindServices, err)
	in.Ingresses, err = c.Ingresses("")
	note(clustersummary.KindIngresses, err)
	in.Nodes, err = c.Nodes()
	note(clustersummary.KindNodes, err)
	in.Namespaces, err = c.Namespaces()
	note(clustersummary.KindNamespaces, err)
	in.Jobs, err = c.Jobs("")
	note(clustersummary.KindJobs, err)
	in.CronJobs, err = c.CronJobs("")
	note(clustersummary.KindCronJobs, err)
	in.ConfigMaps, err = c.ConfigMaps("")
	note(clustersummary.KindConfigMaps, err)
	in.PVCs, err = c.PersistentVolumeClaims("")
	note(clustersummary.KindPVCs, err)
	in.Unavailable = unavailable

	si := clustersummary.SummaryInput{Counts: in}
	if policies, perr := c.NetworkPolicies(""); perr == nil &&
		!contains(unavailable, clustersummary.KindDeployments) && !contains(unavailable, clustersummary.KindStatefulSets) && !contains(unavailable, clustersummary.KindDaemonSets) {
		si.Coverage = &clustersummary.CoverageInput{Policies: policies, Deployments: in.Deployments, StatefulSets: in.StatefulSets, DaemonSets: in.DaemonSets}
	}
	type summaryWire struct {
		clustersummary.Summary
		GitOpsControllers []string         `json:"gitopsControllers"`
		Capacity          *capacitySummary `json:"capacity,omitempty"`
		CacheState        string           `json:"cacheState"`
		ComputedAt        time.Time        `json:"computedAt"`
	}
	out := summaryWire{Summary: clustersummary.Build(si), CacheState: summaryCacheSynced, ComputedAt: time.Now().UTC(), GitOpsControllers: []string{}}
	if !contains(unavailable, clustersummary.KindPods) && !contains(unavailable, clustersummary.KindNodes) {
		out.Capacity = computeCapacity(in.Pods, in.Nodes)
	}
	for _, gk := range [][3]string{{"argoproj.io", "Application", "argocd"}, {"kustomize.toolkit.fluxcd.io", "Kustomization", "flux"}, {"fleet.cattle.io", "GitRepo", "fleet"}} {
		if c.State(gk[0], gk[1]) == objcache.StateSynced {
			out.GitOpsControllers = append(out.GitOpsControllers, gk[2])
		}
	}
	b, err := json.Marshal(out)
	if err != nil {
		return nil
	}
	return b
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- get_policy_findings

type policyFindingsResult struct {
	insightMeta
	Findings []policyreports.Finding `json:"findings"`
}

func (e *ToolExecutor) getPolicyFindings(_ context.Context, raw json.RawMessage) (json.RawMessage, bool, error) {
	c, err := e.cache()
	if err != nil {
		return nil, false, err
	}
	var a struct {
		Group, Kind, Namespace, Name string
	}
	if err := decodeInsightArgs(raw, &a); err != nil {
		return nil, false, err
	}
	if a.Kind == "" || a.Name == "" {
		return nil, false, errors.New("kind and name are required")
	}
	var reports []*unstructured.Unstructured
	for _, k := range [][2]string{{"wgpolicyk8s.io", "PolicyReport"}, {"wgpolicyk8s.io", "ClusterPolicyReport"}} {
		if c.State(k[0], k[1]) != objcache.StateSynced {
			continue
		}
		ns := a.Namespace
		if k[1] == "ClusterPolicyReport" {
			ns = ""
		}
		items, err := c.Dynamic(k[0], k[1], ns)
		if err == nil {
			reports = append(reports, items...)
		}
	}
	m := e.meta([2]string{"wgpolicyk8s.io", "PolicyReport"}, [2]string{"wgpolicyk8s.io", "ClusterPolicyReport"})
	findings := policyreports.BuildIndex(reports).FindingsFor(a.Group, a.Kind, a.Namespace, a.Name)
	for i := range findings {
		findings[i].Message = redact.Text(findings[i].Message)
	}
	if len(findings) > 100 {
		findings = findings[:100]
		m.Truncated = true
	}
	if findings == nil {
		findings = []policyreports.Finding{}
	}
	return marshalInsight(policyFindingsResult{insightMeta: m, Findings: findings})
}

// ---------------------------------------------------------------- explain_scheduling

type schedulingResult struct {
	insightStamp
	Pod string `json:"pod"`
	schedexplain.Explanation
	// Karpenter is each NodePool's verdict for this pod, when the cluster
	// runs Karpenter (CI-S9): whether a new node from that pool could take it.
	Karpenter []karpenter.PoolVerdict `json:"karpenter,omitempty"`
}

func (e *ToolExecutor) explainScheduling(ctx context.Context, raw json.RawMessage) (json.RawMessage, bool, error) {
	c, err := e.cache()
	if err != nil {
		return nil, false, err
	}
	var a struct {
		Namespace string `json:"namespace"`
		Pod       string `json:"pod"`
	}
	if err := decodeInsightArgs(raw, &a); err != nil {
		return nil, false, err
	}
	if err := requireName(a.Namespace, a.Pod, true); err != nil {
		return nil, false, err
	}
	pod, ok, err := c.Pod(a.Namespace, a.Pod)
	if err != nil {
		return nil, false, err
	}
	if !ok {
		return nil, false, notFoundError("Pod", a.Namespace, a.Pod)
	}
	if _, bound := schedexplain.ScheduledNode(pod); bound {
		// Already placed: no node or pod list, no FailedScheduling event —
		// a stale one from before the binding must not be shown as current.
		exp := schedexplain.Explain(pod, nil, nil, "", 0)
		return marshalInsight(schedulingResult{insightStamp: stampOf(e.meta(kindPod)), Pod: a.Namespace + "/" + a.Pod, Explanation: exp})
	}
	nodes, err := c.Nodes()
	if err != nil {
		return nil, false, err
	}
	all, err := c.Pods("")
	if err != nil {
		return nil, false, err
	}
	var scheduled, sameNS []*corev1.Pod
	for _, p := range all {
		if p.Spec.NodeName != "" {
			scheduled = append(scheduled, p)
		}
		if p.Namespace == a.Namespace {
			sameNS = append(sameNS, p)
		}
	}
	msg := e.latestSchedulerMessage(ctx, pod)
	exp := schedexplain.Explain(pod, nodes, scheduled, msg, schedexplain.SimilarPending(pod, sameNS))
	m := e.meta(kindPod, [2]string{"", "Node"})
	out := schedulingResult{insightStamp: stampOf(m), Pod: a.Namespace + "/" + a.Pod, Explanation: exp}
	if c.State("karpenter.sh", "NodePool") == objcache.StateSynced {
		if pools, err := c.Dynamic("karpenter.sh", "NodePool", ""); err == nil && len(pools) > 0 {
			out.Karpenter = karpenter.Evaluate(pod, schedexplain.PodRequests(pod), pools)
		}
	}
	return marshalInsight(out)
}

// latestSchedulerMessage reads the pod's most recent FailedScheduling event
// live — events are not cached. Empty when there is none or the read fails.
func (e *ToolExecutor) latestSchedulerMessage(ctx context.Context, pod *corev1.Pod) string {
	if e.typed == nil {
		return ""
	}
	sel := fields.AndSelectors(
		fields.OneTermEqualSelector("involvedObject.name", pod.Name),
		fields.OneTermEqualSelector("reason", "FailedScheduling"),
	).String()
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	list, err := e.typed.CoreV1().Events(pod.Namespace).List(cctx, metav1.ListOptions{FieldSelector: sel})
	if err != nil || len(list.Items) == 0 {
		return ""
	}
	sort.Slice(list.Items, func(i, j int) bool {
		return eventTime(list.Items[i]).After(eventTime(list.Items[j]))
	})
	return list.Items[0].Message
}

func eventTime(ev corev1.Event) time.Time {
	if !ev.LastTimestamp.IsZero() {
		return ev.LastTimestamp.Time
	}
	if !ev.EventTime.IsZero() {
		return ev.EventTime.Time
	}
	return ev.CreationTimestamp.Time
}

// ---------------------------------------------------------------- get_gitops_insight

var gitOpsKinds = map[string]string{
	"Application":    "argoproj.io",
	"ApplicationSet": "argoproj.io",
	"Kustomization":  "kustomize.toolkit.fluxcd.io",
	"HelmRelease":    "helm.toolkit.fluxcd.io",
	"GitRepository":  "source.toolkit.fluxcd.io",
	"OCIRepository":  "source.toolkit.fluxcd.io",
	"HelmRepository": "source.toolkit.fluxcd.io",
}

type gitOpsInsightResult struct {
	insightMeta
	Summary       *gitopsinsight.Summary       `json:"summary,omitempty"`
	ParsedFailure *gitopsinsight.ParsedFailure `json:"parsedFailure,omitempty"`
	Drift         *gitopsinsight.Drift         `json:"drift,omitempty"`
}

// getGitOpsInsight answers for either a GitOps object (an Argo Application,
// a Flux Kustomization/HelmRelease/source — summary, parsed failure,
// conditions with suggested actions, managed resources) or a managed object
// (its drift from the last configuration a controller applied, when known).
func (e *ToolExecutor) getGitOpsInsight(ctx context.Context, raw json.RawMessage) (json.RawMessage, bool, error) {
	c, err := e.cache()
	if err != nil {
		return nil, false, err
	}
	var a struct {
		Group     string `json:"group"`
		Kind      string `json:"kind"`
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
	}
	if err := decodeInsightArgs(raw, &a); err != nil {
		return nil, false, err
	}
	if a.Kind == "" || a.Name == "" {
		return nil, false, errors.New("kind and name are required")
	}
	out := gitOpsInsightResult{insightMeta: e.meta()}
	if g, ok := gitOpsKinds[a.Kind]; ok && (a.Group == "" || a.Group == g) {
		obj, found, err := c.DynamicGet(g, a.Kind, a.Namespace, a.Name)
		if err != nil {
			out.Coverage = c.Coverage([2]string{g, a.Kind})
			return marshalInsight(out)
		}
		if !found {
			return nil, false, fmt.Errorf("%s %s/%s not found", a.Kind, a.Namespace, a.Name)
		}
		s := gitopsinsight.Summarize(obj)
		out.Summary = &s
		out.ParsedFailure = gitopsinsight.FailureFor(obj)
		out.Truncated = s.Truncated
		return marshalInsight(out)
	}
	objAny, found, err := c.Get(a.Group, a.Kind, a.Namespace, a.Name)
	if err != nil {
		out.Coverage = c.Coverage([2]string{a.Group, a.Kind})
		out.Drift = &gitopsinsight.Drift{Entries: []gitopsinsight.DriftEntry{}, UnavailableReason: "this kind is not in the agent's object cache"}
		return marshalInsight(out)
	}
	if !found {
		return nil, false, fmt.Errorf("%s %s/%s not found", a.Kind, a.Namespace, a.Name)
	}
	mo, ok := objAny.(metav1.Object)
	if !ok {
		return nil, false, errors.New("object has no metadata")
	}
	if d, ok := lastAppliedDrift.get(mo.GetUID()); ok {
		out.Drift = &d
		out.Drift.Controller = argoSyncFor(c, mo, a.Group, a.Kind)
	} else if gitOpsManaged(mo) {
		out.Drift = &gitopsinsight.Drift{Entries: []gitopsinsight.DriftEntry{},
			UnavailableReason: "no drift recorded: either the object matches its last client-side apply, or it was applied server-side/by Helm (no last-applied configuration to compare against)",
			Controller:        argoSyncFor(c, mo, a.Group, a.Kind)}
		if cs := out.Drift.Controller; cs != nil {
			out.Drift.UnavailableReason = "field-level drift needs a last-applied configuration, which this object does not carry; Argo CD's own comparison says " + cs.Status
			// CI-P9 (b): with the chart's Argo CD API access, ask Argo CD
			// for its own desired and live state and diff those.
			if api := argoAPIFromEnv(); api != nil {
				appNS, app, _ := strings.Cut(cs.Application, "/")
				if app == "" {
					app, appNS = appNS, ""
				}
				if d, err := api.managedResourceDrift(ctx, appNS, app, a.Group, a.Kind, a.Namespace, a.Name); err == nil {
					d.Controller = cs
					out.Drift = d
				} else {
					out.Drift.UnavailableReason += " (Argo CD's API could not supply the fields: " + err.Error() + ")"
				}
			}
		}
	} else {
		out.Drift = &gitopsinsight.Drift{Entries: []gitopsinsight.DriftEntry{}, UnavailableReason: "this object is not managed by a GitOps controller ARGUS recognises"}
	}
	return marshalInsight(out)
}

// ---------------------------------------------------------------- Prometheus-backed tools

// promQuerier adapts the agent's metrics proxy (query_metrics' path to the
// configured Prometheus) to the instant-query interface traffic and cost use.
type promQuerier struct{ e *ToolExecutor }

type promSample = struct {
	Labels map[string]string
	Value  float64
}

// promUnreachableError marks a query that never got a Prometheus answer:
// the service-proxy request failed in transport, the API server or proxy
// refused it, or what came back was not a Prometheus response. cost and
// traffic tell it apart from a query Prometheus rejected through its
// Unreachable method.
type promUnreachableError struct{ err error }

func (e *promUnreachableError) Error() string {
	return "Prometheus could not be reached: " + e.err.Error()
}
func (e *promUnreachableError) Unwrap() error     { return e.err }
func (e *promUnreachableError) Unreachable() bool { return true }

// classifyPromError separates Prometheus rejecting a query (HTTP 400/422
// with its own JSON error, which DoRaw surfaces as a StatusError) from
// everything else, which means the query never reached a Prometheus that
// could answer it.
func classifyPromError(err error) error {
	var se apierrors.APIStatus
	if errors.As(err, &se) {
		if c := se.Status().Code; c == 400 || c == 422 {
			return err
		}
	}
	return &promUnreachableError{err: err}
}

func (q promQuerier) query(ctx context.Context, promql string) ([]promSample, error) {
	if q.e.metricsProxy == nil {
		return nil, errors.New("no Prometheus is connected to this agent")
	}
	raw, err := q.e.metricsProxy.Get(ctx, "api/v1/query", map[string]string{"query": promql})
	if err != nil {
		return nil, classifyPromError(err)
	}
	var resp struct {
		Status string `json:"status"`
		Error  string `json:"error"`
		Data   struct {
			ResultType string `json:"resultType"`
			Result     []struct {
				Metric map[string]string `json:"metric"`
				Value  []any             `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		// Not JSON: the proxy reached something that is not Prometheus.
		return nil, &promUnreachableError{err: fmt.Errorf("decode Prometheus response: %w", err)}
	}
	if resp.Status != "success" {
		return nil, fmt.Errorf("prometheus: %s", resp.Error)
	}
	out := make([]promSample, 0, len(resp.Data.Result))
	for _, r := range resp.Data.Result {
		if len(r.Value) != 2 {
			continue
		}
		s, _ := r.Value[1].(string)
		v, err := strconv.ParseFloat(s, 64)
		if err != nil {
			continue
		}
		out = append(out, promSample{Labels: r.Metric, Value: v})
	}
	return out, nil
}

type trafficQuerier struct{ promQuerier }

func (t trafficQuerier) Query(ctx context.Context, promql string) ([]traffic.Sample, error) {
	ss, err := t.query(ctx, promql)
	out := make([]traffic.Sample, len(ss))
	for i, s := range ss {
		out[i] = traffic.Sample{Labels: s.Labels, Value: s.Value}
	}
	return out, err
}

type costQuerier struct{ promQuerier }

func (c costQuerier) Query(ctx context.Context, promql string) ([]cost.Sample, error) {
	ss, err := c.query(ctx, promql)
	out := make([]cost.Sample, len(ss))
	for i, s := range ss {
		out[i] = cost.Sample{Labels: s.Labels, Value: s.Value}
	}
	return out, err
}

type trafficResult struct {
	insightStamp
	*traffic.Result
	// DetectedPrometheus is set when no Prometheus is connected and one was
	// found among the cluster's Services (see detectPrometheus).
	DetectedPrometheus *detectedPrometheus `json:"detectedPrometheus,omitempty"`
}

// detectedPrometheus is a Prometheus-compatible query Service found in the
// object cache that the agent could be pointed at. Detection only: nothing is
// configured or contacted.
type detectedPrometheus = tunnel.MetricsCandidate

// prometheusNameExcludes are Prometheus-ecosystem components whose names
// contain a matching word but which are not a query endpoint.
var prometheusNameExcludes = []string{"exporter", "operator", "adapter", "alertmanager", "pushgateway", "blackbox", "kube-state", "webhook", "vmagent", "vminsert", "vmalert", "sidecar", "store", "compact", "receive", "rule"}

func (e *ToolExecutor) detectPrometheus() *detectedPrometheus {
	if e == nil || e.objects == nil {
		return nil
	}
	svcs, err := e.objects.Services("")
	if err != nil {
		return nil
	}
	return detectMetricsService(svcs)
}

// detectMetricsService looks through Services for an endpoint that answers
// the Prometheus HTTP API at its root, which is what query_metrics' proxy
// path needs: a Prometheus server, a VictoriaMetrics single node (8428), or a
// Thanos query/querier (http on 9090 or 10902). vmselect is left out: it
// serves the API under /select/<tenant>/prometheus, not at the root.
//
// A Prometheus server labelled app.kubernetes.io/name=prometheus or
// app=prometheus, or named like one, with a port 9090 or a port named
// web/http-web. A ClusterIP Service named "prometheus" or "*-prometheus"
// (rancher-monitoring-prometheus, kube-prometheus-stack-prometheus) is
// preferred, then the operator's headless prometheus-operated, then any other
// Prometheus, then Thanos, then VictoriaMetrics. Nil means none was found.
func detectMetricsService(svcs []*corev1.Service) *detectedPrometheus {
	type cand struct {
		rank int
		d    detectedPrometheus
	}
	var best *cand
	for _, svc := range svcs {
		name := strings.ToLower(svc.Name)
		lbl := svc.Labels
		appName := strings.ToLower(lbl["app.kubernetes.io/name"] + " " + lbl["app"])
		flavour := ""
		switch {
		case strings.Contains(appName, "prometheus") || strings.Contains(name, "prometheus"):
			flavour = "prometheus"
		case strings.Contains(name, "thanos-quer") || strings.Contains(appName, "thanos-quer") || lbl["app.kubernetes.io/component"] == "query" && strings.Contains(appName, "thanos"):
			flavour = "thanos"
		case strings.Contains(name, "vmsingle") || strings.Contains(appName, "vmsingle") || strings.Contains(name, "victoria-metrics-single"):
			flavour = "victoriametrics"
		default:
			continue
		}
		excluded := false
		for _, x := range prometheusNameExcludes {
			if strings.Contains(name, x) {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}
		var port int32
		for _, p := range svc.Spec.Ports {
			if (flavour == "victoriametrics" && p.Port == 8428) || (flavour != "victoriametrics" && (p.Port == 9090 || (flavour == "thanos" && p.Port == 10902))) {
				port = p.Port
				break
			}
			if port == 0 && (p.Name == "web" || p.Name == "http-web" || (flavour == "thanos" && p.Name == "http")) {
				port = p.Port
			}
		}
		if port == 0 {
			continue
		}
		headless := svc.Spec.ClusterIP == corev1.ClusterIPNone
		rank := 3
		switch {
		case flavour == "thanos":
			rank = 4
		case flavour == "victoriametrics":
			rank = 5
		case (name == "prometheus" || strings.HasSuffix(name, "-prometheus")) && !headless:
			rank = 0
		case name == "prometheus-operated":
			rank = 1
		case lbl["app.kubernetes.io/name"] == "prometheus" || lbl["app"] == "prometheus":
			rank = 2
		}
		c := cand{rank: rank, d: detectedPrometheus{Namespace: svc.Namespace, Name: svc.Name, Port: port, Flavour: flavour}}
		if best == nil || c.rank < best.rank || (c.rank == best.rank && c.d.Namespace+"/"+c.d.Name < best.d.Namespace+"/"+best.d.Name) {
			best = &c
		}
	}
	if best == nil {
		return nil
	}
	return &best.d
}

func (e *ToolExecutor) getTraffic(ctx context.Context, raw json.RawMessage) (json.RawMessage, bool, error) {
	var a struct {
		Namespace     string `json:"namespace"`
		WindowMinutes int    `json:"windowMinutes"`
		// CompareMinutes reads the same window that long ago as well, for
		// "what changed"; 0 compares with nothing. At most a week.
		CompareMinutes int `json:"compareMinutes"`
	}
	if err := decodeInsightArgs(raw, &a); err != nil {
		return nil, false, err
	}
	if a.CompareMinutes < 0 || a.CompareMinutes > 7*24*60 {
		return nil, false, fmt.Errorf("compareMinutes must be between 0 and %d", 7*24*60)
	}
	m := insightMeta{ObservedAt: time.Now().UTC()}
	if e.metricsProxy == nil {
		return marshalInsight(trafficResult{insightStamp: stampOf(m),
			Result:             traffic.Unavailable(traffic.ReasonNotConfigured, traffic.ReasonTextNotConfigured),
			DetectedPrometheus: e.detectPrometheus()})
	}
	q := trafficQuerier{promQuerier{e}}
	det := traffic.Probe(ctx, q)
	if det.Source == "" {
		return marshalInsight(trafficResult{insightStamp: stampOf(m), Result: traffic.Unavailable(det.ReasonCode, det.Reason)})
	}
	opts := []traffic.Option{traffic.WithEndpointResolver(e.serviceBackingWorkload())}
	if a.CompareMinutes > 0 {
		opts = append(opts, traffic.WithComparison(time.Duration(a.CompareMinutes)*time.Minute))
	}
	res, err := traffic.Flows(ctx, q, det.Source, a.Namespace, time.Duration(a.WindowMinutes)*time.Minute, opts...)
	if err != nil {
		return nil, false, err
	}
	return marshalInsight(trafficResult{insightStamp: stampOf(m), Result: res})
}

// serviceBackingWorkload folds a Service endpoint into the one workload whose
// pods back it, read from the object cache: the Service's EndpointSlices name
// its pods, and each pod's controller (a ReplicaSet's Deployment, or the
// controller itself) is its workload. A Service backed by pods of more than
// one workload, or by none the cache knows, is left as the Service. Nil
// without a cache, so traffic is drawn as the source reported it.
func (e *ToolExecutor) serviceBackingWorkload() traffic.EndpointResolver {
	c := e.objects
	if c == nil {
		return nil
	}
	memo := map[string]*traffic.Endpoint{}
	return func(ep traffic.Endpoint) (traffic.Endpoint, bool) {
		if ep.Kind != traffic.KindService || ep.Namespace == "" {
			return ep, false
		}
		k := ep.Namespace + "/" + ep.Name
		if r, ok := memo[k]; ok {
			if r == nil {
				return ep, false
			}
			return *r, true
		}
		memo[k] = nil
		slices, err := c.EndpointSlices(ep.Namespace)
		if err != nil {
			return ep, false
		}
		owner := ""
		for _, sl := range slices {
			if sl.Labels["kubernetes.io/service-name"] != ep.Name {
				continue
			}
			for _, end := range sl.Endpoints {
				if end.TargetRef == nil || end.TargetRef.Kind != "Pod" {
					continue
				}
				o := podWorkloadName(c, ep.Namespace, end.TargetRef.Name)
				if o == "" || (owner != "" && o != owner) {
					return ep, false
				}
				owner = o
			}
		}
		if owner == "" {
			return ep, false
		}
		r := traffic.Endpoint{Namespace: ep.Namespace, Name: owner, Kind: traffic.KindWorkload}
		memo[k] = &r
		return r, true
	}
}

// podWorkloadName is the name a pod's workload goes by: a ReplicaSet's
// Deployment, otherwise the pod's controller. Empty for a pod with no
// controller or one the cache does not hold.
func podWorkloadName(c *objcache.Cache, ns, name string) string {
	pod, ok, err := c.Pod(ns, name)
	if err != nil || !ok {
		return ""
	}
	ref := metav1.GetControllerOf(pod)
	if ref == nil {
		return ""
	}
	if ref.Kind == "ReplicaSet" {
		if obj, ok, err := c.Get("apps", "ReplicaSet", ns, ref.Name); err == nil && ok {
			if rs, ok := obj.(metav1.Object); ok {
				if up := metav1.GetControllerOf(rs); up != nil {
					return up.Name
				}
			}
		}
	}
	return ref.Name
}

type costResult struct {
	insightMeta
	Summary   *cost.CostSummary   `json:"summary"`
	Workloads *cost.WorkloadCosts `json:"workloads,omitempty"`
	// DetectedPrometheus: see trafficResult.
	DetectedPrometheus *detectedPrometheus `json:"detectedPrometheus,omitempty"`
}

func (e *ToolExecutor) getCostSummary(ctx context.Context, raw json.RawMessage) (json.RawMessage, bool, error) {
	var a struct {
		WindowHours int    `json:"windowHours"`
		Namespace   string `json:"namespace"`
	}
	if err := decodeInsightArgs(raw, &a); err != nil {
		return nil, false, err
	}
	window := time.Duration(a.WindowHours) * time.Hour
	m := insightMeta{ObservedAt: time.Now().UTC()}
	// PROJECT.md PG22: Kubecost, when the chart names it, is the source.
	if kc := kubecostGetterFromEnv(); kc != nil {
		s := cost.FromKubecost(ctx, kc, window)
		if s.Available {
			if tr, err := cost.KubecostTrend(ctx, kc, 7*24*time.Hour, 6*time.Hour); err == nil {
				s.Trend = tr
			}
		}
		return marshalInsight(costResult{insightMeta: m, Summary: s})
	}
	if e.metricsProxy == nil {
		return marshalInsight(costResult{insightMeta: m,
			Summary:            &cost.CostSummary{Available: false, Reason: cost.ReasonNotConfigured, Detail: cost.DetailNotConfigured},
			DetectedPrometheus: e.detectPrometheus()})
	}
	q := costQuerier{promQuerier{e}}
	out := costResult{insightMeta: m, Summary: cost.ComputeSummary(ctx, q, window)}
	if out.Summary != nil && out.Summary.Available {
		out.Summary.Trend = e.openCostTrend(ctx)
	}
	if a.Namespace != "" {
		out.Workloads = cost.ComputeWorkloads(ctx, q, a.Namespace, window, e.podOwnerLookup(a.Namespace))
	}
	out.Truncated = out.Summary != nil && out.Summary.Truncated
	return marshalInsight(out)
}

// podOwnerLookup resolves pods to their top-level workload from the cache
// (ReplicaSet → Deployment), for per-workload cost.
func (e *ToolExecutor) podOwnerLookup(ns string) cost.PodOwnerLookup {
	c := e.objects
	if c == nil {
		return func(string) (cost.WorkloadOwner, bool) { return cost.WorkloadOwner{}, false }
	}
	pods, _ := c.Pods(ns)
	rss, _ := c.ReplicaSets(ns)
	rsOwner := map[string]metav1.OwnerReference{}
	for _, rs := range rss {
		if ref := metav1.GetControllerOf(rs); ref != nil {
			rsOwner[rs.Name] = *ref
		}
	}
	byName := map[string]cost.WorkloadOwner{}
	for _, p := range pods {
		ref := metav1.GetControllerOf(p)
		if ref == nil {
			continue
		}
		if ref.Kind == "ReplicaSet" {
			if dep, ok := rsOwner[ref.Name]; ok {
				byName[p.Name] = cost.WorkloadOwner{Name: dep.Name, Kind: dep.Kind}
				continue
			}
		}
		byName[p.Name] = cost.WorkloadOwner{Name: ref.Name, Kind: ref.Kind}
	}
	return func(pod string) (cost.WorkloadOwner, bool) {
		o, ok := byName[pod]
		return o, ok
	}
}

// ---------------------------------------------------------------- search_objects

// cacheSearchProvider adapts the object cache to objsearch.Provider: every
// synced kind except Secrets (never cached) and Events (not cached).
type cacheSearchProvider struct{ c *objcache.Cache }

func (p cacheSearchProvider) Kinds() []objsearch.KindRef {
	var out []objsearch.KindRef
	for _, k := range p.c.Status() {
		if k.State != objcache.StateSynced {
			continue
		}
		namespaced := true
		switch k.Kind {
		case "Node", "Namespace", "PersistentVolume", "ClusterRole", "ClusterRoleBinding", "StorageClass", "CSIDriver",
			"PriorityClass", "IngressClass", "ValidatingWebhookConfiguration", "MutatingWebhookConfiguration",
			"CustomResourceDefinition", "APIService", "ClusterPolicyReport", "NodePool", "NodeClaim":
			namespaced = false
		}
		out = append(out, objsearch.KindRef{Kind: k.Kind, APIGroup: k.Group, Namespaced: namespaced})
	}
	return out
}

func (p cacheSearchProvider) List(_ context.Context, k objsearch.KindRef, ns string) ([]objsearch.Object, error) {
	items, err := p.c.List(k.APIGroup, k.Kind, ns)
	if err != nil {
		return nil, err
	}
	out := make([]objsearch.Object, 0, len(items))
	for _, it := range items {
		if u, ok := it.(*unstructured.Unstructured); ok {
			out = append(out, objsearch.ObjectFromUnstructured(u, k.Kind, k.APIGroup))
			continue
		}
		if ro, ok := it.(runtime.Object); ok {
			if o, ok := objsearch.ObjectFromTyped(ro, k.Kind, k.APIGroup); ok {
				out = append(out, o)
			}
		}
	}
	return out, nil
}

type searchResult struct {
	insightStamp
	objsearch.Result
}

func (e *ToolExecutor) searchObjects(ctx context.Context, raw json.RawMessage) (json.RawMessage, bool, error) {
	c, err := e.cache()
	if err != nil {
		return nil, false, err
	}
	var a struct {
		Query     string `json:"query"`
		Limit     int    `json:"limit"`
		Namespace string `json:"namespace"`
	}
	if err := decodeInsightArgs(raw, &a); err != nil {
		return nil, false, err
	}
	if strings.TrimSpace(a.Query) == "" {
		return nil, false, errors.New("query is required")
	}
	opts := objsearch.Options{Limit: a.Limit}
	if a.Namespace != "" {
		opts.Namespaces = []string{a.Namespace}
	}
	res := objsearch.Search(ctx, cacheSearchProvider{c}, objsearch.Parse(a.Query), opts)
	return marshalInsight(searchResult{insightStamp: stampOf(e.meta()), Result: res})
}

// capacitySummary is requested resources against allocatable capacity, so an
// over-committed cluster is visible next to its actual usage (owner review
// 2026-10-10, PROJECT.md UX1). Requests count pods that are scheduled and not
// finished; the usage half already comes from metrics.k8s.io in facts.
type capacitySummary struct {
	CPURequestedMillicores   int64 `json:"cpuRequestedMillicores"`
	CPUAllocatableMillicores int64 `json:"cpuAllocatableMillicores"`
	MemoryRequestedBytes     int64 `json:"memoryRequestedBytes"`
	MemoryAllocatableBytes   int64 `json:"memoryAllocatableBytes"`
	PodsCounted              int   `json:"podsCounted"`
}

func computeCapacity(pods []*corev1.Pod, nodes []*corev1.Node) *capacitySummary {
	c := &capacitySummary{}
	for _, n := range nodes {
		c.CPUAllocatableMillicores += n.Status.Allocatable.Cpu().MilliValue()
		c.MemoryAllocatableBytes += n.Status.Allocatable.Memory().Value()
	}
	for _, p := range pods {
		if p.Spec.NodeName == "" || p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		c.PodsCounted++
		var cpu, mem int64
		for _, ct := range p.Spec.Containers {
			cpu += ct.Resources.Requests.Cpu().MilliValue()
			mem += ct.Resources.Requests.Memory().Value()
		}
		// An init container's request applies when it is larger than the
		// sum of the app containers (the scheduler's effective request).
		for _, ct := range p.Spec.InitContainers {
			if v := ct.Resources.Requests.Cpu().MilliValue(); v > cpu {
				cpu = v
			}
			if v := ct.Resources.Requests.Memory().Value(); v > mem {
				mem = v
			}
		}
		c.CPURequestedMillicores += cpu
		c.MemoryRequestedBytes += mem
	}
	return c
}

// openCostTrend is the cluster's allocated hourly spend over the last 7 days
// in 6-hour steps, from OpenCost's series (PROJECT.md PG22). Nil when the
// range query fails or Prometheus keeps less history: absent, never zero.
func (e *ToolExecutor) openCostTrend(ctx context.Context) []cost.TrendPoint {
	end := time.Now().UTC().Truncate(time.Hour)
	raw, err := e.metricsProxy.Get(ctx, "api/v1/query_range", map[string]string{
		"query": cost.OpenCostTrendQuery, "start": strconv.FormatInt(end.Add(-7*24*time.Hour).Unix(), 10),
		"end": strconv.FormatInt(end.Unix(), 10), "step": "21600",
	})
	if err != nil {
		return nil
	}
	var resp struct {
		Status string `json:"status"`
		Data   struct {
			Result []struct {
				Values [][]any `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if json.Unmarshal(raw, &resp) != nil || resp.Status != "success" || len(resp.Data.Result) == 0 {
		return nil
	}
	var out []cost.TrendPoint
	for _, v := range resp.Data.Result[0].Values {
		if len(v) != 2 {
			continue
		}
		ts, _ := v[0].(float64)
		s, _ := v[1].(string)
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			continue
		}
		out = append(out, cost.TrendPoint{Time: time.Unix(int64(ts), 0).UTC(), HourlyCost: f})
	}
	return out
}

// ---------------------------------------------------------------- get_karpenter_capacity

type karpenterCapacityResult struct {
	insightMeta
	Pools []karpenter.Ledger `json:"pools"`
	// Demand is the pending pods grouped by scheduling signature, each
	// group tested against every pool.
	Demand []karpenterDemand `json:"demand"`
}

type karpenterDemand struct {
	Example  string                  `json:"example"`
	Pods     int                     `json:"pods"`
	Verdicts []karpenter.PoolVerdict `json:"verdicts"`
}

// getKarpenterCapacity is the Karpenter capacity view (PROJECT.md PG7): each
// NodePool's limit against what it has provisioned, its NodeClaims by phase,
// and the pending pods it could or could not take.
func (e *ToolExecutor) getKarpenterCapacity(_ context.Context, _ json.RawMessage) (json.RawMessage, bool, error) {
	c, err := e.cache()
	if err != nil {
		return nil, false, err
	}
	m := e.meta([2]string{"karpenter.sh", "NodePool"}, [2]string{"karpenter.sh", "NodeClaim"}, kindPod)
	if c.State("karpenter.sh", "NodePool") != objcache.StateSynced {
		return marshalInsight(karpenterCapacityResult{insightMeta: m, Pools: []karpenter.Ledger{}, Demand: []karpenterDemand{}})
	}
	pools, err := c.Dynamic("karpenter.sh", "NodePool", "")
	if err != nil {
		return nil, false, err
	}
	claims, _ := c.Dynamic("karpenter.sh", "NodeClaim", "")
	out := karpenterCapacityResult{insightMeta: m, Pools: karpenter.Ledgers(pools, claims), Demand: []karpenterDemand{}}
	pods, _ := c.Pods("")
	groups := map[string]*karpenterDemand{}
	var order []string
	for _, p := range pods {
		if p.Spec.NodeName != "" || p.Status.Phase != corev1.PodPending {
			continue
		}
		sig := schedexplain.Signature(p)
		g := groups[sig]
		if g == nil {
			g = &karpenterDemand{Example: p.Namespace + "/" + p.Name, Verdicts: karpenter.Evaluate(p, schedexplain.PodRequests(p), pools)}
			groups[sig] = g
			order = append(order, sig)
		}
		g.Pods++
	}
	for _, sig := range order {
		out.Demand = append(out.Demand, *groups[sig])
	}
	return marshalInsight(out)
}
