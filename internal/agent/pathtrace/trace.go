// Package pathtrace answers "if traffic is sent at this Service, Ingress,
// HTTPRoute, GRPCRoute or Gateway, does it reach a ready pod, and if not,
// which hop breaks first?" from declared cluster state alone.
//
// The output is a hop-ordered diagnosis, not a pile of alerts: findings are
// attached to the hop where the failure is observable, the first broken
// Downstream hop is named BrokenAt, and parallel Upstreams are judged
// independently so one broken Ingress does not condemn a Service that other
// Ingresses still deliver to.
//
// Everything here is a pure function over the agent's object cache (the
// Provider interface): no API calls, no traffic is sent, nothing is created.
// A verdict is therefore a static prediction - the headline says so - and
// "couldn't read" is always reported as unknown, never as healthy or broken.
package pathtrace

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Verdicts and severities on the wire.
const (
	VerdictHealthy  = "healthy"
	VerdictDegraded = "degraded"
	VerdictBroken   = "broken"
	VerdictUnknown  = "unknown"

	SeverityCritical = "critical"
	SeverityWarning  = "warning"
	SeverityInfo     = "info"

	// UnknownClassByDesign covers shapes that inherently can't be verified
	// (selectorless Services); UnknownClassInvestigate covers state the
	// trace tried and failed to read.
	UnknownClassByDesign    = "by-design"
	UnknownClassInvestigate = "investigate"
)

// Caps that bound the result size under the tunnel frame limit.
const (
	// maxBackendsTraced caps the Service+Pods fan-out for Ingress and route
	// subjects.
	maxBackendsTraced = 5
	// gatewayRouteCap caps the attached routes listed for a Gateway subject.
	gatewayRouteCap = 20
	// maxUpstreams caps the Ingresses/routes listed as entries into a Service.
	maxUpstreams = 20
	// maxPodsInConfig caps the per-pod roster on a Pods hop.
	maxPodsInConfig = 10
)

const gatewayGroup = "gateway.networking.k8s.io"

// StateAbsent is the Provider.State value meaning the cluster does not serve
// the kind at all, so an empty answer for it is authoritative.
const StateAbsent = "absent"

// Provider is the read surface the trace needs from the agent's object cache.
// Every list takes a namespace ("" = all namespaces). A list returns an error
// - never an empty slice - when the kind is not readable (not synced, RBAC
// forbidden, not served); the trace turns that into an unknown hop rather
// than "nothing there".
type Provider interface {
	Services(ns string) ([]*corev1.Service, error)
	Pods(ns string) ([]*corev1.Pod, error)
	EndpointSlices(ns string) ([]*discoveryv1.EndpointSlice, error)
	ReplicaSets(ns string) ([]*appsv1.ReplicaSet, error)
	Ingresses(ns string) ([]*networkingv1.Ingress, error)
	IngressClasses() ([]*networkingv1.IngressClass, error)
	NetworkPolicies(ns string) ([]*networkingv1.NetworkPolicy, error)
	// Dynamic lists Gateway API objects by group and kind.
	Dynamic(group, kind, ns string) ([]*unstructured.Unstructured, error)
	// State reports a kind's availability; StateAbsent means the cluster
	// does not serve it.
	State(group, kind string) string
}

// PolicyEvaluator predicts whether core NetworkPolicy admits traffic to
// dstPods on port/proto. The trace has no specific caller, so it always asks
// with srcExternal=false, meaning "an unspecified in-cluster caller": the
// evaluator must answer "allowed" only when every caller is admitted,
// "denied" only when no caller is admitted, and anything else (e.g.
// "unknown") when the answer depends on who calls. port is the pod-side
// (resolved target) port. policies is every NetworkPolicy in the pods'
// namespace; the returned names are the policies that decided the answer.
type PolicyEvaluator func(srcExternal bool, dstPods []*corev1.Pod, port int32, proto corev1.Protocol, policies []*networkingv1.NetworkPolicy) (verdict string, deciding []string)

// Options shape what Build does beyond the core walk.
type Options struct {
	// PolicyEvaluator, when set, turns NetworkPolicies selecting a
	// backend's ready pods into netpol:would-deny / netpol:advisory findings.
	PolicyEvaluator PolicyEvaluator
}

// ResourceRef points at one Kubernetes object in the trace.
type ResourceRef struct {
	Group     string `json:"group,omitempty"`
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
}

// Finding is one observation attached to a hop. Code is stable across runs.
// Hop names the hop it hangs on ("downstream[1]", "upstreams[0]"). Command is
// a read-only kubectl reproducer the operator can paste to see the raw state.
// Resource names the specific object the finding is about when it differs
// from the hop (a named Pod behind the Pods hop).
type Finding struct {
	Code     string       `json:"code"`
	Hop      string       `json:"hop"`
	Severity string       `json:"severity"`
	Message  string       `json:"message"`
	Cause    string       `json:"cause,omitempty"`
	Action   string       `json:"action,omitempty"`
	Command  string       `json:"command,omitempty"`
	Resource *ResourceRef `json:"resource,omitempty"`
}

// Hop is one resource along the path. Edge labels the relation from the
// previous resource ("HTTPRoute->Service"). Meta carries small hop facts
// (ready/selected counts, endpointSource, selectorless, drained). Findings
// are carried flattened on the Trace, not per hop.
type Hop struct {
	Resource ResourceRef    `json:"resource"`
	Edge     string         `json:"edge"`
	Meta     map[string]any `json:"meta,omitempty"`
	Config   *HopConfig     `json:"config,omitempty"`
	Findings []Finding      `json:"-"`
}

// HopConfig is the declared wiring a hop contributes to the path. Only the
// fields relevant to the hop's kind are filled.
type HopConfig struct {
	// Service hops
	Ports       []PortMap         `json:"ports,omitempty"`
	ServiceType string            `json:"serviceType,omitempty"`
	ClusterIP   string            `json:"clusterIP,omitempty"`
	Selector    map[string]string `json:"selector,omitempty"`

	// Pods hops
	ContainerPorts []ContainerPortRef `json:"containerPorts,omitempty"`
	HealthChecks   []HealthCheckRef   `json:"healthChecks,omitempty"`
	Pods           []PodStatus        `json:"pods,omitempty"`
	PodTotal       int                `json:"podTotal,omitempty"`
	// Workload is what runs the selected pods (Deployment, StatefulSet...),
	// nil unless every selected pod agrees on one owner.
	Workload *ResourceRef `json:"workload,omitempty"`

	// Ingress / route hops
	Hostnames []string    `json:"hostnames,omitempty"`
	Rules     []RouteRule `json:"rules,omitempty"`

	// Gateway hops (Addresses is also the Ingress's published address)
	Listeners []GatewayListener `json:"listeners,omitempty"`
	Addresses []string          `json:"addresses,omitempty"`

	// Ingress hops: who serves the Ingress. Only a controller problem is a
	// finding; the healthy case is this label.
	ServedBy      string `json:"servedBy,omitempty"`
	ServedByTitle string `json:"servedByTitle,omitempty"`
}

// PortMap is one Service port and the targetPort pods receive on.
type PortMap struct {
	Name        string `json:"name,omitempty"`
	Port        int32  `json:"port"`
	TargetPort  string `json:"targetPort,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	AppProtocol string `json:"appProtocol,omitempty"`
}

// PodStatus is one row of the Pods hop roster.
type PodStatus struct {
	Name   string `json:"name"`
	IP     string `json:"ip,omitempty"`
	Ready  bool   `json:"ready"`
	Reason string `json:"reason,omitempty"`
}

// ContainerPortRef is a container port declared by the selected pods that
// the Service targets.
type ContainerPortRef struct {
	Container string `json:"container"`
	Name      string `json:"name,omitempty"`
	Port      int32  `json:"port"`
	Protocol  string `json:"protocol,omitempty"`
}

// HealthCheckRef is a readiness/liveness probe declaration on a selected
// pod's container.
type HealthCheckRef struct {
	Container string `json:"container"`
	Type      string `json:"type"`
	Port      string `json:"port,omitempty"`
	Path      string `json:"path,omitempty"`
	Scheme    string `json:"scheme,omitempty"`
}

// RouteRule summarizes one Ingress or Gateway API route rule.
type RouteRule struct {
	Hosts    []string     `json:"hosts,omitempty"`
	Paths    []string     `json:"paths,omitempty"`
	Backends []BackendRef `json:"backends,omitempty"`
}

// BackendRef is a route's destination.
type BackendRef struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
	Port      string `json:"port,omitempty"`
}

// GatewayListener is one Gateway listener.
type GatewayListener struct {
	Name     string `json:"name,omitempty"`
	Port     int32  `json:"port"`
	Protocol string `json:"protocol,omitempty"`
	Hostname string `json:"hostname,omitempty"`
}

// Trace is the diagnosis. Downstream is the chain from the subject toward
// pods; BrokenAt indexes it (-1 when no downstream hop is the break).
// Upstreams are the parallel entries into the subject, judged independently.
type Trace struct {
	Subject    ResourceRef `json:"subject"`
	Upstreams  []Hop       `json:"upstreams"`
	Downstream []Hop       `json:"downstream"`
	Verdict    string      `json:"verdict"`
	BrokenAt   int         `json:"brokenAt"`
	// Headline is the one sentence a reader needs first: where the path
	// breaks and why, or what was checked when nothing broke.
	Headline string `json:"headline"`
	// Reason explains an unknown/degraded/broken verdict in one sentence.
	Reason       string    `json:"reason,omitempty"`
	UnknownClass string    `json:"unknownClass,omitempty"`
	Findings     []Finding `json:"findings"`
	// Truncated is set when a fan-out cap dropped backends, routes or
	// upstreams; the dropped count is stated in a finding.
	Truncated bool `json:"truncated,omitempty"`
}

// errNotFound marks a lookup that read the kind successfully and did not
// find the object - a confirmed absence, unlike a read error.
var errNotFound = errors.New("not found")

// Build traces the path from one entry object. A kind outside the entry set
// gives an unknown trace; callers check IsEntryKind first. ctx bounds the
// fan-out, and a trace it cuts short is returned as unknown.
func Build(ctx context.Context, p Provider, kind, namespace, name string, opts Options) *Trace {
	canonical := NormalizeKind(kind)
	t := &Trace{Subject: ResourceRef{Group: entryKindGroup(canonical), Kind: canonical, Namespace: namespace, Name: name}, BrokenAt: -1}
	defer finish(t)
	giveUp := func(reason string) *Trace {
		t.Verdict, t.BrokenAt, t.Reason, t.UnknownClass = VerdictUnknown, -1, reason, UnknownClassInvestigate
		return t
	}
	if p == nil {
		return giveUp("the object cache is not available yet")
	}
	w := walker{p: p, opts: opts}
	switch canonical {
	case "Service":
		w.serviceEntry(ctx, t)
	case "Ingress":
		w.ingressEntry(ctx, t)
	case "HTTPRoute", "GRPCRoute":
		w.routeEntry(ctx, t, canonical)
	case "Gateway":
		w.gatewayEntry(ctx, t)
	default:
		return giveUp("trace not supported for kind " + kind)
	}
	for _, hops := range [][]Hop{t.Downstream, t.Upstreams} {
		for i := range hops {
			sortFindingsBySeverity(hops[i].Findings)
		}
	}
	if ctx.Err() != nil {
		return giveUp("the trace ran out of time; this is a partial result")
	}
	// A verdict an entry handler already set (lookup failed, kind not
	// served) stands, with its reason: "healthy" computed over an empty
	// walk would be false.
	if t.Verdict == "" {
		t.Verdict, t.BrokenAt = computeVerdict(t)
	}
	if t.Verdict == VerdictUnknown {
		t.Reason = cmp.Or(t.Reason, unknownReason(t))
		t.UnknownClass = cmp.Or(t.UnknownClass, classifyUnknown(t))
	}
	return t
}

// finish enforces the wire invariants (non-nil slices), writes the headline
// and flattens per-hop findings onto the trace.
func finish(t *Trace) {
	if t.Downstream == nil {
		t.Downstream = []Hop{}
	}
	if t.Upstreams == nil {
		t.Upstreams = []Hop{}
	}
	t.Headline = headline(t)
	t.Findings = flattenFindings(t)
}

// flattenFindings lists every hop finding in path order (downstream, then
// upstreams), worst-first within a hop, labelled with the hop it hangs on.
// A finding without its own reproducer gets the hop's.
func flattenFindings(t *Trace) []Finding {
	out := []Finding{}
	add := func(section string, hops []Hop) {
		for i, h := range hops {
			for _, f := range h.Findings {
				f.Hop = fmt.Sprintf("%s[%d]", section, i)
				if f.Command == "" {
					f.Command = reproducerForRef(h.Resource)
				}
				out = append(out, f)
			}
		}
	}
	add("downstream", t.Downstream)
	add("upstreams", t.Upstreams)
	return out
}

// computeVerdict judges Downstream (which BrokenAt indexes), then Upstreams:
// every entry broken breaks the subject; some broken only degrades it, since
// the others still deliver.
func computeVerdict(t *Trace) (string, int) {
	verdict, at := VerdictHealthy, -1
	if branches := downstreamBranches(t.Downstream); len(branches) == 0 {
		verdict, at = chainVerdict(t.Downstream)
	} else {
		verdict, at = branchedVerdict(t, branches)
	}

	if len(t.Upstreams) > 0 {
		broken, warned := 0, 0
		for _, hop := range t.Upstreams {
			// A missing backend on an upstream is about some other route
			// than the one reaching this subject (which exists).
			switch worstSeverity(nonMissingRefFindings(hop.Findings)) {
			case SeverityCritical:
				broken++
			case SeverityWarning:
				warned++
			}
		}
		switch {
		case broken == len(t.Upstreams) && verdict != VerdictBroken:
			// Nothing reaches the subject, though its own chain is clean,
			// so the break is not anchored on it.
			verdict = VerdictBroken
			if t.Reason == "" {
				t.Reason = "every entry path into this resource is broken; the resource itself looks healthy"
			}
		case broken+warned > 0 && verdict == VerdictHealthy:
			verdict = VerdictDegraded
		}
	}

	// Endpoints nobody can verify (a selectorless Service, pods that could
	// not be read) make healthy or degraded a claim the trace cannot back.
	// Broken stays broken: a critical finding is a known problem anyway.
	if verdict != VerdictBroken && hasUnverifiableEndpoints(t) {
		verdict = VerdictUnknown
	}
	return verdict, at
}

// chainVerdict judges a single chain (a Service subject, or an entry with no
// backends): any critical hop breaks it, unless that hop still has ready
// endpoints (hopReachSeverity).
func chainVerdict(hops []Hop) (string, int) {
	verdict, at := VerdictHealthy, -1
	for i, hop := range hops {
		switch hopReachSeverity(hop) {
		case SeverityCritical:
			verdict = VerdictBroken
			if at < 0 {
				at = i
			}
		case SeverityWarning:
			if verdict == VerdictHealthy {
				verdict = VerdictDegraded
			}
		}
	}
	return verdict, at
}

// branchedVerdict judges an entry with backend branches. A critical on the
// entry hop itself means nothing gets in. A broken branch breaks only its
// route, so some broken is degraded and all broken is broken. A critical
// missing-backend finding on the entry hop counts as one broken route, not
// as the entry failing.
func branchedVerdict(t *Trace, branches []branchSpan) (string, int) {
	entry := t.Downstream[0].Findings
	missing := 0
	for _, f := range entry {
		if IsMissingRefCode(f.Code) && f.Severity == SeverityCritical {
			missing++
		}
	}
	verdict, at := VerdictHealthy, -1
	switch worstSeverity(slices.DeleteFunc(slices.Clone(entry), func(f Finding) bool {
		return IsMissingRefCode(f.Code) && f.Severity == SeverityCritical
	})) {
	case SeverityCritical:
		return VerdictBroken, 0
	case SeverityWarning:
		verdict = VerdictDegraded
	}

	// A drained (weight 0) backend carries no traffic on purpose: it is
	// neither a broken route nor one of the routes counted.
	live := slices.DeleteFunc(slices.Clone(branches), func(b branchSpan) bool {
		return b.start < len(t.Downstream) && isDrainedBackendHop(t.Downstream[b.start])
	})
	sev := make([]string, len(live))
	for i, b := range live {
		sev[i] = branchSeverity(t.Downstream, b)
	}
	first := func(s string) int {
		if i := slices.Index(sev, s); i >= 0 {
			return live[i].start
		}
		return -1
	}
	firstBroken, firstDegraded := first(SeverityCritical), first(SeverityWarning)
	broken := min(missing+len(slices.DeleteFunc(slices.Clone(sev), func(s string) bool { return s != SeverityCritical })), len(live))
	if firstBroken < 0 && missing > 0 {
		firstBroken = 0
	}
	switch {
	case broken > 0 && broken == len(live):
		if t.Reason == "" {
			t.Reason = fmt.Sprintf("all %d routes broken; nothing gets through this entry", len(live))
		}
		return VerdictBroken, firstBroken
	case broken > 0:
		if t.Reason == "" {
			t.Reason = fmt.Sprintf("%d of %d routes broken; the other routes still deliver", broken, len(live))
		}
		return VerdictDegraded, firstBroken
	case firstDegraded >= 0:
		return VerdictDegraded, firstDegraded
	}
	return verdict, at
}

// hopFlag reads a boolean hop fact.
func hopFlag(h Hop, key string) bool {
	v, _ := h.Meta[key].(bool)
	return v
}

// unreadable reports a hop whose backing state could not be read.
func unreadable(h Hop) bool {
	src, _ := h.Meta["endpointSource"].(string)
	return src == "unknown"
}

// classifyUnknown: something unreadable wants investigating, and that wins
// over a selectorless Service, which is unknowable by design.
func classifyUnknown(t *Trace) string {
	hops := allHops(t)
	if !slices.ContainsFunc(hops, unreadable) && slices.ContainsFunc(hops, func(h Hop) bool { return hopFlag(h, "selectorless") }) {
		return UnknownClassByDesign
	}
	return UnknownClassInvestigate
}

// isDrainedBackendHop reports a Gateway API backend weighted to 0 on purpose.
func isDrainedBackendHop(h Hop) bool { return hopFlag(h, "drained") }

func allHops(t *Trace) []Hop { return slices.Concat(t.Downstream, t.Upstreams) }

func hasUnverifiableEndpoints(t *Trace) bool {
	return slices.ContainsFunc(allHops(t), func(h Hop) bool { return unreadable(h) || hopFlag(h, "selectorless") })
}

// unknownReason names the main cause of an unknown verdict, in the same
// order classifyUnknown weighs them.
func unknownReason(t *Trace) string {
	hops := allHops(t)
	switch {
	case slices.ContainsFunc(hops, unreadable):
		return "on at least one hop the backing state could not be read - the agent may not be allowed to read it, or its cache has not synced"
	case slices.ContainsFunc(hops, func(h Hop) bool { return hopFlag(h, "selectorless") }):
		return "the Service has no selector, so its endpoints are kept by hand and a ready target cannot be confirmed"
	}
	return "the path cannot be verified from declared state alone"
}

// branchSpan is one backend branch of the flat downstream, [start, end).
type branchSpan struct{ start, end int }

// downstreamBranches splits a flat downstream into backend branches. A named
// hop reached over an edge ending "->Service" starts one, and a
// "Service->Pods" hop right after it belongs to it; each named route a
// Gateway reaches is a branch of one hop (the unnamed truncation hop is
// not). The entry hop is never a branch, and a Service subject has none.
func downstreamBranches(hops []Hop) []branchSpan {
	var out []branchSpan
	for i := 1; i < len(hops); i++ {
		h := hops[i]
		if h.Resource.Name == "" {
			continue
		}
		switch {
		case strings.HasSuffix(h.Edge, "->Service"):
			end := i + 1
			if end < len(hops) && hops[end].Edge == "Service->Pods" {
				end++
			}
			out = append(out, branchSpan{i, end})
		case strings.HasPrefix(h.Edge, "Gateway->"):
			out = append(out, branchSpan{i, i + 1})
		}
	}
	return out
}

// branchContaining is the branch whose span holds idx.
func branchContaining(hops []Hop, idx int) (branchSpan, bool) {
	i := slices.IndexFunc(downstreamBranches(hops), func(b branchSpan) bool { return b.start <= idx && idx < b.end })
	if i < 0 {
		return branchSpan{}, false
	}
	return downstreamBranches(hops)[i], true
}

// missingRefCodePrefix marks a finding about a route backend that doesn't
// exist.
const missingRefCodePrefix = "missing_ref:"

// IsMissingRefCode reports a finding about a route backend that does not
// exist.
func IsMissingRefCode(code string) bool { return strings.HasPrefix(code, missingRefCodePrefix) }

func nonMissingRefFindings(fs []Finding) []Finding {
	return slices.DeleteFunc(slices.Clone(fs), func(f Finding) bool { return IsMissingRefCode(f.Code) })
}

// branchSeverity is the worst reach severity among a branch's hops.
func branchSeverity(hops []Hop, b branchSpan) string {
	worst := ""
	for _, h := range hops[b.start:min(b.end, len(hops))] {
		if s := hopReachSeverity(h); severityRank(s) > severityRank(worst) {
			worst = s
		}
	}
	return worst
}

// hopReachSeverity lowers a critical to a warning on a hop that still has
// ready endpoints: traffic goes to the ready pods, so a failure among some
// serving replicas is degradation, not a break.
func hopReachSeverity(hop Hop) string {
	sev := worstSeverity(hop.Findings)
	if ready, _ := hop.Meta["ready"].(int); sev == SeverityCritical && ready > 0 {
		return SeverityWarning
	}
	return sev
}

func worstSeverity(fs []Finding) string {
	worst := ""
	for _, f := range fs {
		if severityRank(f.Severity) > severityRank(worst) {
			worst = f.Severity
		}
	}
	return worst
}

var severityRanks = map[string]int{SeverityInfo: 1, SeverityWarning: 2, SeverityCritical: 3}

func severityRank(s string) int { return severityRanks[s] }

// sortFindingsBySeverity puts the worst first, by code within a severity.
func sortFindingsBySeverity(fs []Finding) {
	slices.SortStableFunc(fs, func(a, b Finding) int {
		return cmp.Or(cmp.Compare(severityRank(b.Severity), severityRank(a.Severity)), strings.Compare(a.Code, b.Code))
	})
}

// IsEntryKind reports whether kind (any plural/lowercase form) is one of the
// entry kinds the trace supports.
func IsEntryKind(kind string) bool {
	switch NormalizeKind(kind) {
	case "Service", "Ingress", "HTTPRoute", "GRPCRoute", "Gateway":
		return true
	}
	return false
}

// NormalizeKind maps plural/lowercase spellings of an entry kind to its
// canonical Kind; other values are returned unchanged.
func NormalizeKind(k string) string {
	switch strings.ToLower(k) {
	case "service", "services", "svc":
		return "Service"
	case "ingress", "ingresses", "ing":
		return "Ingress"
	case "httproute", "httproutes":
		return "HTTPRoute"
	case "grpcroute", "grpcroutes":
		return "GRPCRoute"
	case "gateway", "gateways":
		return "Gateway"
	}
	return k
}

func entryKindGroup(kind string) string {
	switch kind {
	case "Ingress":
		return "networking.k8s.io"
	case "HTTPRoute", "GRPCRoute", "Gateway":
		return gatewayGroup
	}
	return ""
}
