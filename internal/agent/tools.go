// tools.go implements the agent-side half of the ToolRequest/ToolResult
// wire contract (internal/tunnel.ToolRequest/ToolResult): a deliberately
// small, seven-tool subset of lld/07-analysis-contracts.md §2's full list —
// get_events, get_logs, describe_resource, get_owner_chain, and (each added
// after the first four shipped — see STATUS.md) get_gitops_ownership,
// list_resources, and list_nodeport_allocations (BACKLOG.md "still open" #11,
// 2026-08-29) — chosen because they're the highest-value tools the
// existing detectors' findings actually point at, and because the rest of
// §2's list needs infrastructure that doesn't exist yet (a vector store for
// search_knowledge). query_metrics (BACKLOG.md C4, unblocked 2026-08-30 —
// see query_metrics.go/metrics_client.go) and dry_run_patch (BACKLOG.md C4's
// other half — see dry_run_patch.go) needed real, opt-in infrastructure of
// their own (metrics.prometheusService/dryRun.enabled respectively) rather
// than an unconditional chart change, which is why they are dispatched from
// this same switch but implemented in their own files. All three of
// get_gitops_ownership/list_resources/list_nodeport_allocations below needed
// no new infrastructure and no chart change. For get_gitops_ownership,
// deploy/helm/argus-agent/templates/clusterrole.yaml has granted
// get/list/watch on argoproj.io Applications/ApplicationSets and everything
// under {kustomize,helm,source}.toolkit.fluxcd.io since the chart was
// written; this file is what finally reads it. For list_resources, that same
// ClusterRole's get/list/watch grants already cover every kind in
// supportedGVKs — the "list" verb it needs is the one sweep_detector.go has
// been exercising on those kinds all along (BACKLOG.md C1). For
// list_nodeport_allocations, that ClusterRole's get/list/watch on "services"
// is bound cluster-wide via a ClusterRoleBinding rather than a namespaced
// RoleBinding, so the namespace-less List this tool needs was already
// permitted — see listNodePortAllocations' own doc comment.
//
// ToolExecutor never lists/gets Secrets and never touches pods/exec,
// pods/attach, or pods/portforward. Until real remediation execution
// (below), it never issued a write verb at all — every one of the seven
// tools above stays strictly within
// deploy/helm/argus-agent/templates/clusterrole.yaml's read-only
// argus-investigate grant.
//
// scale_deployment, restart_pod, patch_resource_limits and
// revert_container_image are the four
// deliberate, narrow exceptions: real Patch calls, gated behind three
// independent things all having to be true at once, per
// lld/08-remediation-contracts.md's signing scheme (see
// internal/remediation/sign.go) —
//  1. RBAC: only reachable at all when the agent Deployment runs under the
//     separate, opt-in argus-remediate ServiceAccount
//     (deploy/helm/argus-agent, remediate.enabled=true), never the default
//     argus-investigate-only identity.
//  2. A ValidatingAdmissionPolicy the API server itself enforces,
//     independent of whatever this Go code does or gets wrong, restricting
//     that ServiceAccount's writes to exactly the field paths §3/§4 name.
//  3. This file's own verifySignedPlan: no tool ever calls Patch against a
//     bare target+params argument — all three require a full
//     remediation.SignedPlan envelope, independently re-verified against
//     this agent's own persisted per-cluster key (never a key the caller
//     supplies) before anything is sent to the API server.
//
// patch_resource_limits adds a fourth gate of its own, for the one action
// whose input carries real numbers rather than a single count: it re-runs the
// hub's own value bounds locally (remediation.PatchResourceLimitsParams.
// Validate, the same function the gate used — one definition, not a copy) and
// refuses to execute unless the envelope carries a pre-computed rollback that
// still matches the live object. See patchResourceLimits below.
//
// revert_container_image adds a fourth gate of a different kind, and it is the
// most important agent-side check in this file: the image it is asked to write
// must actually appear in the target Deployment's OWN ReplicaSet history, read
// by this agent, from this cluster, at execution time. A signature proves the
// hub sent the image; it cannot prove the image was ever deployed here. This
// check does — which means a fully compromised hub can, at worst, move a
// workload between images it has already run, and cannot inject an arbitrary
// one. See revertContainerImage below.
//
// These four tools are never added to internal/llm/toolloop.go's
// investigation tool list — the model that proposes a plan can never call
// them; the only caller is internal/api/approvals.go's approve-and-execute
// path. get_events/get_logs/describe_resource/list_resources/
// get_owner_chain/get_gitops_ownership remain exactly as read-only as
// before.
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"argus/internal/agent/objcache"
	"argus/internal/logging"
	"argus/internal/redact"
	"argus/internal/tunnel"
)

const (
	// defaultLogTailLines/maxLogTailLines bound get_logs: a caller that
	// omits tailLines gets a sane default, and one that asks for an
	// unreasonably large tail is capped rather than honored verbatim — the
	// tunnel's own maxTunnelMessageBytes (1 MiB, internal/gateway/server.go)
	// bounds the wire message either way, but capping here keeps a single
	// tool call from producing a message anywhere near that ceiling.
	defaultLogTailLines = int64(200)
	maxLogTailLines     = int64(5000)

	// maxEventResults/maxOwnerChainNodes bound get_events/get_owner_chain
	// output size for the same reason — a tool result is one message on the
	// wire, and "fetch everything, bound nothing" is exactly what lld/07 §2
	// says never to do.
	maxEventResults    = 200
	maxOwnerChainNodes = 100

	// defaultListLimit/maxListLimit bound list_resources, and they carry more
	// weight than the two caps above. get_events and get_owner_chain bound a
	// result set the caller already narrowed by object identity;
	// list_resources is the one tool whose entire purpose is enumeration, so
	// the namespace it gets pointed at may legitimately hold thousands of
	// Pods, and every returned item is spent straight out of the model's
	// context window — the budget the whole investigation shares. 50 is
	// deliberately small enough that a complete result set is cheap to read
	// and reason about; 200 is the ceiling for a caller with a specific
	// reason to want more, and is not raisable by argument.
	//
	// The cap is only half of the design. Truncation is never silent — see
	// listResourcesResult's Truncated/TotalMatched — because the failure mode
	// of a silently short list is not "the model saw less," it is "the model
	// reasoned from absence": WORKLOG.md §86's investigation hedged on
	// exactly that kind of missing-evidence question, and a truncated list
	// mistaken for a complete one converts that honest hedge into a
	// confidently wrong conclusion.
	defaultListLimit = 50
	maxListLimit     = 200

	// defaultNodePortListLimit/maxNodePortListLimit bound
	// list_nodeport_allocations' list shape (BACKLOG.md "still open" #11) the
	// same way defaultListLimit/maxListLimit bound list_resources above. The
	// default is higher than list_resources': every item here is one flat
	// record (port/protocol/namespace/service/servicePort), not a workload
	// object with rendered status fields, so the per-item context cost is
	// much smaller — but a ceiling still exists because a large fleet's
	// cluster could plausibly have allocations spread across a meaningful
	// fraction of the default ~2768-wide NodePort range, and "fetch
	// everything, bound nothing" is the same mistake list_resources' own
	// comment already names.
	defaultNodePortListLimit = 200
	maxNodePortListLimit     = 1000
)

// supportedResource is one entry in supportedGVKs: the plural resource for the
// dynamic client, plus whether the kind is namespaced. The flag exists because
// Node and PersistentVolume are cluster-scoped, and a dynamic Get for those
// must NOT be namespace-qualified — an earlier version of this map was
// documented as "all eight are namespaced" and that stopped being true the
// moment the sweep detector started reporting node-level problems.
type supportedResource struct {
	gvr        schema.GroupVersionResource
	namespaced bool
}

// supportedGVKs is the fixed set of GVKs describe_resource, list_resources,
// get_owner_chain and get_gitops_ownership can operate on: the ones this
// agent's own detectors actually point at (lld/07 §2's describe_resource
// row), not discovery-driven
// support for arbitrary cluster types. Keyed by the exact
// schema.GroupVersionKind a caller's "<apiVersion>/<Kind>" gvk string parses
// into (see parseGVKString).
//
// **This map must stay in step with what the detectors emit.** It fell out of
// step once and the failure was invisible from either side alone: STATUS.md
// §72/§73 added sweep detection for stuck PersistentVolumeClaims, NotReady
// Nodes, blocked HorizontalPodAutoscalers and Services with no ready
// endpoints — so ARGUS would raise an incident naming a PVC, and then the
// investigation loop's very first describe_resource on it came back
// "unsupported gvk". Detection without the ability to investigate what was
// detected is worse than not detecting it, because it produces an incident
// nobody (human or model) can dig into. Caught by driving a real multi-step
// investigation against a live cluster, not by reading either file.
//
// Every kind here is already covered by the argus-investigate ClusterRole's
// existing get/list/watch grants (deploy/helm/argus-agent/templates/clusterrole.yaml)
// — adding these required no RBAC change, which is exactly why the gap was
// possible: nothing failed at deploy time.
var supportedGVKs = map[schema.GroupVersionKind]supportedResource{
	{Group: "", Version: "v1", Kind: "Pod"}:                                {schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}, true},
	{Group: "", Version: "v1", Kind: "Service"}:                            {schema.GroupVersionResource{Group: "", Version: "v1", Resource: "services"}, true},
	{Group: "apps", Version: "v1", Kind: "Deployment"}:                     {schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}, true},
	{Group: "apps", Version: "v1", Kind: "ReplicaSet"}:                     {schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "replicasets"}, true},
	{Group: "apps", Version: "v1", Kind: "StatefulSet"}:                    {schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "statefulsets"}, true},
	{Group: "apps", Version: "v1", Kind: "DaemonSet"}:                      {schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "daemonsets"}, true},
	{Group: "batch", Version: "v1", Kind: "Job"}:                           {schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "jobs"}, true},
	{Group: "batch", Version: "v1", Kind: "CronJob"}:                       {schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "cronjobs"}, true},
	{Group: "", Version: "v1", Kind: "PersistentVolumeClaim"}:              {schema.GroupVersionResource{Group: "", Version: "v1", Resource: "persistentvolumeclaims"}, true},
	{Group: "", Version: "v1", Kind: "Endpoints"}:                          {schema.GroupVersionResource{Group: "", Version: "v1", Resource: "endpoints"}, true},
	{Group: "discovery.k8s.io", Version: "v1", Kind: "EndpointSlice"}:      {schema.GroupVersionResource{Group: "discovery.k8s.io", Version: "v1", Resource: "endpointslices"}, true},
	{Group: "autoscaling", Version: "v2", Kind: "HorizontalPodAutoscaler"}: {schema.GroupVersionResource{Group: "autoscaling", Version: "v2", Resource: "horizontalpodautoscalers"}, true},
	{Group: "networking.k8s.io", Version: "v1", Kind: "Ingress"}:           {schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "ingresses"}, true},

	// Cluster-scoped — see supportedResource.namespaced.
	{Group: "", Version: "v1", Kind: "Node"}:                       {schema.GroupVersionResource{Group: "", Version: "v1", Resource: "nodes"}, false},
	{Group: "", Version: "v1", Kind: "PersistentVolume"}:           {schema.GroupVersionResource{Group: "", Version: "v1", Resource: "persistentvolumes"}, false},
	{Group: "storage.k8s.io", Version: "v1", Kind: "StorageClass"}: {schema.GroupVersionResource{Group: "storage.k8s.io", Version: "v1", Resource: "storageclasses"}, false},
	// Namespace (BACKLOG.md R4, added 2026-08-25): the hub's execution-time
	// preparePlan needs a named Namespace's own annotations to check
	// DESIGN.md §9.3's argus.io/protected modifier — an absolute guardrail
	// no RemediationPlan-level check can see, since it lives on the
	// namespace, not the target object. Originally grants nothing new beyond
	// the ClusterRole's existing "get" on namespaces (client.go's
	// resolveFingerprint kube-system lookup) — this was a second named-lookup
	// caller of that same narrow grant, not a widened one, and list_resources
	// on this kind used to fail with a clean RBAC-denied error rather than
	// actually listing.
	//
	// That changed 2026-08-26 (BACKLOG.md E9, third pass):
	// deploy/helm/argus-agent/templates/clusterrole.yaml now also grants
	// list/watch, for rules.go's "namespace-stuck-terminating" rule, which has
	// no named object to Get and must enumerate Namespaces to find the stuck
	// one. list_resources on this kind now actually lists, same as any other
	// namespaced-in-spirit kind here — see that ClusterRole's own comment for
	// why this particular widening was judged worth it.
	{Group: "", Version: "v1", Kind: "Namespace"}: {schema.GroupVersionResource{Group: "", Version: "v1", Resource: "namespaces"}, false},

	// Velero's Backup CRD, added 2026-08-26 (BACKLOG.md E9, third pass) for
	// rules.go's "velero-backup-partially-failed" rule (status.phase ==
	// PartiallyFailed) — the first entry in this map for a backup/DR tool.
	// Read-only, and only ever reads the Backup object's own status; this
	// agent has no path to the object-storage credentials Velero uses or the
	// backed-up data itself. Namespaced, unlike the cluster-scoped kinds just
	// above: Velero's own CRDs are namespaced.
	{Group: "velero.io", Version: "v1", Kind: "Backup"}: {schema.GroupVersionResource{Group: "velero.io", Version: "v1", Resource: "backups"}, true},

	// Velero's Restore CRD, added 2026-08-26 (BACKLOG.md E9, fourth pass) for
	// rules.go's "velero-restore-partially-failed"/"velero-restore-failed"
	// rules — the same status.phase shape as Backup above, applied to
	// Velero's other primary object. A Backup succeeding says nothing about
	// whether restoring from it will actually work; this is that other half.
	// Same posture as Backup: read-only, status-field-only, namespaced,
	// tolerates Velero not being installed.
	{Group: "velero.io", Version: "v1", Kind: "Restore"}: {schema.GroupVersionResource{Group: "velero.io", Version: "v1", Resource: "restores"}, true},

	// BACKLOG.md E9: kinds nothing in this agent could investigate before —
	// 30 of the issue-catalog's 45 categories name an object kind no
	// detector listed. CronJob and PersistentVolume were already here (see
	// above); these four are new, and each is either read by one of
	// rules.go's four representative rules or listed here for the same
	// "an incident naming this kind must be investigable" reason
	// TestDescribeResourceSupportsEveryKindTheDetectorsEmit already pins for
	// the hand-written checkers. RBAC for all four is
	// deploy/helm/argus-agent/templates/clusterrole.yaml — ConfigMap and
	// NetworkPolicy were already granted there (for other reasons unrelated
	// to describe_resource); PodDisruptionBudget and cert-manager's
	// Certificate needed a new rule added.
	{Group: "policy", Version: "v1", Kind: "PodDisruptionBudget"}:      {schema.GroupVersionResource{Group: "policy", Version: "v1", Resource: "poddisruptionbudgets"}, true},
	{Group: "", Version: "v1", Kind: "ConfigMap"}:                      {schema.GroupVersionResource{Group: "", Version: "v1", Resource: "configmaps"}, true},
	{Group: "networking.k8s.io", Version: "v1", Kind: "NetworkPolicy"}: {schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"}, true},
	{Group: "", Version: "v1", Kind: "ResourceQuota"}:                  {schema.GroupVersionResource{Group: "", Version: "v1", Resource: "resourcequotas"}, true},
	// cert-manager's Certificate — Q1 already decided this is read via the
	// CR's own status.notAfter only, which is exactly and exclusively what
	// rules.go's certificate-expiry-imminent rule reads. No Secret access is
	// granted or needed anywhere for this: the private key/cert material
	// cert-manager stores in a Secret is never touched.
	{Group: "cert-manager.io", Version: "v1", Kind: "Certificate"}: {schema.GroupVersionResource{Group: "cert-manager.io", Version: "v1", Resource: "certificates"}, true},

	// GitOps controller objects — the source-of-truth side. Added for
	// REMEDIATION_ROADMAP.md milestone 2.0: resolving an object's repo URL,
	// path and PINNED revision requires actually fetching the owning
	// Application/Kustomization/GitRepo, which getGitOpsOwnership's own doc
	// comment previously called out as deliberately not done ("expanding that
	// map is a real, separate future change"). This is that change, made
	// deliberately.
	//
	// Read-only like every other entry here, and the agent's ClusterRole
	// already granted argoproj.io and the three fluxcd groups; only
	// fleet.cattle.io is newly added there. Expanding this map also makes
	// these kinds visible to describe_resource/list_resources for the model,
	// which is wanted rather than incidental: "Argo reports this app
	// OutOfSync at revision X" is real diagnostic evidence it could not read
	// before.
	{Group: "argoproj.io", Version: "v1alpha1", Kind: "Application"}:             {schema.GroupVersionResource{Group: "argoproj.io", Version: "v1alpha1", Resource: "applications"}, true},
	{Group: "argoproj.io", Version: "v1alpha1", Kind: "ApplicationSet"}:          {schema.GroupVersionResource{Group: "argoproj.io", Version: "v1alpha1", Resource: "applicationsets"}, true},
	{Group: "kustomize.toolkit.fluxcd.io", Version: "v1", Kind: "Kustomization"}: {schema.GroupVersionResource{Group: "kustomize.toolkit.fluxcd.io", Version: "v1", Resource: "kustomizations"}, true},
	{Group: "helm.toolkit.fluxcd.io", Version: "v2", Kind: "HelmRelease"}:        {schema.GroupVersionResource{Group: "helm.toolkit.fluxcd.io", Version: "v2", Resource: "helmreleases"}, true},
	{Group: "source.toolkit.fluxcd.io", Version: "v1", Kind: "GitRepository"}:    {schema.GroupVersionResource{Group: "source.toolkit.fluxcd.io", Version: "v1", Resource: "gitrepositories"}, true},
	{Group: "fleet.cattle.io", Version: "v1alpha1", Kind: "GitRepo"}:             {schema.GroupVersionResource{Group: "fleet.cattle.io", Version: "v1alpha1", Resource: "gitrepos"}, true},
	{Group: "fleet.cattle.io", Version: "v1alpha1", Kind: "Bundle"}:              {schema.GroupVersionResource{Group: "fleet.cattle.io", Version: "v1alpha1", Resource: "bundles"}, true},

	// BACKLOG.md "still open" #1 (2026-08-29): the widening the live
	// catalogue-fault testing campaign found the most rows waiting on —
	// AJ1 and AQ1 both produced a *confidently wrong* answer at 0.95
	// confidence because the investigation loop had no way to check what it
	// was telling an operator, which this codebase treats as strictly worse
	// than an honest "could not determine" (non-negotiable 8).
	//
	// RBAC kinds — Role/RoleBinding namespaced, ClusterRole/
	// ClusterRoleBinding cluster-scoped, all four read-only (get/list/watch
	// only: deploy/helm/argus-agent/templates/clusterrole.yaml grants
	// nothing else, and non-negotiable 1's exclusion is specifically
	// bind/escalate/impersonate — enumerating and reading these objects is
	// not privilege escalation). Unblocks AC1 (a dangling RoleBinding
	// subject the investigation loop hit "unsupported kind" on, mid-trace,
	// and never asked again) and AJ1 (the model confidently told an
	// operator to create a Role/RoleBinding that already existed, because
	// it had no way to check first).
	{Group: "rbac.authorization.k8s.io", Version: "v1", Kind: "Role"}:               {schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "roles"}, true},
	{Group: "rbac.authorization.k8s.io", Version: "v1", Kind: "RoleBinding"}:        {schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "rolebindings"}, true},
	{Group: "rbac.authorization.k8s.io", Version: "v1", Kind: "ClusterRole"}:        {schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "clusterroles"}, false},
	{Group: "rbac.authorization.k8s.io", Version: "v1", Kind: "ClusterRoleBinding"}: {schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "clusterrolebindings"}, false},
	// ServiceAccount — namespaced, read-only (get/list/watch). Its own
	// object carries no credential material (the auto-mounted token lives in
	// a Secret, still unreachable except via the narrow Secret case below);
	// this is identity/metadata, the same posture as Namespace above. Also
	// unblocks AC1/AJ1: a dangling RoleBinding subject or an
	// "does this ServiceAccount even exist" check both need this.
	{Group: "", Version: "v1", Kind: "ServiceAccount"}: {schema.GroupVersionResource{Group: "", Version: "v1", Resource: "serviceaccounts"}, true},

	// ValidatingAdmissionPolicy — admissionregistration.k8s.io, cluster-scoped,
	// read-only. PROJECT.md B149: this cluster's own status.typeChecking
	// field (populated by the API server itself, not parsed here) is the
	// generic, kind-agnostic signal checkGenericAdmissionPolicyTypeChecking
	// (generic_predicates.go) reads to detect a CEL expression that cannot
	// possibly match anything on its own matched resource kind — the same
	// "read a status field the controller already computed" pattern
	// checkGenericConditions already uses for every other kind, applied to
	// the one kind whose own misconfiguration is otherwise completely
	// invisible: a failing policy blocks every write it guards, silently,
	// with no Kubernetes Event and no watchable victim object (the write
	// never happens at all). No new RBAC verb beyond get/list/watch, and no
	// bind/escalate/impersonate capability — reading a policy's own
	// definition and status is not evaluating or granting it.
	{Group: "admissionregistration.k8s.io", Version: "v1", Kind: "ValidatingAdmissionPolicy"}: {schema.GroupVersionResource{Group: "admissionregistration.k8s.io", Version: "v1", Resource: "validatingadmissionpolicies"}, false},

	// Gateway API — gateway.networking.k8s.io. PROJECT.md's Gateway API item:
	// 32 catalogue entries, 27 pull-request-fixable, and every single one
	// keys on a plain status condition (Accepted=False, Programmed=False,
	// Conflicted=True, ResolvedRefs=False) — no Gateway-specific detector
	// needed at all, the proof case for the kind-agnostic generic
	// predicates (checkGenericConditions/checkGenericDanglingReference).
	// Read-only, get/list/watch, no bind/escalate/impersonate — reading a
	// route's or gateway's own definition and status, never evaluating
	// traffic through it. GatewayClass is cluster-scoped; the rest are
	// namespaced. Versions match the Gateway API standard channel as of
	// this project's own test install (GatewayClass/Gateway/HTTPRoute/
	// GRPCRoute at v1; TCPRoute/TLSRoute/ReferenceGrant are still
	// experimental-channel-only, v1alpha2) — re-verify against whichever
	// CRD channel is actually applied if a future cluster installs a
	// different one.
	{Group: "gateway.networking.k8s.io", Version: "v1", Kind: "GatewayClass"}:        {schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gatewayclasses"}, false},
	{Group: "gateway.networking.k8s.io", Version: "v1", Kind: "Gateway"}:             {schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gateways"}, true},
	{Group: "gateway.networking.k8s.io", Version: "v1", Kind: "HTTPRoute"}:           {schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "httproutes"}, true},
	{Group: "gateway.networking.k8s.io", Version: "v1", Kind: "GRPCRoute"}:           {schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "grpcroutes"}, true},
	{Group: "gateway.networking.k8s.io", Version: "v1alpha2", Kind: "TCPRoute"}:      {schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1alpha2", Resource: "tcproutes"}, true},
	{Group: "gateway.networking.k8s.io", Version: "v1alpha2", Kind: "TLSRoute"}:      {schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1alpha2", Resource: "tlsroutes"}, true},
	{Group: "gateway.networking.k8s.io", Version: "v1beta1", Kind: "ReferenceGrant"}: {schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1beta1", Resource: "referencegrants"}, true},

	// PriorityClass — scheduling.k8s.io, cluster-scoped. Unblocks AE1's
	// PRIO-001 finding, which had no code path anywhere for this kind before
	// this change (verified by grep against this file on 2026-08-28).
	{Group: "scheduling.k8s.io", Version: "v1", Kind: "PriorityClass"}: {schema.GroupVersionResource{Group: "scheduling.k8s.io", Version: "v1", Resource: "priorityclasses"}, false},

	// CertificateSigningRequest — certificates.k8s.io, cluster-scoped.
	// Read-only: this ClusterRole grants get/list/watch on the CSR object
	// itself, never the certificatesigningrequests/approval subresource
	// (that stays permanently excluded — approving a CSR is a write with
	// real trust consequences, and nothing about investigating W2's
	// AUTH-004 finding needs it).
	{Group: "certificates.k8s.io", Version: "v1", Kind: "CertificateSigningRequest"}: {schema.GroupVersionResource{Group: "certificates.k8s.io", Version: "v1", Resource: "certificatesigningrequests"}, false},

	// ServiceMonitor — monitoring.coreos.com/v1, the Prometheus Operator's
	// CRD. Namespaced, added the same way Velero's Backup/Restore and
	// cert-manager's Certificate were: a real CRD-sourced kind this agent
	// has no path to install or configure, tolerated as absent exactly like
	// those (evaluateRule's/ownerChainDown's meta.IsNoMatchError handling).
	// Unblocks AD1's OBS-005 finding. Read-only, and reads only the object's
	// own spec/status — never touches Prometheus's actual scrape data.
	{Group: "monitoring.coreos.com", Version: "v1", Kind: "ServiceMonitor"}: {schema.GroupVersionResource{Group: "monitoring.coreos.com", Version: "v1", Resource: "servicemonitors"}, true},

	// Secret — deliberately the narrowest entry in this entire map, and the
	// only one whose reachability is NOT "the whole object, same as every
	// other kind here." Unblocks AT1. Namespaced; RBAC below grants ONLY
	// "get" (no list, no watch — see clusterrole.yaml's own comment on this
	// grant for why even list/watch is withheld here specifically). Every
	// caller that turns a fetched Secret into what the investigation loop
	// sees MUST go through secretMetadataOnly (describeResource, below) —
	// never mustMarshal(obj.Object) directly. Also listed in
	// neverAWorkloadChildKinds below, so ownerChainDown's downward walk
	// never attempts to List secrets at all (which the withheld "list" RBAC
	// would refuse anyway — this is the same guarantee stated structurally
	// rather than left to an RBAC error to enforce).
	{Group: "", Version: "v1", Kind: "Secret"}: {schema.GroupVersionResource{Group: "", Version: "v1", Resource: "secrets"}, true},
}

// secretGVK is the one entry in supportedGVKs whose full object must never
// reach mustMarshal — see describeResource's secret case and
// secretMetadataOnly below.
var secretGVK = schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Secret"}

// gitOpsSourceKinds are the supportedGVKs entries that describe an object's
// SOURCE rather than its runtime state — the GitOps controllers' own objects,
// added for REMEDIATION_ROADMAP.md milestone 2.0.
//
// They are in supportedGVKs because resolveRepoTarget needs to GET a specific
// one by name, and because letting the investigator describe_resource an Argo
// Application is genuinely useful evidence. They are listed here so
// ownerChainDown can skip them: nothing in this set is ever the child of a
// workload, so listing them on a downward walk is wasted work against CRDs
// most clusters do not have. Keyed on GroupKind, not GroupVersionKind, so a
// version bump in supportedGVKs cannot silently drop an entry out of this set.
var gitOpsSourceKinds = map[schema.GroupKind]bool{
	{Group: "argoproj.io", Kind: "Application"}:                   true,
	{Group: "argoproj.io", Kind: "ApplicationSet"}:                true,
	{Group: "kustomize.toolkit.fluxcd.io", Kind: "Kustomization"}: true,
	{Group: "helm.toolkit.fluxcd.io", Kind: "HelmRelease"}:        true,
	{Group: "source.toolkit.fluxcd.io", Kind: "GitRepository"}:    true,
	{Group: "fleet.cattle.io", Kind: "GitRepo"}:                   true,
	{Group: "fleet.cattle.io", Kind: "Bundle"}:                    true,
}

// neverAWorkloadChildKinds is gitOpsSourceKinds' counterpart for
// BACKLOG.md E9: supportedGVKs entries that, for a different reason, are
// also never the CHILD of a workload via ownerReferences in practice, so
// ownerChainDown's downward walk skips them too — a separate map, not an
// addition to gitOpsSourceKinds, because these are not GitOps
// source-of-truth objects and that map's own doc comment is specifically
// about that.
//
// cert-manager's Certificate was the one entry so far: nothing points a
// Deployment/Pod/etc. at a Certificate as its owner, or the reverse — a
// Certificate is a standalone object other things REFERENCE by name (an
// Ingress's tls.secretName, a Gateway listener), never a controller-owned
// child of a workload. Skipping it also matters for a reason gitOpsSourceKinds'
// own comment already names for its own entries: cert-manager is often not
// installed at all, and listing an absent CRD on every downward walk would be
// wasted work at best — see ownerChainDown's error handling below for the
// other half of this (tolerating the CRD-not-installed case for any kind,
// not just the ones named here).
//
// Velero's Backup joined it 2026-08-26 (BACKLOG.md E9, third pass) for the
// same reason: a Backup is created by a Schedule or by an operator directly,
// never by a workload's controller, and nothing treats a Backup as a
// workload's child either. Velero is also frequently not installed, so
// skipping it avoids a wasted List on every downward walk on top of avoiding
// a walk that could never find anything.
var neverAWorkloadChildKinds = map[schema.GroupKind]bool{
	{Group: "cert-manager.io", Kind: "Certificate"}: true,
	{Group: "velero.io", Kind: "Backup"}:            true,
	// Restore joined Backup 2026-08-26 (BACKLOG.md E9, fourth pass) for the
	// identical reason: created by a Schedule/operator, never by a
	// workload's controller, and never a workload's child either.
	{Group: "velero.io", Kind: "Restore"}: true,
	// BACKLOG.md "still open" #1 (2026-08-29): none of the five kinds below
	// are ever a workload's ownerReferences child in practice — a
	// Role/RoleBinding/ServiceAccount/ServiceMonitor is referenced by name
	// (a RoleBinding subject, a Pod's spec.serviceAccountName, a
	// ServiceMonitor's label selector), never owned by a
	// Deployment/ReplicaSet/StatefulSet/DaemonSet/Job. Skipping them here
	// avoids four wasted List calls on every downward walk against kinds
	// that could never match.
	{Group: "rbac.authorization.k8s.io", Kind: "Role"}:        true,
	{Group: "rbac.authorization.k8s.io", Kind: "RoleBinding"}: true,
	{Group: "", Kind: "ServiceAccount"}:                       true,
	{Group: "monitoring.coreos.com", Kind: "ServiceMonitor"}:  true,
	// ValidatingAdmissionPolicy joined 2026-09-06 (PROJECT.md B149) for the
	// identical reason: cluster-scoped, referenced by name from its own
	// Binding object, never owned by (never an ownerReferences child of) any
	// workload.
	{Group: "admissionregistration.k8s.io", Kind: "ValidatingAdmissionPolicy"}: true,
	// Gateway API's whole kind family joined for the identical reason:
	// GatewayClass/Gateway are referenced by name (an HTTPRoute's
	// parentRefs, a Gateway's own gatewayClassName), never owned by a
	// workload's ownerReferences; HTTPRoute/GRPCRoute/TCPRoute/TLSRoute are
	// themselves never a workload's child either — they reference a
	// Gateway, and are referenced BY nothing a Deployment/StatefulSet/etc.
	// owns.
	{Group: "gateway.networking.k8s.io", Kind: "GatewayClass"}:   true,
	{Group: "gateway.networking.k8s.io", Kind: "Gateway"}:        true,
	{Group: "gateway.networking.k8s.io", Kind: "HTTPRoute"}:      true,
	{Group: "gateway.networking.k8s.io", Kind: "GRPCRoute"}:      true,
	{Group: "gateway.networking.k8s.io", Kind: "TCPRoute"}:       true,
	{Group: "gateway.networking.k8s.io", Kind: "TLSRoute"}:       true,
	{Group: "gateway.networking.k8s.io", Kind: "ReferenceGrant"}: true,
	// Secret is the fifth, and the reason it is here is stronger than "never
	// a workload's child": clusterrole.yaml grants get on secrets but
	// deliberately NOT list/watch, specifically so this agent never
	// enumerates every Secret in a namespace. Without this entry,
	// ownerChainDown's generic per-kind List loop would try exactly that
	// on every single downward walk (for an unrelated target), and rely on
	// an RBAC 403 to fail safe — this says the same thing structurally,
	// which is the stronger and more legible guarantee. See supportedGVKs'
	// own Secret entry and describeResource's secret case for the rest of
	// this guarantee.
	{Group: "", Kind: "Secret"}: true,
}

// listableKindsByName indexes supportedGVKs by bare Kind name so
// list_resources can accept kind: "Deployment" as well as the
// "[group/]version/Kind" gvk string every other tool in this file takes. It's
// a []GVK per name rather than a single GVK on purpose: the Kind names in
// supportedGVKs happen to be unique today, but that is a property of the
// current map, not a rule — the moment two supported groups share a Kind
// name, a bare-kind lookup becomes a coin flip, and resolveListKind reports
// the ambiguity and asks for the full gvk form instead of picking one.
var listableKindsByName = func() map[string][]schema.GroupVersionKind {
	byName := map[string][]schema.GroupVersionKind{}
	for gvk := range supportedGVKs {
		byName[gvk.Kind] = append(byName[gvk.Kind], gvk)
	}
	return byName
}()

// supportedKindNames is the sorted Kind names list_resources accepts, used to
// make an "unsupported kind" error self-correcting: telling the caller what
// IS supported turns a wasted investigation turn into a corrected retry,
// which matters because the caller is usually a model with a limited turn
// budget rather than a human who can go read this file.
func supportedKindNames() string {
	names := make([]string, 0, len(listableKindsByName))
	for name := range listableKindsByName {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// resolveDescribableResource resolves gvk for describe_resource/list_resources
// against supportedGVKs first — the "reviewed" set, every Kind this file's
// authors have actually looked at the shape of — and, only if that lookup
// misses, against the discovered watch set discovery.go builds (the same
// ServerPreferredResources ∩ RBAC mechanism generic_predicates.go's
// kind-agnostic detection already unions in via discoveredWatchSetCache; see
// that file's own doc comment for why this reuses it rather than building a
// second discovery path — BACKLOG.md E13).
//
// The returned reviewed flag is the caller's redaction switch: true means
// redact.Object's existing named-field-class rules are the right (and
// sufficient) control, because the schema has been reviewed against them;
// false means the gvk was found only via discovery — an arbitrary CRD nobody
// here has reviewed — and the caller must route through
// redact.AggressiveObject instead. describeResource/listResources are the
// only two callers; get_owner_chain/get_gitops_ownership/PatchField/rule
// validation/the ownership walk are deliberately untouched consumers of
// supportedGVKs and do not call this (BACKLOG.md E13's own explicit scope
// boundary, inherited from E11's).
//
// Secret is excluded from the discovery fallback explicitly, not only
// incidentally. supportedGVKs already contains the real core/v1 Secret, so a
// lookup for it always resolves on the FIRST branch below (reviewed=true) —
// describeResource's own gvk == secretGVK special case still forces the
// metadata-only shape regardless of what this function returns, and
// listResources' own explicit Secret refusal runs regardless too. The
// early-return guard here is defense in depth for the case that invariant
// ever stops holding (Secret removed from supportedGVKs) or RBAC ever grants
// this identity list/watch on secrets (clusterrole.yaml deliberately does
// not) — either way, a Secret found only via discovery must never be treated
// as just another unreviewed kind.
func (e *ToolExecutor) resolveDescribableResource(ctx context.Context, gvk schema.GroupVersionKind) (res supportedResource, reviewed bool, err error) {
	if res, ok := supportedGVKs[gvk]; ok {
		return res, true, nil
	}
	if gvk == secretGVK {
		return supportedResource{}, false, fmt.Errorf("unsupported gvk %q; supported kinds are: %s", formatGVK(gvk), supportedKindNames())
	}
	if wsc := discoveredWatchSetCache.Load(); wsc != nil {
		discovered, derr := wsc.Get(ctx)
		if derr != nil {
			logger.WarnContext(ctx, "describe_resource/list_resources: discovered watch set unavailable this call, resolving against supportedGVKs only", slog.String("gvk", formatGVK(gvk)), logging.Err(derr))
		} else if dr, ok := discovered[gvk]; ok {
			return supportedResource{gvr: dr.GVR, namespaced: dr.Namespaced}, false, nil
		}
	}
	return supportedResource{}, false, fmt.Errorf("unsupported gvk %q; supported kinds are: %s", formatGVK(gvk), supportedKindNames())
}

// requireNamespaceFor enforces the namespace argument per kind: required for a
// namespaced kind, and rejected for a cluster-scoped one rather than silently
// ignored — a caller passing a namespace for a Node has misunderstood
// something, and saying so is more useful than quietly returning the right
// answer to a differently-shaped question.
func requireNamespaceFor(res supportedResource, namespace string) error {
	if res.namespaced && namespace == "" {
		return errors.New("namespace is required for this kind")
	}
	if !res.namespaced && namespace != "" {
		return fmt.Errorf("this kind is cluster-scoped; omit namespace (got %q)", namespace)
	}
	return nil
}

// resourceInterface returns the dynamic client scoped correctly for this
// kind: namespace-qualified for a namespaced kind, cluster-wide for a
// cluster-scoped one. Centralized so no call site has to remember which is
// which.
func (e *ToolExecutor) resourceInterface(res supportedResource, namespace string) dynamic.ResourceInterface {
	if res.namespaced {
		return e.dynamic.Resource(res.gvr).Namespace(namespace)
	}
	return e.dynamic.Resource(res.gvr)
}

// ToolExecutor runs the supported tools against a real cluster, using
// two client-go clients built once from the same in-cluster/kubeconfig
// resolution facts.go's GatherFacts already uses (loadKubeConfig) — not a
// second, differently-configured client. typed serves get_events/get_logs,
// whose typed APIs (field-selected Event list, the pods/log subresource)
// are simpler to use directly than through the dynamic client. dynamic
// serves describe_resource/list_resources/get_owner_chain/
// get_gitops_ownership, which need to operate uniformly across every Kind in
// supportedGVKs — a dynamic.Interface dispatch keyed by GVR avoids a
// hand-written switch duplicated per type for what is otherwise the same
// Get/List call shape every time.
//
// A nil *ToolExecutor is valid and represents "no reachable cluster" (the
// same condition GatherFacts reports as Reachable: false) — Execute returns
// a clean error for every tool rather than the caller having to nil-check
// before every call.
type ToolExecutor struct {
	typed   kubernetes.Interface
	dynamic dynamic.Interface

	// objects is the object cache (objcache_wiring.go) the cluster-insight
	// tools answer from; nil when disabled or not yet started, in which case
	// those tools report themselves unavailable.
	objects *objcache.Cache

	// clusterID and planSigningKey are this agent's own hub-assigned
	// identity and derived remediation-plan signing key
	// (remediation.DeriveClusterSigningKey), delivered once at enrollment
	// (internal/api/enroll.go) and set here via SetRemediationCredentials
	// after client.go resolves them — never known at newToolExecutor's
	// construction time, since that runs before enrollment/persisted-
	// credential loading. Both empty until then, and scale_deployment/
	// restart_pod both refuse outright rather than executing with either
	// missing.
	clusterID      string
	planSigningKey []byte

	// role is what this agent process is (PROJECT.md E11), set by
	// SetConnectionRole from Config.Role. Empty or tunnel.RoleAll means the
	// pre-E11 single-process shape, which serves every tool.
	//
	// Defence in depth, and nothing more. The thing that actually makes an
	// investigation agent unable to write is that its ServiceAccount holds
	// no write verb — this check cannot add to that, and must never be
	// mistaken for it. What it adds is a CLEAR refusal: without it, a write
	// tool misrouted to a read-only agent reaches the API server and comes
	// back as a 403 that reads like a misconfigured ClusterRole. With it,
	// the agent says which process was asked and why it declined.
	role string

	// dryRunDynamic is the SEPARATE dynamic client dry_run_patch submits
	// through, authenticated as the opt-in argus-dryrun ServiceAccount —
	// never the same client as dynamic above, and never sharing its
	// identity. nil whenever this cluster has not mounted the pack's token
	// (see dryrun_client.go's package doc comment for why this genuinely
	// has to be a second credential rather than a second grant on the same
	// one), which dryRunPatch treats as "unavailable here", not as an
	// internal error.
	dryRunDynamic dynamic.Interface

	// policyDynamic is the THIRD, separate dynamic client
	// open_execution_window/close_execution_window submit through
	// (BACKLOG.md F14), authenticated as the opt-in argus-policy-controller
	// ServiceAccount — never the same client as dynamic or dryRunDynamic
	// above, and never sharing either's identity. nil whenever this cluster
	// has not mounted the pack's token (see policywindow_client.go's
	// package doc comment), which the two tool handlers below treat as
	// "unavailable here" via errPolicyControllerNotConfigured, not as an
	// internal error.
	policyDynamic dynamic.Interface

	// metricsProxy is BACKLOG.md C4's query_metrics half: the abstraction that
	// tool submits its one HTTP GET through, reaching a configured Prometheus
	// via THIS agent's own primary identity (argus-investigate, narrowly
	// widened — deploy/helm/argus-agent/templates/metrics.yaml), never a
	// second credential the way dryRunDynamic/policyDynamic above are. nil
	// whenever this cluster has not configured values.yaml's
	// metrics.prometheusService, which queryMetrics treats as "unavailable
	// here" via errMetricsNotConfigured, not as an internal error. See
	// metrics_client.go's package doc comment for why this is an interface
	// rather than a direct use of typed/dynamic above.
	metricsProxy metricsProxyClient

	// rules is this agent's currently-loaded declarative rule set
	// (BACKLOG.md E9, internal/agent/rules.go) — set once via SetRules after
	// client.go's Run resolves it, the same "known only after construction"
	// shape SetRemediationCredentials already uses above, and for a similar
	// reason: LoadRules and newToolExecutor are independent, order-agnostic
	// steps in Run today, and threading the rule set through newToolExecutor's
	// constructor would couple two things that don't need to know about each
	// other. Read only by reevaluateRule (BACKLOG.md V3) — nil/empty is a
	// normal, common state (an agent with no rules file at all still builds a
	// ToolExecutor), and reevaluateRule reports that as "no such rule" rather
	// than a crash.
	rules []Rule
}

// SetRemediationCredentials installs this agent's own cluster ID and
// derived remediation-plan signing key after enrollment/persisted-
// credential loading resolves them (client.go's Run). Safe to call with an
// empty clusterID/nil key (nothing delivered yet, e.g. an older data dir
// predating this feature, or a hub that hasn't derived one) —
// scale_deployment/restart_pod then refuse every call with a clear error
// instead of verifying against an empty identity.
// SetConnectionRole records which of PROJECT.md E11's roles this agent
// process is serving. Safe on a nil executor (an agent with no reachable
// cluster), like the other setters here.
func (e *ToolExecutor) SetConnectionRole(role string) {
	if e == nil {
		return
	}
	e.role = role
}

func (e *ToolExecutor) SetRemediationCredentials(clusterID string, planSigningKey []byte) {
	if e == nil {
		return
	}
	e.clusterID = clusterID
	e.planSigningKey = planSigningKey
}

// SetRules installs this agent's currently-loaded declarative rule set
// (BACKLOG.md E9) so reevaluate_rule (BACKLOG.md V3) can look a rule ID back
// up by ID. Safe to call with a nil/empty slice — reevaluateRule then simply
// reports every ruleId as unknown, which is the correct answer for an agent
// with no rules file at all. Mirrors SetRemediationCredentials's own
// "installed once, after construction" convention above.
func (e *ToolExecutor) SetRules(rules []Rule) {
	if e == nil {
		return
	}
	e.rules = rules
}

// newToolExecutor builds a ToolExecutor from the same kubeconfig resolution
// facts.go's GatherFacts/KubeSystemUID use. Returns (nil, err) when no
// cluster config is reachable — the caller (client.go) logs this once and
// keeps running with a nil executor, matching GatherFacts' own
// never-fatal-on-no-cluster posture.
//
// dryRunTokenDir is Config.DryRunTokenDir, threaded through so the returned
// executor's dry_run_patch tool has a client to submit through whenever this
// cluster opted into the pack. Failing to build the DRY-RUN half is
// deliberately non-fatal — logged, and dryRunDynamic stays nil — mirroring
// this function's own posture toward the primary client one level up in
// client.go: a misconfigured opt-in pack must not take down an otherwise
// working agent.
//
// metricsNamespace/metricsService/metricsPort are Config.Prometheus*,
// threaded through the same way for query_metrics' proxy client — see
// newMetricsProxyClient, which returns nil (not an error) when any of the
// three is unset, exactly as this cluster opting out of the pack should look.
func newToolExecutor(dryRunTokenDir, policyControllerTokenDir string, metricsNamespace, metricsService string, metricsPort int) (*ToolExecutor, error) {
	cfg, err := loadKubeConfig()
	if err != nil {
		return nil, err
	}
	typed, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("build typed client: %w", err)
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("build dynamic client: %w", err)
	}
	dryRunDyn, err := newDryRunDynamicClient(dryRunTokenDir)
	if err != nil {
		logger.Warn("argus-dryrun client unavailable; dry_run_patch will report itself unavailable until this is fixed", logging.Err(err))
		dryRunDyn = nil
	}
	policyDyn, err := newPolicyControllerDynamicClient(policyControllerTokenDir)
	if err != nil {
		logger.Warn("argus-policy-controller client unavailable; open_execution_window/close_execution_window will report themselves unavailable until this is fixed", logging.Err(err))
		policyDyn = nil
	}
	var metricsProxy metricsProxyClient
	if ext, err := newExternalMetricsClientFromEnv(); err != nil {
		return nil, err
	} else if ext != nil {
		// PROJECT.md PG17: an external endpoint replaces the Service proxy.
		metricsProxy = ext
	} else {
		metricsProxy = newMetricsProxyClient(typed, metricsNamespace, metricsService, metricsPort)
	}
	return &ToolExecutor{typed: typed, dynamic: dyn, dryRunDynamic: dryRunDyn, policyDynamic: policyDyn, metricsProxy: metricsProxy}, nil
}

// NewToolExecutorForTest builds a ToolExecutor directly from the given
// typed/dynamic clients, bypassing newToolExecutor's real kubeconfig
// resolution entirely. Exported specifically so tests outside this package
// (internal/gateway's real-TLS ToolRequest/ToolResult round-trip test, in
// particular — this sandbox has no live cluster to test against either
// side with) can construct one backed by k8s.io/client-go's fake
// clientsets. Production code (client.go's Run) always uses newToolExecutor
// instead; nothing in this file's non-test call graph uses this
// constructor.
func NewToolExecutorForTest(typed kubernetes.Interface, dyn dynamic.Interface) *ToolExecutor {
	return &ToolExecutor{typed: typed, dynamic: dyn}
}

// NewToolExecutorForTestWithDryRun is NewToolExecutorForTest plus a THIRD,
// independent fake dynamic client standing in for the argus-dryrun identity
// — exported for the same cross-package reason NewToolExecutorForTest is
// (this repo's dry_run_patch tests live in this package, but keeping the
// same "exported for tests" shape rather than a package-private field
// assignment matches this file's existing convention and leaves the door
// open for a cross-package test the way internal/gateway's already uses the
// two-arg constructor). Passing a nil dryRun client is equivalent to a
// cluster that never enabled the pack — dryRunPatch reports
// errDryRunNotConfigured exactly as it does in production.
func NewToolExecutorForTestWithDryRun(typed kubernetes.Interface, dyn dynamic.Interface, dryRun dynamic.Interface) *ToolExecutor {
	return &ToolExecutor{typed: typed, dynamic: dyn, dryRunDynamic: dryRun}
}

// NewToolExecutorForTestWithPolicyController is
// NewToolExecutorForTestWithDryRun plus a FOURTH, independent fake dynamic
// client standing in for the argus-policy-controller identity (BACKLOG.md
// F14) — exported for the same cross-package/test reason. Passing a nil
// policyController client is equivalent to a cluster that never enabled the
// pack: open_execution_window/close_execution_window then report
// errPolicyControllerNotConfigured exactly as they do in production.
func NewToolExecutorForTestWithPolicyController(typed kubernetes.Interface, dyn dynamic.Interface, dryRun dynamic.Interface, policyController dynamic.Interface) *ToolExecutor {
	return &ToolExecutor{typed: typed, dynamic: dyn, dryRunDynamic: dryRun, policyDynamic: policyController}
}

// NewToolExecutorForTestWithMetrics is NewToolExecutorForTest plus a fake
// metricsProxyClient standing in for query_metrics' proxy call — exported for
// the same cross-package/test reason the constructors above are. Passing a
// nil metricsProxy is equivalent to a cluster that never configured
// metrics.prometheusService: queryMetrics then reports errMetricsNotConfigured
// exactly as it does in production.
func NewToolExecutorForTestWithMetrics(typed kubernetes.Interface, dyn dynamic.Interface, metrics metricsProxyClient) *ToolExecutor {
	return &ToolExecutor{typed: typed, dynamic: dyn, metricsProxy: metrics}
}

// Execute dispatches one ToolRequest's Tool/Args to the matching
// implementation and returns that tool's Data payload, its Truncated flag,
// and any error. The caller (executeToolRequest, in client.go) is
// responsible for turning a non-nil error into ToolResult.Error and a nil
// Data — this method never returns both an error and non-nil data.
//
// Every error returned by this method and everything it calls is already
// safe to send back over the tunnel as-is: sanitizeK8sErr strips k8s API
// errors down to a short, generic message before they ever reach here, and
// the argument-validation errors constructed directly in this file never
// echo cluster state, only the caller's own (already-untrusted) input.
// Every successful result passes through redact.Object on the way out, in ONE
// place, on purpose. The alternative — each tool redacting its own output —
// puts the guarantee at the mercy of whoever adds the next tool remembering to
// do it, and BUGS.md 84 is the record of what that costs: six read-only tools,
// none of them filtering anything, each individually reasonable. Because the
// filter wraps the dispatch rather than living inside it, a new case in
// executeTool is redacted before its author has an opinion about redaction.
// TestEveryToolRedactsItsOutput enforces that this stays true.
//
// Errors are not JSON, so they do not go through redact.Object; their text
// goes through the pattern layer (redact.Text) instead, here, for the same
// reason the output does: error text crosses the tunnel too, and several
// tools now name the object they could not find or explain a pod's state,
// so cluster-authored text (names, reasons, admissionRejection's bounded
// passthrough) does reach the error path. The redacted error keeps the
// original as its Unwrap target, so errors.Is/As still see it on the agent
// side; only Error() — what is sent — changes.
func (e *ToolExecutor) Execute(ctx context.Context, tool string, args json.RawMessage) (data json.RawMessage, truncated bool, err error) {
	if e == nil {
		return nil, false, errors.New("no reachable cluster")
	}
	data, truncated, err = e.executeTool(ctx, tool, args)
	if err != nil {
		return nil, false, redactError(err)
	}
	return redact.Object(data), truncated, nil
}

// redactedError is an error whose text has been through redact.Text, wrapping
// the original so errors.Is/As keep working.
type redactedError struct {
	text string
	err  error
}

func (r *redactedError) Error() string { return r.text }
func (r *redactedError) Unwrap() error { return r.err }

// redactError applies the pattern redaction layer to err's text.
func redactError(err error) error {
	if err == nil {
		return nil
	}
	return &redactedError{text: redact.Text(err.Error()), err: err}
}

// refuseIfWrongRole is PROJECT.md E11's agent-side half: an investigation
// agent declines every mutating tool outright, ahead of dispatch, using the
// SAME classification the hub routes by (tunnel.RoleForTool) so the two
// cannot disagree about which tools mutate.
//
// Read the comment on ToolExecutor.role before changing this. It is NOT the
// security boundary. The boundary is that this process runs as a
// ServiceAccount holding no write verb on anything, which no Go code here
// can grant itself and no Go code here can take away. What this adds is the
// sentence: without it, a write tool that reached a read-only agent would
// come back as a bare 403 that reads like a misconfigured ClusterRole rather
// than like a request that arrived at the wrong one of a cluster's two
// agents.
//
// Returns nil for every other combination, including a write tool on a
// pre-E11 RoleAll agent — that agent really does hold both grants, and
// refusing it would break every cluster not yet migrated.
func (e *ToolExecutor) refuseIfWrongRole(tool string) error {
	if e.role != tunnel.RoleInvestigate {
		return nil
	}
	if tunnel.RoleForTool(tool) != tunnel.RoleRemediate {
		return nil
	}
	return fmt.Errorf("%q is a write action and this is the investigation agent, which is deployed with a read-only ServiceAccount and holds no write permission on this cluster — write actions are served by the separate remediation agent (the argus-agent chart's remediate.enabled)", tool)
}

// executeTool is Execute's dispatch, split out only so Execute can apply
// capture-time redaction to every tool's output at a single chokepoint. Call
// Execute, never this — this returns unfiltered cluster data.
func (e *ToolExecutor) executeTool(ctx context.Context, tool string, args json.RawMessage) (json.RawMessage, bool, error) {
	if err := e.refuseIfWrongRole(tool); err != nil {
		return nil, false, err
	}

	switch tool {
	case "get_events":
		return e.getEvents(ctx, args)
	case "get_logs":
		return e.getLogs(ctx, args)
	case "describe_resource":
		return e.describeResource(ctx, args)
	case "list_resources":
		return e.listResources(ctx, args)
	case "get_owner_chain":
		return e.getOwnerChain(ctx, args)
	case "get_gitops_ownership":
		return e.getGitOpsOwnership(ctx, args)
	case "get_resource_schema":
		return e.getResourceSchema(ctx, args)
	case "list_nodeport_allocations":
		return e.listNodePortAllocations(ctx, args)
	case "reevaluate_rule":
		return e.reevaluateRule(ctx, args)
	case "scale_deployment":
		return e.scaleDeployment(ctx, args)
	case "upgrade_agent":
		return e.upgradeAgent(ctx, args)
	case "cordon_node":
		return e.cordonNode(ctx, args)
	case "drain_node":
		return e.drainNode(ctx, args)
	case "restart_pod":
		return e.restartPod(ctx, args)
	case "patch_resource_limits":
		return e.patchResourceLimits(ctx, args)
	case "revert_container_image":
		return e.revertContainerImage(ctx, args)
	case "patch_field":
		return e.patchField(ctx, args)
	case "annotate_resource":
		return e.annotateResource(ctx, args)
	case "label_resource":
		return e.labelResource(ctx, args)
	case "delete_resource":
		return e.deleteResource(ctx, args)
	case "create_resource":
		return e.createResource(ctx, args)
	case "dry_run_patch":
		return e.dryRunPatch(ctx, args)
	case "query_metrics":
		return e.queryMetrics(ctx, args)
	case "evaluate_network_policy":
		return e.evaluateNetworkPolicy(ctx, args)
	case "get_subject_permissions":
		return e.getSubjectPermissions(ctx, args)
	case "diagnose_autoscaler":
		return e.diagnoseAutoscaler(ctx, args)
	case "diagnose_rollout":
		return e.diagnoseRollout(ctx, args)
	case "get_policy_findings":
		return e.getPolicyFindings(ctx, args)
	case "explain_scheduling":
		return e.explainScheduling(ctx, args)
	case "get_drain_impact":
		return e.getDrainImpact(ctx, args)
	case "get_karpenter_capacity":
		return e.getKarpenterCapacity(ctx, args)
	case "get_rightsizing":
		return e.getRightsizing(ctx, args)
	case "get_gitops_insight":
		return e.getGitOpsInsight(ctx, args)
	case "get_traffic":
		return e.getTraffic(ctx, args)
	case "get_cost_summary":
		return e.getCostSummary(ctx, args)
	case "search_objects":
		return e.searchObjects(ctx, args)
	case "trace_service_path":
		return e.traceServicePath(ctx, args)
	case "get_neighborhood":
		return e.getNeighborhood(ctx, args)
	case "get_posture_findings":
		return e.getPostureFindings(ctx, args)
	case "get_upgrade_readiness":
		return e.getUpgradeReadiness(ctx, args)
	case "list_certificates":
		return e.listCertificates(ctx, args)
	case "get_helm_release_status":
		return e.getHelmReleaseStatus(ctx, args)
	case "list_helm_releases":
		return e.listHelmReleases(ctx, args)
	case "list_gitops_apps":
		return e.listGitOpsApps(ctx, args)
	case "get_namespace_topology":
		return e.getNamespaceTopology(ctx, args)
	case "get_network_policy_map":
		return e.getNetworkPolicyMap(ctx, args)
	case "open_execution_window":
		return e.openExecutionWindow(ctx, args)
	case "close_execution_window":
		return e.closeExecutionWindow(ctx, args)
	default:
		return nil, false, fmt.Errorf("unknown tool %q", tool)
	}
}

// maxAdmissionMessageLen bounds what admissionRejection will pass through. A
// webhook's message is written by whoever wrote the webhook, so its length is
// not something ARGUS controls; the bound is the actual control here, not the
// category check.
const maxAdmissionMessageLen = 600

// admissionRejection recognises "the cluster evaluated this request and said
// no" and lets that message through, in bounded form.
//
// This is a deliberate, narrow exception to sanitizeK8sErr's rule below, and
// it is what makes BACKLOG.md F12's gate worth having. The gate's whole value
// is telling an operator WHY a change cannot be made before they approve it,
// and for an admission rejection the reason exists only in that message: it
// names the policy, the field and the bound. Generic text turns a precise
// answer ("this ValidatingAdmissionPolicy refuses any change to spec.replicas")
// into "kubernetes API request failed", which is the failure mode this gate was
// built to remove rather than relocate. The same text is what F12's retry loop
// feeds back to the model so it can correct its own patch — with generic text
// there is nothing to correct against.
//
// Found by live testing, not by review: the first end-to-end run of the gate
// against a real ValidatingAdmissionPolicy correctly refused to execute and
// then reported "kubernetes API request failed", proving the mechanism and
// losing the entire point of it in the same breath.
//
// Why this is an acceptable exception, stated rather than assumed. The
// sanitizer's stated worry is leaking "a server URL, a TLS detail, or a chunk
// of an admission webhook's response body". Two of those are not in scope
// here: an Invalid/admission rejection is a statement ABOUT THE SUBMITTED
// REQUEST, produced by policy the cluster's own operator installed. The third
// — an arbitrarily large or noisy webhook body — is real, so it is bounded and
// flattened to one line rather than trusted. And the reader is the operator of
// that same cluster, approving that same cluster's incident, over an mTLS
// tunnel inside their own infrastructure.
//
// Deliberately does NOT cover plain 403s. An RBAC denial names roles,
// bindings and service accounts — genuine cluster-configuration detail with no
// diagnostic value for a remediation approver — so IsForbidden keeps its
// generic "permission denied" below unless the message identifies an admission
// webhook as the decider.
func admissionRejection(err error) (string, bool) {
	if err == nil {
		return "", false
	}
	msg := err.Error()
	// IsInvalid covers what a real cluster actually returns for a
	// ValidatingAdmissionPolicy denial (verified live: `The deployments "x" is
	// invalid: : ValidatingAdmissionPolicy '...' denied request: ...`) and for
	// schema validation failures, which are the other thing this gate is meant
	// to catch before approval.
	admission := apierrors.IsInvalid(err)
	// A ValidatingWebhookConfiguration denial comes back as Forbidden with the
	// API server's own fixed prefix. Matched on that prefix rather than on the
	// reason alone, so an ordinary RBAC 403 keeps its generic message.
	if !admission && apierrors.IsForbidden(err) && strings.Contains(msg, "admission webhook") {
		admission = true
	}
	if !admission {
		return "", false
	}
	// Full copy to the agent's log regardless, so bounding never loses
	// anything for whoever is debugging the cluster itself.
	logger.Error("tool executor: admission rejection", logging.Err(err))

	msg = strings.Join(strings.Fields(msg), " ") // flatten newlines/tabs
	if len(msg) > maxAdmissionMessageLen {
		msg = msg[:maxAdmissionMessageLen] + "… (truncated)"
	}
	return msg, true
}

// sanitizeK8sErr maps a client-go/API-server error to a short, generic
// message safe to send back over the tunnel — never the raw error string,
// which could otherwise carry a server URL, a TLS detail, or a chunk of an
// admission webhook's response body. The real error is always logged
// server-side (agent-side, matching internal/api's "log real error, generic
// detail to the caller" convention) before being discarded.
func sanitizeK8sErr(err error) error {
	if msg, ok := admissionRejection(err); ok {
		return errors.New(msg)
	}
	switch {
	case apierrors.IsNotFound(err):
		return errors.New("resource not found")
	case apierrors.IsForbidden(err), apierrors.IsUnauthorized(err):
		return errors.New("permission denied")
	case apierrors.IsTimeout(err), apierrors.IsServerTimeout(err), errors.Is(err, context.DeadlineExceeded):
		return errors.New("kubernetes API request timed out")
	default:
		logger.Error("tool executor: kubernetes API error", logging.Err(err))
		return errors.New("kubernetes API request failed")
	}
}

// parseGVKString parses this package's wire convention for a gvk argument:
// "<apiVersion>/<Kind>", e.g. "v1/Pod", "apps/v1/Deployment",
// "batch/v1/CronJob" — the same apiVersion+kind shape a manifest already
// uses, just joined with a slash instead of split across two YAML keys, so
// a caller building this string from a Finding's existing GVK field (see
// internal/tunnel.Finding.GVK) has an obvious, mechanical way to do it.
func parseGVKString(s string) (schema.GroupVersionKind, error) {
	idx := strings.LastIndex(s, "/")
	if idx < 0 {
		return schema.GroupVersionKind{}, fmt.Errorf("gvk %q must be of the form \"[group/]version/Kind\"", s)
	}
	apiVersion, kind := s[:idx], s[idx+1:]
	if kind == "" {
		return schema.GroupVersionKind{}, fmt.Errorf("gvk %q has an empty Kind", s)
	}
	gv, err := schema.ParseGroupVersion(apiVersion)
	if err != nil {
		return schema.GroupVersionKind{}, fmt.Errorf("gvk %q has an invalid apiVersion: %w", s, err)
	}
	return gv.WithKind(kind), nil
}

// formatGVK is parseGVKString's inverse — used when this file needs to
// report a GVK it discovered (e.g. an ownerReference's own apiVersion+kind)
// back out in the same wire convention callers send in.
func formatGVK(gvk schema.GroupVersionKind) string {
	return gvk.GroupVersion().String() + "/" + gvk.Kind
}

func mustMarshal(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		// Every caller passes a fixed, locally-defined struct — a marshal
		// failure here would mean a coding error in this file, not a
		// runtime condition worth plumbing an error return through.
		panic(fmt.Sprintf("tools.go: mustMarshal: %v", err))
	}
	return b
}
