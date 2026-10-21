package agent

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"argus/internal/agent/health"
	"argus/internal/agent/helmstatus"
	"argus/internal/agent/objcache"
	"argus/internal/agent/topology"
	"argus/internal/gitopsinsight"
)

// The cluster inventory tools (PROJECT.md AD5/AD6): which Helm releases and
// GitOps applications a cluster runs, and one namespace's relationship map.
// All three answer from the object cache; list_helm_releases adds the D-R12
// label-only Secret gets for each release's newest revision. None of them
// changes anything, and the UI built on them offers no upgrade, rollback,
// sync or suspend control — those go through an approved plan.

// ---------------------------------------------------------------- list_helm_releases

const (
	maxHelmReleases = 200
	// helmStatusConcurrency and helmStatusBudget bound the label-only gets:
	// the whole call must answer inside the gateway's 12s tool timeout, and
	// a release not reached in time says so rather than guessing.
	helmStatusConcurrency = 8
	helmStatusBudget      = 8 * time.Second
	helmLatestMaxGets     = 12
	maxHelmProblems       = 3
)

// helmScanKinds are the cached kinds whose meta.helm.sh annotations name a
// release. Workload kinds come first, so the release's main object is the
// first workload found. Secrets are not a cached kind and are never scanned.
var helmScanKinds = [][2]string{
	{"apps", "Deployment"}, {"apps", "StatefulSet"}, {"apps", "DaemonSet"},
	{"batch", "CronJob"}, {"batch", "Job"},
	{"", "Service"}, {"networking.k8s.io", "Ingress"},
	{"", "ConfigMap"}, {"", "ServiceAccount"}, {"", "PersistentVolumeClaim"},
	{"autoscaling", "HorizontalPodAutoscaler"}, {"policy", "PodDisruptionBudget"},
	{"networking.k8s.io", "NetworkPolicy"},
	{"rbac.authorization.k8s.io", "Role"}, {"rbac.authorization.k8s.io", "RoleBinding"},
	{"rbac.authorization.k8s.io", "ClusterRole"}, {"rbac.authorization.k8s.io", "ClusterRoleBinding"},
	{"admissionregistration.k8s.io", "ValidatingWebhookConfiguration"},
	{"admissionregistration.k8s.io", "MutatingWebhookConfiguration"},
	{"apiextensions.k8s.io", "CustomResourceDefinition"},
}

// helmMainKindRank picks the object a release row opens: a workload over a
// Service over anything else.
var helmMainKindRank = map[string]int{
	"Deployment": 0, "StatefulSet": 1, "DaemonSet": 2, "CronJob": 3, "Job": 4, "Service": 5,
}

type inventoryRef struct {
	Kind      string `json:"kind"`
	APIGroup  string `json:"apiGroup,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
}

type helmObjectProblem struct {
	inventoryRef
	Health string `json:"health"`
	Reason string `json:"reason,omitempty"`
}

type helmKindCount struct {
	Kind  string `json:"kind"`
	Count int    `json:"count"`
}

type helmReleaseRow struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	// Revision/Status come from the newest revision Secret's labels; Updated
	// is that revision's latest metadata timestamp (helmstatus.Revision.Updated).
	// RevisionLowerBound is set when the get budget ran out before the
	// newest revision was pinned: the revision shown is at least this.
	Revision           int        `json:"revision,omitempty"`
	RevisionLowerBound bool       `json:"revisionLowerBound,omitempty"`
	Status             string     `json:"status,omitempty"`
	Updated            *time.Time `json:"updated,omitempty"`
	// CreatedAt is when the newest revision was made: its release Secret's
	// metadata.creationTimestamp. ModifiedAt is Helm's own modifiedAt label
	// on that Secret, verbatim — not reliable as a revision date (see
	// helmstatus.Revision).
	CreatedAt  *time.Time `json:"createdAt,omitempty"`
	ModifiedAt *time.Time `json:"modifiedAt,omitempty"`
	// StatusUnavailable says why Revision/Status are absent.
	StatusUnavailable string `json:"statusUnavailable,omitempty"`
	// LastOperation is set when the newest revision itself failed or is
	// stuck pending (helmstatus.Analyze over that one revision).
	LastOperation *helmstatus.Operation `json:"lastOperation,omitempty"`

	// Objects counts cached objects carrying this release's annotations;
	// Graded those whose health ARGUS can grade (workloads, PVCs), with
	// Health the worst of them. Health is empty when nothing was graded.
	Objects      int                 `json:"objects"`
	ObjectKinds  []helmKindCount     `json:"objectKinds,omitempty"`
	Graded       int                 `json:"graded"`
	HealthCounts map[string]int      `json:"healthCounts,omitempty"`
	Health       string              `json:"health,omitempty"`
	Problems     []helmObjectProblem `json:"problems,omitempty"`
	MainObject   *inventoryRef       `json:"mainObject,omitempty"`
	// Members are the cached objects carrying this release's meta.helm.sh
	// annotations, worst health first then kind/name, capped at
	// maxHelmMembers; MembersTruncated is set when capped (Objects stays the
	// true total). Health is empty for a kind that is not graded.
	Members          []helmMember `json:"members,omitempty"`
	MembersTruncated bool         `json:"membersTruncated,omitempty"`
	// App is the argus.io/app annotation on any of the release's objects.
	App string `json:"app,omitempty"`
}

// appAnnotation lets a team name the application an object belongs to, so
// the Applications view folds it with its siblings in other clusters
// without guessing (PROJECT.md PG19).
const appAnnotation = "argus.io/app"

// maxHelmMembers caps a release row's member list.
const maxHelmMembers = 50

type helmMember struct {
	inventoryRef
	Health string `json:"health,omitempty"`
}

type helmReleasesResult struct {
	insightMeta
	Releases []helmReleaseRow `json:"releases"`
	// Total is the number of distinct releases found before the cap.
	Total int    `json:"total"`
	Note  string `json:"note"`
}

type helmAccumulator struct {
	row      helmReleaseRow
	members  []helmMember
	kinds    map[string]int
	mainRank int
}

func (e *ToolExecutor) listHelmReleases(ctx context.Context, raw json.RawMessage) (json.RawMessage, bool, error) {
	c, err := e.cache()
	if err != nil {
		return nil, false, err
	}
	var a struct {
		Namespace string `json:"namespace"`
	}
	if err := decodeInsightArgs(raw, &a); err != nil {
		return nil, false, err
	}
	now := time.Now()
	acc := map[[2]string]*helmAccumulator{}
	for _, gk := range helmScanKinds {
		objs, err := c.List(gk[0], gk[1], "")
		if err != nil {
			continue // reported through coverage
		}
		for _, o := range objs {
			mo, err := meta.Accessor(o)
			if err != nil {
				continue
			}
			ann := mo.GetAnnotations()
			name, ns := ann["meta.helm.sh/release-name"], ann["meta.helm.sh/release-namespace"]
			if name == "" || ns == "" || (a.Namespace != "" && ns != a.Namespace) {
				continue
			}
			key := [2]string{ns, name}
			r := acc[key]
			if r == nil {
				r = &helmAccumulator{row: helmReleaseRow{Name: name, Namespace: ns, HealthCounts: map[string]int{}}, kinds: map[string]int{}, mainRank: 1 << 30}
				acc[key] = r
			}
			r.row.Objects++
			r.kinds[gk[1]]++
			if a := mo.GetAnnotations()[appAnnotation]; a != "" && r.row.App == "" {
				r.row.App = a
			}
			ref := inventoryRef{Kind: gk[1], APIGroup: gk[0], Namespace: mo.GetNamespace(), Name: mo.GetName()}
			member := helmMember{inventoryRef: ref}
			if rank, ok := helmMainKindRank[gk[1]]; ok {
				// Prefer the workload named after the release among equals.
				if mo.GetName() != name {
					rank = rank*2 + 1
				} else {
					rank *= 2
				}
				if rank < r.mainRank || (rank == r.mainRank && r.row.MainObject != nil && ref.Name < r.row.MainObject.Name) {
					r.mainRank, r.row.MainObject = rank, &ref
				}
			}
			if v, graded := gradeHelmObject(o, now); graded {
				member.Health = string(v.Level)
				r.row.Graded++
				r.row.HealthCounts[string(v.Level)]++
				r.row.Health = string(health.WorseOf(health.Level(r.row.Health), v.Level))
				if (v.Level == health.LevelDegraded || v.Level == health.LevelUnhealthy) && len(r.row.Problems) < maxHelmProblems {
					r.row.Problems = append(r.row.Problems, helmObjectProblem{inventoryRef: ref, Health: string(v.Level), Reason: v.Reason})
				}
			}
			r.members = append(r.members, member)
		}
	}

	keys := make([][2]string, 0, len(acc))
	for k := range acc {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i][0] != keys[j][0] {
			return keys[i][0] < keys[j][0]
		}
		return keys[i][1] < keys[j][1]
	})
	out := helmReleasesResult{
		insightMeta: e.meta(helmScanKinds...),
		Total:       len(keys),
		Releases:    []helmReleaseRow{},
		Note:        "Release names come from the meta.helm.sh annotations on cached objects; revision and status from the newest release Secret's labels only. Chart version, values and manifests are deliberately not read.",
	}
	if len(keys) > maxHelmReleases {
		keys = keys[:maxHelmReleases]
		out.Truncated = true
	}
	for _, k := range keys {
		r := acc[k]
		for kind, n := range r.kinds {
			r.row.ObjectKinds = append(r.row.ObjectKinds, helmKindCount{Kind: kind, Count: n})
		}
		sort.Slice(r.row.ObjectKinds, func(i, j int) bool {
			if r.row.ObjectKinds[i].Count != r.row.ObjectKinds[j].Count {
				return r.row.ObjectKinds[i].Count > r.row.ObjectKinds[j].Count
			}
			return r.row.ObjectKinds[i].Kind < r.row.ObjectKinds[j].Kind
		})
		r.row.Members, r.row.MembersTruncated = sortHelmMembers(r.members)
		if len(r.row.HealthCounts) == 0 {
			r.row.HealthCounts = nil
		}
		out.Releases = append(out.Releases, r.row)
	}
	e.fillHelmStatuses(ctx, out.Releases, now)
	return marshalInsight(out)
}

// sortHelmMembers orders a release's members worst health first (an
// ungraded member after every graded one), then by kind, namespace and name,
// and caps the list at maxHelmMembers.
func sortHelmMembers(ms []helmMember) ([]helmMember, bool) {
	rank := func(m helmMember) int {
		if m.Health == "" {
			return -1
		}
		return health.Rank(health.Level(m.Health))
	}
	sort.SliceStable(ms, func(i, j int) bool {
		a, b := ms[i], ms[j]
		if ra, rb := rank(a), rank(b); ra != rb {
			return ra > rb
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		return a.Name < b.Name
	})
	if len(ms) > maxHelmMembers {
		return ms[:maxHelmMembers], true
	}
	return ms, false
}

// gradeHelmObject grades the kinds internal/agent/health knows; anything
// else (a ConfigMap, a Role) has no health of its own and is not graded.
func gradeHelmObject(o any, now time.Time) (health.Verdict, bool) {
	switch o.(type) {
	case *appsv1.Deployment, *appsv1.StatefulSet, *appsv1.DaemonSet, *batchv1.Job, *batchv1.CronJob, *corev1.PersistentVolumeClaim:
		return health.Workload(o, now), true
	}
	return health.Verdict{}, false
}

// fillHelmStatuses reads each release's newest revision from Secret labels
// (helmSecretMeta, D-R12): find the latest N by named gets, then read that
// one revision's labels. Bounded in concurrency and in wall time.
func (e *ToolExecutor) fillHelmStatuses(ctx context.Context, rows []helmReleaseRow, now time.Time) {
	if e.typed == nil {
		for i := range rows {
			rows[i].StatusUnavailable = "this agent has no cluster client to read release metadata with"
		}
		return
	}
	bctx, cancel := context.WithTimeout(ctx, helmStatusBudget)
	defer cancel()
	g := helmSecretMeta{e}
	sem := make(chan struct{}, helmStatusConcurrency)
	var wg sync.WaitGroup
	for i := range rows {
		wg.Add(1)
		go func(r *helmReleaseRow) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-bctx.Done():
				r.StatusUnavailable = "not read within this call's time budget; refresh to read the rest"
				return
			}
			defer func() { <-sem }()
			readHelmStatus(bctx, g, r, now)
		}(&rows[i])
	}
	wg.Wait()
}

func readHelmStatus(ctx context.Context, g helmstatus.SecretMetaGetter, r *helmReleaseRow, now time.Time) {
	if ctx.Err() != nil {
		r.StatusUnavailable = "not read within this call's time budget; refresh to read the rest"
		return
	}
	key := r.Namespace + "/" + r.Name
	helmRevisionHints.Lock()
	hint := helmRevisionHints.m[key]
	helmRevisionHints.Unlock()
	latest, err := helmstatus.LatestRevisionFrom(ctx, g, r.Namespace, r.Name, hint, helmLatestMaxGets)
	switch {
	case errors.Is(err, helmstatus.ErrNoRevisionFound):
		r.StatusUnavailable = "no release Secret found under this name; the release may be stored elsewhere (a ConfigMap or SQL driver) or the objects were adopted from another tool"
		return
	case latest == 0 && err != nil:
		r.StatusUnavailable = helmStatusErrorText(ctx, err)
		return
	case errors.Is(err, helmstatus.ErrBudgetExhausted):
		r.RevisionLowerBound = true
	}
	helmRevisionHints.Lock()
	helmRevisionHints.m[key] = latest
	helmRevisionHints.Unlock()
	hist, err := helmstatus.History(ctx, g, r.Namespace, r.Name, latest, 1)
	if err != nil || len(hist) == 0 {
		r.Revision = latest
		if err != nil {
			r.StatusUnavailable = helmStatusErrorText(ctx, err)
		} else {
			r.StatusUnavailable = "the newest revision's labels do not describe this release"
		}
		return
	}
	rev := hist[len(hist)-1]
	r.Revision, r.Status = rev.Revision, rev.Status
	if !rev.Updated.IsZero() {
		t := rev.Updated
		r.Updated = &t
	}
	if !rev.CreatedAt.IsZero() {
		t := rev.CreatedAt
		r.CreatedAt = &t
	}
	if !rev.ModifiedAt.IsZero() {
		t := rev.ModifiedAt
		r.ModifiedAt = &t
	}
	if op := helmstatus.Analyze(r.Name, latest, hist, helmstatus.Options{Now: now}).LastOperation; op != nil {
		r.LastOperation = op
	}
}

func helmStatusErrorText(ctx context.Context, err error) string {
	// client-go's rate limiter refuses a wait it knows would overrun the
	// deadline before the deadline itself passes; that is the budget too.
	if ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "rate limiter") {
		return "not read within this call's time budget; refresh to read the rest"
	}
	if strings.Contains(err.Error(), "forbidden") {
		return "the agent may not read release metadata in this namespace"
	}
	return "release metadata could not be read"
}

// ---------------------------------------------------------------- list_gitops_apps

const maxGitOpsApps = 300

// gitOpsAppKinds are the application-level GitOps kinds listed. Flux source
// kinds (GitRepository, …) and Argo ApplicationSets are inputs to these, not
// applications, and stay on get_gitops_insight.
var gitOpsAppKinds = [][2]string{
	{"argoproj.io", "Application"},
	{"kustomize.toolkit.fluxcd.io", "Kustomization"},
	{"helm.toolkit.fluxcd.io", "HelmRelease"},
}

type gitOpsAppRow struct {
	Tool      string `json:"tool"`
	Kind      string `json:"kind"`
	APIGroup  string `json:"apiGroup"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Sync      string `json:"sync,omitempty"`
	Health    string `json:"health,omitempty"`
	// Source: Argo repoURL/path/chart (first source of a multi-source app,
	// with SourceCount saying how many); Flux the sourceRef plus path or
	// chart. TargetRevision is what was asked for (a branch, tag or
	// version), Revision what was last applied.
	RepoURL        string `json:"repoURL,omitempty"`
	Path           string `json:"path,omitempty"`
	Chart          string `json:"chart,omitempty"`
	SourceRef      string `json:"sourceRef,omitempty"`
	SourceCount    int    `json:"sourceCount,omitempty"`
	TargetRevision string `json:"targetRevision,omitempty"`
	Revision       string `json:"revision,omitempty"`
	// Destination is where the managed objects land: Argo's destination
	// server/name + namespace; Flux's targetNamespace (or the object's own).
	DestinationServer    string `json:"destinationServer,omitempty"`
	DestinationNamespace string `json:"destinationNamespace,omitempty"`
	// LastSync is Argo's last operation finish (else reconciledAt) or Flux's
	// last handled reconcile / Ready transition.
	LastSync    string `json:"lastSync,omitempty"`
	AutoSync    string `json:"autoSync,omitempty"`
	Suspended   bool   `json:"suspended,omitempty"`
	Reconciling bool   `json:"reconciling,omitempty"`
	Terminating bool   `json:"terminating,omitempty"`
	Managed     int    `json:"managed"`
	gitopsinsight.Headline
	Problem bool `json:"problem,omitempty"`
	// App is the argus.io/app annotation, when set: a declared application
	// name that overrides matching by source (PROJECT.md PG19).
	App string `json:"app,omitempty"`
}

type gitOpsCounts struct {
	Total       int `json:"total"`
	OutOfSync   int `json:"outOfSync"`
	SyncUnknown int `json:"syncUnknown"`
	Degraded    int `json:"degraded"`
	Suspended   int `json:"suspended"`
	Reconciling int `json:"reconciling"`
}

type gitOpsAppsResult struct {
	insightMeta
	Apps   []gitOpsAppRow `json:"apps"`
	Counts gitOpsCounts   `json:"counts"`
	// Kinds reports, per listed kind, whether it is served and synced in the
	// agent's cache — an absent kind means that controller is not installed
	// (or not visible), which is a coverage fact, not an error.
	Kinds []objcache.KindStatus `json:"kinds"`
}

func (e *ToolExecutor) listGitOpsApps(_ context.Context, raw json.RawMessage) (json.RawMessage, bool, error) {
	c, err := e.cache()
	if err != nil {
		return nil, false, err
	}
	var a struct {
		Namespace string `json:"namespace"`
	}
	if err := decodeInsightArgs(raw, &a); err != nil {
		return nil, false, err
	}
	out := gitOpsAppsResult{insightMeta: e.meta(), Apps: []gitOpsAppRow{}}
	for _, gk := range gitOpsAppKinds {
		st := c.State(gk[0], gk[1])
		if st == "" {
			st = objcache.StateAbsent
		}
		out.Kinds = append(out.Kinds, objcache.KindStatus{Group: gk[0], Kind: gk[1], State: st})
		objs, err := c.Dynamic(gk[0], gk[1], "")
		if err != nil {
			continue
		}
		for _, o := range objs {
			row := gitOpsRow(o)
			if a.Namespace != "" && row.Namespace != a.Namespace && row.DestinationNamespace != a.Namespace {
				continue
			}
			out.Counts.Total++
			if row.Sync == "OutOfSync" {
				out.Counts.OutOfSync++
			}
			if row.Sync == "Unknown" {
				out.Counts.SyncUnknown++
			}
			if row.Health == "Degraded" || row.Health == "Missing" {
				out.Counts.Degraded++
			}
			if row.Suspended {
				out.Counts.Suspended++
			}
			if row.Reconciling {
				out.Counts.Reconciling++
			}
			out.Apps = append(out.Apps, row)
		}
	}
	// Problems first, so a cap never drops one in favour of a healthy app.
	sort.SliceStable(out.Apps, func(i, j int) bool {
		if out.Apps[i].Problem != out.Apps[j].Problem {
			return out.Apps[i].Problem
		}
		if out.Apps[i].Namespace != out.Apps[j].Namespace {
			return out.Apps[i].Namespace < out.Apps[j].Namespace
		}
		return out.Apps[i].Name < out.Apps[j].Name
	})
	if len(out.Apps) > maxGitOpsApps {
		out.Apps = out.Apps[:maxGitOpsApps]
		out.Truncated = true
	}
	return marshalInsight(out)
}

func gitOpsRow(o *unstructured.Unstructured) gitOpsAppRow {
	s := gitopsinsight.Summarize(o)
	group, _, _ := strings.Cut(o.GetAPIVersion(), "/")
	row := gitOpsAppRow{
		Tool: s.Tool, Kind: o.GetKind(), APIGroup: group, Namespace: o.GetNamespace(), Name: o.GetName(),
		Sync: s.Sync, Health: s.Health, Revision: s.LastRevision, AutoSync: s.AutoSync,
		Terminating: s.Terminating, Managed: s.ManagedResourcesTotal,
		Headline: gitopsinsight.HeadlineFor(o, s, time.Now()),
		App:      o.GetAnnotations()[appAnnotation],
	}
	str := func(fields ...string) string { v, _, _ := unstructured.NestedString(o.Object, fields...); return v }
	switch s.Tool {
	case gitopsinsight.ToolArgoCD:
		src, _, _ := unstructured.NestedMap(o.Object, "spec", "source")
		if len(src) == 0 {
			if srcs, _, _ := unstructured.NestedSlice(o.Object, "spec", "sources"); len(srcs) > 0 {
				src, _ = srcs[0].(map[string]any)
				row.SourceCount = len(srcs)
			}
		}
		row.RepoURL, row.Path, row.Chart = stringField(src, "repoURL"), stringField(src, "path"), stringField(src, "chart")
		row.TargetRevision = stringField(src, "targetRevision")
		row.DestinationServer = str("spec", "destination", "server")
		if row.DestinationServer == "" {
			row.DestinationServer = str("spec", "destination", "name")
		}
		row.DestinationNamespace = str("spec", "destination", "namespace")
		row.LastSync = str("status", "operationState", "finishedAt")
		if row.LastSync == "" {
			row.LastSync = s.LastReconcile
		}
		row.Reconciling = s.OperationPhase == "Running"
	case gitopsinsight.ToolFlux:
		row.SourceRef = s.Source
		if o.GetKind() == "HelmRelease" {
			row.Chart = str("spec", "chart", "spec", "chart")
			row.TargetRevision = str("spec", "chart", "spec", "version")
		} else {
			row.Path = str("spec", "path")
		}
		row.DestinationNamespace = str("spec", "targetNamespace")
		if row.DestinationNamespace == "" {
			row.DestinationNamespace = o.GetNamespace()
		}
		row.LastSync = s.LastReconcile
		row.Suspended, _, _ = unstructured.NestedBool(o.Object, "spec", "suspend")
		row.Reconciling = gitopsinsight.FluxStatus(o).Reconciling || s.Sync == "Reconciling"
	}
	// A problem is something a person should look at: drift, an unknown or
	// failed comparison, broken health, a stopped controller. An in-flight
	// sync and a deliberate suspension are counted, not flagged.
	row.Problem = row.Sync == "OutOfSync" || row.Sync == "Unknown" || row.Health == "Degraded" || row.Health == "Missing" || row.Stuck ||
		(row.Text != "" && !row.Reconciling && !row.Suspended && row.Health != "Progressing")
	return row
}

func stringField(m map[string]any, k string) string {
	if m == nil {
		return ""
	}
	v, _ := m[k].(string)
	return v
}

// ---------------------------------------------------------------- get_namespace_topology

const maxNamespaceIndex = 500

type namespaceIndexRow struct {
	Name string `json:"name"`
	Pods int    `json:"pods"`
	// Workloads counts what the namespace map draws a card for: Deployments,
	// StatefulSets, DaemonSets, CronJobs, and Jobs no CronJob owns (those
	// join their CronJob's card).
	Workloads int `json:"workloads"`
	Services  int `json:"services"`
	// NotHealthy is PodsNotHealthy + WorkloadsNotHealthy, kept for clients
	// that predate the split. The picker names the two separately so its
	// workload figure is the same count as the map's status line.
	NotHealthy          int `json:"notHealthy"`
	PodsNotHealthy      int `json:"podsNotHealthy"`
	WorkloadsNotHealthy int `json:"workloadsNotHealthy"`
}

type namespaceTopologyResult struct {
	insightStamp
	*topology.NamespaceGraph
	// Namespaces is the picker index, returned when no namespace was asked
	// for: every namespace with its pod, workload and Service counts, largest
	// first.
	Namespaces          []namespaceIndexRow `json:"namespaces,omitempty"`
	NamespacesTruncated bool                `json:"namespacesTruncated,omitempty"`
}

func (e *ToolExecutor) getNamespaceTopology(_ context.Context, raw json.RawMessage) (json.RawMessage, bool, error) {
	c, err := e.cache()
	if err != nil {
		return nil, false, err
	}
	var a struct {
		Namespace string `json:"namespace"`
		Cap       int    `json:"cap"`
	}
	if err := decodeInsightArgs(raw, &a); err != nil {
		return nil, false, err
	}
	if a.Namespace == "" {
		return marshalInsight(e.namespaceIndex(c))
	}
	p := topologyProvider{c}
	g, err := topology.NamespaceMap(p, a.Namespace, topology.NamespaceOptions{MaxNodes: a.Cap, Dynamic: p})
	if err != nil {
		return nil, false, err
	}
	res := namespaceTopologyResult{insightStamp: stampOf(e.meta()), NamespaceGraph: g}
	b, _, err := marshalInsight(res)
	if err == nil {
		return b, false, nil
	}
	// Over the frame budget: per-node summaries are the expendable part.
	for i := range g.Nodes {
		g.Nodes[i].Summary = nil
	}
	return marshalInsight(res)
}

func (e *ToolExecutor) namespaceIndex(c *objcache.Cache) namespaceTopologyResult {
	now := time.Now()
	rows := map[string]*namespaceIndexRow{}
	row := func(ns string) *namespaceIndexRow {
		r := rows[ns]
		if r == nil {
			r = &namespaceIndexRow{Name: ns}
			rows[ns] = r
		}
		return r
	}
	if nss, err := c.Namespaces(); err == nil {
		for _, n := range nss {
			row(n.Name)
		}
	}
	if pods, err := c.Pods(""); err == nil {
		for _, p := range pods {
			r := row(p.Namespace)
			r.Pods++
			if l := health.PodDisplayLevel(p, now); l == health.LevelDegraded || l == health.LevelUnhealthy {
				r.NotHealthy++
				r.PodsNotHealthy++
			}
		}
	}
	countWorkload := func(ns string, o any) {
		r := row(ns)
		r.Workloads++
		if l := health.Workload(o, now).Level; l == health.LevelDegraded || l == health.LevelUnhealthy {
			r.NotHealthy++
			r.WorkloadsNotHealthy++
		}
	}
	if ds, err := c.Deployments(""); err == nil {
		for _, d := range ds {
			countWorkload(d.Namespace, d)
		}
	}
	if ss, err := c.StatefulSets(""); err == nil {
		for _, s := range ss {
			countWorkload(s.Namespace, s)
		}
	}
	if ds, err := c.DaemonSets(""); err == nil {
		for _, d := range ds {
			countWorkload(d.Namespace, d)
		}
	}
	if cjs, err := c.CronJobs(""); err == nil {
		for _, cj := range cjs {
			countWorkload(cj.Namespace, cj)
		}
	}
	if jobs, err := c.Jobs(""); err == nil {
		for _, j := range jobs {
			if owner := metav1.GetControllerOf(j); owner != nil && owner.Kind == "CronJob" {
				continue // drawn inside its CronJob's card
			}
			countWorkload(j.Namespace, j)
		}
	}
	if sv, err := c.Services(""); err == nil {
		for _, s := range sv {
			row(s.Namespace).Services++
		}
	}
	out := namespaceTopologyResult{insightStamp: stampOf(e.meta(kindNamespace, kindPod, kindDeployment, [2]string{"apps", "StatefulSet"}, [2]string{"apps", "DaemonSet"},
		[2]string{"batch", "CronJob"}, [2]string{"batch", "Job"}, kindService))}
	for _, r := range rows {
		out.Namespaces = append(out.Namespaces, *r)
	}
	sort.Slice(out.Namespaces, func(i, j int) bool {
		a, b := out.Namespaces[i], out.Namespaces[j]
		if a.Pods+a.Workloads+a.Services != b.Pods+b.Workloads+b.Services {
			return a.Pods+a.Workloads+a.Services > b.Pods+b.Workloads+b.Services
		}
		return a.Name < b.Name
	})
	if len(out.Namespaces) > maxNamespaceIndex {
		out.Namespaces = out.Namespaces[:maxNamespaceIndex]
		out.NamespacesTruncated = true
	}
	if out.Namespaces == nil {
		out.Namespaces = []namespaceIndexRow{}
	}
	return out
}
