package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"argus/internal/agent/certexpiry"
	"argus/internal/agent/objcache"
	"argus/internal/agent/posture"
	"argus/internal/logging"
	"argus/internal/tunnel"
)

// The posture detector (docs/CLUSTER_INSIGHT_SPECS.md CI-S4) runs the
// best-practice checks over the object cache on a slow timer and emits each
// high-severity result as a RISK finding — Class=risk, Impact=potential —
// which internal/gateway/promotion.go never promotes to an incident: these
// land on Signals, grouped by check, across the fleet. The full result set
// (both severities, every check) is served on demand by get_posture_findings.

const (
	postureDetectorID      = "k8s-posture"
	postureDetectorVersion = "1"
	postureFirstRunDelay   = 2 * time.Minute
	// postureMaxFindingsPerRun bounds what one scan can put on the finding
	// queue; the rest stay visible through get_posture_findings.
	postureMaxFindingsPerRun = 1000
)

// postureConfig is the operator's posture configuration (agent env).
type postureConfig struct {
	Interval          time.Duration
	IgnoredNamespaces []string
	DisabledChecks    []string
	// EmitWarnings also emits warning-level results as findings; off by
	// default so only danger-level results reach Signals.
	EmitWarnings bool
	// HelmStatus enables the Helm release-status check (CI-S17).
	HelmStatus bool
}

func (pc postureConfig) ignored() []string {
	if len(pc.IgnoredNamespaces) > 0 {
		return pc.IgnoredNamespaces
	}
	return posture.DefaultIgnoredNamespaces
}

var postureVersions = map[string]string{
	"": "v1", "apps": "v1", "batch": "v1", "networking.k8s.io": "v1", "autoscaling": "v2", "policy": "v1",
	"rbac.authorization.k8s.io": "v1", "storage.k8s.io": "v1",
}

func gvkString(group, kind string) string {
	v := postureVersions[group]
	if v == "" {
		v = "v1"
	}
	if group == "" {
		return v + "/" + kind
	}
	return group + "/" + v + "/" + kind
}

// postureScan builds the check input from the cache and runs every check.
func (e *ToolExecutor) postureScan(ctx context.Context, pc postureConfig) (*posture.ScanResults, []objcache.KindStatus, error) {
	c, err := e.cache()
	if err != nil {
		return nil, nil, err
	}
	in := &posture.CheckInput{}
	var errs []error
	collect := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}
	in.Pods, err = c.Pods("")
	collect(err)
	in.Deployments, err = c.Deployments("")
	collect(err)
	in.ReplicaSets, err = c.ReplicaSets("")
	collect(err)
	in.StatefulSets, err = c.StatefulSets("")
	collect(err)
	in.DaemonSets, err = c.DaemonSets("")
	collect(err)
	in.Jobs, err = c.Jobs("")
	collect(err)
	in.CronJobs, err = c.CronJobs("")
	collect(err)
	in.Services, err = c.Services("")
	collect(err)
	in.Ingresses, err = c.Ingresses("")
	collect(err)
	in.HorizontalPodAutoscalers, err = c.HorizontalPodAutoscalers("")
	collect(err)
	in.PodDisruptionBudgets, err = c.PodDisruptionBudgets("")
	collect(err)
	in.ConfigMaps, err = c.ConfigMaps("")
	collect(err)
	in.ServiceAccounts, err = c.ServiceAccounts("")
	collect(err)
	in.LimitRanges, err = c.LimitRanges("")
	collect(err)
	if e.typed != nil {
		if v, err := e.typed.Discovery().ServerVersion(); err == nil {
			in.ClusterVersion = strings.TrimPrefix(v.Major+"."+strings.TrimSuffix(v.Minor, "+"), "")
		}
		if groups, err := e.typed.Discovery().ServerGroups(); err == nil {
			for _, g := range groups.Groups {
				for _, v := range g.Versions {
					in.ServedAPIs = append(in.ServedAPIs, v.GroupVersion)
				}
			}
		}
	}
	apps, _ := c.Dynamic("argoproj.io", "Application", "")
	ks, _ := c.Dynamic("kustomize.toolkit.fluxcd.io", "Kustomization", "")
	hrs, _ := c.Dynamic("helm.toolkit.fluxcd.io", "HelmRelease", "")
	in.GitOpsToolsPresent = len(apps)+len(ks)+len(hrs) > 0
	if len(apps) > 0 {
		in.ArgoAppNames = map[string]struct{}{}
		for _, a := range apps {
			in.ArgoAppNames[a.GetName()] = struct{}{}
		}
	}

	// Storage (2026-10-13 parity review, PG2) — both kinds are already typed,
	// already-watched built-ins (objcache/kinds.go), so no new RBAC.
	in.PersistentVolumeClaims, err = c.PersistentVolumeClaims("")
	collect(err)
	in.PersistentVolumes, err = c.PersistentVolumes()
	collect(err)

	// Certificates (PG2) — the exact same source and reduction
	// tools_certs_helm.go's gatherCertificates uses for the Certificates tab
	// (CI-S16), minus the served-certificate probe: posture is the
	// cert-manager renewal half only. A nil slice (cert-manager's CRD not
	// synced) stays nil; a synced CRD with zero Certificates is set to an
	// empty, non-nil slice so RunChecks evaluates it rather than reporting
	// it missing.
	if certObjs, err := c.Dynamic("cert-manager.io", "Certificate", ""); err == nil {
		cm := make([]certexpiry.Input, 0, len(certObjs))
		for _, u := range certObjs {
			if ci, ok := certexpiry.FromCertManager(u); ok {
				cm = append(cm, ci)
			}
		}
		in.Certificates = certexpiry.Aggregate(certexpiry.Sources{CertManager: cm})
		if in.Certificates == nil {
			in.Certificates = []certexpiry.Cert{}
		}
	}

	// Traefik (PG2) — gated on CRD presence (State == synced), not on the
	// instance list being non-empty: a cluster with Traefik installed but no
	// routes yet is a real, evaluable "nothing wrong" state.
	routeState, mwState := c.State("traefik.io", "IngressRoute"), c.State("traefik.io", "Middleware")
	in.TraefikCRDsPresent = routeState == objcache.StateSynced || mwState == objcache.StateSynced
	if routeState == objcache.StateSynced {
		if objs, err := c.Dynamic("traefik.io", "IngressRoute", ""); err == nil {
			for _, u := range objs {
				in.TraefikRoutes = append(in.TraefikRoutes, traefikIngressRouteFrom(u))
			}
		}
	}
	if mwState == objcache.StateSynced {
		if objs, err := c.Dynamic("traefik.io", "Middleware", ""); err == nil {
			for _, u := range objs {
				in.TraefikMiddlewares = append(in.TraefikMiddlewares, traefikMiddlewareFrom(u))
			}
		}
	}

	// Crossplane (PG2): CrossplaneCRDsPresent/CrossplaneObjects are
	// deliberately left at their zero values. See CrossplaneObjects' own
	// doc comment (posture/types.go) — populating them needs a two-step
	// discovery (read every CompositeResourceDefinition, then dynamically
	// watch whatever Kind/group each one declares) that needs RBAC nobody
	// can grant ahead of time the way Traefik's two fixed kinds above were
	// granted. The check function, its registry entry and a fixture test
	// are built and ready for whenever that wiring lands.

	in.ConfigObjectRefs = posture.CollectConfigObjectRefs(in)
	_ = errs // a missing kind leaves its checks unevaluated; reported via coverage
	res := posture.RunChecks(in)
	res = posture.ApplySettings(res, pc.ignored(), pc.DisabledChecks)
	nsExceptions := map[string]string{}
	if nss, err := c.Namespaces(); err == nil {
		for _, ns := range nss {
			if v := ns.Annotations[posture.IgnoreChecksAnnotation]; v != "" {
				nsExceptions[ns.Name] = v
			}
		}
	}
	res = posture.ApplyExceptions(res, posture.ObjectExceptions(in), nsExceptions)
	cov := c.Coverage(kindPod, kindDeployment, [2]string{"apps", "StatefulSet"}, [2]string{"apps", "DaemonSet"},
		[2]string{"batch", "Job"}, [2]string{"batch", "CronJob"}, kindService, [2]string{"networking.k8s.io", "Ingress"},
		kindHPA, [2]string{"policy", "PodDisruptionBudget"}, [2]string{"", "ConfigMap"}, [2]string{"", "ServiceAccount"},
		[2]string{"", "PersistentVolumeClaim"}, [2]string{"", "PersistentVolume"})
	return res, cov, nil
}

// traefikNamespacedRef reads a {name, namespace?} reference map, defaulting
// namespace to defaultNS (Traefik's same-namespace-as-the-referrer
// convention) when the reference omits one.
func traefikNamespacedRef(m map[string]any, defaultNS string) (posture.NamespacedRef, bool) {
	name, _ := m["name"].(string)
	if name == "" {
		return posture.NamespacedRef{}, false
	}
	ns, _ := m["namespace"].(string)
	if ns == "" {
		ns = defaultNS
	}
	return posture.NamespacedRef{Namespace: ns, Name: name}, true
}

func traefikIngressRouteFrom(u *unstructured.Unstructured) posture.TraefikIngressRoute {
	r := posture.TraefikIngressRoute{Namespace: u.GetNamespace(), Name: u.GetName()}
	routes, _, _ := unstructured.NestedSlice(u.Object, "spec", "routes")
	for _, rt := range routes {
		route, ok := rt.(map[string]any)
		if !ok {
			continue
		}
		if svcs, ok := route["services"].([]any); ok {
			for _, s := range svcs {
				if sm, ok := s.(map[string]any); ok {
					if ref, ok := traefikNamespacedRef(sm, r.Namespace); ok {
						r.Services = append(r.Services, ref)
					}
				}
			}
		}
		if mws, ok := route["middlewares"].([]any); ok {
			for _, m := range mws {
				if mm, ok := m.(map[string]any); ok {
					if ref, ok := traefikNamespacedRef(mm, r.Namespace); ok {
						r.Middlewares = append(r.Middlewares, ref)
					}
				}
			}
		}
	}
	return r
}

func traefikMiddlewareFrom(u *unstructured.Unstructured) posture.TraefikMiddleware {
	m := posture.TraefikMiddleware{Namespace: u.GetNamespace(), Name: u.GetName()}
	if svc, ok, _ := unstructured.NestedMap(u.Object, "spec", "errors", "service"); ok {
		if ref, ok := traefikNamespacedRef(svc, m.Namespace); ok {
			m.ErrorsService = &ref
		}
	}
	if chain, _, _ := unstructured.NestedSlice(u.Object, "spec", "chain", "middlewares"); len(chain) > 0 {
		for _, c := range chain {
			if cm, ok := c.(map[string]any); ok {
				if ref, ok := traefikNamespacedRef(cm, m.Namespace); ok {
					m.ChainMiddlewares = append(m.ChainMiddlewares, ref)
				}
			}
		}
	}
	return m
}

// runPostureDetector is the posture detector's loop. It waits for the cache
// to sync before the first scan so an incomplete cache does not read as a
// clean cluster.
func runPostureDetector(ctx context.Context, executor *ToolExecutor, findingCh chan<- tunnel.Finding, cooldown time.Duration, pc postureConfig) {
	if pc.Interval <= 0 {
		pc.Interval = time.Hour
	}
	lastSent := map[string]time.Time{}
	timer := time.NewTimer(postureFirstRunDelay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		timer.Reset(pc.Interval)
		if executor == nil || executor.objects == nil || executor.objects.SyncedAt().IsZero() {
			continue
		}
		res, _, err := executor.postureScan(ctx, pc)
		if err != nil {
			logger.WarnContext(ctx, "posture scan failed", logging.Err(err))
			continue
		}
		now := time.Now()
		sent := 0
		findings := append([]posture.Finding(nil), res.Findings...)
		sort.SliceStable(findings, func(i, j int) bool { return findings[i].Severity == "danger" && findings[j].Severity != "danger" })
		for _, f := range findings {
			if f.Excepted || (f.Severity != "danger" && !pc.EmitWarnings) {
				continue
			}
			if sent >= postureMaxFindingsPerRun {
				break
			}
			meta := res.Checks[f.CheckID]
			sev := "medium"
			if f.Severity == "danger" {
				sev = "high"
			}
			title := meta.Title
			if title == "" {
				title = f.CheckID
			}
			fp := computeFingerprint(f.Namespace, f.Kind, f.Name, "posture:"+f.CheckID)
			if !shouldSend(fp, now, lastSent, cooldown) {
				continue
			}
			finding := tunnel.Finding{
				DetectorID:      postureDetectorID,
				DetectorVersion: postureDetectorVersion,
				Fingerprint:     fp,
				GVK:             gvkString(f.Group, f.Kind),
				Namespace:       f.Namespace,
				ObjectName:      f.Name,
				Reason:          "Posture" + upperFirst(f.CheckID),
				Message:         fmt.Sprintf("%s (%s): %s", title, f.Category, f.Message),
				OccurrenceCount: 1,
				Severity:        sev,
				Class:           tunnel.FindingClassRisk,
				Confidence:      tunnel.FindingConfidenceVerified,
				Impact:          tunnel.FindingImpactPotential,
				OccurredAt:      now,
				RuleID:          f.CheckID,
			}
			if emitFinding(finding, findingCh) {
				lastSent[fp] = now
				sent++
			}
		}
		certs := executor.emitCertificateFindings(ctx, findingCh, lastSent, cooldown)
		helm := 0
		if pc.HelmStatus {
			helm = executor.emitHelmFindings(ctx, findingCh, lastSent, cooldown)
		}
		logger.InfoContext(ctx, "posture scan complete", slog.Int("results", len(res.Findings)), slog.Int("emitted", sent),
			slog.Int("certificate_findings", certs), slog.Int("helm_findings", helm))
	}
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// ---------------------------------------------------------------- get_posture_findings

var postureCfgMu sync.RWMutex
var activePostureConfig postureConfig

type postureResult struct {
	insightMeta
	Summary  posture.ScanSummary          `json:"summary"`
	Checks   map[string]posture.CheckMeta `json:"checks"`
	Findings []posture.Finding            `json:"findings"`
	Total    int                          `json:"total"`
}

func (e *ToolExecutor) getPostureFindings(ctx context.Context, raw json.RawMessage) (json.RawMessage, bool, error) {
	var a struct {
		Namespace string `json:"namespace"`
		CheckID   string `json:"checkId"`
		Category  string `json:"category"`
		Limit     int    `json:"limit"`
		// The organisation's hub-side posture settings (CI-P9 d), applied on
		// top of this agent's own chart values.
		DisabledChecks    []string `json:"disabledChecks"`
		IgnoredNamespaces []string `json:"ignoredNamespaces"`
	}
	if err := decodeInsightArgs(raw, &a); err != nil {
		return nil, false, err
	}
	if a.Limit <= 0 || a.Limit > 500 {
		a.Limit = 500
	}
	postureCfgMu.RLock()
	pc := activePostureConfig
	postureCfgMu.RUnlock()
	res, cov, err := e.postureScan(ctx, pc)
	if err != nil {
		return nil, false, err
	}
	res = posture.ApplySettings(res, a.IgnoredNamespaces, a.DisabledChecks)
	var out []posture.Finding
	for _, f := range res.Findings {
		if (a.Namespace == "" || f.Namespace == a.Namespace) && (a.CheckID == "" || f.CheckID == a.CheckID) && (a.Category == "" || strings.EqualFold(f.Category, a.Category)) {
			out = append(out, f)
		}
	}
	total := len(out)
	m := insightMeta{ObservedAt: time.Now().UTC(), Coverage: cov}
	if len(out) > a.Limit {
		out = out[:a.Limit]
		m.Truncated = true
	}
	if out == nil {
		out = []posture.Finding{}
	}
	return marshalInsight(postureResult{insightMeta: m, Summary: res.Summary, Checks: res.Checks, Findings: out, Total: total})
}

// postureCooldown re-sends an unchanged posture finding at most once per
// day, or once per scan interval when that is longer — enough to keep the
// Signals row current without re-emitting the whole fleet every hour.
func postureCooldown(interval time.Duration) time.Duration {
	if interval > 24*time.Hour {
		return interval
	}
	return 24 * time.Hour
}
