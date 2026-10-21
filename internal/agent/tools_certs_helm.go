package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"argus/internal/agent/certexpiry"
	"argus/internal/agent/helmstatus"
	"argus/internal/agent/objcache"
	"argus/internal/tunnel"
)

// ---------------------------------------------------------------- certificates (CI-S16)

const (
	certProbeTimeout     = 3 * time.Second
	certProbeConcurrency = 8
	certProbeMaxHosts    = 100
)

// certProbeServed is the opt-in served-certificate source
// (certExpiry.probeIngressHosts on the agent chart). Off by default: when on,
// the investigate agent opens a TLS connection to each Ingress address with
// the host as SNI, reads the presented certificate's expiry and closes —
// no HTTP request, no verification, no Secret read. lld/01-threat-model.md
// records this as the agent's one outbound probe.
var certProbeServed bool

type certsResult struct {
	insightMeta
	Certificates []certexpiry.Cert `json:"certificates"`
	ServedProbed bool              `json:"servedProbed"`
	ProbeErrors  int               `json:"probeErrors,omitempty"`
	// UncoveredTLSSecrets is PG5's state-coverage count (2026-10-13 parity
	// review): how many distinct Ingress/Gateway TLS secretNames this scan
	// could not explain — no cert-manager Certificate issues them, and
	// (unless ServedProbed) no served-endpoint reading was attempted either.
	// Never implied to be the complete picture: ServedProbed being false
	// means the second half of the check didn't run at all, not that it
	// found nothing.
	UncoveredTLSSecrets int `json:"uncoveredTLSSecrets"`
}

func (e *ToolExecutor) gatherCertificates(ctx context.Context, namespace string) (certsResult, error) {
	c, err := e.cache()
	if err != nil {
		return certsResult{}, err
	}
	out := certsResult{insightMeta: e.meta([2]string{"cert-manager.io", "Certificate"}), ServedProbed: certProbeServed}
	certObjs, _ := c.Dynamic("cert-manager.io", "Certificate", namespace)
	requests, _ := c.Dynamic("cert-manager.io", "CertificateRequest", namespace)
	orders, _ := c.Dynamic("acme.cert-manager.io", "Order", namespace)
	challenges, _ := c.Dynamic("acme.cert-manager.io", "Challenge", namespace)
	var cm []certexpiry.Input
	issuedSecrets := make(map[string]bool, len(certObjs))
	for _, u := range certObjs {
		in, ok := certexpiry.FromCertManager(u)
		if !ok {
			continue
		}
		in.RequestChain = certexpiry.RequestChainFor(u, requests, orders, challenges)
		cm = append(cm, in)
		if in.SecretName != "" {
			issuedSecrets[in.Namespace+"/"+in.SecretName] = true
		}
	}
	var served []certexpiry.Input
	if certProbeServed {
		served, out.ProbeErrors = e.probeServedCertificates(ctx, namespace)
	}
	out.Certificates = certexpiry.Aggregate(certexpiry.Sources{CertManager: cm, Served: served})
	if out.Certificates == nil {
		out.Certificates = []certexpiry.Cert{}
	}
	if len(out.Certificates) > 500 {
		out.Certificates = out.Certificates[:500]
		out.Truncated = true
	}

	probedSecrets := make(map[string]bool, len(served))
	for _, s := range served {
		if s.SecretName != "" {
			probedSecrets[s.Namespace+"/"+s.SecretName] = true
		}
	}
	out.UncoveredTLSSecrets = e.countUncoveredTLSSecrets(c, namespace, issuedSecrets, probedSecrets)
	return out, nil
}

// countUncoveredTLSSecrets is PG5's state-coverage half: every distinct
// Ingress spec.tls[].secretName and Gateway spec.listeners[].tls.
// certificateRefs[].name this scan can see, minus whatever a cert-manager
// Certificate issues or a served-endpoint probe already read. Counts
// secrets, not Ingresses/Gateways, so N shared Ingresses pointing at one
// Secret count once.
func (e *ToolExecutor) countUncoveredTLSSecrets(c *objcache.Cache, namespace string, issued, probed map[string]bool) int {
	referenced := make(map[string]bool)
	if ings, err := e.objects.Ingresses(namespace); err == nil {
		for _, ing := range ings {
			for _, tls := range ing.Spec.TLS {
				if tls.SecretName != "" {
					referenced[ing.Namespace+"/"+tls.SecretName] = true
				}
			}
		}
	}
	if gws, err := c.Dynamic("gateway.networking.k8s.io", "Gateway", namespace); err == nil {
		for _, gw := range gws {
			listeners, _, _ := unstructured.NestedSlice(gw.Object, "spec", "listeners")
			for _, l := range listeners {
				lm, ok := l.(map[string]any)
				if !ok {
					continue
				}
				refs, _, _ := unstructured.NestedSlice(lm, "tls", "certificateRefs")
				for _, r := range refs {
					rm, ok := r.(map[string]any)
					if !ok {
						continue
					}
					name, _ := rm["name"].(string)
					if name == "" {
						continue
					}
					ns, _ := rm["namespace"].(string)
					if ns == "" {
						ns = gw.GetNamespace()
					}
					referenced[ns+"/"+name] = true
				}
			}
		}
	}
	uncovered := 0
	for key := range referenced {
		if !issued[key] && !probed[key] {
			uncovered++
		}
	}
	return uncovered
}

func (e *ToolExecutor) probeServedCertificates(ctx context.Context, namespace string) ([]certexpiry.Input, int) {
	ings, err := e.objects.Ingresses(namespace)
	if err != nil {
		return nil, 0
	}
	type target struct{ addr, sni, ns, name, secret string }
	var targets []target
	for _, ing := range ings {
		var addr string
		for _, lb := range ing.Status.LoadBalancer.Ingress {
			if lb.IP != "" {
				addr = lb.IP
			} else if lb.Hostname != "" {
				addr = lb.Hostname
			}
			if addr != "" {
				break
			}
		}
		if addr == "" {
			continue
		}
		for _, tls := range ing.Spec.TLS {
			for _, h := range tls.Hosts {
				targets = append(targets, target{addr: net.JoinHostPort(addr, "443"), sni: h, ns: ing.Namespace, name: ing.Name, secret: tls.SecretName})
				if len(targets) >= certProbeMaxHosts {
					break
				}
			}
		}
	}
	var mu sync.Mutex
	var out []certexpiry.Input
	errs := 0
	sem := make(chan struct{}, certProbeConcurrency)
	var wg sync.WaitGroup
	for _, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(t target) {
			defer wg.Done()
			defer func() { <-sem }()
			in, err := certexpiry.ProbeServedCertificate(ctx, t.addr, t.sni, certProbeTimeout)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs++
				return
			}
			in.Namespace, in.SecretName = t.ns, t.secret
			if in.Name == "" {
				in.Name = t.sni
			}
			out = append(out, in)
		}(t)
	}
	wg.Wait()
	return out, errs
}

func (e *ToolExecutor) listCertificates(ctx context.Context, raw json.RawMessage) (json.RawMessage, bool, error) {
	var a struct {
		Namespace string `json:"namespace"`
	}
	if err := decodeInsightArgs(raw, &a); err != nil {
		return nil, false, err
	}
	res, err := e.gatherCertificates(ctx, a.Namespace)
	if err != nil {
		return nil, false, err
	}
	return marshalInsight(res)
}

// emitCertificateFindings raises a risk finding for every certificate within
// 30 days of expiry (or already expired), on the posture detector's timer.
func (e *ToolExecutor) emitCertificateFindings(ctx context.Context, findingCh chan<- tunnel.Finding, lastSent map[string]time.Time, cooldown time.Duration) int {
	res, err := e.gatherCertificates(ctx, "")
	if err != nil {
		return 0
	}
	now := time.Now()
	sent := 0
	for _, cert := range res.Certificates {
		if cert.Health != certexpiry.HealthDegraded && cert.Health != certexpiry.HealthUnhealthy {
			continue
		}
		sev := "medium"
		if cert.Health == certexpiry.HealthUnhealthy {
			sev = "high"
		}
		days := "unknown"
		if cert.DaysLeft != nil {
			days = fmt.Sprintf("%d", *cert.DaysLeft)
		}
		gvk, kind := "cert-manager.io/v1/Certificate", "Certificate"
		if cert.Source != "cert-manager" {
			gvk, kind = "networking.k8s.io/v1/Ingress", "Ingress"
		}
		fp := computeFingerprint(cert.Namespace, kind, cert.Name, "CertificateExpiring")
		if !shouldSend(fp, now, lastSent, cooldown) {
			continue
		}
		f := tunnel.Finding{
			DetectorID: "k8s-certificates", DetectorVersion: "1", Fingerprint: fp,
			GVK: gvk, Namespace: cert.Namespace, ObjectName: cert.Name,
			Reason:          "CertificateExpiring",
			Message:         fmt.Sprintf("Certificate for %s expires %s (%s days left; source %s)", cert.Domains, cert.Expiry, days, cert.Source),
			OccurrenceCount: 1, Severity: sev, OccurredAt: now,
			Class: tunnel.FindingClassRisk, Confidence: tunnel.FindingConfidenceVerified, Impact: tunnel.FindingImpactPotential,
			RuleID: "certificateExpiry",
		}
		if emitFinding(f, findingCh) {
			lastSent[fp] = now
			sent++
		}
	}
	return sent
}

// ---------------------------------------------------------------- Helm release status (CI-S17)

// helmSecretMeta reads Helm release Secrets by exact name and returns their
// LABELS ONLY. This is the second consumer of the agent's single named
// Secret get (the first is describe_resource); lld/14-adrs.md records the
// decision. The payload — values, manifests, notes — is dropped in this
// function and never stored, logged or returned.
type helmSecretMeta struct{ e *ToolExecutor }

func (h helmSecretMeta) GetSecretMeta(ctx context.Context, ns, name string) (helmstatus.SecretMeta, bool, error) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	sec, err := h.e.typed.CoreV1().Secrets(ns).Get(cctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return helmstatus.SecretMeta{}, false, nil
	}
	if err != nil {
		return helmstatus.SecretMeta{}, false, err
	}
	sec.Data, sec.StringData = nil, nil
	return helmstatus.SecretMeta{Labels: sec.Labels, CreationTimestamp: sec.CreationTimestamp.Time}, true, nil
}

var helmRevisionHints = struct {
	sync.Mutex
	m map[string]int
}{m: map[string]int{}}

type helmStatusResult struct {
	insightMeta
	Release        string                `json:"release"`
	Namespace      string                `json:"namespace"`
	LatestRevision int                   `json:"latestRevision"`
	History        []helmstatus.Revision `json:"history"`
	Analysis       helmstatus.Analysis   `json:"analysis"`
	Note           string                `json:"note"`
	// HookJobs is PG4's evidence (2026-10-13 parity review): failed or stuck
	// Helm lifecycle hook Jobs correlated to this release. Always Inferred
	// (see helmstatus.HookJob's own doc comment) — never absent because of
	// RBAC, since Jobs are already a typed, cached, always-granted kind.
	HookJobs []helmstatus.HookJob `json:"hookJobs,omitempty"`
}

func (e *ToolExecutor) helmReleaseStatus(ctx context.Context, ns, release string) (helmStatusResult, error) {
	if e.typed == nil {
		return helmStatusResult{}, errors.New("no cluster client")
	}
	key := ns + "/" + release
	helmRevisionHints.Lock()
	hint := helmRevisionHints.m[key]
	helmRevisionHints.Unlock()
	g := helmSecretMeta{e}
	latest, err := helmstatus.LatestRevisionFrom(ctx, g, ns, release, hint, 12)
	if err != nil && latest == 0 {
		return helmStatusResult{}, fmt.Errorf("helm release %s: %w", key, err)
	}
	helmRevisionHints.Lock()
	helmRevisionHints.m[key] = latest
	helmRevisionHints.Unlock()
	hist, err := helmstatus.History(ctx, g, ns, release, latest, 10)
	if err != nil {
		return helmStatusResult{}, err
	}
	var hookJobs []helmstatus.HookJob
	if e.objects != nil {
		if jobs, err := e.objects.Jobs(ns); err == nil {
			hookJobs = helmstatus.CorrelateHookJobs(release, ns, jobs, time.Now())
		}
	}
	return helmStatusResult{
		insightMeta: insightMeta{ObservedAt: time.Now().UTC()},
		Release:     release, Namespace: ns, LatestRevision: latest, History: hist,
		Analysis: helmstatus.Analyze(release, latest, hist, helmstatus.Options{}),
		Note:     "Read from Helm release Secret labels only; chart version, values and manifests are deliberately not read.",
		HookJobs: hookJobs,
	}, nil
}

func (e *ToolExecutor) getHelmReleaseStatus(ctx context.Context, raw json.RawMessage) (json.RawMessage, bool, error) {
	var a struct {
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
	}
	if err := decodeInsightArgs(raw, &a); err != nil {
		return nil, false, err
	}
	if err := requireName(a.Namespace, a.Name, true); err != nil {
		return nil, false, err
	}
	res, err := e.helmReleaseStatus(ctx, a.Namespace, a.Name)
	if err != nil {
		return nil, false, err
	}
	return marshalInsight(res)
}

// discoverHelmReleases finds release names from the meta.helm.sh annotations
// on objects already in the cache — no Secret is listed.
func (e *ToolExecutor) discoverHelmReleases(limit int) [][2]string {
	c := e.objects
	if c == nil {
		return nil
	}
	seen := map[[2]string]bool{}
	add := func(o metav1.Object) {
		a := o.GetAnnotations()
		name, ns := a["meta.helm.sh/release-name"], a["meta.helm.sh/release-namespace"]
		if name != "" && ns != "" {
			seen[[2]string{ns, name}] = true
		}
	}
	if ds, err := c.Deployments(""); err == nil {
		for _, o := range ds {
			add(o)
		}
	}
	if ss, err := c.StatefulSets(""); err == nil {
		for _, o := range ss {
			add(o)
		}
	}
	if ds, err := c.DaemonSets(""); err == nil {
		for _, o := range ds {
			add(o)
		}
	}
	if sv, err := c.Services(""); err == nil {
		for _, o := range sv {
			add(o)
		}
	}
	out := make([][2]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i][0]+"/"+out[i][1] < out[j][0]+"/"+out[j][1] })
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// emitHelmFindings raises a risk finding for each release whose latest
// operation failed or is stuck pending.
func (e *ToolExecutor) emitHelmFindings(ctx context.Context, findingCh chan<- tunnel.Finding, lastSent map[string]time.Time, cooldown time.Duration) int {
	now := time.Now()
	sent := 0
	for _, r := range e.discoverHelmReleases(200) {
		res, err := e.helmReleaseStatus(ctx, r[0], r[1])
		if err != nil || res.Analysis.LastOperation == nil {
			continue
		}
		op := res.Analysis.LastOperation
		if op.Status != helmstatus.StatusFailed && op.Status != helmstatus.StatusStuck {
			continue
		}
		fp := computeFingerprint(r[0], "HelmRelease", r[1], "HelmRelease"+string(op.Status))
		if !shouldSend(fp, now, lastSent, cooldown) {
			continue
		}
		f := tunnel.Finding{
			DetectorID: "k8s-helm", DetectorVersion: "1", Fingerprint: fp,
			GVK: "helm.sh/v3/Release", Namespace: r[0], ObjectName: r[1],
			Reason:          "HelmRelease" + upperFirst(string(op.Status)),
			Message:         fmt.Sprintf("Helm release %s/%s revision %d: %s", r[0], r[1], res.LatestRevision, op.Message),
			OccurrenceCount: 1, Severity: "high", OccurredAt: now,
			Class: tunnel.FindingClassRisk, Confidence: tunnel.FindingConfidenceVerified, Impact: tunnel.FindingImpactPotential,
			RuleID: "helmRelease",
		}
		if emitFinding(f, findingCh) {
			lastSent[fp] = now
			sent++
		}
	}
	return sent
}
