package posture

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"argus/internal/agent/certexpiry"
)

// Fixture tests for the nine checks added by the 2026-10-13 parity review
// (PROJECT.md PG2). The storage checks are also verified live on rke2; see
// docs/VERIFICATION.md.

func TestPVCPending(t *testing.T) {
	old := metav1.NewTime(time.Now().Add(-time.Hour))
	recent := metav1.NewTime(time.Now().Add(-time.Second))
	input := &CheckInput{
		PersistentVolumeClaims: []*corev1.PersistentVolumeClaim{
			{ObjectMeta: metav1.ObjectMeta{Name: "stuck", Namespace: "default", CreationTimestamp: old},
				Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimPending}},
			{ObjectMeta: metav1.ObjectMeta{Name: "just-started", Namespace: "default", CreationTimestamp: recent},
				Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimPending}},
			{ObjectMeta: metav1.ObjectMeta{Name: "bound", Namespace: "default", CreationTimestamp: old},
				Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound}},
		},
	}
	names := findingNames(RunChecks(input).Findings, "pvcPending")
	if !names["stuck"] {
		t.Error("expected pvcPending finding for stuck")
	}
	if names["just-started"] {
		t.Error("just-started has not been Pending long enough to flag")
	}
	if names["bound"] {
		t.Error("bound PVC should never be flagged pending")
	}
}

func TestOrphanPVC(t *testing.T) {
	input := &CheckInput{
		PersistentVolumeClaims: []*corev1.PersistentVolumeClaim{
			{ObjectMeta: metav1.ObjectMeta{Name: "used", Namespace: "default"}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound}},
			{ObjectMeta: metav1.ObjectMeta{Name: "orphan", Namespace: "default"}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound}},
			{ObjectMeta: metav1.ObjectMeta{Name: "still-pending", Namespace: "default"}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimPending}},
		},
		Pods: []*corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
			Spec: corev1.PodSpec{Volumes: []corev1.Volume{{
				Name:         "data",
				VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "used"}},
			}}},
		}},
	}
	names := findingNames(RunChecks(input).Findings, "orphanPVC")
	if !names["orphan"] {
		t.Error("expected orphanPVC finding for orphan")
	}
	if names["used"] {
		t.Error("used PVC is mounted, should not be flagged")
	}
	if names["still-pending"] {
		t.Error("a Pending (not Bound) PVC is pvcPending's concern, not orphanPVC's")
	}
}

func TestPVReleasedOrFailed(t *testing.T) {
	input := &CheckInput{
		PersistentVolumes: []*corev1.PersistentVolume{
			{ObjectMeta: metav1.ObjectMeta{Name: "released-pv"}, Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeReleased}},
			{ObjectMeta: metav1.ObjectMeta{Name: "failed-pv"}, Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeFailed, Message: "detach timed out"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "bound-pv"}, Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeBound}},
		},
	}
	findings := RunChecks(input).Findings
	var released, failed *Finding
	for i := range findings {
		if findings[i].CheckID != "pvReleasedOrFailed" {
			continue
		}
		switch findings[i].Name {
		case "released-pv":
			released = &findings[i]
		case "failed-pv":
			failed = &findings[i]
		case "bound-pv":
			t.Error("a Bound PV should never be flagged")
		}
	}
	if released == nil || released.Severity != SeverityWarning {
		t.Errorf("released-pv: got %+v, want a warning finding", released)
	}
	if failed == nil || failed.Severity != SeverityDanger {
		t.Errorf("failed-pv: got %+v, want a danger finding", failed)
	}
	if failed != nil && !contains(failed.Message, "detach timed out") {
		t.Errorf("failed-pv message should include the PV's own status.message, got %q", failed.Message)
	}
}

func TestCertificateExpiry(t *testing.T) {
	soon := time.Now().Add(20 * 24 * time.Hour)
	urgent := time.Now().Add(3 * 24 * time.Hour)
	healthy := time.Now().Add(90 * 24 * time.Hour)
	input := &CheckInput{
		Certificates: certexpiry.Aggregate(certexpiry.Sources{CertManager: []certexpiry.Input{
			{Name: "soon", Namespace: "default", NotAfter: &soon, Source: certexpiry.SourceCertManager},
			{Name: "urgent", Namespace: "default", NotAfter: &urgent, Source: certexpiry.SourceCertManager},
			{Name: "healthy", Namespace: "default", NotAfter: &healthy, Source: certexpiry.SourceCertManager},
		}}),
	}
	findings := RunChecks(input).Findings
	byName := map[string]Finding{}
	for _, f := range findings {
		if f.CheckID == "certificateExpiry" {
			byName[f.Name] = f
		}
	}
	if f, ok := byName["soon"]; !ok || f.Severity != SeverityWarning {
		t.Errorf("soon (20d): got %+v, want a warning finding", f)
	}
	if f, ok := byName["urgent"]; !ok || f.Severity != SeverityDanger {
		t.Errorf("urgent (3d): got %+v, want a danger finding", f)
	}
	if _, ok := byName["healthy"]; ok {
		t.Error("healthy (90d) must not be flagged")
	}
}

func TestTraefikIngressRouteMissingServiceAndMiddleware(t *testing.T) {
	input := &CheckInput{
		TraefikCRDsPresent: true,
		Services: []*corev1.Service{
			{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "web"}},
		},
		TraefikMiddlewares: []TraefikMiddleware{
			{Namespace: "web", Name: "strip-prefix"},
		},
		TraefikRoutes: []TraefikIngressRoute{
			{Namespace: "web", Name: "good",
				Services:    []NamespacedRef{{Namespace: "web", Name: "api"}},
				Middlewares: []NamespacedRef{{Namespace: "web", Name: "strip-prefix"}}},
			{Namespace: "web", Name: "bad-service",
				Services: []NamespacedRef{{Namespace: "web", Name: "missing-svc"}}},
			{Namespace: "web", Name: "bad-middleware",
				Services:    []NamespacedRef{{Namespace: "web", Name: "api"}},
				Middlewares: []NamespacedRef{{Namespace: "web", Name: "missing-mw"}}},
		},
	}
	findings := RunChecks(input).Findings
	svcNames := findingNames(findings, "traefikIngressRouteMissingService")
	mwNames := findingNames(findings, "traefikIngressRouteMissingMiddleware")
	if !svcNames["bad-service"] {
		t.Error("expected traefikIngressRouteMissingService for bad-service")
	}
	if svcNames["good"] || svcNames["bad-middleware"] {
		t.Error("only bad-service references a missing Service")
	}
	if !mwNames["bad-middleware"] {
		t.Error("expected traefikIngressRouteMissingMiddleware for bad-middleware")
	}
	if mwNames["good"] || mwNames["bad-service"] {
		t.Error("only bad-middleware references a missing Middleware")
	}
}

func TestTraefikErrorsMiddlewareAndChain(t *testing.T) {
	input := &CheckInput{
		TraefikCRDsPresent: true,
		Services: []*corev1.Service{
			{ObjectMeta: metav1.ObjectMeta{Name: "error-pages", Namespace: "web"}},
		},
		TraefikMiddlewares: []TraefikMiddleware{
			{Namespace: "web", Name: "good-errors", ErrorsService: &NamespacedRef{Namespace: "web", Name: "error-pages"}},
			{Namespace: "web", Name: "bad-errors", ErrorsService: &NamespacedRef{Namespace: "web", Name: "missing-svc"}},
			{Namespace: "web", Name: "member-1"},
			{Namespace: "web", Name: "good-chain", ChainMiddlewares: []NamespacedRef{{Namespace: "web", Name: "member-1"}}},
			{Namespace: "web", Name: "bad-chain", ChainMiddlewares: []NamespacedRef{{Namespace: "web", Name: "missing-mw"}}},
		},
	}
	findings := RunChecks(input).Findings
	errNames := findingNames(findings, "traefikErrorsMiddlewareMissingService")
	chainNames := findingNames(findings, "traefikMiddlewareChainMissingMember")
	if !errNames["bad-errors"] {
		t.Error("expected traefikErrorsMiddlewareMissingService for bad-errors")
	}
	if errNames["good-errors"] {
		t.Error("good-errors references a real Service, must not be flagged")
	}
	if !chainNames["bad-chain"] {
		t.Error("expected traefikMiddlewareChainMissingMember for bad-chain")
	}
	if chainNames["good-chain"] {
		t.Error("good-chain references a real Middleware, must not be flagged")
	}
}

func TestTraefikChecksSkippedWhenCRDsAbsent(t *testing.T) {
	input := &CheckInput{
		TraefikCRDsPresent: false,
		TraefikRoutes:      []TraefikIngressRoute{{Namespace: "web", Name: "x", Services: []NamespacedRef{{Namespace: "web", Name: "missing"}}}},
	}
	for _, f := range RunChecks(input).Findings {
		if f.CheckID == "traefikIngressRouteMissingService" {
			t.Error("Traefik checks must not run when TraefikCRDsPresent is false, even with routes supplied")
		}
	}
}

func TestCrossplaneNotReady(t *testing.T) {
	input := &CheckInput{
		CrossplaneCRDsPresent: true,
		CrossplaneObjects: []CrossplaneObject{
			{Group: "database.example.org", Kind: "XPostgreSQLInstanceClaim", Namespace: "apps", Name: "pg",
				Ready: ptr(false), Message: "composition revision not found"},
			{Group: "database.example.org", Kind: "XPostgreSQLInstanceClaim", Namespace: "apps", Name: "pg-ready",
				Ready: ptr(true)},
			{Group: "database.example.org", Kind: "XPostgreSQLInstanceClaim", Namespace: "apps", Name: "pg-unknown",
				Ready: nil},
		},
	}
	findings := RunChecks(input).Findings
	names := findingNames(findings, "crossplaneNotReady")
	if !names["pg"] {
		t.Error("expected crossplaneNotReady for pg")
	}
	if names["pg-ready"] {
		t.Error("a Ready claim must not be flagged")
	}
	if names["pg-unknown"] {
		t.Error("an unknown (nil) Ready condition must not be flagged — unknown is not a finding")
	}
	for _, f := range findings {
		if f.Name == "pg" && !contains(f.Message, "composition revision not found") {
			t.Errorf("message should include the object's own status message, got %q", f.Message)
		}
	}
}
