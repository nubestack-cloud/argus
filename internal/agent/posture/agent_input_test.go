package posture

import (
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const hashedValue = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

func TestSecretInConfigMapReadsKeyNamesOnly(t *testing.T) {
	input := &CheckInput{ConfigMaps: []*corev1.ConfigMap{{
		ObjectMeta: metav1.ObjectMeta{Name: "hashed", Namespace: "app"},
		Data: map[string]string{
			"db_password":   hashedValue,
			"api_token":     hashedValue,
			"log_level":     hashedValue,
			"client_secret": hashedValue,
		},
	}}}
	var keys []string
	for _, f := range RunChecks(input).Findings {
		if f.CheckID == "secretInConfigMap" {
			keys = append(keys, f.Message)
			if strings.Contains(f.Message, hashedValue) {
				t.Fatalf("finding leaked a value: %q", f.Message)
			}
		}
	}
	joined := strings.Join(keys, "|")
	if !strings.Contains(joined, `"db_password"`) || !strings.Contains(joined, `"client_secret"`) {
		t.Fatalf("credential key names not flagged: %v", keys)
	}
	if strings.Contains(joined, `"api_token"`) || strings.Contains(joined, `"log_level"`) {
		t.Fatalf("ambiguous or benign key flagged: %v", keys)
	}
}

func TestRegistryExcludesChecksNeedingUncollectedInputs(t *testing.T) {
	for _, id := range []string{
		"tlsCertificateExpiry", "crossplaneStuck", "traefikRouteMissingService", "traefikRouteMissingMiddleware",
		"traefikChainMissingMiddleware", "traefikErrorsMissingService", "cnpg-no-declarative-backup",
	} {
		if _, ok := CheckRegistry[id]; ok {
			t.Errorf("%s is in the catalogue but its input is never collected", id)
		}
	}
	meta := CheckRegistry["orphanConfigMapSecret"]
	if !strings.Contains(meta.Description, "Only ConfigMaps are judged") {
		t.Errorf("orphan check must say it evaluates ConfigMaps only: %q", meta.Description)
	}
	for id, m := range CheckRegistry {
		if m.ID != id || m.Title == "" || m.Description == "" || m.Remediation == "" {
			t.Errorf("incomplete catalogue entry %q: %+v", id, m)
		}
	}
	if got := CheckRegistry["privileged"].Frameworks; len(got) != 2 || got[0] != FrameworkNSACISA || got[1] != FrameworkCIS {
		t.Errorf("privileged frameworks = %v", got)
	}
}

func TestApplySettingsDefaultIgnoredNamespaces(t *testing.T) {
	results := &ScanResults{Findings: []Finding{
		{Kind: "Pod", Namespace: "kube-system", Name: "a", CheckID: "privileged", Category: CategorySecurity, Severity: SeverityDanger},
		{Kind: "Pod", Namespace: "cattle-system", Name: "b", CheckID: "privileged", Category: CategorySecurity, Severity: SeverityDanger},
		{Kind: "Pod", Namespace: "cattle-fleet-system", Name: "c", CheckID: "privileged", Category: CategorySecurity, Severity: SeverityDanger},
		{Kind: "Pod", Namespace: "argus-system", Name: "d", CheckID: "privileged", Category: CategorySecurity, Severity: SeverityDanger},
		{Kind: "Pod", Namespace: "shop", Name: "e", CheckID: "privileged", Category: CategorySecurity, Severity: SeverityDanger},
		{Kind: "Pod", Namespace: "shop", Name: "f", CheckID: "hostPID", Category: CategorySecurity, Severity: SeverityDanger},
	}}
	got := ApplySettings(results, DefaultIgnoredNamespaces, []string{"hostPID"})
	if len(got.Findings) != 1 || got.Findings[0].Name != "e" {
		t.Fatalf("findings = %+v", got.Findings)
	}
	if got.Summary.Danger != 1 || len(results.Findings) != 6 {
		t.Fatalf("summary = %+v; input must not be modified", got.Summary)
	}
}

func TestManagedBy(t *testing.T) {
	apps := map[string]struct{}{"shop": {}}
	for _, tc := range []struct {
		name        string
		labels      map[string]string
		annotations map[string]string
		want        management
	}{
		{name: "nothing", want: byNobody},
		{name: "generic name label", labels: map[string]string{"app.kubernetes.io/name": "api"}, want: byNobody},
		{name: "instance naming no Application", labels: map[string]string{"app.kubernetes.io/instance": "api"}, want: byNobody},
		{name: "instance naming an Application", labels: map[string]string{"app.kubernetes.io/instance": "shop"}, want: byGitOps},
		{name: "helm", annotations: map[string]string{"meta.helm.sh/release-name": "api"}, labels: map[string]string{"app.kubernetes.io/instance": "api"}, want: byHelm},
		{name: "helm rendered by an Application", annotations: map[string]string{"meta.helm.sh/release-name": "api"}, labels: map[string]string{"app.kubernetes.io/instance": "shop"}, want: byGitOps},
		{name: "argo instance beats helm", annotations: map[string]string{"meta.helm.sh/release-name": "api"}, labels: map[string]string{"argocd.argoproj.io/instance": "shop"}, want: byGitOps},
		{name: "argo tracking id", annotations: map[string]string{"argocd.argoproj.io/tracking-id": "argocd_shop:apps/Deployment:shop/api"}, want: byGitOps},
		{name: "malformed tracking id", annotations: map[string]string{"argocd.argoproj.io/tracking-id": "no-colon"}, want: byNobody},
		{name: "empty namespaced app", annotations: map[string]string{"argocd.argoproj.io/tracking-id": "argocd_:apps/Deployment:shop/api"}, want: byNobody},
		{name: "flux kustomization", labels: map[string]string{"kustomize.toolkit.fluxcd.io/name": "apps", "kustomize.toolkit.fluxcd.io/namespace": "flux-system"}, want: byGitOps},
		{name: "flux helmrelease needs namespace", labels: map[string]string{"helm.toolkit.fluxcd.io/name": "api"}, want: byNobody},
	} {
		t.Run(tc.name, func(t *testing.T) {
			obj := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Labels: tc.labels, Annotations: tc.annotations}}
			if got := managedBy(obj, apps); got != tc.want {
				t.Fatalf("managedBy = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestShortAge(t *testing.T) {
	for d, want := range map[string]string{"-5s": "0s", "45s": "45s", "12m": "12m", "5h": "5h", "49h": "2d"} {
		dur, err := time.ParseDuration(d)
		if err != nil {
			t.Fatal(err)
		}
		if got := shortAge(dur); got != want {
			t.Errorf("shortAge(%s) = %q, want %q", d, got, want)
		}
	}
}

func TestBuiltinGroups(t *testing.T) {
	for kind, want := range map[string]string{"Deployment": "apps", "Pod": "", "Widget": "", "PodDisruptionBudget": "policy"} {
		if got := object(kind, "ns", "x").group; got != want {
			t.Errorf("%s: group %q, want %q", kind, got, want)
		}
	}
}
