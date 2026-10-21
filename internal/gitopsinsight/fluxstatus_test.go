package gitopsinsight

import (
	"strconv"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// flux builds a Kustomization. shape is "generation/observedGeneration",
// either side "-" for absent, optionally followed by " suspended". Each
// condition is "Type=Status" or "Type=Status:Reason", or a full map.
func flux(shape string, conds ...any) *unstructured.Unstructured {
	gens, flags, _ := strings.Cut(shape, " ")
	gen, seen, _ := strings.Cut(gens, "/")
	meta := map[string]any{"namespace": "flux-system", "name": "apps"}
	status := map[string]any{}
	if n, err := strconv.ParseInt(gen, 10, 64); err == nil {
		meta["generation"] = n
	}
	if n, err := strconv.ParseInt(seen, 10, 64); err == nil {
		status["observedGeneration"] = n
	}
	var list []any
	for _, c := range conds {
		if s, ok := c.(string); ok {
			typ, rest, _ := strings.Cut(s, "=")
			st, reason, _ := strings.Cut(rest, ":")
			c = map[string]any{"type": typ, "status": st, "reason": reason}
		}
		list = append(list, c)
	}
	status["conditions"] = list
	obj := map[string]any{"apiVersion": "kustomize.toolkit.fluxcd.io/v1", "kind": "Kustomization", "metadata": meta, "status": status}
	if flags == "suspended" {
		obj["spec"] = map[string]any{"suspend": true}
	}
	return &unstructured.Unstructured{Object: obj}
}

func TestFluxStatus(t *testing.T) {
	cases := []struct {
		why   string
		obj   *unstructured.Unstructured
		state string // "Sync/Health"
	}{
		{"applied", flux("4/4", "Ready=True"), "Synced/Healthy"},
		// Flux sets Reconciling without clearing Ready; kubectl shows Ready.
		{"a lingering Reconciling does not outvote Ready", flux("4/4", "Ready=True", "Healthy=True", "Reconciling=True"), "Synced/Healthy"},
		// Applied and unhealthy are two facts; sync must not swallow health.
		{"applied but its workloads unhealthy", flux("4/4", "Ready=True", "Healthy=False"), "Synced/Degraded"},
		{"a new spec not yet acted on, despite the old Ready", flux("5/4", "Ready=True"), "Reconciling/Progressing"},
		// Flux writes -1 before its first pass: present and different.
		{"never reconciled", flux("1/-1", "Ready=Unknown", "Reconciling=True"), "Reconciling/Progressing"},
		// Absence is not drift: some kinds never write observedGeneration.
		{"no observedGeneration", flux("7/-", "Ready=True"), "Synced/Healthy"},
		{"no generation", flux("-/7", "Ready=True"), "Synced/Healthy"},
		{"stalled beats Ready", flux("4/4", "Ready=True", "Stalled=True"), "OutOfSync/Degraded"},
		// Seen on the lab cluster: a Kustomization pointed at a missing path
		// sits like this for good and never stalls.
		{"a named failure on retry", flux("1/-1", "Reconciling=True:ProgressingWithRetry", "Ready=False:ArtifactFailed"), "OutOfSync/Degraded"},
		{"a first attempt still running", flux("1/-1", "Reconciling=True:Progressing", "Ready=Unknown:Progressing"), "Reconciling/Progressing"},
		{"working towards Ready", flux("4/4", "Ready=Unknown", "Reconciling=True"), "Reconciling/Progressing"},
		{"not ready, no reason", flux("4/4", "Ready=False"), "OutOfSync/Degraded"},
		{"not ready, settled cause", flux("4/4", "Ready=False:BuildFailed"), "OutOfSync/Degraded"},
		{"not ready while a retry is under way", flux("4/4", "Ready=False:ProgressingWithRetry"), "OutOfSync/Progressing"},
		{"not ready while waiting", flux("4/4", "Ready=False:DependencyNotReadyWait"), "OutOfSync/Progressing"},
		// Suspension leaves the last apply in place, but a spec changed while
		// suspended will not be applied.
		{"suspended after applying", flux("4/4 suspended", "Ready=True"), "Synced/Suspended"},
		{"suspended with an unapplied spec", flux("5/4 suspended", "Ready=True"), "Unknown/Suspended"},
		{"suspended, never ready", flux("4/4 suspended", "Ready=False"), "Unknown/Suspended"},
		{"nothing reported", flux("4/4"), "Unknown/Unknown"},
		// Source kinds have no Healthy condition: applied is healthy.
		{"a source kind", flux("2/2", "Ready=True", "ArtifactInStorage=True"), "Synced/Healthy"},
		{"a HelmRelease", flux("2/2", "Ready=True", "Released=True"), "Synced/Healthy"},
	}
	for _, c := range cases {
		got := FluxStatus(c.obj)
		if s := got.Sync + "/" + got.Health; s != c.state {
			t.Errorf("%s: %s, want %s", c.why, s, c.state)
		}
	}
}

// Reconciling is reported whatever it did to the answer, so a controller
// wedged mid-pass shows beside a correct Synced.
func TestFluxStatusReportsReconcilingActivity(t *testing.T) {
	if got := FluxStatus(flux("4/4", "Ready=True", "Reconciling=True")); got.Sync != "Synced" || !got.Reconciling {
		t.Errorf("wedged = %+v", got)
	}
	if got := FluxStatus(flux("4/4", "Ready=True", "Reconciling=False")); got.Reconciling {
		t.Errorf("idle = %+v", got)
	}
}

func TestParseFluxInventoryID(t *testing.T) {
	for id, want := range map[string]string{
		"payments_api_apps_Deployment":                            "apps Deployment payments api",
		"data_etl_nightly_job_batch_CronJob":                      "batch CronJob data etl_nightly_job",
		"monitoring_grafana-dashboards__ConfigMap":                " ConfigMap monitoring grafana-dashboards",
		"monitoring_alert-rules_core_ConfigMap":                   " ConfigMap monitoring alert-rules",
		"gpu_trainer_kubeflow.org_PyTorchJob":                     "kubeflow.org PyTorchJob gpu trainer",
		"_ci-runner_rbac.authorization.k8s.io_ClusterRoleBinding": "rbac.authorization.k8s.io ClusterRoleBinding  ci-runner",
		"too_few_parts":       "!",
		"ns__apps_Deployment": "!",
		"ns_name_apps_":       "!",
	} {
		g, k, ns, n, ok := ParseFluxInventoryID(id)
		got := strings.Join([]string{g, k, ns, n}, " ")
		if !ok {
			got = "!"
		}
		if got != want {
			t.Errorf("%q: %q, want %q", id, got, want)
		}
	}
}
