package argusagentchart

// chart_persistence_test.go is BUGS.md 128's chart-level fix, verified the
// same "no live cluster needed, `helm template` renders locally" way
// chart_test.go's own header comment already establishes for this chart:
// `agent-data` (templates/deployment.yaml) is an emptyDir by default, and a
// real PersistentVolumeClaim (templates/pvc.yaml) only when
// persistence.enabled opts in (values.yaml) — reused here via
// decodeYAMLDocs/helmTemplateRaw, already defined in chart_metrics_test.go.

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// pvcObject mirrors the subset of a rendered PersistentVolumeClaim this test
// reads.
type pvcObject struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name      string `yaml:"name"`
		Namespace string `yaml:"namespace"`
	} `yaml:"metadata"`
	Spec struct {
		AccessModes      []string `yaml:"accessModes"`
		StorageClassName *string  `yaml:"storageClassName"`
		Resources        struct {
			Requests struct {
				Storage string `yaml:"storage"`
			} `yaml:"requests"`
		} `yaml:"resources"`
	} `yaml:"spec"`
}

// deploymentVolumeObject mirrors just enough of a rendered Deployment to
// read the `agent-data` volume's own shape.
type deploymentVolumeObject struct {
	Kind string `yaml:"kind"`
	Spec struct {
		Template struct {
			Spec struct {
				Volumes []struct {
					Name                  string    `yaml:"name"`
					EmptyDir              *struct{} `yaml:"emptyDir"`
					PersistentVolumeClaim *struct {
						ClaimName string `yaml:"claimName"`
					} `yaml:"persistentVolumeClaim"`
				} `yaml:"volumes"`
			} `yaml:"spec"`
		} `yaml:"template"`
	} `yaml:"spec"`
}

func agentDataVolume(t *testing.T, deployments []deploymentVolumeObject) *struct {
	Name                  string    `yaml:"name"`
	EmptyDir              *struct{} `yaml:"emptyDir"`
	PersistentVolumeClaim *struct {
		ClaimName string `yaml:"claimName"`
	} `yaml:"persistentVolumeClaim"`
} {
	t.Helper()
	if len(deployments) != 1 {
		t.Fatalf("rendered %d Deployment objects, want exactly 1", len(deployments))
	}
	for i := range deployments[0].Spec.Template.Spec.Volumes {
		v := &deployments[0].Spec.Template.Spec.Volumes[i]
		if v.Name == "agent-data" {
			return v
		}
	}
	t.Fatal("no agent-data volume found in the rendered Deployment")
	return nil
}

// TestPersistenceDisabledByDefaultRendersEmptyDirNoPVC is the default-state
// regression this fix must not break: with persistence left at its default
// (false), the chart must render exactly the same emptyDir it always has —
// no PersistentVolumeClaim at all — since this chart cannot assume a
// StorageClass exists across a fleet of 200+ heterogeneous clusters
// (values.yaml's `persistence` comment).
func TestPersistenceDisabledByDefaultRendersEmptyDirNoPVC(t *testing.T) {
	out, err := helmTemplateRaw(t)
	if err != nil {
		t.Fatalf("helm template (defaults) failed: %v\n%s", err, out)
	}
	pvcs := decodeYAMLDocs[pvcObject](t, out, func(k string) bool { return k == "PersistentVolumeClaim" })
	if len(pvcs) != 0 {
		t.Fatalf("rendered %d PersistentVolumeClaim object(s) with persistence.enabled left at its default (false), want 0", len(pvcs))
	}
	deployments := decodeYAMLDocs[deploymentVolumeObject](t, out, func(k string) bool { return k == "Deployment" })
	vol := agentDataVolume(t, deployments)
	if vol.EmptyDir == nil {
		t.Errorf("agent-data volume = %+v, want an emptyDir (persistence.enabled is false)", vol)
	}
	if vol.PersistentVolumeClaim != nil {
		t.Errorf("agent-data volume unexpectedly carries a persistentVolumeClaim with persistence.enabled false: %+v", vol.PersistentVolumeClaim)
	}
}

// TestPersistenceEnabledRendersPVCAndMountsIt is BUGS.md 128's actual fix,
// proved: persistence.enabled=true renders a real PersistentVolumeClaim
// (default size/accessModes, no storageClassName so the cluster's own
// default StorageClass is used), and the Deployment's agent-data volume
// mounts that exact claim instead of an emptyDir.
func TestPersistenceEnabledRendersPVCAndMountsIt(t *testing.T) {
	out, err := helmTemplateRaw(t, "--set", "persistence.enabled=true")
	if err != nil {
		t.Fatalf("helm template --set persistence.enabled=true failed: %v\n%s", err, out)
	}
	pvcs := decodeYAMLDocs[pvcObject](t, out, func(k string) bool { return k == "PersistentVolumeClaim" })
	if len(pvcs) != 1 {
		t.Fatalf("rendered %d PersistentVolumeClaim object(s), want exactly 1", len(pvcs))
	}
	pvc := pvcs[0]
	if pvc.Metadata.Name != "argus-agent-data" {
		t.Errorf("PVC name = %q, want %q", pvc.Metadata.Name, "argus-agent-data")
	}
	if pvc.Metadata.Namespace != "argus-system" {
		t.Errorf("PVC namespace = %q, want %q (values.yaml's default namespace.name)", pvc.Metadata.Namespace, "argus-system")
	}
	if len(pvc.Spec.AccessModes) != 1 || pvc.Spec.AccessModes[0] != "ReadWriteOnce" {
		t.Errorf("PVC accessModes = %v, want [ReadWriteOnce] (values.yaml's default)", pvc.Spec.AccessModes)
	}
	if pvc.Spec.StorageClassName != nil {
		t.Errorf("PVC storageClassName = %v, want omitted entirely (values.yaml's default storageClassName is empty, which should ask for the cluster's own default class, not name one)", *pvc.Spec.StorageClassName)
	}
	if pvc.Spec.Resources.Requests.Storage != "64Mi" {
		t.Errorf("PVC storage request = %q, want %q (values.yaml's default persistence.size)", pvc.Spec.Resources.Requests.Storage, "64Mi")
	}

	deployments := decodeYAMLDocs[deploymentVolumeObject](t, out, func(k string) bool { return k == "Deployment" })
	vol := agentDataVolume(t, deployments)
	if vol.EmptyDir != nil {
		t.Errorf("agent-data volume unexpectedly carries an emptyDir with persistence.enabled true: %+v", vol.EmptyDir)
	}
	if vol.PersistentVolumeClaim == nil || vol.PersistentVolumeClaim.ClaimName != "argus-agent-data" {
		t.Errorf("agent-data volume's persistentVolumeClaim = %+v, want claimName argus-agent-data", vol.PersistentVolumeClaim)
	}
}

// TestPersistenceEnabledHonoursExplicitStorageClassAndSize proves the
// operator-facing knobs BUGS.md 128's fix direction calls for (enable it
// per-cluster on whichever StorageClass that cluster actually provisions —
// e.g. the disposable `kind` cluster's `local-path-storage`) actually reach
// the rendered PVC.
func TestPersistenceEnabledHonoursExplicitStorageClassAndSize(t *testing.T) {
	out, err := helmTemplateRaw(t,
		"--set", "persistence.enabled=true",
		"--set", "persistence.storageClass=local-path",
		"--set", "persistence.size=256Mi",
	)
	if err != nil {
		t.Fatalf("helm template failed: %v\n%s", err, out)
	}
	pvcs := decodeYAMLDocs[pvcObject](t, out, func(k string) bool { return k == "PersistentVolumeClaim" })
	if len(pvcs) != 1 {
		t.Fatalf("rendered %d PersistentVolumeClaim object(s), want exactly 1", len(pvcs))
	}
	pvc := pvcs[0]
	if pvc.Spec.StorageClassName == nil || *pvc.Spec.StorageClassName != "local-path" {
		t.Errorf("PVC storageClassName = %v, want %q", pvc.Spec.StorageClassName, "local-path")
	}
	if pvc.Spec.Resources.Requests.Storage != "256Mi" {
		t.Errorf("PVC storage request = %q, want %q", pvc.Spec.Resources.Requests.Storage, "256Mi")
	}
}

// renderedStorageClass renders with persistence on plus extraSet and returns
// the PVC's storageClassName, nil when omitted.
func renderedStorageClass(t *testing.T, extraSet ...string) *string {
	t.Helper()
	out, err := helmTemplateRaw(t, append([]string{"--set", "persistence.enabled=true"}, extraSet...)...)
	if err != nil {
		t.Fatalf("helm template failed: %v\n%s", err, out)
	}
	pvcs := decodeYAMLDocs[pvcObject](t, out, func(k string) bool { return k == "PersistentVolumeClaim" })
	if len(pvcs) != 1 {
		t.Fatalf("rendered %d PersistentVolumeClaim object(s), want exactly 1", len(pvcs))
	}
	return pvcs[0].Spec.StorageClassName
}

// PROJECT.md K2: persistence.storageClass is the key, matching the hub
// chart; persistence.storageClassName is the old name, kept as a deprecated
// alias so an existing install's values keep working.
func TestPersistenceStorageClassNameIsADeprecatedAlias(t *testing.T) {
	if got := renderedStorageClass(t, "--set", "persistence.storageClassName=legacy"); got == nil || *got != "legacy" {
		t.Errorf("old key alone: storageClassName = %v, want %q (the alias must still work)", got, "legacy")
	}
	if got := renderedStorageClass(t,
		"--set", "persistence.storageClass=new",
		"--set", "persistence.storageClassName=legacy",
	); got == nil || *got != "new" {
		t.Errorf("both keys set: storageClassName = %v, want %q (the new key wins)", got, "new")
	}
}

// The install notes warn while the old key is in use, and say nothing when
// it is not. NOTES.txt is not rendered by `helm template`, so this uses a
// client-only dry-run install against an empty kubeconfig — no cluster is
// contacted.
func TestPersistenceStorageClassNameNotesWarning(t *testing.T) {
	warn := "DEPRECATED: persistence.storageClassName"
	if notes := helmInstallNotes(t, "--set", "persistence.enabled=true", "--set", "persistence.storageClassName=legacy"); !strings.Contains(notes, warn) {
		t.Errorf("NOTES with the old key set do not warn:\n%s", notes)
	}
	if notes := helmInstallNotes(t, "--set", "persistence.enabled=true", "--set", "persistence.storageClass=new"); strings.Contains(notes, warn) {
		t.Errorf("NOTES warn about the old key when only the new one is set:\n%s", notes)
	}
}

func helmInstallNotes(t *testing.T, extraSet ...string) string {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not on PATH; skipping rendered-chart verification")
	}
	_, thisFile, _, _ := runtime.Caller(0)
	kubeconfig := fakeKubeconfig(t)
	args := append([]string{"install", "notes-test", filepath.Dir(thisFile), "--dry-run=client", "--disable-openapi-validation",
		"--set", "hub.apiUrl=https://example.com",
		"--set", "enrollment.token=dummy",
	}, extraSet...)
	cmd := exec.Command("helm", args...)
	cmd.Env = append(os.Environ(), "KUBECONFIG="+kubeconfig)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "dry-run") && strings.Contains(string(out), "flag") {
			t.Skipf("this helm does not support --dry-run=client: %s", out)
		}
		t.Fatalf("helm %v failed: %v\n%s", args, err, out)
	}
	notes := string(out)
	if i := strings.Index(notes, "NOTES:"); i >= 0 {
		return notes[i:]
	}
	t.Fatalf("no NOTES section in dry-run output:\n%s", out)
	return ""
}
