package argushubchart

// The bundled Postgres has no backup machinery at all: no CronJob, no second
// volume, and no pre-upgrade dump Job. Before an upgrade the operator takes a
// copy off the cluster (docs/INSTALL.md, "Upgrading").

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestNoBackupObjects(t *testing.T) {
	out := renderMinimal(t, "argus-hub", "--set", "ingress.host=argus.example.org", "--is-upgrade")
	for _, unwanted := range []string{"kind: CronJob", "kind: Job", "postgres-backup", "helm.sh/hook"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("rendered %q", unwanted)
		}
	}
}

// A values file written for either earlier backup (the nightly CronJob, then
// the pre-upgrade dump) still installs: its keys are accepted and ignored.
func TestOldBackupValuesAreAccepted(t *testing.T) {
	renderMinimal(t, "argus-hub", "--set", "ingress.host=argus.example.org",
		"--set", "postgres.bundled.backup.enabled=true",
		"--set", "postgres.bundled.backup.schedule=0 3 * * *",
		"--set", "postgres.bundled.backup.persistence.size=5Gi",
		"--set", "postgres.bundled.backup.beforeUpgrade=true",
		"--set", "postgres.bundled.backup.keep=2")
}

// The notes say there are no backups, and where the copy before an upgrade
// comes from.
func TestPostgresBackupNotes(t *testing.T) {
	notes := helmInstallNotes(t)
	for _, want := range []string{"No backups", "take a copy off the cluster", "postgres.mode=external"} {
		if !strings.Contains(notes, want) {
			t.Errorf("NOTES lack %q:\n%s", want, notes)
		}
	}
}

// helmInstallNotes renders NOTES.txt, which `helm template` skips, through a
// client-only dry-run install against an empty kubeconfig — no cluster is
// contacted.
func helmInstallNotes(t *testing.T, extraSet ...string) string {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not on PATH; skipping rendered-chart verification")
	}
	_, thisFile, _, _ := runtime.Caller(0)
	kubeconfig := fakeKubeconfig(t)
	args := append([]string{"install", "notes-test", filepath.Dir(thisFile), "--dry-run=client", "--disable-openapi-validation",
		"--set", "tunnel.publicEndpoint=hub.example.com:8443",
	}, extraSet...)
	cmd := exec.Command("helm", args...)
	cmd.Env = append(os.Environ(), "KUBECONFIG="+kubeconfig)
	out, err := runHelm(cmd)
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
