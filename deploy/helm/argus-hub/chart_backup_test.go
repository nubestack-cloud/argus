package argushubchart

// The bundled Postgres has no scheduled backup: only a dump before each
// `helm upgrade`, onto the database's own volume, so a bad upgrade can be
// rolled back. That hook needs a live release (it looks the StatefulSet up),
// so it is proven on a cluster; these check what rendering alone can.

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// No CronJob, no second volume, no Job to bind one.
func TestNoScheduledBackup(t *testing.T) {
	out := renderMinimal(t, "argus-hub", "--set", "ingress.host=argus.example.org")
	for _, unwanted := range []string{"kind: CronJob", "name: argus-hub-postgres-backup\n", "postgres-backup-bind"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("rendered %q", unwanted)
		}
	}
	if strings.Contains(out, "postgres-backup-pre-upgrade") {
		t.Error("the pre-upgrade backup rendered outside an upgrade of a live release")
	}
}

// A values file written for the old nightly backup still installs: its keys
// are accepted and ignored.
func TestOldBackupValuesAreAccepted(t *testing.T) {
	renderMinimal(t, "argus-hub", "--set", "ingress.host=argus.example.org",
		"--set", "postgres.bundled.backup.enabled=true",
		"--set", "postgres.bundled.backup.schedule=0 3 * * *",
		"--set", "postgres.bundled.backup.persistence.size=5Gi")
}

// The notes say there is no backup policy, and where the way back from an
// upgrade is.
func TestPostgresBackupNotes(t *testing.T) {
	notes := helmInstallNotes(t)
	for _, want := range []string{"No scheduled backups", "Before every helm upgrade", "Rolling back an upgrade", "postgres.mode=external"} {
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
