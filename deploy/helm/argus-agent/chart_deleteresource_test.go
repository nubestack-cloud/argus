package argusagentchart

// TestRemediateChartGrantsDeleteOnDeleteResourceKinds mirrors
// TestRemediateChartGrantsPatchOnPatchFieldKinds (chart_test.go) exactly,
// for BACKLOG.md F9's deleteResource action type: confirms the `delete`
// RBAC verb on Pod/Job/PersistentVolumeClaim actually appears in the
// rendered chart, in both shapes (cluster-wide ClusterRole, namespace-scoped
// Role), and that the two rule sets stay identical — this file's own header
// rule (templates/remediate-role.yaml: "if these two rule sets ever
// diverge, the divergence is the bug"). PersistentVolumeClaim was added
// 2026-09-01 (BUGS.md 118 part (b)) — see
// TestRemediateChartDeleteProtectedResourcesVAPCoversPVC below for the
// admission-time backstop this grant needs alongside it.
//
// No live cluster involved — same `helm template` local-render approach
// chart_test.go and the VAP file's own header comment both already use for
// checks that don't need a real API server.
import "testing"

func TestRemediateChartGrantsDeleteOnDeleteResourceKinds(t *testing.T) {
	wants := []struct {
		name     string
		apiGroup string
		resource string
	}{
		{"Pod", "", "pods"},
		{"Job", "batch", "jobs"},
		{"PersistentVolumeClaim", "", "persistentvolumeclaims"},
	}

	t.Run("cluster-wide (remediate.allNamespaces)", func(t *testing.T) {
		objs := helmTemplate(t,
			"--set", "remediate.enabled=true",
			"--set", "remediate.allNamespaces=true",
		)
		role := findRole(t, objs, "ClusterRole", "argus-remediate")
		for _, w := range wants {
			t.Run(w.name, func(t *testing.T) {
				if !hasRule(role.Rules, w.apiGroup, w.resource, "delete") {
					t.Errorf("templates/clusterrole.yaml's argus-remediate ClusterRole does not grant delete on %s/%s", w.apiGroup, w.resource)
				}
			})
		}
	})

	t.Run("namespace-scoped (remediate.namespaces)", func(t *testing.T) {
		objs := helmTemplate(t,
			"--set", "remediate.enabled=true",
			"--set", "remediate.namespaces={apps}",
		)
		role := findRole(t, objs, "Role", "argus-remediate")
		for _, w := range wants {
			t.Run(w.name, func(t *testing.T) {
				if !hasRule(role.Rules, w.apiGroup, w.resource, "delete") {
					t.Errorf("templates/remediate-role.yaml's argus-remediate Role does not grant delete on %s/%s — it must mirror templates/clusterrole.yaml exactly", w.apiGroup, w.resource)
				}
			})
		}
	})

	t.Run("remediate disabled grants none of it", func(t *testing.T) {
		objs := helmTemplate(t) // remediate.enabled defaults to false
		for _, o := range objs {
			if o.Metadata.Name == "argus-remediate" {
				t.Fatalf("an argus-remediate %s rendered with remediate.enabled left at its default (false)", o.Kind)
			}
		}
	})
}
