package agent

import (
	"strings"
	"testing"

	"argus/internal/tunnel"
)

// connection_role_test.go covers the agent half of PROJECT.md E11: what a
// process does differently depending on which of a cluster's two tunnel
// connections it is serving.
//
// Read ToolExecutor.role's own comment before adding to this file. None of
// this is the security boundary — the boundary is that the investigation
// agent runs under a ServiceAccount holding no write verb, which is enforced
// by the cluster's API server and cannot be granted or revoked by any code
// here. What these tests pin is that the agent says so CLEARLY instead of
// producing a bare 403 that reads like a broken ClusterRole.

// TestInvestigationAgentRefusesEveryWriteTool is defence in depth in front
// of RBAC, and it uses the SAME classification the hub routes by so the two
// cannot drift into disagreeing about which tools mutate.
func TestInvestigationAgentRefusesEveryWriteTool(t *testing.T) {
	e := &ToolExecutor{role: tunnel.RoleInvestigate}

	for _, tool := range []string{
		"scale_deployment", "restart_pod", "patch_resource_limits",
		"revert_container_image", "patch_field", "annotate_resource",
		"label_resource", "delete_resource", "create_resource",
		"open_execution_window", "close_execution_window",
	} {
		err := e.refuseIfWrongRole(tool)
		if err == nil {
			t.Errorf("%s was dispatched by the investigation agent rather than refused", tool)
			continue
		}
		if !strings.Contains(err.Error(), "read-only") {
			t.Errorf("%s refused with %q, which does not say why — an operator needs to know this is the wrong agent, not a missing grant", tool, err)
		}
	}
}

// TestInvestigationAgentStillServesEveryReadTool proves the refusal is
// narrow. A role check that also broke investigation would be a worse defect
// than the one it fixes.
func TestInvestigationAgentStillServesEveryReadTool(t *testing.T) {
	e := &ToolExecutor{role: tunnel.RoleInvestigate}

	for _, tool := range []string{
		"get_events", "get_logs", "describe_resource", "list_resources",
		"get_owner_chain", "get_gitops_ownership", "get_resource_schema",
		"list_nodeport_allocations", "reevaluate_rule", "query_metrics",
		"dry_run_patch",
	} {
		if err := e.refuseIfWrongRole(tool); err != nil {
			t.Errorf("%s was refused as a write action by the investigation agent: %v", tool, err)
		}
	}
}

// TestLegacySingleProcessAgentServesEverything is the backward-compatibility
// half on this side: an agent with no role configured is the pre-E11 shape
// and must behave exactly as it did.
func TestLegacySingleProcessAgentServesEverything(t *testing.T) {
	for _, role := range []string{"", tunnel.RoleAll, tunnel.RoleRemediate} {
		e := &ToolExecutor{role: role}
		if err := e.refuseIfWrongRole("scale_deployment"); err != nil {
			t.Errorf("an agent with role %q refused a write action (%v) — only the investigation role may do that", role, err)
		}
	}
}

// TestEffectiveRoleDefaultsToAllRatherThanFailing: a typo in a chart value
// must not stop an agent connecting at all, and RoleAll is the behaviour it
// had before the field existed.
func TestEffectiveRoleDefaultsToAllRatherThanFailing(t *testing.T) {
	for _, in := range []string{"", "nonsense", "INVESTIGATE"} {
		if got := effectiveRole(Config{Role: in}); got != tunnel.RoleAll {
			t.Errorf("effectiveRole(%q) = %q, want %q", in, got, tunnel.RoleAll)
		}
	}
	for _, in := range []string{tunnel.RoleInvestigate, tunnel.RoleRemediate} {
		if got := effectiveRole(Config{Role: in}); got != in {
			t.Errorf("effectiveRole(%q) = %q", in, got)
		}
	}
}
