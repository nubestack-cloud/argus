package api

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// AutomationGate is PROJECT.md T14's answer to "why isn't this happening
// automatically?" — a closed set of gate IDENTIFIERS, one per place in this
// codebase that can refuse an automatic analysis or an automatic execution.
// Mirrors migration 000110's incidents.automation_gate CHECK constraint
// exactly; a value here that isn't in that CHECK fails the very next write.
//
// # Why this file, and why a shared constant set
//
// internal/autoanalyze (the automatic-INVESTIGATION sweep) and
// internal/api/unattended.go (the automatic-EXECUTION sweep) are the only two
// callers, and they used to only log.Printf their refusal reason — real,
// correct, and invisible to anyone who wasn't reading the hub's stdout at the
// exact moment it happened. This file gives both of them ONE place to WRITE
// that same reason onto the incident, at the exact moment they decide to
// refuse — never a second function that re-derives what they decided, per
// this task's own central trap: "a new reporting function that re-evaluates
// the gates ... is precisely the bug."
//
// SetAutomationGate is called by the enforcing code itself (autoanalyze's
// selectEligible/collectEligible, unattended.go's collectUnattended/
// sweepUnattended), never by a read path — a GET handler only ever reads
// incidents.automation_gate/automation_gate_reason back, verbatim, and
// internal/orchestrator.SetState (the one place incidents.state is ever
// written) clears all three columns on every transition, so a reason can
// never outlive the state it was computed against.
type AutomationGate string

const (
	// GateSeverityNotSelected: autoanalyze — this incident's severity isn't
	// one of org_settings.auto_analysis_severities.
	GateSeverityNotSelected AutomationGate = "severity_not_selected"
	// GateDailySpendCeiling: autoanalyze — today's measured spend has reached
	// or exceeded org_settings.cost.dailySpendCeilingUsd (api.SpendCeilingBreached).
	GateDailySpendCeiling AutomationGate = "daily_spend_ceiling"
	// GateNoAIProvider: autoanalyze — the poller has backed off after an
	// investigation failed with no usable AI provider configured at all.
	GateNoAIProvider AutomationGate = "no_ai_provider"
	// GateClusterUnreachable: either sweeper — the target cluster is not
	// currently connected over the tunnel (gateway.Gateway.IsConnected).
	GateClusterUnreachable AutomationGate = "cluster_unreachable"
	// GateNamespaceScope: unattended.go — the plan's target namespace is not
	// in org_settings.autonomy_unattended_namespaces.
	GateNamespaceScope AutomationGate = "namespace_scope"
	// GateMaintenanceWindow: unattended.go — orchestrator.CheckWindows refused
	// (a change freeze is open, or no maintenance window is currently open).
	GateMaintenanceWindow AutomationGate = "maintenance_window"
	// GateCircuitBreaker: unattended.go — orchestrator.CheckBreaker found (or
	// just tripped) an open breaker for this cluster or the fleet.
	GateCircuitBreaker AutomationGate = "circuit_breaker"
	// GateBlastRadius: unattended.go — orchestrator.CheckBlastRadius refused;
	// the per-cluster or fleet-wide unattended-execution budget is spent.
	GateBlastRadius AutomationGate = "blast_radius"
	// GateBatchHold: unattended.go — orchestrator.BatchMembership holds this
	// incident behind an in-flight batch's wave 1.
	GateBatchHold AutomationGate = "batch_hold"
	// GateUnattendedExecutionDisabled: unattended.go — the feature itself is
	// off, or on with an empty namespace allowlist (which denies everything —
	// see collectUnattended's own comment).
	GateUnattendedExecutionDisabled AutomationGate = "unattended_execution_disabled"
)

// SetAutomationGate persists the exact gate and reason the caller just
// enforced against incidentID. Idempotent and cheap — one UPDATE, no read —
// and safe to call every sweep tick for the same incident: it always writes
// the CURRENT decision, so a stale reason from three ticks ago is never left
// standing once the real cause has changed.
func SetAutomationGate(ctx context.Context, tx pgx.Tx, incidentID string, gate AutomationGate, reason string) error {
	_, err := tx.Exec(ctx,
		`UPDATE incidents SET automation_gate = $2, automation_gate_reason = $3, automation_gate_at = now() WHERE id = $1`,
		incidentID, string(gate), reason)
	return err
}
