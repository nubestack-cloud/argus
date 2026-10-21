-- PROJECT.md T14: "expose the backend's real automation decision wherever an
-- automatic analysis or execution did not run."
--
-- Before this migration, the reason automatic analysis/execution did NOT
-- happen for a given incident existed only as a log.Printf line inside
-- internal/autoanalyze's sweep and internal/api/unattended.go's sweeper —
-- both of which decide, correctly, but never carry that decision anywhere an
-- operator can see it per-incident. An operator watching an incident sit at
-- Detected or AwaitingApproval with nothing visibly happening had to
-- reconstruct the answer by reading several settings pages (severities,
-- spend ceiling, unattended namespaces, maintenance windows, breaker
-- thresholds, blast-radius caps) and guessing which one applied right now.
--
-- These three columns are where the ENFORCING code path (never a second,
-- read-time reimplementation of the same policy — see the Go call sites)
-- writes the one decisive gate and reason, at the moment it refuses:
--
--   - internal/autoanalyze's sweep, for "why hasn't this been auto-analyzed"
--     (severity not selected, daily spend ceiling reached, no usable AI
--     provider, cluster unreachable).
--   - internal/api/unattended.go's sweepUnattended/collectUnattended, for
--     "why hasn't this AutoApprove'd plan executed automatically yet"
--     (cluster unreachable, namespace not in the unattended allowlist, a
--     freeze/maintenance window, an open circuit breaker, the blast-radius
--     budget, or a held batch wave).
--
-- automation_gate is a closed set of gate IDENTIFIERS (never a raw enforcing
-- function's internal state) so the UI can key styling/grouping off it
-- without parsing automation_gate_reason's prose. automation_gate_reason is
-- the exact human-readable sentence the enforcing code already produces
-- today via log.Printf, now persisted instead of only logged.
--
-- Cleared to NULL by internal/orchestrator.SetState on every transition,
-- regardless of which path drives it (a human approval, an executed plan, a
-- resolve/dismiss, a reopen) — the single choke point every state change
-- already passes through — so a gate reason can never outlive the state it
-- was computed for. It is repopulated on the very next sweep tick if, and
-- only if, the incident is still eligible and still gated.
ALTER TABLE incidents
  ADD COLUMN automation_gate text
    CHECK (automation_gate IN (
      'severity_not_selected', 'daily_spend_ceiling', 'no_ai_provider',
      'cluster_unreachable', 'namespace_scope', 'maintenance_window',
      'circuit_breaker', 'blast_radius', 'batch_hold',
      'unattended_execution_disabled'
    )),
  ADD COLUMN automation_gate_reason text,
  ADD COLUMN automation_gate_at timestamptz;

-- automation_gate_reason must never be set without automation_gate, and vice
-- versa — a gate identifier with no reason (or a reason with no identifier
-- for the UI to key off) is exactly the "opaque gate" DESIGN.md §9.2 says
-- must never happen.
ALTER TABLE incidents
  ADD CONSTRAINT incidents_automation_gate_pair
  CHECK ((automation_gate IS NULL) = (automation_gate_reason IS NULL));
