-- BACKLOG.md C8 (decided 2026-08-30) / BUGS.md 104: a mutating tunnel call
-- (scale_deployment/restart_pod/patch_resource_limits/revert_container_image)
-- whose OWN error is the disconnect/timeout shape — the request may have
-- reached the agent and been fully applied, only the ACK back was lost — was
-- unconditionally recorded as outcome:'failed', identically to an explicit
-- ToolResult.Error. A real, live-reproduced SIGKILL mid-patch proved this
-- wrong in the specific direction that matters most for trust: the patch had
-- genuinely applied, and remediation_executions/incidents.state said it had
-- not.
--
-- This widens both CHECK constraints the same way migrations 000040, 000056,
-- 000072, 000076 and 000079 already widened remediation_recommendations'
-- action_type constraint for a new enum value, and the same way migration
-- 000062 widened incidents_state_check for StateDiagnosed — the precedent
-- this codebase already has for "a new enum member needs its CHECK widened
-- explicitly; nothing does this automatically."

ALTER TABLE remediation_executions DROP CONSTRAINT remediation_executions_outcome_check;
ALTER TABLE remediation_executions ADD CONSTRAINT remediation_executions_outcome_check
  CHECK (outcome IN ('succeeded', 'failed', 'unknown'));

-- ExecutionUnknown (internal/orchestrator/state.go) is where the incident
-- lands when outcome = 'unknown': not a Failed variant (see that state
-- constant's own doc comment for why StateFailed would repeat the exact lie
-- this fix exists to stop asserting), a distinct destination
-- recordExecutionOutcome writes in the same transaction as the outcome row
-- above.
ALTER TABLE incidents DROP CONSTRAINT incidents_state_check;
ALTER TABLE incidents ADD CONSTRAINT incidents_state_check CHECK (state IN (
  'Detected', 'Investigating', 'RecommendationReady', 'NeedsHumanInvestigation',
  'AwaitingApproval', 'Executing', 'AwaitingMerge', 'Validating',
  'Resolved', 'Failed', 'Reopened', 'Dismissed', 'Diagnosed', 'ExecutionUnknown'
));
