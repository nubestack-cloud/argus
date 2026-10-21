-- Rejecting a proposed fix stopped meaning "dismiss this incident".
--
-- internal/api/approvals.go encoded a rejection as AwaitingApproval ->
-- Dismissed. Dismissed means "this is real but needs no action from ARGUS"
-- (internal/api/incident_triage.go) and it is terminal, so a human clicking
-- "this proposed fix is unsafe" silently produced "this fault no longer
-- matters": the incident left the queue with the fault still live in the
-- cluster and nobody assigned to it. The one thing a rejection definitely does
-- not establish is that the problem went away.
--
-- PlanRejected is a new state rather than a reuse of NeedsHumanInvestigation
-- for the reason 000081 (ExecutionUnknown) and 000094 (ValidationUnknown) each
-- gave: NeedsHumanInvestigation asserts the INVESTIGATION stopped short, and
-- here it did the opposite -- it produced a root cause and a concrete plan,
-- and a person read that plan and refused it. Reusing it would swap one false
-- claim for another.
--
-- No new column. The rejection reason is already durable in
-- remediation_approval_decisions.reason and on the timeline
-- (EventApprovalRejected); this codebase has already written two rejection
-- reasons that nothing read back (grants.justification until 2026-08-22,
-- incidents.pr_rejection_reason), and a third write-only field would be worse
-- than none. What this state adds is that the incident stays where that reason
-- can be found.
--
-- Widening incidents_state_check follows the precedent 000062 (Diagnosed),
-- 000081 (ExecutionUnknown) and 000094 (ValidationUnknown) already set: a new
-- enum member needs its CHECK widened explicitly; nothing does this
-- automatically.

ALTER TABLE incidents DROP CONSTRAINT incidents_state_check;
ALTER TABLE incidents ADD CONSTRAINT incidents_state_check CHECK (state IN (
  'Detected', 'Investigating', 'RecommendationReady', 'NeedsHumanInvestigation',
  'AwaitingApproval', 'Executing', 'AwaitingMerge', 'Validating',
  'Resolved', 'Failed', 'Reopened', 'Dismissed', 'Diagnosed', 'ExecutionUnknown',
  'ValidationUnknown', 'PlanRejected'
));

-- Deliberately NOT backfilled. Every already-Dismissed incident whose latest
-- decision is 'rejected' was closed under the old meaning, and re-opening it
-- would assert something this migration cannot check: that the fault is still
-- live weeks later. Reviving incidents an operator has stopped looking at, on
-- an upgrade, is its own kind of dishonesty. The rejection record on those rows
-- is unchanged and still readable; the fix applies from here forward.
