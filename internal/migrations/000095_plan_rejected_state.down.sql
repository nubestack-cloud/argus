-- Any row sitting in PlanRejected would violate the narrowed constraint.
--
-- Moved to NeedsHumanInvestigation, NOT to the Dismissed this state replaced
-- and NOT back to AwaitingApproval. Dismissed would re-assert, row by row,
-- exactly the "this fault no longer matters" claim the up-migration exists to
-- stop making, and 000094's own down-migration established that a rollback
-- must not reintroduce the lie it removed. AwaitingApproval would be worse
-- than a lie: it would put a plan a human explicitly refused back into the
-- queue where a second approver could execute it.
--
-- NeedsHumanInvestigation is imprecise about HOW the incident got there --
-- that is the cost of rolling back -- but it is true about the two things that
-- matter operationally: the incident is open, and it is a human's. The
-- rejection itself is untouched in remediation_approval_decisions and on the
-- timeline either way.
UPDATE incidents SET state = 'NeedsHumanInvestigation' WHERE state = 'PlanRejected';

ALTER TABLE incidents DROP CONSTRAINT incidents_state_check;
ALTER TABLE incidents ADD CONSTRAINT incidents_state_check CHECK (state IN (
  'Detected', 'Investigating', 'RecommendationReady', 'NeedsHumanInvestigation',
  'AwaitingApproval', 'Executing', 'AwaitingMerge', 'Validating',
  'Resolved', 'Failed', 'Reopened', 'Dismissed', 'Diagnosed', 'ExecutionUnknown',
  'ValidationUnknown'
));
