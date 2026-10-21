DROP INDEX IF EXISTS incidents_auto_analysis_retry_after_idx;
ALTER TABLE incidents DROP COLUMN IF EXISTS auto_analysis_retry_after;
ALTER TABLE incidents DROP COLUMN IF EXISTS auto_analysis_last_error;
ALTER TABLE incidents DROP COLUMN IF EXISTS auto_analysis_attempts;

-- Any row sitting in ValidationUnknown would violate the narrowed constraint.
-- Moved to Validating rather than Resolved: this migration exists precisely
-- because resolving an unverified fix is the lie being removed, and a
-- rollback must not reintroduce it row by row. Validating is where the
-- sweeper would have kept them, and it is a legal predecessor of every exit.
UPDATE incidents SET state = 'Validating' WHERE state = 'ValidationUnknown';

ALTER TABLE incidents DROP CONSTRAINT incidents_state_check;
ALTER TABLE incidents ADD CONSTRAINT incidents_state_check CHECK (state IN (
  'Detected', 'Investigating', 'RecommendationReady', 'NeedsHumanInvestigation',
  'AwaitingApproval', 'Executing', 'AwaitingMerge', 'Validating',
  'Resolved', 'Failed', 'Reopened', 'Dismissed', 'Diagnosed', 'ExecutionUnknown'
));
