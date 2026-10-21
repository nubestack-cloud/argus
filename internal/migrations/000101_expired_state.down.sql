-- Reverses 000101. Reclassified rows go back to Dismissed (the state they
-- were in immediately before this migration ran) before the CHECK
-- constraint that allows 'Expired' at all is removed — dropping the
-- constraint first would leave any 'Expired' row (including ones created
-- after this migration, by ordinary use) unable to satisfy the narrower
-- constraint being restored.
UPDATE incidents SET state = 'Dismissed' WHERE state = 'Expired';

ALTER TABLE incidents DROP CONSTRAINT incidents_state_check;
ALTER TABLE incidents ADD CONSTRAINT incidents_state_check CHECK (state IN (
  'Detected', 'Investigating', 'RecommendationReady', 'NeedsHumanInvestigation',
  'AwaitingApproval', 'Executing', 'AwaitingMerge', 'Validating',
  'Resolved', 'Failed', 'Reopened', 'Dismissed', 'Diagnosed', 'ExecutionUnknown',
  'ValidationUnknown', 'PlanRejected'
));
