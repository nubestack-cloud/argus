ALTER TABLE incidents DROP CONSTRAINT incidents_state_check;
ALTER TABLE incidents ADD CONSTRAINT incidents_state_check CHECK (state IN (
  'Detected', 'Investigating', 'RecommendationReady', 'NeedsHumanInvestigation',
  'AwaitingApproval', 'Executing', 'AwaitingMerge', 'Validating',
  'Resolved', 'Failed', 'Reopened', 'Dismissed', 'Diagnosed'
));

ALTER TABLE remediation_executions DROP CONSTRAINT remediation_executions_outcome_check;
ALTER TABLE remediation_executions ADD CONSTRAINT remediation_executions_outcome_check
  CHECK (outcome IN ('succeeded', 'failed'));
