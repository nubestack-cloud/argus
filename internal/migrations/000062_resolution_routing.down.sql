ALTER TABLE remediation_recommendations DROP COLUMN sibling_of_recommendation_id;

ALTER TABLE incidents DROP CONSTRAINT incidents_state_check;
ALTER TABLE incidents ADD CONSTRAINT incidents_state_check CHECK (state IN (
  'Detected', 'Investigating', 'RecommendationReady', 'NeedsHumanInvestigation',
  'AwaitingApproval', 'Executing', 'AwaitingMerge', 'Validating',
  'Resolved', 'Failed', 'Reopened', 'Dismissed'
));

ALTER TABLE incidents
  DROP COLUMN route,
  DROP COLUMN route_reason,
  DROP COLUMN applier;
