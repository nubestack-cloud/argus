ALTER TABLE remediation_recommendations DROP CONSTRAINT remediation_recommendations_risk_level_check;
ALTER TABLE remediation_recommendations ADD CONSTRAINT remediation_recommendations_risk_level_check
  CHECK (risk_level IN ('low', 'medium', 'high'));
