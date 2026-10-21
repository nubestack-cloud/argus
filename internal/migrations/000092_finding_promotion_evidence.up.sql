ALTER TABLE findings
  ADD COLUMN signal_class text NOT NULL DEFAULT 'fault'
    CHECK (signal_class IN ('fault', 'risk', 'anomaly')),
  ADD COLUMN confidence text NOT NULL DEFAULT 'verified'
    CHECK (confidence IN ('verified', 'inferred', 'unverified')),
  ADD COLUMN impact text NOT NULL DEFAULT 'degraded'
    CHECK (impact IN ('unavailable', 'degraded', 'potential', 'none'));

-- These mechanism names were already stable on the wire before evidence
-- dimensions existed. Backfill their honest meaning without reinterpreting
-- arbitrary detector reasons or changing historical incident state.
UPDATE findings
   SET signal_class = 'anomaly', confidence = 'unverified', impact = 'none'
 WHERE reason LIKE 'GenericConditionAnomaly:%'
    OR reason LIKE 'GenericDanglingReference:%'
    OR reason = 'GenericPeerConditionShapeOutlier';
