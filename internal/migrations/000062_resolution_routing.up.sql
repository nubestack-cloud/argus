-- BACKLOG.md F17 / lld/08-remediation-contracts.md §12, ADR-18 (accepted):
-- computes a resolution Route in non-AI code before the model proposes, and
-- persists it — closing the finding that today "the pull-request/in-place
-- choice is made by the model from a prompt sentence... guidance has no
-- representation, and DESIGN.md §10.1's pullRequest+inPlace pair is
-- unrepresentable."

-- §12.6: the route lives on the INCIDENT, not the recommendation, because it
-- is a property of the object's ownership, not of any one proposal —
-- re-analysing must not silently re-route (§12.9 decision B).
ALTER TABLE incidents
  ADD COLUMN route text
    CHECK (route IN ('pullRequest', 'inPlace', 'pullRequest+inPlace', 'guidance')),
  -- The §12.4 table row (or gap-filling rule — see internal/resolution's own
  -- comments) that fired, shown to the operator. Free text rather than an
  -- enum: it is prose explaining a decision, not a value anything branches
  -- on.
  ADD COLUMN route_reason text,
  ADD COLUMN applier text
    CHECK (applier IN ('gitopsController', 'none', 'unknown'));

-- §12.7: Diagnosed is a new terminal state — see internal/orchestrator/
-- state.go's own doc comment for why it is not a reuse of
-- NeedsHumanInvestigation. The partitioned table's CHECK constraint has to
-- be widened explicitly; nothing has needed to since migration 000005
-- defined it.
ALTER TABLE incidents DROP CONSTRAINT incidents_state_check;
ALTER TABLE incidents ADD CONSTRAINT incidents_state_check CHECK (state IN (
  'Detected', 'Investigating', 'RecommendationReady', 'NeedsHumanInvestigation',
  'AwaitingApproval', 'Executing', 'AwaitingMerge', 'Validating',
  'Resolved', 'Failed', 'Reopened', 'Dismissed', 'Diagnosed'
));

-- §12.6: "two live recommendations may coexist for one incident when
-- route = 'pullRequest+inPlace', distinguished by action_type." Deliberately
-- NOT overloading superseded_at for the sibling relationship — that column
-- is what stops the unattended sweeper executing a stale plan
-- (internal/api/unattended.go filters superseded_at IS NULL), and the
-- paired route's in-place sibling is not stale, it is a companion. A
-- separate, purely-descriptive column keeps that safety property untouched.
--
-- Self-referencing rather than a join table: a sibling pair is always
-- exactly two rows, symmetric, and never outlives the recommendation it
-- points at.
ALTER TABLE remediation_recommendations
  ADD COLUMN sibling_of_recommendation_id text REFERENCES remediation_recommendations(id);

-- No index on any of these: read by incident id / recommendation id (each a
-- primary key) for exactly one row, same as every other narrow per-row
-- column in these two tables.
