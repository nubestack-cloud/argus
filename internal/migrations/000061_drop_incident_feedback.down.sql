-- Recreates incident_feedback exactly as migration 000053 declared it, so a
-- rollback restores the schema and its reasoning verbatim. See WISHLIST.md W1.

-- Feedback capture (BACKLOG L1) — the entry point to the "Learn" pillar
-- STATUS.md lists as not existing at all. CapIncidentFeedback has been defined
-- since the start with no handler behind it; this is the table that handler needs.
--
-- THE ONE DECISION THAT MATTERS HERE: feedback binds to an ANALYSIS, not just to
-- an incident.
--
-- Feedback on "the incident" is nearly useless for the thing this data exists to
-- enable. L3's calibration curve needs a (predicted confidence, actual outcome)
-- pair, and the confidence belongs to one analysis — an incident can be analysed
-- several times, by different models, at different prompt versions, reaching
-- different conclusions with different confidence. "The root cause was wrong" is
-- unattributable unless it says WHICH root cause. Getting this wrong would not
-- fail; it would quietly produce a calibration curve that means nothing, which is
-- worse than having none.
--
-- analysis_id is still nullable, because the other consumer wants the other rows:
-- a knowledge base (L2) is interested in "what actually fixed this" even for an
-- incident nobody ever analysed. So the column is optional and the calibration
-- query is what filters on it, rather than the schema forbidding the useful case.
CREATE TABLE incident_feedback (
  id              text        PRIMARY KEY,
  tenant_id       text        NOT NULL REFERENCES organisations(id),
  -- NO foreign key to incidents, and it is not an omission. incidents is
  -- RANGE-partitioned on first_seen, so its primary key is (id, first_seen) and
  -- there is no unique constraint on id alone for a reference to match. Postgres
  -- refuses the FK outright. Every other table in this schema that carries an
  -- incident_id -- analyses, remediation_recommendations, remediation_executions,
  -- findings -- is in the same position and none of them has one either. Written
  -- down here because the first attempt at this table DID declare the FK and the
  -- migration failed on it; the next person will try the same thing.
  incident_id     text        NOT NULL,
  cluster_id      text        NOT NULL REFERENCES clusters(id),

  -- The analysis being judged. NULL means feedback about the incident with no
  -- analysis attached — usable by a knowledge base, not by calibration.
  analysis_id     text        REFERENCES analyses(id),

  -- Was the diagnosis right? 'partly' is a real answer and not a fudge: the most
  -- common useful case is a correct causal chain with the wrong final attribution,
  -- and collapsing that into correct/wrong would throw away the distinction that
  -- makes the feedback worth reading.
  root_cause_verdict text NOT NULL
    CHECK (root_cause_verdict IN ('correct', 'partly', 'wrong', 'unsure')),

  -- Was the proposed fix right? Separate from the diagnosis because they come
  -- apart in both directions — a right diagnosis with a wrong remedy, and (rarely,
  -- and worth knowing about) a wrong diagnosis whose remedy happened to work.
  -- 'not_proposed' covers an incident that never got as far as a recommendation,
  -- which must not be recorded as the fix being wrong.
  fix_verdict text NOT NULL
    CHECK (fix_verdict IN ('correct', 'partly', 'wrong', 'not_proposed', 'unsure')),

  -- What it actually was, and what actually fixed it. Free text, and the single
  -- most valuable column here for a future knowledge base — everything else is an
  -- enum a model could have guessed.
  actual_cause    text,
  actual_fix      text,
  notes           text,

  submitted_by    text        NOT NULL REFERENCES users(id),
  submitted_at    timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now()
);

-- One row per person per analysis, so a calibration curve cannot be skewed by
-- somebody clicking twice. Two people are deliberately allowed to DISAGREE about
-- the same analysis: that is real signal, and aggregating it is L3's problem, not
-- something to suppress here.
--
-- COALESCE because a NULL analysis_id would never conflict with itself under a
-- plain UNIQUE, which would let one person leave unlimited un-analysed feedback on
-- one incident.
CREATE UNIQUE INDEX incident_feedback_one_per_person
  ON incident_feedback (incident_id, COALESCE(analysis_id, ''), submitted_by);

CREATE INDEX incident_feedback_incident ON incident_feedback (incident_id, submitted_at DESC);

-- The calibration read path (L3): every judged analysis, newest first. Partial,
-- because rows with no analysis can never appear in a calibration curve.
CREATE INDEX incident_feedback_calibration
  ON incident_feedback (analysis_id, submitted_at DESC)
  WHERE analysis_id IS NOT NULL;

ALTER TABLE incident_feedback ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_feedback FORCE ROW LEVEL SECURITY;

CREATE POLICY incident_feedback_tenant_scope ON incident_feedback
  USING (tenant_id = current_setting('app.tenant_id', true));

-- The cluster-scoped policy carries the "empty means unrestricted" branch, because
-- the fleet-wide calibration read runs as a background/aggregate query with no
-- accessible-cluster list. Omitting it is the trap WORKLOG §152 hit on
-- cluster_facts: the join reads as zero rows and the feature silently does nothing,
-- with no error anywhere.
CREATE POLICY incident_feedback_cluster_scope ON incident_feedback
  AS RESTRICTIVE
  USING (
    COALESCE(current_setting('app.accessible_cluster_ids', true), '') = ''
    OR cluster_id = ANY (string_to_array(current_setting('app.accessible_cluster_ids', true), ','))
  )
  WITH CHECK (
    COALESCE(current_setting('app.accessible_cluster_ids', true), '') = ''
    OR cluster_id = ANY (string_to_array(current_setting('app.accessible_cluster_ids', true), ','))
  );
