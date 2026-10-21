-- Correlate incidents by the OBJECT they are about, not only by fingerprint.
-- Closes the noise problem measured in CAPABILITIES.md §5.
--
-- The problem, measured on a live cluster rather than reasoned about:
--
--   one Deployment with a bad image  -> 3 incidents (ErrImagePull, Failed, ImagePullBackOff)
--   one OOM-killed container         -> 3 incidents (OOMKilled, CrashLoopBackOff, BackOff)
--   one failed Job                   -> 2 incidents (BackoffLimitExceeded, JobFailed)
--   one missing ConfigMap (2 pods)   -> 4 incidents (FailedMount, PendingTimeout, per pod)
--
-- About 3.7x more incidents than there were problems. The failed Job is the
-- sharpest case: two DIFFERENT detectors reported the same fault in the same
-- second, so no amount of per-detector deduplication can merge them — their
-- fingerprints legitimately differ, because a fingerprint is
-- hash(namespace, kind, name, REASON) and the reasons really are different.
--
-- One broken object is one problem. An operator paged three times for one
-- broken pod stops reading the list, and with auto-analysis enabled it is also
-- three paid investigations of the same thing.
--
-- WHY A NEW COLUMN RATHER THAN CHANGING THE FINGERPRINT
--
-- The fingerprint stays exactly as it is, on both findings and incidents.
-- Dropping the reason from it would destroy the per-reason recurrence
-- deduplication the agent-side detectors rely on (each detector resends its own
-- fingerprint on a cooldown, and collapsing reasons would make a flapping
-- object's distinct symptoms indistinguishable). This column is ADDITIVE: the
-- fingerprint keeps identifying "this symptom", and object_key identifies
-- "this thing", which is the level an incident should actually live at.
--
-- incidents.fingerprint therefore changes meaning slightly: it becomes the
-- fingerprint of the finding that OPENED the incident, not an identifier for
-- it. Every fingerprint that ever attached is still recoverable from the
-- findings rows, which is what internal/fleetgroup is switched to reading.
--
-- FORMAT: gvk|namespace|object_name, matching the tuple a Finding already
-- carries. Namespace is empty for cluster-scoped objects (Nodes), which is
-- fine and intended — an empty segment is still a distinct, stable key.
-- Built in Go (internal/gateway.objectCorrelationKey) as well as here, and the
-- two must agree; the backfill below is the only place this file needs it.
ALTER TABLE incidents ADD COLUMN object_key text;

-- The lookup this exists to serve: "is there an open incident for this object
-- on this cluster?" State is included so the common case (open incidents only)
-- is answered from the index.
--
-- Not UNIQUE, deliberately. incidents is PARTITION BY RANGE (first_seen), and
-- Postgres requires a unique index on a partitioned table to include the
-- partition key — a (cluster_id, object_key, first_seen) unique index would not
-- actually catch two racing inserts, since those differ in first_seen, which is
-- exactly the normal case. Concurrency is handled where it can be handled
-- correctly: a pg_advisory_xact_lock on the object key in
-- internal/gateway/finding.go, the same reasoning migration 000004's own
-- correlation lock records.
CREATE INDEX incidents_object_key_idx ON incidents (cluster_id, object_key, state);

-- Backfill from each incident's earliest finding.
--
-- Required for correctness, not tidiness: an already-open incident with a NULL
-- object_key would not match the new lookup, so the next finding for that same
-- object would open a SECOND incident — this migration would briefly cause the
-- very duplication it exists to remove.
--
-- DISTINCT ON (incident_id) ORDER BY occurred_at picks the finding that opened
-- the incident, matching what the Go path now writes. Findings with an empty
-- object_name are skipped: they cannot form a meaningful object identity, and
-- the Go path deliberately falls back to fingerprint correlation for them
-- rather than merging unrelated objects under a degenerate key.
UPDATE incidents i
   SET object_key = sub.object_key
  FROM (
        SELECT DISTINCT ON (incident_id)
               incident_id,
               gvk || '|' || coalesce(namespace, '') || '|' || object_name AS object_key
          FROM findings
         WHERE incident_id IS NOT NULL
           AND coalesce(object_name, '') <> ''
         ORDER BY incident_id, occurred_at
       ) sub
 WHERE i.id = sub.incident_id
   AND i.object_key IS NULL;
