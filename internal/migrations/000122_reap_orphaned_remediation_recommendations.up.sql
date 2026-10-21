-- PROJECT.md B186, first of the two orphan sets migration 000120 deliberately
-- left: remediation_recommendations whose incident no longer exists.
--
-- 000120's own "Scope" note named this set and declined to take the decision,
-- because a recommendation is not a leaf: four things reference it (approval
-- decisions, executions, execution attempts, and its own sibling
-- self-reference), so an order has to be chosen and justified. This file is
-- that decision.
--
-- # Census
--
-- Measured on this repository's development database before writing it, as a
-- read-only census (role `postgres`, because `argus_app` returns zero rows
-- under RLS with no tenant set and would have made the debris look absent):
--
--   remediation_recommendations total .......................... 1133
--   ... orphaned (no incidents row with that id) ............... 1120
--   ... orphaned AND the cluster row is also gone .............. 1120
--   ... orphaned but on a cluster that still exists ................ 0
--   ... orphaned and on a LIVE (non-archived) cluster .............. 0
--   rows that survive this DELETE ................................. 13
--   surviving rows whose cluster row is gone ....................... 0
--
-- Five independent signals were checked against the same 1,120 rows and all
-- five agree that nothing real is in the set:
--
--   1. no incidents row for incident_id                       (1120 of 1120)
--   2. no analyses row for analysis_id                        (1120 of 1120)
--   3. no timeline_events row for incident_id                 (1120 of 1120)
--   4. no findings row for incident_id                        (1120 of 1120)
--   5. no clusters row for cluster_id at all — not archived, GONE
--                                                             (1120 of 1120)
--
-- Signal 5 is the strongest and is the one this file's predicate actually
-- uses, alongside signal 1. 776 DISTINCT cluster ids across 1,120 rows — about
-- 1.4 recommendations per cluster — is not a fleet, it is one throwaway cluster
-- per test run. The complement holds too: all 13 surviving rows have a
-- surviving cluster, and none of the three non-archived clusters contributes a
-- single row to the set. B175 required three agreeing signals and verified 0 of
-- 4 real clusters matched; this is the same bar met with two more signals.
--
-- # Why the predicate is CONJUNCTIVE, and not just "the incident is gone"
--
-- On this database the two predicates select exactly the same 1,120 rows, so
-- the conjunction costs nothing here. It is there for the database this
-- migration has not seen. "The incident is gone" is true of any recommendation
-- whose incident was removed by DELETE /api/v1/demo-data on a cluster that is
-- still enrolled and still being investigated — debris, but debris attached to
-- a live cluster, which is the one case worth being slower about. "And the
-- cluster is gone too" is unambiguous: nothing can reach the row, and nothing
-- can re-associate it, because cluster ids are ULIDs and are never reissued.
--
-- This is a one-time catch-up, not the mechanism, so narrowing it costs only
-- that some future debris waits for the mechanism instead of for this file.
--
-- # The deletion order, and why the sibling reference is not part of it
--
-- Four things reference remediation_recommendations(id):
--
--   remediation_execution_attempts.recommendation_id   (FK, NO ACTION)
--   remediation_executions.recommendation_id           (FK, NO ACTION)
--   remediation_approval_decisions.recommendation_id   (FK, NO ACTION)
--   remediation_recommendations.sibling_of_recommendation_id (FK, NO ACTION,
--                                                             self)
--
-- The first three are children and are deleted first, most-dependent first:
-- execution attempts reference BOTH a recommendation and (by plain column, no
-- foreign key) an execution, so deleting them first makes the order of the
-- other two irrelevant rather than load-bearing. Then executions, then
-- approval decisions, then the recommendations themselves.
--
-- Measured on the same census, so the order is justified rather than merely
-- plausible:
--
--   execution attempts referencing an orphan recommendation ......... 0
--   executions referencing an orphan recommendation ................. 8
--   approval decisions referencing an orphan recommendation ......... 0
--   execution attempts referencing one of those 8 executions ........ 0
--   surviving executions rolled back by one of those 8 .............. 0
--
-- The 8 executions are four (succeeded, failed) pairs written in the same
-- second on four throwaway clusters — a fixture inserting one of each, not a
-- record of anything that ran on a real cluster.
--
-- The self-reference is NOT solved by ordering, because it cannot be: 344 of
-- the orphans point at another orphan, and a set that references itself has no
-- root to start from. It is solved by the last DELETE being ONE statement.
-- Postgres queues a foreign key's referential-integrity check as an AFTER ROW
-- trigger that fires at the END of the statement, so a parent and the child
-- pointing at it may be removed together in a single DELETE; splitting the
-- same rows across two statements would fail on the first. Confirmed against a
-- real Postgres 16 with these exact rows, not reasoned about. The measured
-- edges say no surviving row points into the set (0 live recommendations name
-- an orphan as a sibling), so nothing outside it is affected either way.
--
-- # What this does not touch
--
-- audit_events, for the reason internal/dbtest/residue.go exempts it and
-- migration 000120 restated: it is a hash chain, and deleting from its middle
-- breaks `argusctl audit verify`. Nothing else here is an audit record —
-- remediation_approval_decisions would be, and this migration deletes none
-- (there are none to delete, and the statement is present so that the ORDER is
-- stated rather than discovered).
--
-- # Why this is a one-time DELETE rather than a foreign key or a reaper here
--
-- No foreign key to incidents can exist: incidents is PARTITION BY RANGE
-- (first_seen) with PRIMARY KEY (id, first_seen) (migration 000005), so
-- `REFERENCES incidents(id)` has no unique constraint to bind to, and the
-- composite form that IS declarable makes internal/partition's DROP TABLE
-- retention job fail. Migration 000120 measured both; internal/orchestrator/
-- orphanreaper.go states the same conclusion for every incident_id-carrying
-- table and names remediation_recommendations among them.
--
-- The ongoing mechanism therefore belongs in that reaper, whose own SCOPE note
-- says to extend its table list "if a future measurement finds it needed" —
-- this census is that measurement. The upstream fix is PROJECT.md B188: the
-- fixtures that manufacture these rows delete their cluster and their incident
-- and stop there. This file is only the backlog those two were too late for.
--
-- Runs as the migration superuser, so RLS is bypassed and this sees every
-- tenant's rows — which is what a one-time catch-up wants.

-- The predicate is spelled out in each statement rather than materialised once
-- into a temporary table. It is safe to re-evaluate, and checked to be: it
-- reads only remediation_recommendations, incidents and clusters, and the
-- statements below delete from remediation_execution_attempts,
-- remediation_executions and remediation_approval_decisions before touching
-- remediation_recommendations at all — so every evaluation sees the same rows.
-- A temporary table would have been the alternative, and was rejected because
-- it makes this file depend on how golang-migrate wraps a multi-statement
-- migration, which is a worse thing to depend on than a repeated WHERE clause.

-- 1. Execution attempts. First because this is the only table referencing both
--    a recommendation and an execution, so removing it makes the order of the
--    two below a matter of taste rather than of correctness.
DELETE FROM remediation_execution_attempts a
 WHERE a.recommendation_id IN (
       SELECT r.id FROM remediation_recommendations r
        WHERE NOT EXISTS (SELECT 1 FROM incidents i WHERE i.id = r.incident_id)
          AND NOT EXISTS (SELECT 1 FROM clusters c WHERE c.id = r.cluster_id))
    OR a.execution_id IN (
       SELECT e.id FROM remediation_executions e
        WHERE e.recommendation_id IN (
              SELECT r.id FROM remediation_recommendations r
               WHERE NOT EXISTS (SELECT 1 FROM incidents i WHERE i.id = r.incident_id)
                 AND NOT EXISTS (SELECT 1 FROM clusters c WHERE c.id = r.cluster_id)))
    OR a.undo_of_execution_id IN (
       SELECT e.id FROM remediation_executions e
        WHERE e.recommendation_id IN (
              SELECT r.id FROM remediation_recommendations r
               WHERE NOT EXISTS (SELECT 1 FROM incidents i WHERE i.id = r.incident_id)
                 AND NOT EXISTS (SELECT 1 FROM clusters c WHERE c.id = r.cluster_id)));

-- 2. rolled_back_by_execution_id is a plain column with no foreign key, so a
--    surviving execution pointing at a deleted one would be left dangling
--    rather than refused. None does (measured: 0), and clearing the pointer on
--    any that did is the honest repair — the execution it named is gone, so
--    "was rolled back by <nothing>" is the true statement, not a preserved id
--    that resolves to nothing.
UPDATE remediation_executions x
   SET rolled_back_by_execution_id = NULL
 WHERE x.rolled_back_by_execution_id IN (
       SELECT e.id FROM remediation_executions e
        WHERE e.recommendation_id IN (
              SELECT r.id FROM remediation_recommendations r
               WHERE NOT EXISTS (SELECT 1 FROM incidents i WHERE i.id = r.incident_id)
                 AND NOT EXISTS (SELECT 1 FROM clusters c WHERE c.id = r.cluster_id)));

-- 3. Executions.
DELETE FROM remediation_executions e
 WHERE e.recommendation_id IN (
       SELECT r.id FROM remediation_recommendations r
        WHERE NOT EXISTS (SELECT 1 FROM incidents i WHERE i.id = r.incident_id)
          AND NOT EXISTS (SELECT 1 FROM clusters c WHERE c.id = r.cluster_id));

-- 4. Approval decisions. None exist in the set on this database; the statement
--    is here so the ORDER is stated rather than discovered by a future
--    database that does have some.
DELETE FROM remediation_approval_decisions d
 WHERE d.recommendation_id IN (
       SELECT r.id FROM remediation_recommendations r
        WHERE NOT EXISTS (SELECT 1 FROM incidents i WHERE i.id = r.incident_id)
          AND NOT EXISTS (SELECT 1 FROM clusters c WHERE c.id = r.cluster_id));

-- 5. The recommendations themselves, in ONE statement — see "The deletion
--    order" above for why the 344-row sibling self-reference makes this the
--    only shape that works.
DELETE FROM remediation_recommendations r
 WHERE NOT EXISTS (SELECT 1 FROM incidents i WHERE i.id = r.incident_id)
   AND NOT EXISTS (SELECT 1 FROM clusters c WHERE c.id = r.cluster_id);
