-- Reverses 000039. Dropping this index costs no data — only the query plan for
-- GET /incidents/{id}, which reverts to a sequential scan of every findings
-- partition on every poll.
DROP INDEX IF EXISTS findings_incident_idx;
