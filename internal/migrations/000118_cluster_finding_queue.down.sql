-- Drops the three columns. Nothing else depends on them, and there is nothing
-- to preserve: they are a mirror of an agent-side counter that the next
-- heartbeat after a re-apply rewrites in full.
ALTER TABLE clusters DROP COLUMN finding_queue_pending;
ALTER TABLE clusters DROP COLUMN finding_queue_dropped;
ALTER TABLE clusters DROP COLUMN finding_queue_capacity;
