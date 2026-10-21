REVOKE CREATE ON SCHEMA public FROM argus_app;

-- CURRENT_USER, not a hardcoded "postgres" — migrations always run as
-- whichever role ARGUS_MIGRATE_DATABASE_URL authenticates as (the same role
-- that owned these tables before the up migration ran), which need not
-- literally be named "postgres" in every deployment (e.g. a managed
-- Postgres service's admin role is often named differently).
ALTER TABLE findings     OWNER TO CURRENT_USER;
ALTER TABLE incidents    OWNER TO CURRENT_USER;
ALTER TABLE audit_events OWNER TO CURRENT_USER;
