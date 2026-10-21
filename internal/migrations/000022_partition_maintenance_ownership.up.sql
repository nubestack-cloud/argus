-- Grants internal/partition's daily maintenance job (see that package's doc
-- comment) the privileges it actually needs to create and drop partitions
-- of findings/incidents/audit_events at runtime, as the argus_app role the
-- hub always connects as (migration 000009's SR-2 precondition, enforced by
-- internal/data.DB.CheckRLSPreconditions).
--
-- Why ownership, not a bigger GRANT: Postgres requires the role issuing
-- `CREATE TABLE ... PARTITION OF parent` (an implicit ATTACH PARTITION) or
-- `ALTER TABLE parent ATTACH/DETACH PARTITION` to OWN the parent table —
-- there is no separate grantable privilege for "manage this table's
-- partitions" the way SELECT/INSERT/UPDATE/DELETE are grantable. Since
-- migration 000005/000004/000008 created these three tables as the
-- migration-owning role (postgres, per ARGUS_MIGRATE_DATABASE_URL), argus_app
-- has never been able to attach or drop a partition of any of them — which
-- is exactly why, prior to this migration, not one real dated partition was
-- ever created by anything at runtime, and every row has landed in each
-- table's `_default` partition since this project began.
--
-- This does NOT weaken row-level security: 000005/000008 already set FORCE
-- ROW LEVEL SECURITY on all three tables, and FORCE is specifically what
-- makes RLS apply even to the table's own owner — an owner with FORCE RLS
-- set still can't read/write a row outside its scope, ownership only grants
-- DDL rights (CREATE/ALTER/DROP), which RLS never governed in the first
-- place. SR-2's other precondition (argus_app has no BYPASSRLS) is
-- unaffected — ownership and BYPASSRLS are unrelated role attributes.
--
-- CREATE ON SCHEMA public is also needed: creating a new partition creates
-- a brand-new relation in the schema, which requires CREATE privilege on
-- the schema itself, not just ownership of the parent being partitioned.
-- argus_app previously had USAGE only (migration 000009).
ALTER TABLE findings     OWNER TO argus_app;
ALTER TABLE incidents    OWNER TO argus_app;
ALTER TABLE audit_events OWNER TO argus_app;

GRANT CREATE ON SCHEMA public TO argus_app;
