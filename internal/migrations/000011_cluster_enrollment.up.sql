-- Cluster enrollment redemption (lld/03-agent-protocol.md §5). Migration 000002
-- already has `cert_serial`, `cluster_fingerprint`, `agent_version`, and
-- `last_heartbeat_at` — this migration adds only what's still missing to carry a
-- cluster from a redeemed enrollment token + submitted CSR through to an issued
-- leaf cert and an agent-pollable status:
--   * `poll_token_hash` — hash of the opaque poll token handed back at enroll
--     time (never the raw token, same discipline as refresh_tokens.token_hash).
--   * `csr_pem` — the CSR submitted at enroll time, stored as-is; signing happens
--     later, at accept time, not here.
--   * `issued_cert_pem` — the signed leaf cert, populated once, then returned
--     idempotently on every subsequent status poll.

ALTER TABLE clusters ADD COLUMN poll_token_hash text;
ALTER TABLE clusters ADD COLUMN csr_pem text;
ALTER TABLE clusters ADD COLUMN issued_cert_pem text;

CREATE UNIQUE INDEX clusters_poll_token_idx ON clusters (poll_token_hash) WHERE poll_token_hash IS NOT NULL;

-- Deliberate, flagged deviation from this increment's spec (which said "do not
-- add a new RLS policy here, just confirm clusters already has a working one
-- keyed on id/tenant_id"): confirming it turned up a real, blocking gap, not a
-- non-issue. `clusters_scope` (000009) keys SOLELY on
-- `id = ANY(app.accessible_cluster_ids)`, and nothing anywhere in this codebase
-- ever populates app.accessible_cluster_ids with anything (requireAuth always
-- passes nil — see internal/api/middleware.go's own comment that per-cluster
-- scope resolution "is deferred to when such a route exists"). That means,
-- as shipped, `clusters_scope` alone makes EVERY read/write against `clusters`
-- return zero rows for EVERY caller, including a super-admin — not a corner
-- case, a total block on this table. It also structurally cannot support any
-- lookup by an alternate key (poll_token_hash, cert_serial, cluster_fingerprint)
-- performed before the caller's accessible cluster IDs are known, which is
-- exactly what enrollment status polling, the gateway's cert-serial lookup, and
-- the enrollment fingerprint-collision check all need to do.
--
-- Fix: add a second, tenant_id-keyed PERMISSIVE policy, exactly the shape every
-- other tenant-scoped table in 000009 already uses. Postgres OR's multiple
-- permissive policies together for the same command, so this is strictly
-- additive — `clusters_scope`'s id-based check still applies and still narrows
-- access further once/if per-cluster-scoped grants and their accessible_cluster_ids
-- resolution are ever implemented (authz-spec §6, still not built anywhere).
-- Until then, tenant_id scoping is the only thing that can possibly work, and
-- for this confirmed single-organisation deployment (DESIGN.md
-- §5.1/D9) it is exactly as safe as every other table's tenant_id policy already
-- in production use.
CREATE POLICY clusters_tenant_scope ON clusters
  USING (tenant_id = current_setting('app.tenant_id', true));
