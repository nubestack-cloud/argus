-- PROJECT.md T10 / lld/01-threat-model.md T12, SR-13 ("the ceiling check and
-- the investigation-start action must be the same atomic operation").
--
-- Before this table, internal/api/spend.go's TodaySpendUSD/
-- SpendCeilingBreached were read-only: the daily spend ceiling was checked
-- once, before any work started, and the real cost was only recorded AFTER
-- an investigation finished (analyses.cost_usd). Nothing tied the two
-- together, so N concurrent automatic investigations
-- (internal/autoanalyze's runWaves runs up to maxConcurrentInvestigations at
-- once, each in its OWN transaction) could each read the same "spend so
-- far" figure, each see headroom under the ceiling, and each proceed — the
-- textbook check-then-act race SR-13 names.
--
-- spend_reservations is what makes "check the ceiling" and "claim the work"
-- one atomic step (internal/api.ReserveSpend): before an automatic
-- investigation is allowed to start, it reserves an upper-bound estimate of
-- what it might cost, INSIDE the same transaction that marks the incident
-- Investigating (see internal/autoanalyze's investigateOne). Concurrent
-- reservation attempts for the same tenant+day serialize on a Postgres
-- advisory transaction lock (ReserveSpend's own doc comment), so two
-- concurrent investigations can no longer both observe the same pre-work
-- total and both proceed past it.
--
-- A reservation is reconciled exactly once, by whichever of
-- internal/api.SettleSpendReservation (a real, possibly chargeable outcome
-- is now known) or internal/api.ReleaseSpendReservation (the investigation
-- produced no chargeable result at all — it failed, or its cost basis was
-- never chargeable, e.g. a subscription-billed CLI run) runs at the end of
-- that same investigation's own transaction.
--
-- No foreign key on incident_id: this table is a short-lived accounting
-- ledger for one day's reservations, not a durable record that needs to
-- survive or cascade with the incident row the way analyses/evidence do —
-- see TodaySpend's own doc comment on why analyses.cost_usd, not this
-- table, is the durable source of truth for real spend once a reservation
-- settles.
CREATE TABLE spend_reservations (
  id            text PRIMARY KEY,
  tenant_id     text NOT NULL REFERENCES organisations(id),
  cluster_id    text,
  incident_id   text NOT NULL,
  day           date NOT NULL,
  reserved_usd  double precision NOT NULL,
  -- 'reserved': a projected cost, not yet reconciled — counted toward the
  --   ceiling by ReserveSpend's own open-reservations sum.
  -- 'settled': reconciled to a real outcome. Its own actual_usd may be zero
  --   (a non-chargeable cost basis, or pricing that computed to zero) or
  --   more/less than reserved_usd (a genuine over/under-run, recorded
  --   rather than discarded — see SettleSpendReservation's own doc
  --   comment). No longer counted itself once settled, because a
  --   chargeable actual cost is, by then, already inside analyses.cost_usd,
  --   which TodaySpendUSD sums directly.
  -- 'released': the investigation never produced a chargeable result at
  --   all (it failed before persisting anything, or its cost basis was
  --   never chargeable) — the full reservation is freed, actual_usd = 0.
  status        text NOT NULL DEFAULT 'reserved' CHECK (status IN ('reserved', 'settled', 'released')),
  actual_usd    double precision,
  created_at    timestamptz NOT NULL DEFAULT now(),
  settled_at    timestamptz
);

-- The only query this table's own logic ever runs against more than one
-- row: sum still-open reservations for one tenant on one day, taken under
-- the same advisory lock as the insert that competes with it (ReserveSpend).
CREATE INDEX spend_reservations_open_idx ON spend_reservations (tenant_id, day)
  WHERE status = 'reserved';

-- Tenant-scoped, not cluster-scoped: DailySpendCeilingUsd is a single
-- org-wide setting (internal/settings.Config), not per-cluster, so the
-- ceiling this table backs is an org-wide total — matching the tenant-only
-- RLS shape migration 000009 already uses for enrollment_tokens/
-- notification_routes rather than the cluster-scoped shape.
ALTER TABLE spend_reservations ENABLE ROW LEVEL SECURITY;
ALTER TABLE spend_reservations FORCE ROW LEVEL SECURITY;
CREATE POLICY spend_reservations_scope ON spend_reservations
  USING (tenant_id = current_setting('app.tenant_id', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON spend_reservations TO argus_app;
