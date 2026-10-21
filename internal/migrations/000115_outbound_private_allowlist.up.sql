-- org_settings.outbound_private_allowlist — the operator's explicit, named
-- exceptions to internal/outbound's default-deny on private destinations.
--
-- THE DECISION THIS IMPLEMENTS (owner, 2026-09-19). Outbound connections to AI
-- providers and Git repositories are default-deny for private/internal
-- destinations. That is correct for the common case and wrong for two real
-- deployments this product is meant to serve: a self-hosted vLLM, and an
-- internal GitHub Enterprise Server on a private address — the latter is
-- already treated as intended reachability by lld/01-threat-model.md's B7 row.
-- Two options were considered and REJECTED: allowing private destinations by
-- default, and shipping no opt-in at all. What ships is the third: keep
-- default-deny, and let an operator NAME specific destinations they trust.
--
-- WHY A LIST AND NOT A BOOLEAN. A boolean here would be the rejected
-- "allow private by default" option one click away — flip it and every private
-- address in the deployment is reachable again by an admin-supplied URL. A list
-- cannot degrade that way: internal/outbound.ParseAllowlist refuses any entry
-- that is not wholly inside a loopback/link-local/RFC1918/RFC4193 range, so
-- '0.0.0.0/0' is a validation error rather than a spelling of "off", and an
-- address nobody named stays refused.
--
-- SHAPE. A jsonb array of {"destination": "...", "reason": "..."} objects.
-- jsonb rather than the text[] every other list-shaped column on this table
-- uses (autonomy_unattended_namespaces, disabled_detector_ids) because an entry
-- is a PAIR: the reason is not decoration, it is the same requirement
-- internal/outbound.Policy.Reason already imposes on the compile-time private
-- allowance (NewClient panics without one), carried down to a per-entry
-- exception so that a list read a year later can still be reviewed. Two
-- parallel text[] columns would let the two halves drift out of alignment,
-- which for this table means an exception losing its justification.
--
-- destination is an IP literal, a CIDR, or a bare hostname. What a hostname
-- MEANS is the subtle part and lives next to the code that implements it
-- (internal/outbound/allowlist.go, parsedEntry.host): it is never matched
-- against the hostname in the URL being dialled — the guard resolves the
-- entry's own name at dial time and permits exactly the addresses it resolves
-- to, so the check stays "is the resolved address one the operator named" and
-- the DNS-rebinding defence (SR-9) is not reopened by a string comparison.
--
-- SCOPE. Consulted only by the AI-provider client (internal/llm) and the
-- repository clients (internal/scm) — the only two callers of
-- internal/outbound that are default-deny for private addresses.
-- internal/notify, internal/idp and internal/knowledge do not read it and are
-- unchanged, because for those three the question does not arise: each already
-- holds a wholesale compile-time AllowPrivate for a destination that is private
-- by design (an internal chat receiver, a Dex broker, an Ollama server).
--
-- DEFAULT '[]' — nothing allowlisted, which is today's exact behaviour. There
-- is no env-var fallback tier, for the same reason the autonomy and detection
-- settings have none: a brand-new, DB-backed-from-day-one setting with no prior
-- deploy-time convention to preserve, and an env var here would let an
-- unrelated redeploy silently widen an egress guard.
ALTER TABLE org_settings
  ADD COLUMN outbound_private_allowlist jsonb NOT NULL DEFAULT '[]'::jsonb;

-- The database's own half of the validation. internal/outbound.ParseAllowlist
-- is the real, complete check (range containment, metadata refusal, duplicate
-- and hostname-shape rejection) and runs at the API boundary, again in
-- internal/settings.Update, and again on read at dial time. This constraint
-- only guarantees the SHAPE, so a row hand-edited in psql cannot make
-- settings.Resolve fail to unmarshal and take every investigation down with it:
-- an array, of objects, each carrying a non-empty destination and a non-empty
-- reason. It deliberately does not try to re-express the range rules in SQL —
-- two implementations of a security rule drift, and the one that would drift
-- silently here is the one nothing tests.
ALTER TABLE org_settings
  ADD CONSTRAINT org_settings_outbound_private_allowlist_shape CHECK (
    jsonb_typeof(outbound_private_allowlist) = 'array'
    AND NOT jsonb_path_exists(outbound_private_allowlist,
          '$[*] ? (@.type() != "object")')
    AND NOT jsonb_path_exists(outbound_private_allowlist,
          '$[*] ? (!exists(@.destination ? (@.type() == "string" && @ <> "")))')
    AND NOT jsonb_path_exists(outbound_private_allowlist,
          '$[*] ? (!exists(@.reason ? (@.type() == "string" && @ <> "")))')
  );
