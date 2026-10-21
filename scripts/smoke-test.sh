#!/usr/bin/env bash
# End-to-end smoke test against a running hub — the exact sequence used to verify
# each increment while building it (STATUS.md §4), now saved as a repeatable
# script instead of re-typed curl commands every time.
#
# Prerequisite: the stack is already up —
#   docker build -t argus/hub:dev . && docker compose -f deploy/compose/docker-compose.yaml up -d
#
# Usage:
#   ./scripts/smoke-test.sh
#   ARGUS_ADMIN_PASSWORD=... ./scripts/smoke-test.sh   # skip log-scraping on a
#                                                        # non-fresh stack (bootstrap
#                                                        # only prints its password once)
set -uo pipefail

API="${ARGUS_API_URL:-http://localhost:8080}"
COMPOSE_FILE="${ARGUS_COMPOSE_FILE:-$(dirname "$0")/../deploy/compose/docker-compose.yaml}"
HUB_IMAGE="${ARGUS_HUB_IMAGE:-nubestack/argus-hub:${ARGUS_VERSION:-0.2.0}}"  # the image compose runs

# BACKLOG.md E4/BUGS.md 91: the disposable, safe-to-abuse `kind` cluster
# (context kind-argus-disposable, RUNBOOK.md's "Standing test infrastructure"
# section) that section 11's real agent process points at, below, so its
# ownership-gated plan/approval assertions (11b3/11b3a/11b3d/11b3e/11b3f) can
# exercise a real plan-authoring/approval/execution flow instead of the
# "no reachable cluster" degradation BUGS.md 91 recorded. Overridable so a
# different disposable cluster (a fresh `kind create cluster`, RUNBOOK.md's
# recreate instructions) can be pointed at without editing this script.
DISPOSABLE_KUBECONFIG="${ARGUS_DISPOSABLE_KUBECONFIG:-$HOME/key/kind-argus-disposable.yaml}"

# agent_enrollment_blocked distinguishes "this environment already has the
# target cluster enrolled" from "enrollment is broken".
#
# The sections below launch a REAL agent against $DISPOSABLE_KUBECONFIG. The
# hub refuses a second enrollment of a cluster it already knows — 409
# "A cluster with this fingerprint is already enrolled"
# (internal/api/enroll.go) — and that refusal is CORRECT product behaviour,
# not a defect: a cluster's fingerprint is derived from the cluster itself,
# so re-enrolling one that is already registered would fork its identity and
# its history. On a standing dev stack where the disposable cluster is
# permanently enrolled, these sections therefore cannot run, and reporting
# that as FAIL leaves the suite permanently red — which is worse than useless,
# because a suite nobody trusts is a suite nobody reads. Skip loudly instead.
agent_enrollment_blocked() {
  grep -qiE 'already enrolled|already-enrolled' "$1" 2>/dev/null
}

PASS=0
FAIL=0

check_status() {
  local desc="$1" expected="$2" actual="$3"
  if [[ "$actual" == "$expected" ]]; then
    echo "  PASS: $desc (got $actual)"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: $desc (expected $expected, got $actual)"
    FAIL=$((FAIL + 1))
  fi
}

json_field() {
  python3 -c "import sys,json; print(json.load(sys.stdin).get('$1',''))"
}

# json_arg_file writes its one argument (a JSON response body) to a fresh
# temp file and prints that file's path.
#
# BUGS.md 113 (found live while verifying this task's own fix, a genuinely
# separate/third defect from that entry's two named causes): several
# verifiers below pass a JSON response as a python3 argv element rather than
# over stdin (this file's own "argv-not-stdin" comment explains why stdin is
# unavailable — the heredoc already uses it to feed the script's source in).
# That works until the response itself gets big enough to blow the OS's
# ARG_MAX -- confirmed live against this repo's own long-running dev stack
# (hundreds of accumulated incidents/findings across a fleet's history):
# `GET /incidents` and `GET /incidents?state=...` unfiltered/lightly-filtered
# across the whole tenant returned "Argument list too long" from python3
# itself, silently skipping every assertion in that block. A file path is a
# short argv element regardless of how large the JSON behind it is, so
# reading the body from a file sidesteps the limit entirely.
json_arg_file() {
  local f
  f=$(mktemp)
  printf '%s' "$1" >"$f"
  echo "$f"
}

# psql_scalar runs a single-column query against the live stack's Postgres
# and returns its one result, trimmed — used by §5b below to check
# audit_events' row count directly rather than through the (super-admin-only)
# read API, matching this task's own verification instruction to confirm via
# a direct Postgres query.
psql_scalar() {
  docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -tA -c "$1" | tr -d '\r\n'
}

# analyze_and_wait INCIDENT_ID OUTFILE -- PROJECT.md M1: POST .../analyze
# answers 202 once the run is claimed and investigates in the background, so
# the analysis is no longer in the response body. Prints the POST's status
# code. On 202 it polls GET /incidents/{id} until the incident leaves
# Investigating (bounded by ANALYZE_WAIT_SECONDS, default 300 -- printing
# "timeout" instead if it never does), then writes OUTFILE as the incident's
# latest analysis plus the fields the old synchronous body carried, read from
# where they now live: incidentState (the incident's state), stateReason (the
# summary of the AnalysisCompleted timeline event the run wrote) and
# analysisError (the incident's, non-null only if the run failed). On any
# other status OUTFILE holds the POST's own (problem) body.
analyze_and_wait() {
  local inc="$1" out="$2" code deadline detail state timeline
  code=$(curl -sS -o "$out" -w "%{http_code}" -X POST \
    "$API/api/v1/incidents/$inc/analyze" -H "Authorization: Bearer $access_token")
  if [[ "$code" != "202" ]]; then
    echo "$code"
    return
  fi
  deadline=$(( $(date +%s) + ${ANALYZE_WAIT_SECONDS:-300} ))
  while :; do
    detail=$(curl -sS "$API/api/v1/incidents/$inc" -H "Authorization: Bearer $access_token")
    state=$(printf '%s' "$detail" | json_field state)
    [[ -n "$state" && "$state" != "Investigating" ]] && break
    if (( $(date +%s) >= deadline )); then
      echo "timeout"
      return
    fi
    sleep 1
  done
  timeline=$(curl -sS "$API/api/v1/incidents/$inc/timeline" -H "Authorization: Bearer $access_token")
  python3 - "$(json_arg_file "$detail")" "$(json_arg_file "$timeline")" "$out" <<'PYEOF'
import json, sys
detail = json.load(open(sys.argv[1]))
timeline = json.load(open(sys.argv[2]))
out = dict(detail.get("analysis") or {})
out["incidentState"] = detail.get("state")
completed = [e for e in timeline.get("events", []) if e.get("eventType") == "AnalysisCompleted"]
out["stateReason"] = completed[-1].get("summary") if completed else None
out["analysisError"] = detail.get("analysisError")
json.dump(out, open(sys.argv[3], "w"))
PYEOF
  echo "$code"
}

# --- PROJECT.md B175: this script cleans up its own throwaway clusters ---
#
# Every Go DB-backed fixture in this repo now refuses to leak: internal/dbtest
# count-checks each delete before committing it, and AssertNoClusterResidue
# asks pg_class which tables are cluster-scoped rather than trusting an
# author's list. This script was the one remaining producer of residue, and it
# is a prolific one — a read-only census of the development database on
# 2026-09-25 found 171 clusters with this script's own display names
# (smoketest-cluster 33, smoketest-decommission-cluster 29,
# smoketest-autoanalyze-cluster 28, smoketest-cost-cluster 24,
# smoketest-toolloop-cluster 22, smoketest-storm-cluster 19,
# smoketest-insights-cluster 15), one of them not even archived and therefore
# showing up in the product as fleet.
#
# The mechanism deliberately mirrors AssertNoClusterResidue rather than
# re-deriving a table list here: a migration that adds a cluster-scoped table
# joins this cleanup on the same day, with nobody remembering to. Two rules
# carried over from it verbatim:
#
#   * audit_events is EXEMPT. It is a hash chain and `argusctl audit verify`
#     re-verifies it straight against Postgres, so deleting this script's rows
#     out of its middle would break verification for every row after them.
#     Test-written audit rows are the accepted cost of tamper-evidence.
#   * Residue is REPORTED, not assumed away. What is left behind, if anything,
#     is named with its table and row count, so the fix is never a hunt.
#
# Clusters register themselves as they are created (register_smoketest_cluster),
# so a section that is skipped or that fails before enrolling contributes
# nothing, and a section added later cannot forget to extend a hardcoded list —
# it just has to register.
SMOKETEST_CLUSTER_IDS=()

register_smoketest_cluster() {
  [[ -n "${1:-}" ]] && SMOKETEST_CLUSTER_IDS+=("$1")
  return 0
}

# cleanup_smoketest_clusters deletes every registered cluster and everything
# cluster-scoped hanging off it, then reports anything that survived.
#
# Idempotent and safe to call more than once — same discipline as
# restore_original_ai_provider and restore_original_automation_and_cost above,
# and for the same reason: it is called explicitly just before the summary (so
# its PASS/FAIL lands IN that summary rather than after it) and again from the
# single EXIT trap (so a run that dies half way through still cleans up).
# Clearing the array at the end is what makes the second call a no-op.
cleanup_smoketest_clusters() {
  [[ ${#SMOKETEST_CLUSTER_IDS[@]} -eq 0 ]] && return 0

  local ids_literal residue psql_status
  # Built as a quoted SQL array literal rather than one statement per id:
  # every element is a cluster id this script received from the hub's own
  # enroll response or minted itself, so there is nothing user-supplied here,
  # and one DO block means the whole delete is one transaction.
  ids_literal=$(printf "'%s'," "${SMOKETEST_CLUSTER_IDS[@]}")
  ids_literal="ARRAY[${ids_literal%,}]"

  # -q so psql prints only the final SELECT's rows: without it the CREATE
  # TABLE and DO command tags land in $residue and every clean run reports
  # itself as having leaked "CREATE TABLE, DO".
  residue=$(docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -tAq -v ON_ERROR_STOP=1 <<SQL
CREATE TEMP TABLE smoketest_residue (table_name text, rows bigint);

DO \$\$
DECLARE
  ids text[] := $ids_literal;
  t text;
  pass int;
  blocked int;
  n bigint;
BEGIN
  -- Repeated passes rather than a hand-ordered delete list. Some of these
  -- tables reference each other (evidence -> analyses,
  -- remediation_executions -> remediation_recommendations, ...), and the
  -- catalogue hands them back alphabetically, so a single pass hits foreign
  -- key violations in an order nobody can predict from here. Deleting what
  -- can be deleted and going round again converges without this script
  -- having to know the dependency graph -- and a table that STILL cannot be
  -- emptied after six passes is left alone and reported below rather than
  -- forced, because at that point the right answer is a human looking at it.
  FOR pass IN 1..6 LOOP
    blocked := 0;
    FOR t IN
      SELECT c.relname
        FROM pg_class c
        JOIN pg_namespace ns ON ns.oid = c.relnamespace
        JOIN pg_attribute a ON a.attrelid = c.oid
                           AND a.attname = 'cluster_id'
                           AND a.attnum > 0
                           AND NOT a.attisdropped
       WHERE ns.nspname = 'public'
         AND c.relkind IN ('r', 'p')
         AND c.relname <> 'audit_events'
         AND NOT EXISTS (SELECT 1 FROM pg_inherits i WHERE i.inhrelid = c.oid)
       ORDER BY c.relname
    LOOP
      BEGIN
        EXECUTE format('DELETE FROM %I WHERE cluster_id = ANY(\$1)', t) USING ids;
      EXCEPTION WHEN foreign_key_violation THEN
        blocked := blocked + 1;
      END;
    END LOOP;
    EXIT WHEN blocked = 0;
  END LOOP;

  -- clusters keys on id, not cluster_id, so it is deleted separately -- and
  -- last, since everything above references it.
  BEGIN
    DELETE FROM clusters WHERE id = ANY(ids);
  EXCEPTION WHEN foreign_key_violation THEN
    NULL;
  END;

  -- Whatever survived, named with its row count -- the same thing
  -- AssertNoClusterResidue reports, and for the same reason: "something
  -- leaked" is not actionable, "incident_notifications=3" is.
  FOR t IN
    SELECT c.relname
      FROM pg_class c
      JOIN pg_namespace ns ON ns.oid = c.relnamespace
      JOIN pg_attribute a ON a.attrelid = c.oid
                         AND a.attname = 'cluster_id'
                         AND a.attnum > 0
                         AND NOT a.attisdropped
     WHERE ns.nspname = 'public'
       AND c.relkind IN ('r', 'p')
       AND c.relname <> 'audit_events'
       AND NOT EXISTS (SELECT 1 FROM pg_inherits i WHERE i.inhrelid = c.oid)
     ORDER BY c.relname
  LOOP
    EXECUTE format('SELECT count(*) FROM %I WHERE cluster_id = ANY(\$1)', t) INTO n USING ids;
    IF n > 0 THEN
      INSERT INTO smoketest_residue VALUES (t, n);
    END IF;
  END LOOP;
  SELECT count(*) INTO n FROM clusters WHERE id = ANY(ids);
  IF n > 0 THEN
    INSERT INTO smoketest_residue VALUES ('clusters', n);
  END IF;
END \$\$;

-- Empty output means a clean run.
SELECT table_name || '=' || rows FROM smoketest_residue ORDER BY table_name;
SQL
)
  psql_status=$?
  # paste -sd takes a LIST of delimiters and cycles through it, so ', ' would
  # join the first pair with a comma and the second with a space. One
  # delimiter, then widen it.
  residue=$(echo "$residue" | tr -d '\r' | grep -v '^$' | paste -sd',' - | sed 's/,/, /g')

  # psql's own exit status is checked before the empty-residue check, because
  # -q makes a run that failed outright look exactly like a run that found
  # nothing: both print nothing. Reporting "clean" because the query never ran
  # is the same failure mode AssertNoClusterResidue's own doc comment warns
  # about ("a check that reports clean because it cannot see is worse than no
  # check").
  if [[ "$psql_status" != "0" ]]; then
    echo "  FAIL: the cleanup query itself failed (psql exit $psql_status) -- this run's ${#SMOKETEST_CLUSTER_IDS[@]} throwaway cluster(s) are still in the database"
    FAIL=$((FAIL + 1))
  elif [[ -z "$residue" ]]; then
    echo "  PASS: removed this run's ${#SMOKETEST_CLUSTER_IDS[@]} throwaway cluster(s) and every cluster-scoped row hanging off them (audit_events exempt -- hash chain)"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: this run left rows behind after cleanup -- $residue. Every run leaks that much more into whatever database it ran against; see internal/dbtest/residue.go for the same check on the Go side"
    FAIL=$((FAIL + 1))
  fi
  SMOKETEST_CLUSTER_IDS=()
}

echo "== 1. Health and readiness =="
status=$(curl -sS -o /dev/null -w "%{http_code}" "$API/healthz")
check_status "GET /healthz" 200 "$status"
status=$(curl -sS -o /dev/null -w "%{http_code}" "$API/readyz")
check_status "GET /readyz (SR-2 RLS preconditions)" 200 "$status"

# BACKLOG D7z. A 200 status alone proves nothing here: static.go's SPA
# fallback serves index.html (200) for ANY unmatched path, so a renamed or
# deleted font file would still "pass" a status-code check while silently
# serving HTML — the browser rejects it as a font with no failed request and
# no console error, and the wordmark just quietly reverts to the system
# stack. Checking the real payload instead: the first 4 bytes of a WOFF2
# file are always the "wOF2" magic signature, which the SPA's HTML fallback
# (starting "<!do...") can never produce by accident.
#
# BOTH faces are checked, not just one. The lockup is a grotesque for the name
# and a monospace for the byline under it, and either one missing degrades to
# the system stack independently — a loop rather than two copies of the block so
# adding a third face cannot quietly skip the check.
for font in argus-wordmark-archivo-600 argus-byline-plexmono-400; do
  font_magic=$(curl -sS "$API/fonts/$font.woff2" | head -c4)
  if [[ "$font_magic" == "wOF2" ]]; then
    echo "  PASS: GET /fonts/$font.woff2 serves the real font (magic bytes wOF2)"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: GET /fonts/$font.woff2 did not return WOFF2 magic bytes — got: $font_magic (SPA fallback serving index.html instead of the font is the likely cause)"
    FAIL=$((FAIL + 1))
  fi
done

echo "== 2. Login =="
ADMIN_PASSWORD="${ARGUS_ADMIN_PASSWORD:-}"
if [[ -z "$ADMIN_PASSWORD" ]]; then
  ADMIN_PASSWORD=$(docker compose -f "$COMPOSE_FILE" logs hub-api 2>/dev/null | grep -oP 'password: \K\S+' | head -1)
fi
if [[ -z "$ADMIN_PASSWORD" ]]; then
  # docker-compose.yaml's dev profile pins ARGUS_BOOTSTRAP_PASSWORD to this
  # fixed value precisely so it doesn't change on every volume wipe — bootstrap
  # deliberately never logs a password that came from that env var (only a
  # generated one), so the log-scrape above finds nothing on that profile and
  # this is the correct next fallback, not a hardcoded secret guess.
  ADMIN_PASSWORD="dev-admin-password-123"
  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/auth/login" \
    -H "Content-Type: application/json" -d "{\"email\":\"admin@localhost\",\"password\":\"$ADMIN_PASSWORD\"}")
  if [[ "$status" != "200" ]]; then
    ADMIN_PASSWORD=""
  fi
fi
if [[ -z "$ADMIN_PASSWORD" ]]; then
  echo "  Could not find a bootstrap password in 'docker compose logs hub-api' and"
  echo "  ARGUS_ADMIN_PASSWORD was not set. On a stack that's been up for a while,"
  echo "  bootstrap only prints its password once — pass it explicitly:"
  echo "    ARGUS_ADMIN_PASSWORD=... ./scripts/smoke-test.sh"
  exit 1
fi

status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/auth/login" \
  -H "Content-Type: application/json" -d '{"email":"admin@localhost","password":"wrong-password"}')
check_status "login with wrong password" 401 "$status"

# PROJECT.md B164: the refresh token is no longer in the login response body.
# It is set as an HttpOnly, Path-scoped cookie, so page scripts cannot read it
# and a logout can revoke the whole token family server-side. Everything below
# therefore carries it in a curl cookie jar rather than a JSON field.
COOKIE_JAR="$(mktemp -t argus-smoke-cookies.XXXXXX)"
trap 'rm -f "$COOKIE_JAR" "$COOKIE_JAR".fresh' EXIT
refresh_cookie() { awk '$6 == "argus_refresh" { print $7 }' "$1" 2>/dev/null | tail -1; }

login_headers=$(curl -sS -D - -o /tmp/argus-smoke-login-body -c "$COOKIE_JAR" \
  -X POST "$API/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"admin@localhost\",\"password\":\"$ADMIN_PASSWORD\"}")
login_resp=$(cat /tmp/argus-smoke-login-body); rm -f /tmp/argus-smoke-login-body
access_token=$(echo "$login_resp" | json_field accessToken)
refresh_token=$(refresh_cookie "$COOKIE_JAR")
if ! grep -qi 'set-cookie:.*argus_refresh.*httponly' <<<"$login_headers"; then
  echo "  FAIL: login did not set an HttpOnly argus_refresh cookie (B164)"
  FAIL=$((FAIL + 1))
else
  echo "  PASS: login sets the refresh token as an HttpOnly cookie, not a body field"
  PASS=$((PASS + 1))
fi
if [[ -n "$access_token" && -n "$refresh_token" ]]; then
  echo "  PASS: login with correct password (tokens issued)"
  PASS=$((PASS + 1))
else
  echo "  FAIL: login with correct password — response: $login_resp"
  FAIL=$((FAIL + 1))
  echo "Cannot continue without a valid session. Aborting."
  exit 1
fi

# --- BUGS.md 113: own the AI provider configuration for the rest of this run ---
#
# Sections 11b/13/15 below point the investigation loop at a scripted fake
# LLM (scripts/fake-llm-server) so its assertions can check deterministic,
# scripted token/cost/tool-call numbers. They used to do that with a plain
# PUT to /api/v1/admin/settings' legacy "llm" section — which, since
# migration 000034 introduced the `ai_providers` table, only edits whichever
# row org_settings.active_ai_provider_id already points at
# (internal/settings.UpdateActiveProvider); it never repoints which row is
# active. On a stack with an already-configured, active `kind: "cli"`
# provider — which is exactly this dev stack's normal state — that PUT wrote
# baseUrl/model/apiKey onto the cli row's unused api-mode columns while
# `kind` stayed "cli", so internal/llm.Router kept dispatching every
# investigation to the real CLI runner. Every downstream assertion expecting
# the fake server's scripted, deterministic response was actually grading a
# real model call, which is why it failed unpredictably rather than never.
#
# The fix: this script creates and activates its OWN `kind: "api"` provider
# row through the same admin surface a real operator would use
# (POST/PUT/activate /api/v1/admin/ai-providers — internal/api/ai_providers.go),
# repointed at whichever fake-llm-server port the calling section is running,
# and restores whatever provider was active before on every exit path —
# normal completion, an early `exit` elsewhere in this script, or Ctrl-C —
# via a real `trap ... EXIT`. Nothing else in this script uses one (see
# cleanup_section11's neighboring comment on why a RETURN trap wouldn't even
# apply here), but nothing else needs this strong a guarantee either:
# leaving a dev stack's real provider silently swapped for a throwaway fake
# one is precisely the kind of state a partially-failed run must never
# leave behind.
SMOKETEST_PROVIDER_NAME="smoketest-fake-llm-provider"
SMOKETEST_PROVIDER_ID=""
ORIGINAL_ACTIVE_PROVIDER_ID=""
ORIGINAL_ACTIVE_PROVIDER_CAPTURED=0

restore_original_ai_provider() {
  # Idempotent and safe to call more than once — the EXIT trap below and any
  # explicit end-of-section call both reach this, exactly like
  # cleanup_section11's own idempotency note.
  if [[ -n "$SMOKETEST_PROVIDER_ID" ]]; then
    if [[ -n "$ORIGINAL_ACTIVE_PROVIDER_ID" ]]; then
      curl -sS -X POST "$API/api/v1/admin/ai-providers/$ORIGINAL_ACTIVE_PROVIDER_ID/activate" \
        -H "Authorization: Bearer $access_token" >/dev/null
    fi
    # Safe even when ORIGINAL_ACTIVE_PROVIDER_ID was empty (nothing was
    # active before this script touched anything): deleting the
    # now-inactive smoketest row lets ai_providers' ON DELETE SET NULL FK
    # revert org_settings.active_ai_provider_id to NULL, exactly the state
    # this stack started in.
    curl -sS -X DELETE "$API/api/v1/admin/ai-providers/$SMOKETEST_PROVIDER_ID" \
      -H "Authorization: Bearer $access_token" >/dev/null
    SMOKETEST_PROVIDER_ID=""
  fi
}
# Trap registered once, below, after BUGS.md 133's own restore function
# exists — a second `trap ... EXIT` would silently REPLACE this one, not add
# to it, so this file has exactly one `trap ... EXIT` line, calling both
# restore functions, not two competing ones.

# --- BUGS.md 133: same shape as 113, one section over ---
#
# Section 8 below (and a few later sections' own sub-tests) PUT a hardcoded
# "cleared" automation/cost baseline (autoAnalysisEnabled:false,
# autoAnalysisSeverities:[], dailySpendCeilingUsd:null, ...) to give their own
# assertions a known starting point, and leave that hardcoded baseline in
# place afterward — correct for a throwaway stack nobody else is using, wrong
# for this one: a real operator's real autoAnalysisEnabled/autoAnalysisSeverities/
# dailySpendCeilingUsd choice is exactly as real and exactly as easy to
# silently clobber as 113's AI-provider row was, and this script did just
# that, live, on 2026-09-04 (confirmed in BUGS.md 133's own writeup) — with
# BACKLOG.md T1 landed the same day, "auto-analysis is silently off" is not a
# theoretical risk of running this script, it is what actually happened.
#
# Captured here (immediately after login, before section 8's first write) and
# restored on every exit path via the SAME trap 113 already installed above —
# a second `trap ... EXIT` would silently replace, not add to, the first one,
# so this extends that one call rather than adding a second.
ORIGINAL_AUTOMATION_AND_COST_CAPTURED=0
ORIGINAL_AUTO_ANALYSIS_ENABLED=""
ORIGINAL_AUTO_ANALYSIS_SEVERITIES=""
ORIGINAL_DAILY_SPEND_CEILING=""

capture_original_automation_and_cost() {
  local resp
  resp=$(curl -sS "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token")
  ORIGINAL_AUTO_ANALYSIS_ENABLED=$(echo "$resp" | python3 -c "import sys,json; print(json.dumps(json.load(sys.stdin)['automation']['autoAnalysisEnabled']))")
  ORIGINAL_AUTO_ANALYSIS_SEVERITIES=$(echo "$resp" | python3 -c "import sys,json; print(json.dumps(json.load(sys.stdin)['automation']['autoAnalysisSeverities']))")
  ORIGINAL_DAILY_SPEND_CEILING=$(echo "$resp" | python3 -c "import sys,json; print(json.dumps(json.load(sys.stdin)['cost']['dailySpendCeilingUsd']))")
  ORIGINAL_AUTOMATION_AND_COST_CAPTURED=1
}
capture_original_automation_and_cost

restore_original_automation_and_cost() {
  # Idempotent, same discipline as restore_original_ai_provider above: safe
  # to call more than once, and a no-op if the capture above never ran (it
  # always does, right above, but this guard matches this file's own
  # established convention rather than assuming its own call order).
  if [[ "$ORIGINAL_AUTOMATION_AND_COST_CAPTURED" == "1" ]]; then
    curl -sS -X PUT "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token" \
      -H "Content-Type: application/json" \
      -d "{\"automation\":{\"autoAnalysisEnabled\":$ORIGINAL_AUTO_ANALYSIS_ENABLED,\"autoAnalysisSeverities\":$ORIGINAL_AUTO_ANALYSIS_SEVERITIES},\"cost\":{\"dailySpendCeilingUsd\":$ORIGINAL_DAILY_SPEND_CEILING}}" \
      >/dev/null
    ORIGINAL_AUTOMATION_AND_COST_CAPTURED=0
  fi
}
trap 'restore_original_ai_provider; restore_original_automation_and_cost; cleanup_smoketest_clusters' EXIT

# activate_fake_llm_provider BASE_URL MODEL — (re)points a single dedicated
# smoketest provider row at the given fake-llm-server instance. The first
# call captures whatever was active before (once) and creates+activates the
# row; later calls (this run's other fake-llm-server ports) just update the
# SAME row's baseUrl/model, since it's already active — no need to flip
# org_settings.active_ai_provider_id more than once until the final restore.
activate_fake_llm_provider() {
  local base_url="$1" model="$2"
  if [[ -z "$SMOKETEST_PROVIDER_ID" ]]; then
    # The fake model server runs on this machine, which the hub container
    # reaches at host.docker.internal: a private address the hub's outbound
    # guard refuses for AI providers until it is allowlisted, as an admin
    # would for a self-hosted model (Settings -> Outbound access).
    curl -sS -o /dev/null -X PUT "$API/api/v1/admin/settings" \
      -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" \
      -d '{"outbound":{"privateDestinations":[{"destination":"host.docker.internal","reason":"smoke test fake model server"}]}}'
    if [[ "$ORIGINAL_ACTIVE_PROVIDER_CAPTURED" -eq 0 ]]; then
      ORIGINAL_ACTIVE_PROVIDER_ID=$(curl -sS "$API/api/v1/admin/ai-providers" \
        -H "Authorization: Bearer $access_token" | json_field activeProviderId)
      ORIGINAL_ACTIVE_PROVIDER_CAPTURED=1
    fi
    local create_resp
    create_resp=$(curl -sS -X POST "$API/api/v1/admin/ai-providers" \
      -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" \
      -d "{\"name\":\"$SMOKETEST_PROVIDER_NAME\",\"kind\":\"api\",\"baseUrl\":\"$base_url\",\"model\":\"$model\",\"apiKey\":\"\"}")
    SMOKETEST_PROVIDER_ID=$(python3 - "$create_resp" "$SMOKETEST_PROVIDER_NAME" <<'PYEOF'
import json, sys
resp = json.loads(sys.argv[1])
name = sys.argv[2]
for p in resp.get("providers", []):
    if p.get("name") == name:
        print(p.get("id", ""))
        break
PYEOF
)
    if [[ -n "$SMOKETEST_PROVIDER_ID" ]]; then
      curl -sS -X POST "$API/api/v1/admin/ai-providers/$SMOKETEST_PROVIDER_ID/activate" \
        -H "Authorization: Bearer $access_token" >/dev/null
    else
      echo "  FAIL: could not create/find the smoketest AI provider row — response: $create_resp"
      FAIL=$((FAIL + 1))
    fi
  else
    curl -sS -X PUT "$API/api/v1/admin/ai-providers/$SMOKETEST_PROVIDER_ID" \
      -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" \
      -d "{\"name\":\"$SMOKETEST_PROVIDER_NAME\",\"kind\":\"api\",\"baseUrl\":\"$base_url\",\"model\":\"$model\",\"apiKey\":\"\"}" >/dev/null
  fi
}

echo "== 3. Authenticated route + capability enforcement =="
status=$(curl -sS -o /dev/null -w "%{http_code}" "$API/api/v1/users/me/effective-permissions")
check_status "effective-permissions with no token" 401 "$status"

grants=$(curl -sS "$API/api/v1/users/me/effective-permissions" -H "Authorization: Bearer $access_token" | json_field grants)
if [[ -n "$grants" && "$grants" != "[]" ]]; then
  echo "  PASS: effective-permissions with valid token returns non-empty grants"
  PASS=$((PASS + 1))
else
  echo "  FAIL: effective-permissions with valid token returned no grants"
  FAIL=$((FAIL + 1))
fi

status=$(curl -sS -o /dev/null -w "%{http_code}" "$API/api/v1/roles")
check_status "roles reference with no token" 401 "$status"

roles_body=$(curl -sS "$API/api/v1/roles" -H "Authorization: Bearer $access_token")
if echo "$roles_body" | grep -q '"super-admin"' && echo "$roles_body" | grep -q '"viewer"'; then
  echo "  PASS: roles reference includes super-admin and viewer"
  PASS=$((PASS + 1))
else
  echo "  FAIL: roles reference missing expected role ids — response: $roles_body"
  FAIL=$((FAIL + 1))
fi

echo "== 4. Cluster enrollment tokens (cluster:onboard) =="
status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/clusters/enrollment-tokens" \
  -H "Content-Type: application/json" -d '{"ttlClass":"B"}')
check_status "enrollment-tokens with no auth" 401 "$status"

status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/clusters/enrollment-tokens" \
  -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" -d '{"ttlClass":"B"}')
check_status "enrollment-tokens as super-admin (class B)" 201 "$status"

status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/clusters/enrollment-tokens" \
  -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" -d '{"ttlClass":"C","maxRedemptions":10}')
check_status "enrollment-tokens as super-admin (class C, bulk)" 201 "$status"

status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/clusters/enrollment-tokens" \
  -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" -d '{"ttlClass":"Z"}')
check_status "enrollment-tokens with invalid ttlClass" 400 "$status"

status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/clusters/enrollment-tokens" \
  -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" -d '{"ttlClass":"B","maxRedemptions":5}')
check_status "enrollment-tokens with maxRedemptions>1 on non-bulk class" 400 "$status"

echo "== 4b. Capability denial for a non-onboard role =="
TEST_VIEWER_ID="usr_smoketest0000000000000"
viewer_hash=$(docker run --rm "$HUB_IMAGE" hash-password "smoke-test-password" | tr -d '\r\n')
docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -v ON_ERROR_STOP=1 >/dev/null <<SQL
DO \$\$
DECLARE org_id text;
BEGIN
  SELECT id INTO org_id FROM organisations LIMIT 1;
  DELETE FROM refresh_tokens WHERE user_id = '$TEST_VIEWER_ID';
  DELETE FROM grants WHERE principal_id = '$TEST_VIEWER_ID';
  DELETE FROM users WHERE id = '$TEST_VIEWER_ID';
  INSERT INTO users (id, tenant_id, email, display_name, password_hash, must_change_password)
  VALUES ('$TEST_VIEWER_ID', org_id, 'smoketest-viewer@localhost', 'Smoke Test Viewer', '$viewer_hash', false);
  INSERT INTO grants (id, tenant_id, principal_type, principal_id, role_id, scope, granted_by)
  VALUES ('grt_smoketest0000000000000', org_id, 'user', '$TEST_VIEWER_ID', 'viewer', '{"type":"AllClusters"}', '$TEST_VIEWER_ID');
END \$\$;
SQL

viewer_token=$(curl -sS -X POST "$API/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"smoketest-viewer@localhost","password":"smoke-test-password"}' | json_field accessToken)

if [[ -n "$viewer_token" ]]; then
  echo "  PASS: viewer test user can log in"
  PASS=$((PASS + 1))
else
  echo "  FAIL: viewer test user could not log in"
  FAIL=$((FAIL + 1))
fi

status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/clusters/enrollment-tokens" \
  -H "Authorization: Bearer $viewer_token" -H "Content-Type: application/json" -d '{"ttlClass":"B"}')
check_status "viewer denied cluster:onboard (403)" 403 "$status"

status=$(curl -sS -o /dev/null -w "%{http_code}" "$API/api/v1/users/me/effective-permissions" \
  -H "Authorization: Bearer $viewer_token")
check_status "viewer can still read their own effective-permissions" 200 "$status"

status=$(curl -sS -o /dev/null -w "%{http_code}" "$API/api/v1/roles" \
  -H "Authorization: Bearer $viewer_token")
check_status "viewer can read the roles reference too (no capability gate, by design)" 200 "$status"

# The Overview's fleet aggregate (internal/api/fleet_summary.go): cluster:read
# gates it, which the viewer holds; no token is a 401.
fleet_body=$(curl -sS "$API/api/v1/fleet/summary" -H "Authorization: Bearer $access_token")
if echo "$fleet_body" | grep -q '"intervalSeconds"' && echo "$fleet_body" | grep -q '"clusters"'; then
  echo "  PASS: GET /fleet/summary returns the interval and the cluster list"
  PASS=$((PASS + 1))
else
  echo "  FAIL: GET /fleet/summary — response: $fleet_body"
  FAIL=$((FAIL + 1))
fi
status=$(curl -sS -o /dev/null -w "%{http_code}" "$API/api/v1/fleet/summary")
check_status "GET /fleet/summary without a token is rejected (401)" 401 "$status"
status=$(curl -sS -o /dev/null -w "%{http_code}" "$API/api/v1/fleet/summary" -H "Authorization: Bearer $viewer_token")
check_status "viewer can read the fleet summary (holds cluster:read)" 200 "$status"

# Cleanup — this is a throwaway test fixture, not application state.
docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -v ON_ERROR_STOP=1 >/dev/null <<SQL
DELETE FROM refresh_tokens WHERE user_id = '$TEST_VIEWER_ID';
DELETE FROM grants WHERE principal_id = '$TEST_VIEWER_ID';
DELETE FROM users WHERE id = '$TEST_VIEWER_ID';
SQL

echo "== 5. Refresh token rotation and reuse detection =="
refresh_resp=$(curl -sS -X POST "$API/api/v1/auth/refresh" \
  -b "$COOKIE_JAR" -c "$COOKIE_JAR" -H "Content-Type: application/json")
new_refresh_token=$(refresh_cookie "$COOKIE_JAR")
if [[ -n "$new_refresh_token" && "$new_refresh_token" != "$refresh_token" ]]; then
  echo "  PASS: refresh rotates to a new token"
  PASS=$((PASS + 1))
else
  echo "  FAIL: refresh did not return a new, different token — response: $refresh_resp"
  FAIL=$((FAIL + 1))
fi

# The token a rotation superseded is accepted once more for
# authz.RefreshReuseGrace (10s), so two tabs refreshing together do not log
# each other out. Past that window, presenting it is reuse.
sleep 11
status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/auth/refresh" \
  -H "Cookie: argus_refresh=$refresh_token" -H "Content-Type: application/json")
check_status "reusing the now-revoked refresh token (after the grace window) is rejected" 401 "$status"

echo "== 5b. Routine refreshes are not audited; reuse detection is, distinctly and exactly once =="
# The bug this whole section closes: the GUI's AuthContext.tsx calls
# POST /auth/refresh silently on every page load AND periodically in the
# background (proactive renewal at 80% of token lifetime) — none of that is
# a new session, so none of it should write an audit_events row. Only the
# genuine compromise signal (presenting an already-rotated token) should.
#
# Starts from a FRESH login rather than reusing $new_refresh_token from §5
# above — that whole rotation chain was deliberately poisoned by §5's own
# reuse-detection check (which revokes every token in the chain, not just
# the one presented), so continuing to refresh with it here would itself
# look like a second reuse attempt, not a routine one.
curl -sS -o /dev/null -c "$COOKIE_JAR".fresh -X POST "$API/api/v1/auth/login" \
  -H "Content-Type: application/json" -d "{\"email\":\"admin@localhost\",\"password\":\"$ADMIN_PASSWORD\"}"
fresh_refresh_token=$(refresh_cookie "$COOKIE_JAR".fresh)

audit_count_before_routine=$(psql_scalar "SELECT count(*) FROM audit_events;")

# Simulate exactly what the GUI's renewal timer does: always refresh with
# the LATEST token, never an old one — three sequential, non-overlapping
# rotations, same as STATUS.md's frontend-side verification already covers.
cur_token="$fresh_refresh_token"
oldest_rotated_away_token="$fresh_refresh_token"
refresh_loop_ok=true
for _ in 1 2 3; do
  curl -sS -o /dev/null -b "$COOKIE_JAR".fresh -c "$COOKIE_JAR".fresh \
    -X POST "$API/api/v1/auth/refresh" -H "Content-Type: application/json"
  next_token=$(refresh_cookie "$COOKIE_JAR".fresh)
  if [[ -z "$next_token" || "$next_token" == "$cur_token" ]]; then
    refresh_loop_ok=false
    break
  fi
  cur_token="$next_token"
done
if [[ "$refresh_loop_ok" == true ]]; then
  echo "  PASS: three sequential routine refreshes all rotated successfully"
  PASS=$((PASS + 1))
else
  echo "  FAIL: a routine sequential refresh in the simulated renewal loop failed unexpectedly"
  FAIL=$((FAIL + 1))
fi

audit_count_after_routine=$(psql_scalar "SELECT count(*) FROM audit_events;")
if [[ "$audit_count_after_routine" == "$audit_count_before_routine" ]]; then
  echo "  PASS: audit_events grew by 0 rows across 3 routine refreshes (was $audit_count_before_routine, still $audit_count_after_routine)"
  PASS=$((PASS + 1))
else
  echo "  FAIL: audit_events grew from $audit_count_before_routine to $audit_count_after_routine across routine refreshes — routine refresh must not be audited"
  FAIL=$((FAIL + 1))
fi

# Deliberately reuse an OLD, already-rotated-away token from earlier in this
# very loop (not the current, still-valid one) — a genuine
# reuse-of-an-already-rotated-token case, the same shape as this section's
# very first check above, checked again here specifically for its audit
# side effect.
status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/auth/refresh" \
  -H "Cookie: argus_refresh=$oldest_rotated_away_token" -H "Content-Type: application/json")
check_status "reusing an old (already-rotated) refresh token from the renewal loop is rejected" 401 "$status"

audit_count_after_reuse=$(psql_scalar "SELECT count(*) FROM audit_events;")
if [[ "$audit_count_after_reuse" == "$((audit_count_after_routine + 1))" ]]; then
  echo "  PASS: exactly one new audit_events row appeared for the detected reuse (was $audit_count_after_routine, now $audit_count_after_reuse)"
  PASS=$((PASS + 1))
else
  echo "  FAIL: expected audit_events to grow by exactly 1 for the reuse (was $audit_count_after_routine, now $audit_count_after_reuse)"
  FAIL=$((FAIL + 1))
fi

newest_row=$(psql_scalar "SELECT outcome || '|' || coalesce(details->>'event','') FROM audit_events ORDER BY occurred_at DESC LIMIT 1;")
if [[ "$newest_row" == "denied|refresh_token.reuse_detected" ]]; then
  echo "  PASS: the new row is Outcome=denied with details.event=refresh_token.reuse_detected ($newest_row)"
  PASS=$((PASS + 1))
else
  echo "  FAIL: newest audit_events row does not match the expected reuse-detected shape: got '$newest_row'"
  FAIL=$((FAIL + 1))
fi

# A normal, unrelated audited action (another login) must still work and
# still write exactly one row — this fix must not have collaterally damaged
# audit coverage for anything else on this path.
audit_count_before_login=$(psql_scalar "SELECT count(*) FROM audit_events;")
relogin_resp=$(curl -sS -X POST "$API/api/v1/auth/login" \
  -H "Content-Type: application/json" -d "{\"email\":\"admin@localhost\",\"password\":\"$ADMIN_PASSWORD\"}")
relogin_access_token=$(echo "$relogin_resp" | json_field accessToken)
audit_count_after_login=$(psql_scalar "SELECT count(*) FROM audit_events;")
if [[ -n "$relogin_access_token" && "$audit_count_after_login" == "$((audit_count_before_login + 1))" ]]; then
  echo "  PASS: an ordinary login still succeeds and still writes exactly one audit_events row — unaffected by this fix"
  PASS=$((PASS + 1))
else
  echo "  FAIL: ordinary login's audit coverage looks broken (access_token empty=$([[ -z \"$relogin_access_token\" ]] && echo yes || echo no), audit count $audit_count_before_login -> $audit_count_after_login)"
  FAIL=$((FAIL + 1))
fi

echo "== 6. Cluster enrollment redemption, accept, and certificate issuance =="
# Exercises internal/authz.RedeemEnrollmentToken and the internal/api/enroll.go
# + clusters.go handlers end to end. Does NOT exercise the live mTLS tunnel
# itself (internal/gateway) — that needs a real agent binary presenting the
# issued cert, which is scripts/smoke-test.sh's declared non-goal here; run
# the actual agent (cmd/agent, a parallel effort) against this stack for that.

CSR_DIR=$(mktemp -d)
openssl ecparam -genkey -name prime256v1 -noout -out "$CSR_DIR/key.pem" 2>/dev/null
openssl req -new -key "$CSR_DIR/key.pem" -subj "/CN=smoketest-fingerprint" -out "$CSR_DIR/csr.pem" 2>/dev/null

if [[ -s "$CSR_DIR/csr.pem" ]]; then
  echo "  PASS: generated a throwaway ECDSA P-256 key + CSR via openssl"
  PASS=$((PASS + 1))
else
  echo "  FAIL: could not generate a CSR with openssl — skipping section 6"
  FAIL=$((FAIL + 1))
fi

CLUSTER_FINGERPRINT="smoketest-fp-$(date +%s)-$$"

enroll_token=$(curl -sS -X POST "$API/api/v1/clusters/enrollment-tokens" \
  -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" \
  -d '{"ttlClass":"B"}' | json_field token)

enroll_payload=$(python3 - "$enroll_token" "$CSR_DIR/csr.pem" "$CLUSTER_FINGERPRINT" <<'PYEOF'
import json, sys
token, csr_path, fingerprint = sys.argv[1], sys.argv[2], sys.argv[3]
csr = open(csr_path).read()
print(json.dumps({
    "token": token,
    "csrPem": csr,
    "clusterFingerprint": fingerprint,
    "displayName": "smoketest-cluster",
}))
PYEOF
)

enroll_resp=$(curl -sS -X POST "$API/api/v1/clusters/enroll" \
  -H "Content-Type: application/json" -d "$enroll_payload")
cluster_id=$(echo "$enroll_resp" | json_field clusterId)
register_smoketest_cluster "$cluster_id"
poll_token=$(echo "$enroll_resp" | json_field pollToken)
enroll_status=$(echo "$enroll_resp" | json_field status)

if [[ -n "$cluster_id" && -n "$poll_token" && "$enroll_status" == "pendingApproval" ]]; then
  echo "  PASS: POST /clusters/enroll (cluster $cluster_id, status pendingApproval)"
  PASS=$((PASS + 1))
else
  echo "  FAIL: enroll response missing expected fields — response: $enroll_resp"
  FAIL=$((FAIL + 1))
  echo "Cannot continue section 6 without a valid enrolled cluster. Skipping the rest of it."
  cluster_id=""
fi

bad_payload='{"token":"bad.token","csrPem":"not-a-csr","clusterFingerprint":"smoketest-bad"}'
status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/clusters/enroll" \
  -H "Content-Type: application/json" -d "$bad_payload")
check_status "enroll with a malformed token/CSR" 400 "$status"

status=$(curl -sS -o /dev/null -w "%{http_code}" "$API/api/v1/clusters/enroll/status?pollToken=not-a-real-poll-token")
check_status "enroll/status with an unrecognized poll token" 404 "$status"

if [[ -n "$cluster_id" ]]; then
  # A fresh token is required here — the first one is already spent (class B
  # is single-redemption, enforced by RedeemEnrollmentToken/checkEnrollmentTokenRedeemable)
  # and re-presenting a spent token correctly fails at redemption (400) before
  # ever reaching the fingerprint check this is actually testing.
  second_token=$(curl -sS -X POST "$API/api/v1/clusters/enrollment-tokens" \
    -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" \
    -d '{"ttlClass":"B"}' | json_field token)
  dup_payload=$(python3 - "$second_token" "$CSR_DIR/csr.pem" "$CLUSTER_FINGERPRINT" <<'PYEOF'
import json, sys
token, csr_path, fingerprint = sys.argv[1], sys.argv[2], sys.argv[3]
csr = open(csr_path).read()
print(json.dumps({
    "token": token,
    "csrPem": csr,
    "clusterFingerprint": fingerprint,
    "displayName": "smoketest-cluster-dup",
}))
PYEOF
)
  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/clusters/enroll" \
    -H "Content-Type: application/json" -d "$dup_payload")
  check_status "re-enrolling the same cluster_fingerprint (fresh token) is rejected" 409 "$status"

  poll_resp=$(curl -sS "$API/api/v1/clusters/enroll/status?pollToken=$poll_token")
  poll_status=$(echo "$poll_resp" | json_field status)
  check_status "enroll/status before accept" "pendingApproval" "$poll_status"

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/clusters/$cluster_id/accept")
  check_status "accept with no auth" 401 "$status"

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/clusters/$cluster_id/accept" \
    -H "Authorization: Bearer $access_token")
  check_status "accept cluster as super-admin (cluster:accept)" 200 "$status"

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/clusters/$cluster_id/accept" \
    -H "Authorization: Bearer $access_token")
  check_status "re-accepting an already-Provisioning cluster is rejected" 409 "$status"

  poll_resp=$(curl -sS "$API/api/v1/clusters/enroll/status?pollToken=$poll_token")
  poll_status=$(echo "$poll_resp" | json_field status)
  cert_pem=$(echo "$poll_resp" | json_field certPem)
  ca_pem=$(echo "$poll_resp" | json_field caPem)
  if [[ "$poll_status" == "issued" && -n "$cert_pem" && -n "$ca_pem" ]]; then
    echo "  PASS: enroll/status after accept returns issued with certPem + caPem"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: enroll/status after accept — response: $poll_resp"
    FAIL=$((FAIL + 1))
  fi

  poll_resp2=$(curl -sS "$API/api/v1/clusters/enroll/status?pollToken=$poll_token")
  cert_pem2=$(echo "$poll_resp2" | json_field certPem)
  if [[ -n "$cert_pem" && "$cert_pem2" == "$cert_pem" ]]; then
    echo "  PASS: re-polling enroll/status returns the same certificate idempotently"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: re-polling enroll/status returned a different or missing certificate"
    FAIL=$((FAIL + 1))
  fi

  clusters_resp=$(curl -sS "$API/api/v1/clusters" -H "Authorization: Bearer $access_token")
  if echo "$clusters_resp" | grep -q "$cluster_id"; then
    echo "  PASS: GET /clusters lists the enrolled cluster"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: GET /clusters did not list cluster $cluster_id — response: $clusters_resp"
    FAIL=$((FAIL + 1))
  fi

  detail_resp=$(curl -sS "$API/api/v1/clusters/$cluster_id" -H "Authorization: Bearer $access_token")
  detail_state=$(echo "$detail_resp" | json_field state)
  check_status "GET /clusters/{id} reflects the Provisioning state" "Provisioning" "$detail_state"

  echo "-- 6a. Renaming a cluster (POST /clusters/{id}/rename, cluster:onboard) --"
  # Closes a real, user-reported gap: a cluster enrolled without a
  # displayName (or one enrolled before an operator thought to set one)
  # falls back to "cluster-" + a short fingerprint hash — meaningless to
  # look at. This is the fix, for a cluster in ANY state, not just
  # newly-enrolled ones.
  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/clusters/$cluster_id/rename" \
    -H "Content-Type: application/json" -d '{"displayName":"renamed-no-auth"}')
  check_status "rename with no auth" 401 "$status"

  rename_resp=$(curl -sS -X POST "$API/api/v1/clusters/$cluster_id/rename" \
    -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" \
    -d '{"displayName":"  smoketest-cluster-renamed  "}')
  renamed_name=$(echo "$rename_resp" | json_field displayName)
  check_status "rename trims surrounding whitespace and round-trips the new name" "smoketest-cluster-renamed" "$renamed_name"

  detail_resp=$(curl -sS "$API/api/v1/clusters/$cluster_id" -H "Authorization: Bearer $access_token")
  detail_name=$(echo "$detail_resp" | json_field displayName)
  check_status "GET /clusters/{id} reflects the new name (real DB state, not just the response body)" "smoketest-cluster-renamed" "$detail_name"

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/clusters/$cluster_id/rename" \
    -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" -d '{"displayName":"   "}')
  check_status "rename to a blank/whitespace-only name is rejected" 400 "$status"

  too_long_name=$(python3 -c "print('x' * 201)")
  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/clusters/$cluster_id/rename" \
    -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" \
    -d "{\"displayName\":\"$too_long_name\"}")
  check_status "rename beyond the length limit is rejected" 400 "$status"

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/clusters/does-not-exist/rename" \
    -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" -d '{"displayName":"whatever"}')
  check_status "renaming a nonexistent cluster is rejected" 404 "$status"

  # Capability denial for cluster:onboard (the same capability rename
  # reuses) is already thoroughly exercised in section 4b against
  # POST /clusters/enrollment-tokens via the shared requireCapability
  # middleware — not re-proven per-handler here.

  # Rename back to the original name: this exact cluster_id is reused by
  # later sections (7's finding-ingestion clusterDisplayName assertions,
  # 9's audit-event clusterDisplayName join) that expect "smoketest-cluster"
  # — leaving the rename in place here would fail those for a reason that
  # has nothing to do with what they're actually testing.
  curl -sS -X POST "$API/api/v1/clusters/$cluster_id/rename" \
    -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" \
    -d '{"displayName":"smoketest-cluster"}' >/dev/null
fi

echo "== 7. Finding ingestion and incident correlation (tunnel) =="
# Simulates the spoke-side Detection Controller's output (internal/tunnel.Finding)
# over a REAL mTLS tunnel connection, presenting the exact cert/key/CA issued to
# the cluster enrolled in section 6 above — same technique this codebase's other
# hand-driven tunnel verifications use (see STATUS.md's "Agent enrollment
# handshake and tunnel" entries), except saved as a small, throwaway Go program
# (scripts/simulate-finding) instead of a one-off manual step, since this needs
# to be repeatable and the real spoke-side detector (a parallel, independent
# task) doesn't exist yet — the wire contract is fixed regardless of who sends
# it. Exercises internal/gateway's handleFinding correlation rule end to end:
# two Findings sharing one fingerprint — deliberately sent second-newest-first
# (finding1's occurredAt is LATER than finding2's), to exercise the "never
# regress last_seen on out-of-order delivery" rule, not just the trivial
# forward-in-time case — must correlate into ONE incident with
# occurrenceCount 2; a third Finding with a different fingerprint must open a
# SEPARATE incident.
if [[ -n "$cluster_id" && -n "$cert_pem" && -n "$ca_pem" ]]; then
  # hubEndpoint is exactly what a real agent learns this same way (see
  # internal/agent/client.go's pollEnrollStatus) — reusing it here rather than
  # a hardcoded address/env var keeps this test honest about how a cluster
  # actually learns where to dial.
  tunnel_addr=$(echo "$poll_resp" | json_field hubEndpoint)

  FINDINGS_DIR=$(mktemp -d)
  printf '%s' "$cert_pem" > "$FINDINGS_DIR/cert.pem"
  printf '%s' "$ca_pem" > "$FINDINGS_DIR/ca.pem"
  cp "$CSR_DIR/key.pem" "$FINDINGS_DIR/key.pem"

  FP_A="smoketest-finding-fp-a-$(date +%s)-$$"
  FP_B="smoketest-finding-fp-b-$(date +%s)-$$"

  NOW_EPOCH=$(date -u +%s)
  TS_0=$(date -u -d "@$NOW_EPOCH" +%Y-%m-%dT%H:%M:%SZ)
  TS_MINUS_60=$(date -u -d "@$((NOW_EPOCH - 60))" +%Y-%m-%dT%H:%M:%SZ)
  TS_MINUS_120=$(date -u -d "@$((NOW_EPOCH - 120))" +%Y-%m-%dT%H:%M:%SZ)

  python3 - "$FP_A" "$FP_B" "$TS_MINUS_60" "$TS_MINUS_120" "$TS_0" > "$FINDINGS_DIR/findings.json" <<'PYEOF'
import json, sys
fp_a, fp_b, ts_minus_60, ts_minus_120, ts_0 = sys.argv[1:6]
findings = [
    {
        "detectorId": "smoketest-detector", "detectorVersion": "0.1.0",
        "fingerprint": fp_a, "gvk": "apps/v1/Deployment",
        "namespace": "default", "objectName": "smoketest-deploy",
        "objectUid": "smoketest-uid-a", "resourceVersion": "1",
        "reason": "CrashLoopBackOff", "message": "first occurrence (later timestamp, sent first)",
        "occurrenceCount": 5, "severity": "medium", "occurredAt": ts_minus_60,
    },
    {
        "detectorId": "smoketest-detector", "detectorVersion": "0.1.0",
        "fingerprint": fp_a, "gvk": "apps/v1/Deployment",
        "namespace": "default", "objectName": "smoketest-deploy",
        "objectUid": "smoketest-uid-a", "resourceVersion": "2",
        "reason": "CrashLoopBackOff", "message": "second occurrence (earlier timestamp, sent second -- out of order)",
        "occurrenceCount": 7, "severity": "medium", "occurredAt": ts_minus_120,
    },
    {
        "detectorId": "smoketest-detector", "detectorVersion": "0.1.0",
        "fingerprint": fp_b, "gvk": "v1/Pod",
        "namespace": "default", "objectName": "smoketest-pod",
        "objectUid": "smoketest-uid-b", "resourceVersion": "1",
        "reason": "OOMKilled", "message": "different fingerprint -- must open a separate incident",
        "occurrenceCount": 9, "severity": "high", "occurredAt": ts_0,
    },
]
json.dump(findings, sys.stdout)
PYEOF

  sim_output=$(go run ./scripts/simulate-finding \
    -addr "$tunnel_addr" \
    -cert "$FINDINGS_DIR/cert.pem" -key "$FINDINGS_DIR/key.pem" -ca "$FINDINGS_DIR/ca.pem" \
    -send-inventory -findings "$FINDINGS_DIR/findings.json" 2>&1)
  sim_status=$?

  if [[ $sim_status -eq 0 ]] && echo "$sim_output" | grep -q "SUMMARY sent=3 acked=3"; then
    echo "  PASS: simulate-finding sent 3 Finding messages over a real mTLS tunnel, all acked"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: simulate-finding did not complete cleanly (exit $sim_status): $sim_output"
    FAIL=$((FAIL + 1))
  fi

  detail_resp=$(curl -sS "$API/api/v1/clusters/$cluster_id" -H "Authorization: Bearer $access_token")
  detail_state=$(echo "$detail_resp" | json_field state)
  check_status "cluster promoted to Active by the simulated tunnel's InventoryDelta" "Active" "$detail_state"

  status=$(curl -sS -o /dev/null -w "%{http_code}" "$API/api/v1/incidents")
  check_status "GET /incidents with no auth" 401 "$status"

  incidents_resp=$(curl -sS "$API/api/v1/incidents" -H "Authorization: Bearer $access_token")

  # NOTE: the JSON response is passed as an argv element, not piped to
  # stdin — `python3 - <<HEREDOC` already uses stdin to feed the script's
  # own source to the interpreter, so a same-command pipe into stdin would
  # never reach json.load(sys.stdin) inside the script (stdin is already
  # exhausted reading the program text itself by the time it runs). But the
  # argv element itself is a FILE PATH (json_arg_file), not the response
  # body inline — BUGS.md 113: on a long-lived dev stack with hundreds of
  # accumulated incidents, this unfiltered list is big enough that passing
  # it as a literal argv string hits the OS's ARG_MAX ("Argument list too
  # long" from python3 itself, silently skipping this whole block).
  incidents_resp_file=$(json_arg_file "$incidents_resp")
  verify_output=$(python3 - "$incidents_resp_file" "$cluster_id" "$FP_A" "$FP_B" "$TS_MINUS_60" "$TS_0" "smoketest-cluster" <<'PYEOF'
import json, sys

with open(sys.argv[1]) as f:
    resp = json.load(f)
cluster_id, fp_a, fp_b, ts_a, ts_b, display_name = sys.argv[2:8]

# BUGS.md 113 (found live re-running this suite after the argv/ARG_MAX fix
# finally let this check execute): incidentSummary's object-identity split
# (objectGvk/objectNamespace/objectName, BACKLOG.md A3b) and openingReason
# are `omitempty` in the Go struct, but "omit if nil" is not "rare" here --
# every finding names its own object and the reason that opened its
# incident, so a fresh, non-fleet-grouped, non-workload-grouped incident
# still carries all four of these non-null on the wire. Only the genuinely
# conditional ones (fleetGroupId/workloadGroupId/workloadKey/objectGroupId/
# relatedWorkloadKey/resolvedAt) are correctly absent for this fixture.
EXPECTED_LIST_KEYS = {
    "id", "clusterId", "clusterDisplayName", "fingerprint", "severity",
    "state", "firstSeen", "lastSeen", "occurrenceCount",
    "objectGvk", "objectNamespace", "objectName", "openingReason",
}

results = []


def check(cond, desc, detail=""):
    results.append((bool(cond), desc, detail))


incidents = resp.get("incidents", [])
by_fp = {inc.get("fingerprint"): inc for inc in incidents if inc.get("clusterId") == cluster_id}

inc_a = by_fp.get(fp_a)
inc_b = by_fp.get(fp_b)

check(inc_a is not None, "incident A (fingerprint fp_a) present in GET /incidents")
check(inc_b is not None, "incident B (fingerprint fp_b) present in GET /incidents")

if inc_a is not None:
    check(set(inc_a.keys()) == EXPECTED_LIST_KEYS,
          "incident A list element has exactly the specified keys", sorted(inc_a.keys()))
    check(inc_a.get("occurrenceCount") == 2,
          "incident A occurrenceCount == 2 (two findings, same fingerprint, correlated)", inc_a.get("occurrenceCount"))
    check(inc_a.get("state") == "Detected", "incident A state == Detected", inc_a.get("state"))
    check(inc_a.get("firstSeen") == ts_a, "incident A firstSeen == the later-occurredAt finding's timestamp", inc_a.get("firstSeen"))
    check(inc_a.get("lastSeen") == ts_a,
          "incident A lastSeen did NOT regress to the out-of-order finding's earlier occurredAt", inc_a.get("lastSeen"))
    check(inc_a.get("clusterDisplayName") == display_name, "incident A clusterDisplayName matches the enrolled cluster", inc_a.get("clusterDisplayName"))
    check(inc_a.get("severity") == "medium", "incident A severity == medium (from the finding that created it)", inc_a.get("severity"))

if inc_b is not None:
    check(set(inc_b.keys()) == EXPECTED_LIST_KEYS,
          "incident B list element has exactly the specified keys", sorted(inc_b.keys()))
    check(inc_b.get("occurrenceCount") == 1,
          "incident B occurrenceCount == 1 (separate incident, different fingerprint)", inc_b.get("occurrenceCount"))
    check(inc_b.get("state") == "Detected", "incident B state == Detected", inc_b.get("state"))
    check(inc_b.get("firstSeen") == ts_b, "incident B firstSeen == its finding's occurredAt", inc_b.get("firstSeen"))
    if inc_a is not None:
        check(inc_b.get("id") != inc_a.get("id"), "incident B is a genuinely separate incident from incident A")

if len(incidents) >= 2:
    ordering_ok = all(incidents[i]["lastSeen"] >= incidents[i + 1]["lastSeen"] for i in range(len(incidents) - 1))
    check(ordering_ok, "GET /incidents is ordered by lastSeen DESC")

for passed, desc, detail in results:
    tag = "PASS" if passed else "FAIL"
    suffix = f" (got {detail})" if detail != "" else ""
    print(f"  {tag}: {desc}{suffix}")

print(f"INC_A_ID={inc_a.get('id','') if inc_a else ''}")
print(f"INC_B_ID={inc_b.get('id','') if inc_b else ''}")
PYEOF
)
  rm -f "$incidents_resp_file"

  echo "$verify_output" | grep -E "^  (PASS|FAIL):"
  pass_count=$(echo "$verify_output" | grep -c "^  PASS:")
  fail_count=$(echo "$verify_output" | grep -c "^  FAIL:")
  PASS=$((PASS + pass_count))
  FAIL=$((FAIL + fail_count))

  inc_a_id=$(echo "$verify_output" | grep "^INC_A_ID=" | cut -d= -f2-)
  inc_b_id=$(echo "$verify_output" | grep "^INC_B_ID=" | cut -d= -f2-)

  status=$(curl -sS -o /dev/null -w "%{http_code}" "$API/api/v1/incidents/not-a-real-incident-id" \
    -H "Authorization: Bearer $access_token")
  check_status "GET /incidents/{id} with an unrecognized id" 404 "$status"

  if [[ -n "$inc_a_id" ]]; then
    detail_a=$(curl -sS "$API/api/v1/incidents/$inc_a_id" -H "Authorization: Bearer $access_token")
    # Same argv-not-stdin fix as the incidents-list verifier above.
    verify_detail_a=$(python3 - "$detail_a" "$FP_A" "$TS_MINUS_60" "$TS_MINUS_120" <<'PYEOF'
import json, sys

detail = json.loads(sys.argv[1])
fp_a, ts_minus_60, ts_minus_120 = sys.argv[2:5]

EXPECTED_DETAIL_KEYS = {
    "id", "clusterId", "clusterDisplayName", "fingerprint", "severity",
    "state", "firstSeen", "lastSeen", "occurrenceCount", "findings",
    "analysis",  # added when POST /incidents/{id}/analyze (internal/api/analyze.go) landed — null until analyzed
    "findingGroups",  # per-reason counts and time ranges over the WHOLE history, since "findings" became a bounded slice of it (internal/api/incidents.go's maxFindingsPerReason)
    # Both of these landed before this list was last updated, so this exact-key
    # check was failing on them: "evidence" (recorded MCP tool calls) and
    # "ownership" ("will the fix hold") are top-level fields of this response.
    "evidence", "ownership",
    # BUGS.md 113: the rest of handleGetIncident's map literal
    # (internal/api/incidents.go) — the remaining incidentSummary fields
    # (three group ids/keys plus the object-identity split, plus
    # resolvedAt) that this handler builds by hand rather than getting for
    # free from a struct marshal, and the three later additions
    # (unattendedBatch, pullRequest, reopenedBy). All are always present as
    # keys (null when not applicable), never omitted, per that handler's
    # own comment.
    "openingReason", "objectGvk", "objectNamespace", "objectName",
    "unattendedBatch", "pullRequest", "reopenedBy",
    # 2026-09-18: always-present additions — the resolution route, the gate
    # that stopped an automatic path (PROJECT.md T14), prior occurrences of
    # the same object (T7), and the bounded pre-incident change list (T15).
    "route", "routeReason", "automationGate", "priorIncidents", "recentChanges",
    # PROJECT.md M1: POST /analyze is asynchronous, so the run's start, source
    # and failure reason are read from here -- always present, null when unknown.
    "analysisStartedAt", "analysisBackend", "analysisModel", "analysisError",
}
# OMITTED-WHEN-NULL, by design rather than by accident: these carry
# `omitempty` on incidentSummary, and FleetGroupID's own struct comment says
# so explicitly ("omitted (not just null) when this incident isn't part of a
# fleet-wide group"). handleGetIncident used to hand-build its map and always
# emitted them as null; it now derives the response from the shared struct
# (one source of truth, which is what stopped the list/detail divergence),
# and that derivation honours omitempty. So they MAY appear, and their
# absence is not a defect.
OPTIONAL_DETAIL_KEYS = {
    "fleetGroupId", "workloadGroupId", "workloadKey", "resolvedAt",
    "objectGroupId", "relatedWorkloadKey", "resolutionKind",
    "applier", "objectsFolded",
}
EXPECTED_FINDING_KEYS = {
    "id", "detectorId", "gvk", "namespace", "objectName", "reason",
    "message", "severity", "occurrenceCount", "occurredAt",
}

results = []


def check(cond, desc, detail_val=""):
    results.append((bool(cond), desc, detail_val))


_actual = set(detail.keys())
check(EXPECTED_DETAIL_KEYS <= _actual and _actual <= (EXPECTED_DETAIL_KEYS | OPTIONAL_DETAIL_KEYS),
      "incident A detail has every required key and no unexpected one",
      "missing=%s unexpected=%s" % (sorted(EXPECTED_DETAIL_KEYS - _actual), sorted(_actual - EXPECTED_DETAIL_KEYS - OPTIONAL_DETAIL_KEYS)))
check(detail.get("fingerprint") == fp_a, "incident A detail fingerprint matches", detail.get("fingerprint"))
check(detail.get("occurrenceCount") == 2, "incident A detail occurrenceCount == 2", detail.get("occurrenceCount"))

findings = detail.get("findings", [])
check(len(findings) == 2, "incident A detail has exactly 2 findings", len(findings))

if len(findings) == 2:
    check(set(findings[0].keys()) == EXPECTED_FINDING_KEYS, "finding[0] has exactly the specified keys", sorted(findings[0].keys()))
    check(findings[0].get("occurredAt") == ts_minus_60,
          "findings[0] is the LATER-occurredAt finding (occurred_at DESC ordering)", findings[0].get("occurredAt"))
    check(findings[0].get("occurrenceCount") == 5, "findings[0].occurrenceCount == 5 (the first-sent finding's own count)", findings[0].get("occurrenceCount"))
    check(findings[1].get("occurredAt") == ts_minus_120,
          "findings[1] is the EARLIER-occurredAt, out-of-order finding", findings[1].get("occurredAt"))
    check(findings[1].get("occurrenceCount") == 7, "findings[1].occurrenceCount == 7 (the second-sent finding's own count)", findings[1].get("occurrenceCount"))
    check(findings[0].get("gvk") == "apps/v1/Deployment", "findings[0].gvk passed through correctly", findings[0].get("gvk"))
    check(findings[0].get("namespace") == "default", "findings[0].namespace passed through correctly", findings[0].get("namespace"))

for passed, desc, detail_val in results:
    tag = "PASS" if passed else "FAIL"
    suffix = f" (got {detail_val})" if detail_val != "" else ""
    print(f"  {tag}: {desc}{suffix}")
PYEOF
)
    echo "$verify_detail_a"
    pass_count=$(echo "$verify_detail_a" | grep -c "^  PASS:")
    fail_count=$(echo "$verify_detail_a" | grep -c "^  FAIL:")
    PASS=$((PASS + pass_count))
    FAIL=$((FAIL + fail_count))
  else
    echo "  FAIL: could not resolve incident A's id from GET /incidents -- skipping GET /incidents/{id} checks for it"
    FAIL=$((FAIL + 1))
  fi

  if [[ -n "$inc_b_id" ]]; then
    detail_b=$(curl -sS "$API/api/v1/incidents/$inc_b_id" -H "Authorization: Bearer $access_token")
    # Same argv-not-stdin fix as the incidents-list verifier above.
    verify_detail_b=$(python3 - "$detail_b" "$FP_B" "$TS_0" <<'PYEOF'
import json, sys

detail = json.loads(sys.argv[1])
fp_b, ts_0 = sys.argv[2:4]

results = []


def check(cond, desc, detail_val=""):
    results.append((bool(cond), desc, detail_val))


check(detail.get("fingerprint") == fp_b, "incident B detail fingerprint matches", detail.get("fingerprint"))
check(detail.get("occurrenceCount") == 1, "incident B detail occurrenceCount == 1", detail.get("occurrenceCount"))
check(detail.get("firstSeen") == ts_0, "incident B detail firstSeen == its finding's occurredAt", detail.get("firstSeen"))
check(detail.get("lastSeen") == ts_0, "incident B detail lastSeen == its finding's occurredAt", detail.get("lastSeen"))

findings = detail.get("findings", [])
check(len(findings) == 1, "incident B detail has exactly 1 finding", len(findings))
if len(findings) == 1:
    check(findings[0].get("occurrenceCount") == 9, "incident B's finding.occurrenceCount == 9", findings[0].get("occurrenceCount"))
    check(findings[0].get("reason") == "OOMKilled", "incident B's finding.reason passed through correctly", findings[0].get("reason"))

for passed, desc, detail_val in results:
    tag = "PASS" if passed else "FAIL"
    suffix = f" (got {detail_val})" if detail_val != "" else ""
    print(f"  {tag}: {desc}{suffix}")
PYEOF
)
    echo "$verify_detail_b"
    pass_count=$(echo "$verify_detail_b" | grep -c "^  PASS:")
    fail_count=$(echo "$verify_detail_b" | grep -c "^  FAIL:")
    PASS=$((PASS + pass_count))
    FAIL=$((FAIL + fail_count))
  else
    echo "  FAIL: could not resolve incident B's id from GET /incidents -- skipping GET /incidents/{id} checks for it"
    FAIL=$((FAIL + 1))
  fi

  echo "== 7b. GET /incidents?clusterId= filter (internal/api/incidents.go) =="
  # Reuses section 7's own fixtures (cluster_id plus fp_a/fp_b, already
  # fetched unfiltered into $incidents_resp above) rather than enrolling a
  # second cluster just for this — the filter's correctness (only this
  # cluster's incidents come back) is checkable regardless of whether any
  # OTHER cluster's incidents happen to exist in this shared dev stack right
  # now; whether the filtered response is actually SMALLER than the
  # unfiltered one additionally depends on that, so it's checked but not
  # required to pass.
  filtered_resp=$(curl -sS "$API/api/v1/incidents?clusterId=$cluster_id" -H "Authorization: Bearer $access_token")

  # BUGS.md 113: $incidents_resp is the same unfiltered, potentially-huge
  # response section 7 already hit ARG_MAX with — same json_arg_file fix.
  incidents_resp_file=$(json_arg_file "$incidents_resp")
  filter_verify_output=$(python3 - "$incidents_resp_file" "$filtered_resp" "$cluster_id" "$FP_A" "$FP_B" <<'PYEOF'
import json, sys

with open(sys.argv[1]) as f:
    all_resp = json.load(f)
filtered_resp = json.loads(sys.argv[2])
cluster_id, fp_a, fp_b = sys.argv[3:6]

results = []


def check(cond, desc, detail=""):
    results.append((bool(cond), desc, detail))


all_incidents = all_resp.get("incidents", [])
filtered = filtered_resp.get("incidents", [])
expected_ids = {inc["id"] for inc in all_incidents if inc.get("clusterId") == cluster_id}
filtered_ids = {inc["id"] for inc in filtered}

check(len(filtered) > 0, "?clusterId= filter returns at least one incident", len(filtered))
check(all(inc.get("clusterId") == cluster_id for inc in filtered),
      "every incident returned by ?clusterId= filter actually belongs to that cluster")
check(filtered_ids == expected_ids,
      "?clusterId= filter's result set matches client-side-filtering the unfiltered list to the same cluster",
      sorted(filtered_ids) if filtered_ids != expected_ids else "match")
check({fp_a, fp_b} <= {inc.get("fingerprint") for inc in filtered},
      "both of this cluster's incidents (fp_a, fp_b) are present in the filtered response")

if len(all_incidents) > len(filtered):
    check(True, "?clusterId= filter actually narrows results (unfiltered list has incidents from other clusters too)",
          f"{len(filtered)} of {len(all_incidents)}")
else:
    print("  NOTE: unfiltered /incidents currently returns only this cluster's incidents "
          "(no other cluster has any yet in this run) -- correctness is verified above, "
          "but this run can't demonstrate the filter shrinking the result set below the "
          "unfiltered count.")

for passed, desc, detail in results:
    tag = "PASS" if passed else "FAIL"
    suffix = f" (got {detail})" if detail != "" else ""
    print(f"  {tag}: {desc}{suffix}")
PYEOF
)
  rm -f "$incidents_resp_file"

  echo "$filter_verify_output"
  pass_count=$(echo "$filter_verify_output" | grep -c "^  PASS:")
  fail_count=$(echo "$filter_verify_output" | grep -c "^  FAIL:")
  PASS=$((PASS + pass_count))
  FAIL=$((FAIL + fail_count))

  status=$(curl -sS -o /dev/null -w "%{http_code}" "$API/api/v1/incidents?clusterId=$cluster_id")
  check_status "GET /incidents?clusterId= with no auth" 401 "$status"

  echo "== 7c. GET /incidents?state= filter (internal/api/incidents.go) =="
  # Both of section 7's fixture incidents (fp_a, fp_b) are freshly correlated
  # and so both sit in state Detected (checked explicitly in section 7 above)
  # -- no state-transition code exists yet to move them anywhere else. That
  # makes "?state=Detected includes both" and "?state=<anything else> excludes
  # both" the two checks this run can actually make, without needing a second
  # fixture incident in some other state.
  state_detected_resp=$(curl -sS "$API/api/v1/incidents?state=Detected" -H "Authorization: Bearer $access_token")
  state_resolved_resp=$(curl -sS "$API/api/v1/incidents?state=Resolved" -H "Authorization: Bearer $access_token")

  # BUGS.md 113: both of these are tenant-wide by state, not scoped to this
  # run's own fixtures, and on a long-lived dev stack are exactly the kind
  # of response that hits ARG_MAX as a literal argv string (confirmed live)
  # -- same json_arg_file fix as sections 7/7b above.
  state_detected_resp_file=$(json_arg_file "$state_detected_resp")
  state_resolved_resp_file=$(json_arg_file "$state_resolved_resp")
  state_verify_output=$(python3 - "$state_detected_resp_file" "$state_resolved_resp_file" "$FP_A" "$FP_B" <<'PYEOF'
import json, sys

with open(sys.argv[1]) as f:
    detected_resp = json.load(f)
with open(sys.argv[2]) as f:
    resolved_resp = json.load(f)
fp_a, fp_b = sys.argv[3:5]

results = []


def check(cond, desc, detail=""):
    results.append((bool(cond), desc, detail))


detected = detected_resp.get("incidents", [])
resolved = resolved_resp.get("incidents", [])
detected_fps = {inc.get("fingerprint") for inc in detected}
resolved_fps = {inc.get("fingerprint") for inc in resolved}

check(all(inc.get("state") == "Detected" for inc in detected),
      "every incident returned by ?state=Detected is actually in state Detected")
check({fp_a, fp_b} <= detected_fps,
      "both fixture incidents (fp_a, fp_b) are present in ?state=Detected")
check(not ({fp_a, fp_b} & resolved_fps),
      "neither fixture incident (still Detected) shows up in ?state=Resolved",
      sorted({fp_a, fp_b} & resolved_fps))
check(len(resolved) < len(detected) or len(detected) > 0,
      "?state= actually narrows the result set relative to a different state value",
      f"Detected={len(detected)} Resolved={len(resolved)}")

for passed, desc, detail in results:
    tag = "PASS" if passed else "FAIL"
    suffix = f" (got {detail})" if detail != "" else ""
    print(f"  {tag}: {desc}{suffix}")
PYEOF
)
  rm -f "$state_detected_resp_file" "$state_resolved_resp_file"

  echo "$state_verify_output"
  pass_count=$(echo "$state_verify_output" | grep -c "^  PASS:")
  fail_count=$(echo "$state_verify_output" | grep -c "^  FAIL:")
  PASS=$((PASS + pass_count))
  FAIL=$((FAIL + fail_count))

  status=$(curl -sS -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $access_token" \
    "$API/api/v1/incidents?state=NotARealState")
  check_status "GET /incidents?state=<invalid> is rejected" 400 "$status"

  status=$(curl -sS -o /dev/null -w "%{http_code}" "$API/api/v1/incidents?state=Detected")
  check_status "GET /incidents?state= with no auth" 401 "$status"

  echo "== 7d. GET /clusters/{id} facts.nodes degrades gracefully with no metrics-server / no reachable cluster (internal/tunnel.NodeStatus) =="
  # simulate-finding's InventoryDelta (like a real agent with no reachable
  # kubeconfig) reports Reachable: false and an explicit empty Nodes list --
  # this checks that shape survives the round trip through cluster_facts'
  # jsonb column and back out of GET /clusters/{id} unchanged, i.e. "nodes"
  # is always a real (possibly empty) JSON array, never a missing key or a
  # null. See this task's own real-agent run (recorded in STATUS.md) for the
  # "agent against a reachable cluster with no metrics-server" case this
  # single-cluster smoke run can't exercise on its own.
  facts_detail_resp=$(curl -sS "$API/api/v1/clusters/$cluster_id" -H "Authorization: Bearer $access_token")
  facts_verify_output=$(python3 - "$facts_detail_resp" <<'PYEOF'
import json, sys

detail = json.loads(sys.argv[1])
facts = detail.get("facts") or {}

results = []


def check(cond, desc, detail_val=""):
    results.append((bool(cond), desc, detail_val))


check("nodes" in facts, "facts.nodes key is present", sorted(facts.keys()))
check(isinstance(facts.get("nodes"), list), "facts.nodes is a JSON array, never null", facts.get("nodes"))
check(facts.get("reachable") is False, "facts.reachable == false (no live cluster behind this simulated agent)", facts.get("reachable"))

for passed, desc, detail_val in results:
    tag = "PASS" if passed else "FAIL"
    suffix = f" (got {detail_val})" if detail_val != "" else ""
    print(f"  {tag}: {desc}{suffix}")
PYEOF
)
  echo "$facts_verify_output"
  pass_count=$(echo "$facts_verify_output" | grep -c "^  PASS:")
  fail_count=$(echo "$facts_verify_output" | grep -c "^  FAIL:")
  PASS=$((PASS + pass_count))
  FAIL=$((FAIL + fail_count))

  echo "== 7e. Detection settings -- hub-side disabled-detector filter and storm protection (internal/gateway/finding.go's handleFinding, PUT .../settings' \"detection\" section) =="
  # This is the first real, hub-side, live-editable slice of
  # lld/06-detection-framework.md's fuller design -- closing the gap
  # STATUS.md's Phase 1 row has repeatedly flagged ("both detectors are
  # hardcoded, not policy-driven"). NOT the RemediationPolicy CRD/cluster-side
  # controller that document's fuller design eventually calls for -- see
  # STATUS.md's own section on this for exactly what's real here and what
  # isn't. Both controls below are enforced entirely inside handleFinding,
  # which re-resolves settings fresh on every call -- fully live, no agent or
  # hub restart.
  #
  # BUGS.md 121: the storm-protection/disabled-detector checks below used to
  # run against section 7's own smoketest-cluster ($cluster_id). Section 7
  # already opened two real incidents (fp_a/fp_b) on that cluster, well
  # inside any 300-second storm window this section configures, so
  # countIncidentsCreatedSince (internal/gateway/finding.go) -- correctly --
  # counted them too, throwing off which of THIS section's own new-fingerprint
  # findings should land inside vs. outside the ceiling. Enrolling a
  # brand-new, throwaway cluster here (same CSR+enroll+accept+poll idiom
  # section 6 above uses -- no need for section 11/13/15's real `cmd/agent`
  # process, since this section only ever needs to hand-drive
  # scripts/simulate-finding, exactly like section 7 already does) removes
  # the interaction entirely: this cluster starts this section with zero
  # incidents, so the ceiling math needs no baseline compensation at all.
  #
  # The one check that deliberately keeps targeting section 7's ORIGINAL
  # cluster/incident (fp_a via $tunnel_addr/$FINDINGS_DIR/$inc_a_id below) is
  # "an existing incident keeps updating while storm protection is engaged"
  # -- storm-protection settings are tenant-wide (PUT /admin/settings), so
  # proving a DIFFERENT cluster's already-open incident is unaffected is if
  # anything a stronger version of that assertion than same-cluster was.
  SECTION7E_CSR_DIR=$(mktemp -d)
  openssl ecparam -genkey -name prime256v1 -noout -out "$SECTION7E_CSR_DIR/key.pem" 2>/dev/null
  openssl req -new -key "$SECTION7E_CSR_DIR/key.pem" -subj "/CN=smoketest-storm-fingerprint" -out "$SECTION7E_CSR_DIR/csr.pem" 2>/dev/null

  section7e_fingerprint="smoketest-storm-cluster-fp-$(date +%s)-$$"
  section7e_enroll_token=$(curl -sS -X POST "$API/api/v1/clusters/enrollment-tokens" \
    -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" \
    -d '{"ttlClass":"B"}' | json_field token)
  section7e_enroll_payload=$(python3 - "$section7e_enroll_token" "$SECTION7E_CSR_DIR/csr.pem" "$section7e_fingerprint" <<'PYEOF'
import json, sys
token, csr_path, fingerprint = sys.argv[1], sys.argv[2], sys.argv[3]
csr = open(csr_path).read()
print(json.dumps({
    "token": token,
    "csrPem": csr,
    "clusterFingerprint": fingerprint,
    "displayName": "smoketest-storm-cluster",
}))
PYEOF
)
  section7e_enroll_resp=$(curl -sS -X POST "$API/api/v1/clusters/enroll" \
    -H "Content-Type: application/json" -d "$section7e_enroll_payload")
  section7e_cluster_id=$(echo "$section7e_enroll_resp" | json_field clusterId)
  register_smoketest_cluster "$section7e_cluster_id"
  section7e_poll_token=$(echo "$section7e_enroll_resp" | json_field pollToken)

  SECTION7E_FINDINGS_DIR=$(mktemp -d)
  section7e_tunnel_addr=""
  if [[ -n "$section7e_cluster_id" && -n "$section7e_poll_token" ]]; then
    curl -sS -X POST "$API/api/v1/clusters/$section7e_cluster_id/accept" \
      -H "Authorization: Bearer $access_token" >/dev/null
    section7e_poll_resp=$(curl -sS "$API/api/v1/clusters/enroll/status?pollToken=$section7e_poll_token")
    section7e_cert_pem=$(echo "$section7e_poll_resp" | json_field certPem)
    section7e_ca_pem=$(echo "$section7e_poll_resp" | json_field caPem)
    section7e_tunnel_addr=$(echo "$section7e_poll_resp" | json_field hubEndpoint)
    printf '%s' "$section7e_cert_pem" > "$SECTION7E_FINDINGS_DIR/cert.pem"
    printf '%s' "$section7e_ca_pem" > "$SECTION7E_FINDINGS_DIR/ca.pem"
    cp "$SECTION7E_CSR_DIR/key.pem" "$SECTION7E_FINDINGS_DIR/key.pem"
  fi

  if [[ -n "$section7e_cluster_id" && -n "$section7e_tunnel_addr" ]]; then
    echo "  PASS: enrolled a fresh throwaway cluster for section 7e's storm-protection/disabled-detector checks (BUGS.md 121, cluster $section7e_cluster_id)"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: could not enroll+accept a fresh cluster for section 7e -- enroll response: $section7e_enroll_resp"
    FAIL=$((FAIL + 1))
  fi

  # send_one_finding dials a fresh tunnel connection and sends exactly one
  # Finding, returning simulate-finding's own stdout/stderr (a "SUMMARY
  # sent=1 acked=1" line on success) -- ack-ing a Finding only means the hub
  # received and processed the message without a transport/decode error; it
  # says nothing about whether that processing resulted in a new incident,
  # which is exactly the thing each check below verifies separately via
  # GET /incidents. Takes the tunnel address and the cert/key/ca directory
  # explicitly (BUGS.md 121) so callers can target either this section's own
  # fresh cluster or section 7's original one (the fp_a re-send below).
  #
  # gvk/namespace/object_name are ALSO explicit parameters now (found live
  # while verifying BUGS.md 121's own fix): internal/gateway/finding.go
  # correlates a Finding by OBJECT identity (gvk|namespace|objectName), not
  # by fingerprint, whenever the Finding names an object at all (migration
  # 000036, argus-context's own lesson #8 -- "one broken object legitimately
  # emits several reasons"). This function used to hardcode the SAME
  # objectName ("smoketest-detection-pod") for every call regardless of
  # fingerprint, so a second, third, fourth call with a DIFFERENT fingerprint
  # never opened a new incident at all -- it silently correlated into
  # whichever incident the FIRST call for that object already created,
  # bypassing the storm-protection/disabled-detector code path this section
  # exists to exercise entirely. Every call site below now passes a distinct
  # object identity per fingerprint (so each really is "a new object, does
  # it open a new incident"), except the one deliberately reusing fp_a's own
  # original §7 object (gvk=apps/v1/Deployment / smoketest-deploy) so
  # that call correlates into fp_a's already-open incident as intended.
  send_one_finding() {
    local addr="$1" findings_dir="$2" gvk="$3" namespace="$4" object_name="$5" detector_id="$6" fingerprint="$7" reason="$8" severity="$9" occurred_at="${10}"
    python3 - "$gvk" "$namespace" "$object_name" "$detector_id" "$fingerprint" "$reason" "$severity" "$occurred_at" > "$findings_dir/one_finding.json" <<'PYEOF'
import json, sys
gvk, namespace, object_name, detector_id, fingerprint, reason, severity, occurred_at = sys.argv[1:9]
findings = [{
    "detectorId": detector_id, "detectorVersion": "v1", "fingerprint": fingerprint,
    "gvk": gvk, "namespace": namespace, "objectName": object_name,
    "objectUid": "smoketest-detection-uid-" + fingerprint, "resourceVersion": "1",
    "reason": reason, "message": "smoke-test synthetic finding for section 7e", "occurrenceCount": 1,
    "severity": severity, "occurredAt": occurred_at,
}]
json.dump(findings, sys.stdout)
PYEOF
    go run ./scripts/simulate-finding \
      -addr "$addr" \
      -cert "$findings_dir/cert.pem" -key "$findings_dir/key.pem" -ca "$findings_dir/ca.pem" \
      -findings "$findings_dir/one_finding.json" 2>&1
  }

  # fingerprint_has_incident reports "True"/"False": whether the given
  # cluster currently has ANY incident (open or closed) carrying the given
  # fingerprint -- the observable proxy for "did that finding actually
  # create/reach a new incident," since there's no standalone GET /findings
  # endpoint to check the findings row directly. Takes clusterId explicitly
  # (BUGS.md 121) rather than assuming section 7's cluster.
  fingerprint_has_incident() {
    curl -sS "$API/api/v1/incidents?clusterId=$1" -H "Authorization: Bearer $access_token" \
      | python3 -c "import sys,json; fps={i['fingerprint'] for i in json.load(sys.stdin)['incidents']}; print('$2' in fps)"
  }

  put_detection_settings() {
    # $1=disabledDetectorIdsJsonArray $2=maxOrNull $3=windowOrNull
    curl -sS -o /dev/null -w "%{http_code}" -X PUT "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token" \
      -H "Content-Type: application/json" \
      -d "{\"detection\":{\"disabledDetectorIds\":$1,\"stormProtectionMaxNewIncidents\":$2,\"stormProtectionWindowSeconds\":$3}}"
  }

  # BUGS.md 127: unlike section 11/13/15's own hand-inserted fixture rows
  # (a `smoketest...`-prefixed incidents.id, deleted by a plain `LIKE`),
  # every incident/finding this section creates comes from a REAL Finding
  # sent over the real tunnel to the real gateway, so its id is an ordinary
  # hub-generated `inc_<ulid>` -- there is no id prefix to delete by. Scoped
  # by cluster_id instead: section7e_cluster_id (BUGS.md 121) is a
  # throwaway cluster enrolled solely for this section's own checks and
  # never touched by anything else in this script, so every incident/
  # finding on it IS this section's fixture set, in its entirety. Same
  # FK-safe delete order section 11's own cleanup comment established
  # (evidence/analysis_embeddings before analyses; approval decisions/
  # executions before recommendations; findings and incidents last) even
  # though this section never runs a real analysis against any of these
  # incidents today -- so the same fixture shape stays safe to clean up
  # even if a future addition to this section ever does.
  #
  # Called AFTER section 7f, not before: 7f's dry-run replay reads these
  # same real findings/incidents rows back out of the database, so cleaning
  # them up before 7f runs would break the very thing 7f exists to verify.
  #
  # The cluster row itself is deliberately left behind, same as sections
  # 11/13/15's fresh clusters (this is a dev stack; not application state
  # worth tearing down via a decommission call) -- this fix is about the
  # incidents/findings rows that were actually accumulating unboundedly
  # (BUGS.md 127's own live count: 149 still `Detected` across six runs),
  # not about the cluster row, which sections 11/13/15 already established
  # is fine to leave.
  cleanup_section7e() {
    if [[ -n "${section7e_cluster_id:-}" ]]; then
      docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -v ON_ERROR_STOP=1 >/dev/null <<SQL
DELETE FROM remediation_approval_decisions WHERE incident_id IN (SELECT id FROM incidents WHERE cluster_id = '$section7e_cluster_id');
DELETE FROM remediation_execution_attempts WHERE incident_id IN (SELECT id FROM incidents WHERE cluster_id = '$section7e_cluster_id');
DELETE FROM remediation_executions WHERE incident_id IN (SELECT id FROM incidents WHERE cluster_id = '$section7e_cluster_id');
DELETE FROM remediation_recommendations WHERE incident_id IN (SELECT id FROM incidents WHERE cluster_id = '$section7e_cluster_id');
DELETE FROM evidence WHERE analysis_id IN (SELECT id FROM analyses WHERE incident_id IN (SELECT id FROM incidents WHERE cluster_id = '$section7e_cluster_id'));
DELETE FROM analysis_embeddings WHERE incident_id IN (SELECT id FROM incidents WHERE cluster_id = '$section7e_cluster_id');
DELETE FROM analyses WHERE incident_id IN (SELECT id FROM incidents WHERE cluster_id = '$section7e_cluster_id');
DELETE FROM findings WHERE cluster_id = '$section7e_cluster_id';
DELETE FROM incidents WHERE cluster_id = '$section7e_cluster_id';
SQL
    fi
    rm -rf "$SECTION7E_CSR_DIR" "$SECTION7E_FINDINGS_DIR"
  }

  TS_NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  STORM_TS=$(date -u -d "@$(( $(date -u +%s) + 1 ))" +%Y-%m-%dT%H:%M:%SZ)

  # -- Storm protection: cap new-incident creation per cluster per window --
  # Baselines against however many incidents this section's own fresh
  # cluster already has (BUGS.md 121: should be zero, since it was enrolled
  # moments ago above) rather than assuming a fixed number, so this check
  # stays robust even if that enrollment above partially failed.
  baseline_resp=$(curl -sS "$API/api/v1/incidents?clusterId=$section7e_cluster_id" -H "Authorization: Bearer $access_token")
  baseline_count=$(echo "$baseline_resp" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['incidents']))")
  storm_max=$((baseline_count + 2))

  status=$(put_detection_settings "[]" "$storm_max" "300")
  check_status "PUT detection.stormProtectionMaxNewIncidents=$storm_max/windowSeconds=300 accepted" 200 "$status"

  FP_STORM_1="smoketest-storm-1-$(date +%s)-$$"
  FP_STORM_2="smoketest-storm-2-$(date +%s)-$$"
  FP_STORM_3="smoketest-storm-3-$(date +%s)-$$"
  FP_STORM_4="smoketest-storm-4-$(date +%s)-$$"

  send_one_finding "$section7e_tunnel_addr" "$SECTION7E_FINDINGS_DIR" "v1/Pod" "default" "smoketest-detection-pod-$FP_STORM_1" "k8s-pod-conditions" "$FP_STORM_1" "CrashLoopBackOff" "medium" "$STORM_TS" > /dev/null
  send_one_finding "$section7e_tunnel_addr" "$SECTION7E_FINDINGS_DIR" "v1/Pod" "default" "smoketest-detection-pod-$FP_STORM_2" "k8s-pod-conditions" "$FP_STORM_2" "CrashLoopBackOff" "medium" "$STORM_TS" > /dev/null
  send_one_finding "$section7e_tunnel_addr" "$SECTION7E_FINDINGS_DIR" "v1/Pod" "default" "smoketest-detection-pod-$FP_STORM_3" "k8s-pod-conditions" "$FP_STORM_3" "CrashLoopBackOff" "medium" "$STORM_TS" > /dev/null
  send_one_finding "$section7e_tunnel_addr" "$SECTION7E_FINDINGS_DIR" "v1/Pod" "default" "smoketest-detection-pod-$FP_STORM_4" "k8s-pod-conditions" "$FP_STORM_4" "CrashLoopBackOff" "medium" "$STORM_TS" > /dev/null

  # The ceiling allows exactly 2 MORE new incidents beyond baseline_count --
  # storm 1 and 2 must open real incidents, 3 and 4 must be suppressed
  # (recorded, per handleFinding's doc comment, but never linked to a new
  # incident).
  check_status "storm-protection: new incident #1 (within budget) is created" "True" "$(fingerprint_has_incident "$section7e_cluster_id" "$FP_STORM_1")"
  check_status "storm-protection: new incident #2 (within budget) is created" "True" "$(fingerprint_has_incident "$section7e_cluster_id" "$FP_STORM_2")"
  check_status "storm-protection: new incident #3 (ceiling already hit) is suppressed" "False" "$(fingerprint_has_incident "$section7e_cluster_id" "$FP_STORM_3")"
  check_status "storm-protection: new incident #4 (ceiling already hit) is suppressed" "False" "$(fingerprint_has_incident "$section7e_cluster_id" "$FP_STORM_4")"

  # An EXISTING incident (fp_a, from section 7's ORIGINAL cluster) must keep
  # updating completely normally while storm protection is actively
  # suppressing brand-new ones on this section's own fresh cluster --
  # storm-protection settings are tenant-wide, so this deliberately targets
  # section 7's $tunnel_addr/$FINDINGS_DIR (BUGS.md 121), not this section's
  # fresh cluster, proving suppression elsewhere never touches correlation
  # against an already-open incident on a different cluster either.
  if [[ -n "$inc_a_id" ]]; then
    count_before=$(curl -sS "$API/api/v1/incidents/$inc_a_id" -H "Authorization: Bearer $access_token" | json_field occurrenceCount)
    send_one_finding "$tunnel_addr" "$FINDINGS_DIR" "apps/v1/Deployment" "default" "smoketest-deploy" "k8s-warning-events" "$FP_A" "CrashLoopBackOff" "medium" "$STORM_TS" > /dev/null
    count_after=$(curl -sS "$API/api/v1/incidents/$inc_a_id" -H "Authorization: Bearer $access_token" | json_field occurrenceCount)
    if [[ "$count_after" =~ ^[0-9]+$ && "$count_before" =~ ^[0-9]+$ && "$count_after" -eq $((count_before + 1)) ]]; then
      echo "  PASS: storm-protection engaged does not block an existing incident's own updates (occurrenceCount $count_before -> $count_after)"
      PASS=$((PASS + 1))
    else
      echo "  FAIL: existing incident fp_a did not update normally while storm protection was engaged (occurrenceCount $count_before -> $count_after)"
      FAIL=$((FAIL + 1))
    fi
  else
    echo "  SKIP: no inc_a_id from section 7 -- skipping the existing-incident-still-updates check"
  fi

  # The suppression itself must be audited, not silent (internal/audit,
  # handleFinding's audit.RecordEvent call) -- ?since= (the only time-bounded
  # filter GET /audit-events exposes) narrows to just this section's own
  # writes, and detailsSummary (the list endpoint's stringified digest of the
  # full `details` blob) is checked for the exact event marker
  # handleFinding's audit.Event.Details sets.
  audit_since_resp=$(curl -sS "$API/api/v1/audit-events?since=$TS_NOW&limit=50" -H "Authorization: Bearer $access_token")
  # detailsSummary never carries the raw snake_case "event" value verbatim --
  # summarizeActionDetails (internal/api/audit.go) always runs it through
  # humanizeAuditToken first (underscores -> spaces, each word capitalized),
  # by design, so a real admin sees "Storm Protection Suppressed New
  # Incident" rather than the internal event key. This check was matching
  # the pre-humanization string, which summarizeActionDetails has never
  # actually produced -- fixed to match its real, correct output instead of
  # loosening what the product does.
  storm_audit_count=$(echo "$audit_since_resp" | python3 -c "
import sys, json
events = json.load(sys.stdin).get('auditEvents', [])
print(sum(1 for e in events if 'Storm Protection Suppressed New Incident' in e.get('detailsSummary', '') and e.get('clusterId') == '$section7e_cluster_id'))
")
  if [[ "$storm_audit_count" =~ ^[0-9]+$ && "$storm_audit_count" -ge 2 ]]; then
    echo "  PASS: storm-protection suppression is audited, not silent ($storm_audit_count storm_protection_suppressed_new_incident audit events for this cluster)"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: expected at least 2 storm_protection_suppressed_new_incident audit events for this cluster, found $storm_audit_count"
    FAIL=$((FAIL + 1))
  fi

  # Clearing the ceiling (both fields explicitly null) must lift suppression
  # immediately -- no restart, same as setting it.
  status=$(put_detection_settings "[]" "null" "null")
  check_status "PUT detection storm-protection fields cleared (both null) accepted" 200 "$status"

  FP_STORM_5="smoketest-storm-5-$(date +%s)-$$"
  send_one_finding "$section7e_tunnel_addr" "$SECTION7E_FINDINGS_DIR" "v1/Pod" "default" "smoketest-detection-pod-$FP_STORM_5" "k8s-pod-conditions" "$FP_STORM_5" "CrashLoopBackOff" "medium" "$STORM_TS" > /dev/null
  check_status "storm-protection cleared: a brand-new incident is created again" "True" "$(fingerprint_has_incident "$section7e_cluster_id" "$FP_STORM_5")"

  # A real k8s-warning-events finding recorded WHILE the detector is still
  # enabled -- found necessary verifying BUGS.md 121 (pre-existing, and
  # independent of it): internal/gateway's handleFinding drops a disabled
  # detector's finding entirely, before any findings-table insert ("gateway:
  # dropping finding from disabled detector ... -- hub-side filter only",
  # confirmed live in hub-api's own log), unlike storm protection, which
  # records the finding and only skips the incident link. §7f's dry-run
  # replay can only ever see findings that actually made it into the table,
  # so FP_DISABLED below (sent AFTER disabling) never gives it anything to
  # replay -- this fixture is the one real k8s-warning-events row that
  # exists BEFORE the disable, so 7f has more than the lone post-re-enable
  # row (FP_REENABLED) to work with.
  FP_WARNING_BASELINE="smoketest-warning-baseline-$(date +%s)-$$"
  send_one_finding "$section7e_tunnel_addr" "$SECTION7E_FINDINGS_DIR" "v1/Pod" "default" "smoketest-detection-pod-$FP_WARNING_BASELINE" "k8s-warning-events" "$FP_WARNING_BASELINE" "FailedScheduling" "medium" "$TS_NOW" > /dev/null
  check_status "k8s-warning-events finding recorded while still enabled (baseline for 7f's disabled-detector-filter replay)" "True" "$(fingerprint_has_incident "$section7e_cluster_id" "$FP_WARNING_BASELINE")"

  # -- Disabled-detector filter: a hub-side drop, never an agent-side one --
  status=$(put_detection_settings '["k8s-warning-events"]' "null" "null")
  check_status "PUT detection.disabledDetectorIds=[\"k8s-warning-events\"] accepted" 200 "$status"

  FP_DISABLED="smoketest-disabled-detector-$(date +%s)-$$"
  FP_STILL_ENABLED="smoketest-still-enabled-detector-$(date +%s)-$$"

  send_one_finding "$section7e_tunnel_addr" "$SECTION7E_FINDINGS_DIR" "v1/Pod" "default" "smoketest-detection-pod-$FP_DISABLED" "k8s-warning-events" "$FP_DISABLED" "FailedScheduling" "medium" "$TS_NOW" > /dev/null
  send_one_finding "$section7e_tunnel_addr" "$SECTION7E_FINDINGS_DIR" "v1/Pod" "default" "smoketest-detection-pod-$FP_STILL_ENABLED" "k8s-pod-conditions" "$FP_STILL_ENABLED" "OOMKilled" "high" "$TS_NOW" > /dev/null

  check_status "disabled detector's finding never becomes an incident" "False" "$(fingerprint_has_incident "$section7e_cluster_id" "$FP_DISABLED")"
  check_status "the OTHER (still-enabled) detector's finding still becomes an incident" "True" "$(fingerprint_has_incident "$section7e_cluster_id" "$FP_STILL_ENABLED")"

  # Re-enabling must also be immediately live.
  status=$(put_detection_settings "[]" "null" "null")
  check_status "PUT detection.disabledDetectorIds=[] (re-enable) accepted" 200 "$status"

  FP_REENABLED="smoketest-reenabled-detector-$(date +%s)-$$"
  send_one_finding "$section7e_tunnel_addr" "$SECTION7E_FINDINGS_DIR" "v1/Pod" "default" "smoketest-detection-pod-$FP_REENABLED" "k8s-warning-events" "$FP_REENABLED" "FailedScheduling" "medium" "$TS_NOW" > /dev/null
  check_status "re-enabled detector's finding becomes an incident again" "True" "$(fingerprint_has_incident "$section7e_cluster_id" "$FP_REENABLED")"

  echo "== 7f. Detection dry-run (POST /api/v1/detection/dry-run) -- replays section 7e's real findings/incidents against a CANDIDATE, never saving it =="
  # The read-only-simulation half of the same feature 7e (live enforcement)
  # and 8c (REST-layer validation) exercise -- internal/api/detection_dryrun.go.
  # It calls the EXACT SAME decision functions handleFinding used live just
  # above (internal/gateway's exported IsDetectorDisabled/StormProtection*),
  # replayed in Go against the real findings/incidents rows this section just
  # created over a real mTLS tunnel, never a second hand-copied
  # reimplementation. This section's fixture set is exactly what this
  # feature needs to show a meaningful difference: two detectors, a genuine
  # storm (5 same-cluster, same-instant new-fingerprint findings, 2 of which
  # were ACTUALLY suppressed live under 7e's own ceiling and 3 of which were
  # ACTUALLY created), plus a disabled-detector episode -- so a candidate
  # different from what was live at the time has real, checkable, non-zero
  # effects to report.
  before_dryrun_settings=$(curl -sS "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token")

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/detection/dry-run" \
    -H "Content-Type: application/json" \
    -d '{"disabledDetectorIds":[],"stormProtectionMaxNewIncidents":null,"stormProtectionWindowSeconds":null}')
  check_status "POST /detection/dry-run with no auth" 401 "$status"

  # -- Disabled-detector filter, replayed against this run's real history --
  dryrun_filter_resp=$(curl -sS -X POST "$API/api/v1/detection/dry-run?days=1" -H "Authorization: Bearer $access_token" \
    -H "Content-Type: application/json" \
    -d '{"disabledDetectorIds":["k8s-warning-events"],"stormProtectionMaxNewIncidents":null,"stormProtectionWindowSeconds":null}')
  dryrun_filter_verify=$(python3 - "$dryrun_filter_resp" "$section7e_cluster_id" <<'PYEOF'
import json, sys
resp = json.loads(sys.argv[1])
cluster_id = sys.argv[2]
f = resp.get("disabledDetectorFilter", {})
buckets = [b for b in f.get("byClusterDetector", []) if b.get("clusterId") == cluster_id]
warning_bucket = next((b for b in buckets if b.get("detectorId") == "k8s-warning-events"), None)
podcond_bucket = next((b for b in buckets if b.get("detectorId") == "k8s-pod-conditions"), None)

results = []
def check(cond, desc, detail=""):
    results.append((bool(cond), desc, detail))

check(resp.get("totalFindingsInWindow", 0) > 0, "totalFindingsInWindow > 0", resp.get("totalFindingsInWindow"))
check(f.get("filteredCount", 0) >= 2,
      "disabledDetectorFilter.filteredCount >= 2 (this run's own k8s-warning-events findings that DID get a findings row)",
      f.get("filteredCount"))
check(warning_bucket is not None and warning_bucket.get("filteredUnderCandidate") is True and warning_bucket.get("findingCount", 0) >= 2,
      "k8s-warning-events bucket for this cluster is flagged filteredUnderCandidate=true with findingCount >= 2", warning_bucket)
check(podcond_bucket is None or podcond_bucket.get("filteredUnderCandidate") is False,
      "k8s-pod-conditions bucket (not disabled in THIS candidate) is not flagged filtered", podcond_bucket)

for passed, desc, detail in results:
    tag = "PASS" if passed else "FAIL"
    suffix = f" (got {detail})" if detail != "" else ""
    print(f"  {tag}: {desc}{suffix}")
PYEOF
)
  echo "$dryrun_filter_verify"
  pass_count=$(echo "$dryrun_filter_verify" | grep -c "^  PASS:")
  fail_count=$(echo "$dryrun_filter_verify" | grep -c "^  FAIL:")
  PASS=$((PASS + pass_count))
  FAIL=$((FAIL + fail_count))

  # -- Storm protection, replayed with a candidate ceiling STRICTER than
  # whatever was actually live when 7e's own storm fixtures were sent --
  # must find real incidents that WERE actually created (storm 1/2 under
  # 7e's ceiling, storm 5 after it was cleared) simulating as suppressed
  # under this tighter candidate.
  dryrun_storm_resp=$(curl -sS -X POST "$API/api/v1/detection/dry-run?days=1" -H "Authorization: Bearer $access_token" \
    -H "Content-Type: application/json" \
    -d '{"disabledDetectorIds":[],"stormProtectionMaxNewIncidents":1,"stormProtectionWindowSeconds":300}')
  dryrun_storm_verify=$(python3 - "$dryrun_storm_resp" "$section7e_cluster_id" <<'PYEOF'
import json, sys
resp = json.loads(sys.argv[1])
cluster_id = sys.argv[2]
sp = resp.get("stormProtection", {})
buckets = [b for b in sp.get("byClusterDetector", []) if b.get("clusterId") == cluster_id]

results = []
def check(cond, desc, detail=""):
    results.append((bool(cond), desc, detail))

check(sp.get("candidateConfigured") is True, "stormProtection.candidateConfigured is true", sp.get("candidateConfigured"))
check(sp.get("eligibleOpportunities", 0) >= 3,
      "stormProtection.eligibleOpportunities >= 3 (this run's own new-fingerprint findings)", sp.get("eligibleOpportunities"))
check(sp.get("newlySuppressedCount", 0) >= 1,
      "at least one incident ACTUALLY created (storm 1/2/5) would be suppressed instead under this stricter candidate",
      sp.get("newlySuppressedCount"))
check(sp.get("candidate", {}).get("suppressedCount", 0) >= sp.get("actual", {}).get("suppressedCount", 0),
      "the stricter candidate suppresses at least as many opportunities as actually happened live",
      (sp.get("candidate"), sp.get("actual")))
check(len(buckets) > 0, "byClusterDetector includes at least one bucket for this run's own cluster", buckets)

for passed, desc, detail in results:
    tag = "PASS" if passed else "FAIL"
    suffix = f" (got {detail})" if detail != "" else ""
    print(f"  {tag}: {desc}{suffix}")
PYEOF
)
  echo "$dryrun_storm_verify"
  pass_count=$(echo "$dryrun_storm_verify" | grep -c "^  PASS:")
  fail_count=$(echo "$dryrun_storm_verify" | grep -c "^  FAIL:")
  PASS=$((PASS + pass_count))
  FAIL=$((FAIL + fail_count))

  # -- Pure simulation: org_settings must be byte-for-byte unchanged after
  # every dry-run call above -- this endpoint must never write anything.
  after_dryrun_settings=$(curl -sS "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token")
  if [[ "$before_dryrun_settings" == "$after_dryrun_settings" ]]; then
    echo "  PASS: org_settings is byte-for-byte unchanged after every dry-run call above (pure simulation, nothing saved)"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: org_settings changed after a dry-run call -- this endpoint must never write anything"
    FAIL=$((FAIL + 1))
  fi

  echo "== 7g. GET /findings -- the fleet-wide findings surface (PROJECT.md F31, internal/api/findings.go) =="
  # Sections 7 and 7e between them have produced both kinds of row this
  # endpoint exists to tell apart: findings that opened incidents (fp_a/fp_b),
  # and findings the hub stored WITHOUT opening one (7e's storm-protection
  # suppressions, plus anything the evidence boundary retained). Everything
  # below reuses those fixtures rather than making more.
  #
  # The headline check is the truncation one: `counts` must be identical on a
  # ?limit=1 page and on the unlimited one. A total derived from the returned
  # array -- the recorded bug this endpoint was required not to reproduce --
  # would collapse to 1 there and still look entirely plausible.
  findings_resp=$(curl -sS "$API/api/v1/findings?clusterId=$cluster_id" -H "Authorization: Bearer $access_token")
  findings_page_resp=$(curl -sS "$API/api/v1/findings?clusterId=$cluster_id&limit=1" -H "Authorization: Bearer $access_token")
  findings_retained_resp=$(curl -sS "$API/api/v1/findings?clusterId=$cluster_id&disposition=retained_unpromoted" -H "Authorization: Bearer $access_token")

  # Same ARG_MAX precaution as sections 7/7b/7c above (BUGS.md 113): a busy
  # cluster's findings list is far longer than its incident list.
  findings_resp_file=$(json_arg_file "$findings_resp")
  findings_page_resp_file=$(json_arg_file "$findings_page_resp")
  findings_retained_resp_file=$(json_arg_file "$findings_retained_resp")

  findings_verify_output=$(python3 - "$findings_resp_file" "$findings_page_resp_file" "$findings_retained_resp_file" "$cluster_id" <<'PYEOF'
import json, sys

with open(sys.argv[1]) as f:
    full = json.load(f)
with open(sys.argv[2]) as f:
    page = json.load(f)
with open(sys.argv[3]) as f:
    retained = json.load(f)
cluster_id = sys.argv[4]

results = []


def check(cond, desc, detail=""):
    results.append((bool(cond), desc, detail))


findings = full.get("findings")
counts = full.get("counts") or {}
rule = full.get("promotionRule") or {}
dispositions = {"correlated", "retained_unpromoted", "suppressed"}

check(isinstance(findings, list), "GET /findings returns a findings array")
check(isinstance(full.get("window"), dict) and full["window"].get("since"),
      "the response states the time window its rows and counts were taken over")
check(all(f.get("clusterId") == cluster_id for f in findings or []),
      "every row respects ?clusterId=")
check(all(f.get("disposition") in dispositions for f in findings or []),
      "every row carries one of the three known dispositions")
check(all((f.get("incidentId") is not None) == (f.get("disposition") == "correlated")
          for f in findings or []),
      "incidentId is present on exactly the rows whose disposition is correlated")
check(all(f.get("class") and f.get("confidence") and f.get("impact") for f in findings or []),
      "every row carries its class/confidence/impact evidence tuple")
check(all(isinstance(f.get("promotion"), dict) and "promotable" in f["promotion"]
          for f in findings or []),
      "every row carries a promotion verdict")
check(all((f.get("promotion") or {}).get("unmet") for f in findings or []
          if f.get("disposition") == "retained_unpromoted"),
      "every retained finding names which criteria it failed -- the whole point is that an operator can see WHY it stayed a finding")

# The rule itself, in the response rather than only in internal/gateway.
criteria = rule.get("criteria") or []
check(rule.get("summary") and rule.get("source"), "the promotion rule is stated in the response")
check({c.get("dimension") for c in criteria} == {"class", "confidence", "impact"},
      "the rule names all three evidence criteria", sorted(c.get("dimension") for c in criteria))
check(all(c.get("accepted") and c.get("statement") for c in criteria),
      "every criterion says which values it accepts")
check(bool(rule.get("notRecorded")),
      "the response discloses what it CANNOT show (findings dropped before storage)")

# Counts: whole-set, internally consistent, and never the page length.
check(counts.get("all") == counts.get("correlated", 0) + counts.get("retainedUnpromoted", 0) + counts.get("suppressed", 0),
      "counts.all is exactly its own disposition breakdown", counts)
check(counts.get("all", 0) >= len(findings or []),
      "counts.all is at least the number of rows returned", f"all={counts.get('all')} rows={len(findings or [])}")
check(len(page.get("findings") or []) <= 1, "?limit=1 returns at most one row")
check(page.get("counts") == counts,
      "counts on a ?limit=1 page are IDENTICAL to the unlimited page's -- the true total, not the page length",
      f"page={page.get('counts')} full={counts}")
if counts.get("all", 0) > 1:
    check(bool(page.get("nextCursor")),
          "a full page hands back a nextCursor so the rest of the list is reachable")

# The disposition filter and the row labels agree.
check(all(f.get("disposition") == "retained_unpromoted" for f in retained.get("findings") or []),
      "every row returned by ?disposition=retained_unpromoted labels itself that way")
check((retained.get("counts") or {}).get("retainedUnpromoted") == len(retained.get("findings") or [])
      or bool(retained.get("nextCursor")),
      "the retained count matches the retained rows (or the page was truncated and says so)")

for passed, desc, detail in results:
    tag = "PASS" if passed else "FAIL"
    suffix = f" (got {detail})" if detail != "" else ""
    print(f"  {tag}: {desc}{suffix}")
PYEOF
)
  rm -f "$findings_resp_file" "$findings_page_resp_file" "$findings_retained_resp_file"

  echo "$findings_verify_output"
  pass_count=$(echo "$findings_verify_output" | grep -c "^  PASS:")
  fail_count=$(echo "$findings_verify_output" | grep -c "^  FAIL:")
  PASS=$((PASS + pass_count))
  FAIL=$((FAIL + fail_count))

  status=$(curl -sS -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $access_token" \
    "$API/api/v1/findings?class=nonsense")
  check_status "GET /findings?class=<invalid> is rejected" 400 "$status"

  status=$(curl -sS -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $access_token" \
    "$API/api/v1/findings?since=yesterday")
  check_status "GET /findings?since=<unparseable> is rejected" 400 "$status"

  status=$(curl -sS -o /dev/null -w "%{http_code}" "$API/api/v1/findings")
  check_status "GET /findings with no auth" 401 "$status"

  # The capability gate is incident:read, which every builtin role including
  # viewer holds -- so there is no builtin fixture that produces a 403 here,
  # and inventing a custom role just to manufacture one would test the role
  # editor rather than this route. The denial is covered directly in
  # internal/api/findings_test.go's TestFindingsRouteRequiresCapability
  # (grants for an unrelated capability -> 403). What IS checkable here, and
  # matters, is the positive half: the lowest-privilege builtin role can read
  # the findings surface, because a trust surface only a super-admin can open
  # answers nobody's question.
  # Section 4b's viewer was deleted when 4b finished, so this check makes its
  # own, the same way, and removes it again.
  findings_viewer_hash=$(docker run --rm "$HUB_IMAGE" hash-password "smoke-test-password" | tr -d '\r\n')
  docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -v ON_ERROR_STOP=1 >/dev/null <<SQL
DO \$\$
DECLARE org_id text;
BEGIN
  SELECT id INTO org_id FROM organisations LIMIT 1;
  INSERT INTO users (id, tenant_id, email, display_name, password_hash, must_change_password)
  VALUES ('$TEST_VIEWER_ID', org_id, 'smoketest-viewer@localhost', 'Smoke Test Viewer', '$findings_viewer_hash', false);
  INSERT INTO grants (id, tenant_id, principal_type, principal_id, role_id, scope, granted_by)
  VALUES ('grt_smoketest0000000000000', org_id, 'user', '$TEST_VIEWER_ID', 'viewer', '{"type":"AllClusters"}', '$TEST_VIEWER_ID');
END \$\$;
SQL
  findings_viewer_token=$(curl -sS -X POST "$API/api/v1/auth/login" -H "Content-Type: application/json" \
    -d '{"email":"smoketest-viewer@localhost","password":"smoke-test-password"}' | json_field accessToken)
  status=$(curl -sS -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $findings_viewer_token" \
    "$API/api/v1/findings")
  check_status "viewer (incident:read) can read GET /findings" 200 "$status"
  docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -v ON_ERROR_STOP=1 >/dev/null <<SQL
DELETE FROM refresh_tokens WHERE user_id = '$TEST_VIEWER_ID';
DELETE FROM grants WHERE principal_id = '$TEST_VIEWER_ID';
DELETE FROM users WHERE id = '$TEST_VIEWER_ID';
SQL

  rm -rf "$FINDINGS_DIR"
  cleanup_section7e
else
  echo "  SKIP: section 6 did not produce an enrolled cluster with an issued cert -- skipping section 7 entirely"
fi

rm -rf "$CSR_DIR"

echo "== 8. Org settings (GET/PUT /api/v1/admin/settings, org:settings:write) =="
# internal/api/settings.go, internal/settings, migration 000018_org_settings.
# Unlike section 4b/6's throwaway per-run fixtures, org_settings is a
# singleton row that persists across runs of this script on the same stack
# -- so this section explicitly forces a known baseline first (a PUT that
# clears every field) rather than assuming "unconfigured" is still true from
# a previous run, and leaves it cleared again at the end for the same reason.

status=$(curl -sS -o /dev/null -w "%{http_code}" "$API/api/v1/admin/settings")
check_status "GET /admin/settings with no auth" 401 "$status"

status=$(curl -sS -o /dev/null -w "%{http_code}" -X PUT "$API/api/v1/admin/settings" \
  -H "Content-Type: application/json" -d '{}')
check_status "PUT /admin/settings with no auth" 401 "$status"

clear_all_body='{"llm":{"baseUrl":"","model":"","apiKey":""},"notify":{"webhookUrl":""},"automation":{"autoAnalysisEnabled":false,"autoAnalysisSeverities":[]},"retention":{"auditRetentionDays":null,"incidentRetentionDays":null,"findingRetentionDays":null},"detection":{"disabledDetectorIds":[],"stormProtectionMaxNewIncidents":null,"stormProtectionWindowSeconds":null},"autonomy":{"autoApproveMaxRisk":null,"minConfidenceForAutoApprove":null,"requireReversibleForAutoApprove":true},"cost":{"pricePerMillionInputTokens":null,"pricePerMillionCachedTokens":null,"pricePerMillionOutputTokens":null,"dailySpendCeilingUsd":null}}'
clear_resp=$(curl -sS -w "\n%{http_code}" -X PUT "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/json" -d "$clear_all_body")
check_status "PUT /admin/settings clearing every section to its baseline" 200 "$(tail -n1 <<<"$clear_resp")"
[[ "$(tail -n1 <<<"$clear_resp")" == "200" ]] || echo "    response: $(head -n -1 <<<"$clear_resp" | head -c 400)"

settings_resp=$(curl -sS "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token")
verify_settings_baseline=$(python3 - "$settings_resp" <<'PYEOF'
import json, sys
resp = json.loads(sys.argv[1])
EXPECTED_KEYS = {"llm", "notify", "analysis", "automation", "retention", "detection", "autonomy", "cost", "appearance"}
# BUGS.md 113: providerKind/cliRunnerUrl/cliAgent/cliRunnerTokenSet landed
# 2026-08-21 (bf3f624), cliBackendAvailable later still — internal/api/settings.go's
# llmSettingsView has carried all eight of these since, not just the original three.
EXPECTED_LLM_KEYS = {"baseUrl", "model", "apiKeySet", "providerKind", "cliRunnerUrl", "cliAgent", "cliRunnerTokenSet", "cliBackendAvailable"}
EXPECTED_NOTIFY_KEYS = {"webhookConfigured"}
EXPECTED_ANALYSIS_KEYS = {"maxIterations", "timeLimitSeconds", "effectiveMaxIterations", "effectiveTimeLimitSeconds",
                          "retrievalEnabled"}
EXPECTED_AUTOMATION_KEYS = {"autoAnalysisEnabled", "autoAnalysisSeverities"}
EXPECTED_RETENTION_KEYS = {"auditRetentionDays", "incidentRetentionDays", "findingRetentionDays"}
# BUGS.md 113/111: disabledRuleIds is 111's rule-level control alongside
# disabledDetectorIds (internal/api/settings.go's detectionSettingsView) --
# caught live re-running this suite after 111 landed mid-session.
EXPECTED_DETECTION_KEYS = {"disabledDetectorIds", "disabledRuleIds", "stormProtectionMaxNewIncidents", "stormProtectionWindowSeconds"}
# BUGS.md 113: unattendedExecutionEnabled landed 2026-08-22 (6a15c8b) along
# with its blast-radius caps (maxUnattendedPerCluster/maxUnattendedFleetWide/
# unattendedWindowSeconds/unattendedNamespaces) and their Effective* pairs —
# internal/api/settings.go's autonomySettingsView has carried all of these
# since, not just the original three.
EXPECTED_AUTONOMY_KEYS = {
    "autoApproveMaxRisk", "minConfidenceForAutoApprove", "requireReversibleForAutoApprove",
    "effectiveAutoApproveMaxRisk", "effectiveMinConfidenceForAutoApprove",
    "unattendedExecutionEnabled", "maxUnattendedPerCluster", "maxUnattendedFleetWide",
    "unattendedWindowSeconds", "unattendedNamespaces",
    "effectiveMaxUnattendedPerCluster", "effectiveMaxUnattendedFleetWide", "effectiveUnattendedWindowSeconds",
    "effectiveRequireReversibleForAutoApprove",
}
EXPECTED_COST_KEYS = {"pricePerMillionInputTokens", "pricePerMillionCachedTokens", "pricePerMillionOutputTokens",
                      "pricingConfigured", "dailySpendCeilingUsd", "todaySpendUsd",
                      "ceilingBreached", "ceilingEnforceable", "spendCountable"}
results = []
def check(cond, desc, detail=""):
    results.append((bool(cond), desc, detail))
check(EXPECTED_KEYS <= set(resp.keys()), "GET response has every expected section {llm, notify, analysis, automation, retention, detection, autonomy, cost, appearance}", sorted(resp.keys()))
llm = resp.get("llm", {})
notify = resp.get("notify", {})
analysis = resp.get("analysis", {})
automation = resp.get("automation", {})
retention = resp.get("retention", {})
detection = resp.get("detection", {})
autonomy = resp.get("autonomy", {})
check(set(llm.keys()) == EXPECTED_LLM_KEYS, "llm object has exactly {baseUrl, model, apiKeySet, providerKind, cliRunnerUrl, cliAgent, cliRunnerTokenSet, cliBackendAvailable}", sorted(llm.keys()))
check(set(notify.keys()) == EXPECTED_NOTIFY_KEYS, "notify object has exactly {webhookConfigured}", sorted(notify.keys()))
check(set(analysis.keys()) == EXPECTED_ANALYSIS_KEYS,
      "analysis object has exactly {maxIterations, timeLimitSeconds, effectiveMaxIterations, effectiveTimeLimitSeconds}",
      sorted(analysis.keys()))
check(set(automation.keys()) == EXPECTED_AUTOMATION_KEYS,
      "automation object has exactly {autoAnalysisEnabled, autoAnalysisSeverities}", sorted(automation.keys()))
check(set(retention.keys()) == EXPECTED_RETENTION_KEYS,
      "retention object has exactly {auditRetentionDays, incidentRetentionDays, findingRetentionDays}", sorted(retention.keys()))
check(llm.get("apiKeySet") is False, "after clearing, apiKeySet == false", llm.get("apiKeySet"))
check(notify.get("webhookConfigured") is False, "after clearing, webhookConfigured == false", notify.get("webhookConfigured"))
check(llm.get("baseUrl") == "", "after clearing, baseUrl == \"\"", llm.get("baseUrl"))
check(llm.get("model") == "", "after clearing, model == \"\"", llm.get("model"))
check(automation.get("autoAnalysisEnabled") is False, "after clearing, autoAnalysisEnabled == false", automation.get("autoAnalysisEnabled"))
check(automation.get("autoAnalysisSeverities") == [], "after clearing, autoAnalysisSeverities == [] (nothing selected)", automation.get("autoAnalysisSeverities"))
check(retention.get("auditRetentionDays") is None, "shipped default: auditRetentionDays == null (keep forever)", retention.get("auditRetentionDays"))
check(retention.get("incidentRetentionDays") is None, "shipped default: incidentRetentionDays == null (keep forever)", retention.get("incidentRetentionDays"))
check(retention.get("findingRetentionDays") is None, "shipped default: findingRetentionDays == null (keep forever)", retention.get("findingRetentionDays"))
check(set(detection.keys()) == EXPECTED_DETECTION_KEYS,
      "detection object has exactly {disabledDetectorIds, disabledRuleIds, stormProtectionMaxNewIncidents, stormProtectionWindowSeconds}", sorted(detection.keys()))
check(detection.get("disabledDetectorIds") == [], "after clearing, disabledDetectorIds == [] (no detector disabled)", detection.get("disabledDetectorIds"))
check(detection.get("stormProtectionMaxNewIncidents") is None, "shipped default: stormProtectionMaxNewIncidents == null (no ceiling)", detection.get("stormProtectionMaxNewIncidents"))
check(detection.get("stormProtectionWindowSeconds") is None, "shipped default: stormProtectionWindowSeconds == null (no ceiling)", detection.get("stormProtectionWindowSeconds"))
check(set(autonomy.keys()) == EXPECTED_AUTONOMY_KEYS,
      "autonomy object has exactly {autoApproveMaxRisk, minConfidenceForAutoApprove, requireReversibleForAutoApprove, unattendedExecutionEnabled, maxUnattendedPerCluster, maxUnattendedFleetWide, unattendedWindowSeconds, unattendedNamespaces, effectiveMaxUnattendedPerCluster, effectiveMaxUnattendedFleetWide, effectiveUnattendedWindowSeconds, effectiveAutoApproveMaxRisk, effectiveMinConfidenceForAutoApprove}", sorted(autonomy.keys()))
check(autonomy.get("autoApproveMaxRisk") is None, "after clearing, autoApproveMaxRisk == null (not \"never auto-approve\" -- falls back to the hardcoded default below)", autonomy.get("autoApproveMaxRisk"))
check(autonomy.get("minConfidenceForAutoApprove") is None, "after clearing, minConfidenceForAutoApprove == null", autonomy.get("minConfidenceForAutoApprove"))
check(autonomy.get("requireReversibleForAutoApprove") is True, "after clearing, requireReversibleForAutoApprove == true (the column's own NOT NULL DEFAULT)", autonomy.get("requireReversibleForAutoApprove"))
check(autonomy.get("effectiveAutoApproveMaxRisk") == "low", "shipped default: effectiveAutoApproveMaxRisk == \"low\" (internal/orchestrator.DefaultAutonomyPolicy)", autonomy.get("effectiveAutoApproveMaxRisk"))
check(autonomy.get("effectiveMinConfidenceForAutoApprove") == 0.9, "shipped default: effectiveMinConfidenceForAutoApprove == 0.9 (internal/orchestrator.DefaultAutonomyPolicy)", autonomy.get("effectiveMinConfidenceForAutoApprove"))
# analysis is untouched by clear_all_body (no "analysis" key in that PUT), so
# with no DB override its raw fields fall back to whatever
# ARGUS_ANALYSIS_MAX_ITERATIONS/ARGUS_ANALYSIS_TIME_LIMIT_SECONDS this hub
# was started with -- docker-compose.yaml sets both (defaulting to 8/180,
# the same numbers as the hardcoded default, but via the env-var tier, which
# is why the raw fields are non-null here rather than null: null only
# happens when NEITHER the DB row NOR the env var configures it).
check(analysis.get("maxIterations") == 8, "analysis.maxIterations == 8 (this hub's ARGUS_ANALYSIS_MAX_ITERATIONS)", analysis.get("maxIterations"))
check(analysis.get("timeLimitSeconds") == 180, "analysis.timeLimitSeconds == 180 (this hub's ARGUS_ANALYSIS_TIME_LIMIT_SECONDS)", analysis.get("timeLimitSeconds"))
check(analysis.get("effectiveMaxIterations") == 8, "analysis.effectiveMaxIterations == 8", analysis.get("effectiveMaxIterations"))
check(analysis.get("effectiveTimeLimitSeconds") == 180, "analysis.effectiveTimeLimitSeconds == 180", analysis.get("effectiveTimeLimitSeconds"))
cost = resp.get("cost", {})
check(set(cost.keys()) == EXPECTED_COST_KEYS,
      "cost object has exactly {pricePerMillionInputTokens, pricePerMillionCachedTokens, pricePerMillionOutputTokens, pricingConfigured, dailySpendCeilingUsd, todaySpendUsd}",
      sorted(cost.keys()))
check(cost.get("pricePerMillionInputTokens") is None, "after clearing, cost.pricePerMillionInputTokens == null (no pricing configured)", cost.get("pricePerMillionInputTokens"))
check(cost.get("pricePerMillionCachedTokens") is None, "after clearing, cost.pricePerMillionCachedTokens == null", cost.get("pricePerMillionCachedTokens"))
check(cost.get("pricePerMillionOutputTokens") is None, "after clearing, cost.pricePerMillionOutputTokens == null", cost.get("pricePerMillionOutputTokens"))
check(cost.get("pricingConfigured") is False, "after clearing, cost.pricingConfigured == false", cost.get("pricingConfigured"))
check(cost.get("dailySpendCeilingUsd") is None, "shipped default: cost.dailySpendCeilingUsd == null (no ceiling)", cost.get("dailySpendCeilingUsd"))
check(isinstance(cost.get("todaySpendUsd"), (int, float)) and cost.get("todaySpendUsd") >= 0,
      "cost.todaySpendUsd is a real, non-negative number (not asserted == 0: earlier runs of this script against a persistent stack may have already spent real money today)",
      cost.get("todaySpendUsd"))
for passed, desc, detail in results:
    tag = "PASS" if passed else "FAIL"
    suffix = f" (got {detail})" if detail != "" else ""
    print(f"  {tag}: {desc}{suffix}")
PYEOF
)
echo "$verify_settings_baseline"
pass_count=$(echo "$verify_settings_baseline" | grep -c "^  PASS:")
fail_count=$(echo "$verify_settings_baseline" | grep -c "^  FAIL:")
PASS=$((PASS + pass_count))
FAIL=$((FAIL + fail_count))

set_body='{"llm":{"baseUrl":"http://smoketest-llm.invalid/v1","model":"smoketest-model","apiKey":"smoketest-super-secret-key"},"notify":{"webhookUrl":"https://smoketest-webhook.invalid/hook/smoketest-secret-token"}}'
put_resp=$(curl -sS -X PUT "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/json" -d "$set_body")

if echo "$put_resp" | grep -qE "smoketest-super-secret-key|smoketest-secret-token"; then
  echo "  FAIL: PUT response leaked a secret value -- response: $put_resp"
  FAIL=$((FAIL + 1))
else
  echo "  PASS: PUT response never echoes apiKey or webhookUrl's actual value"
  PASS=$((PASS + 1))
fi

verify_after_set=$(python3 - "$put_resp" <<'PYEOF'
import json, sys
resp = json.loads(sys.argv[1])
results = []
def check(cond, desc, detail=""):
    results.append((bool(cond), desc, detail))
# The legacy {llm:{baseUrl,model,apiKey}} shape edits whichever provider is
# ACTIVE, preserving its kind (internal/settings.UpdateActiveProvider). For a
# cli-kind provider — this dev stack's normal state — normalizeForKind
# deliberately blanks BaseURL/Model (providers.go: `out.BaseURL = ""`),
# because a CLI runner has no base URL to set. So these three assertions are
# only meaningful when an api-kind provider is active; asserting them against
# a cli provider reports correct normalisation as a defect.
_kind = resp.get("llm", {}).get("providerKind")
if _kind != "api":
    print("  SKIP: active provider is kind=%r, so baseUrl/model/apiKey are correctly blanked by normalizeForKind — activate an api-kind provider to exercise these" % _kind)
else:
    check(resp.get("llm", {}).get("baseUrl") == "http://smoketest-llm.invalid/v1", "PUT response reflects the new baseUrl", resp.get("llm", {}).get("baseUrl"))
    check(resp.get("llm", {}).get("model") == "smoketest-model", "PUT response reflects the new model", resp.get("llm", {}).get("model"))
    check(resp.get("llm", {}).get("apiKeySet") is True, "PUT response shows apiKeySet == true", resp.get("llm", {}).get("apiKeySet"))
# webhookConfigured is provider-independent, so it is asserted either way.
check(resp.get("notify", {}).get("webhookConfigured") is True, "PUT response shows webhookConfigured == true", resp.get("notify", {}).get("webhookConfigured"))
for passed, desc, detail in results:
    tag = "PASS" if passed else "FAIL"
    suffix = f" (got {detail})" if detail != "" else ""
    print(f"  {tag}: {desc}{suffix}")
PYEOF
)
echo "$verify_after_set"
pass_count=$(echo "$verify_after_set" | grep -c "^  PASS:")
fail_count=$(echo "$verify_after_set" | grep -c "^  FAIL:")
PASS=$((PASS + pass_count))
FAIL=$((FAIL + fail_count))

get_after_set=$(curl -sS "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token")
if echo "$get_after_set" | grep -qE "smoketest-super-secret-key|smoketest-secret-token"; then
  echo "  FAIL: GET response leaked a secret value -- response: $get_after_set"
  FAIL=$((FAIL + 1))
else
  echo "  PASS: GET response never echoes apiKey or webhookUrl's actual value"
  PASS=$((PASS + 1))
fi

# Omitting "apiKey" (present llm section, no apiKey key at all) must leave
# the stored key unchanged; omitting "notify" entirely must leave the
# webhook untouched too -- the pointer/section-presence semantics
# PUT /api/v1/admin/settings exists to get right.
partial_body='{"llm":{"baseUrl":"http://smoketest-llm.invalid/v2","model":"smoketest-model-2"}}'
partial_resp=$(curl -sS -X PUT "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/json" -d "$partial_body")
verify_partial=$(python3 - "$partial_resp" <<'PYEOF'
import json, sys
resp = json.loads(sys.argv[1])
results = []
def check(cond, desc, detail=""):
    results.append((bool(cond), desc, detail))
_kind2 = resp.get("llm", {}).get("providerKind")
if _kind2 != "api":
    print("  SKIP: active provider is kind=%r — baseUrl/apiKey are correctly blanked for a CLI provider, so the partial-PUT assertions below do not apply" % _kind2)
else:
    check(resp.get("llm", {}).get("baseUrl") == "http://smoketest-llm.invalid/v2", "partial PUT (apiKey omitted) still overwrites baseUrl", resp.get("llm", {}).get("baseUrl"))
    check(resp.get("llm", {}).get("apiKeySet") is True, "partial PUT with apiKey OMITTED leaves the previously-set key unchanged (apiKeySet still true)", resp.get("llm", {}).get("apiKeySet"))
check(resp.get("notify", {}).get("webhookConfigured") is True, "PUT with \"notify\" section entirely omitted leaves the webhook untouched (still true)", resp.get("notify", {}).get("webhookConfigured"))
for passed, desc, detail in results:
    tag = "PASS" if passed else "FAIL"
    suffix = f" (got {detail})" if detail != "" else ""
    print(f"  {tag}: {desc}{suffix}")
PYEOF
)
echo "$verify_partial"
pass_count=$(echo "$verify_partial" | grep -c "^  PASS:")
fail_count=$(echo "$verify_partial" | grep -c "^  FAIL:")
PASS=$((PASS + pass_count))
FAIL=$((FAIL + fail_count))

# apiKey present as "" must explicitly clear it, distinct from omitting it above.
clear_key_resp=$(curl -sS -X PUT "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/json" -d '{"llm":{"baseUrl":"http://smoketest-llm.invalid/v2","model":"smoketest-model-2","apiKey":""}}')
clear_key_set=$(echo "$clear_key_resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['llm']['apiKeySet'])")
check_status "apiKey present as \"\" explicitly clears it (apiKeySet -> False)" "False" "$clear_key_set"

echo "== 8a. Per-data-type retention (internal/partition's daily job's config surface) =="
# migration 000021_retention_settings, internal/settings' Retention* fields,
# internal/api/settings.go's "retention" section. NULL/absent must mean
# "keep forever" -- confirmed by the baseline check above already (freshly
# cleared, all three null) -- so this section only needs to prove the
# opt-in round trip and the up-front validation, not re-prove the default.
retention_set_resp=$(curl -sS -X PUT "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/json" \
  -d '{"retention":{"auditRetentionDays":365,"incidentRetentionDays":180,"findingRetentionDays":30}}')
verify_retention_set=$(python3 - "$retention_set_resp" <<'PYEOF'
import json, sys
resp = json.loads(sys.argv[1])
retention = resp.get("retention", {})
results = []
def check(cond, desc, detail=""):
    results.append((bool(cond), desc, detail))
check(retention.get("auditRetentionDays") == 365, "PUT response reflects auditRetentionDays == 365", retention.get("auditRetentionDays"))
check(retention.get("incidentRetentionDays") == 180, "PUT response reflects incidentRetentionDays == 180", retention.get("incidentRetentionDays"))
check(retention.get("findingRetentionDays") == 30, "PUT response reflects findingRetentionDays == 30", retention.get("findingRetentionDays"))
# The other sections are untouched by a PUT that only mentions "retention" --
# apiKey was cleared just above, so apiKeySet must still read false here.
check(resp.get("llm", {}).get("apiKeySet") is False, "PUT with only \"retention\" present leaves llm untouched (apiKeySet still false)", resp.get("llm", {}).get("apiKeySet"))
for passed, desc, detail in results:
    tag = "PASS" if passed else "FAIL"
    suffix = f" (got {detail})" if detail != "" else ""
    print(f"  {tag}: {desc}{suffix}")
PYEOF
)
echo "$verify_retention_set"
pass_count=$(echo "$verify_retention_set" | grep -c "^  PASS:")
fail_count=$(echo "$verify_retention_set" | grep -c "^  FAIL:")
PASS=$((PASS + pass_count))
FAIL=$((FAIL + fail_count))

get_after_retention_set=$(curl -sS "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token")
get_audit_retention=$(echo "$get_after_retention_set" | python3 -c "import sys,json; print(json.load(sys.stdin)['retention']['auditRetentionDays'])")
check_status "GET reflects the retention PUT even after re-fetching (auditRetentionDays == 365)" "365" "$get_audit_retention"

status=$(curl -sS -o /dev/null -w "%{http_code}" -X PUT "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/json" -d '{"retention":{"auditRetentionDays":0}}')
check_status "PUT retention.auditRetentionDays=0 rejected with 400 (non-positive has no valid meaning)" 400 "$status"

status=$(curl -sS -o /dev/null -w "%{http_code}" -X PUT "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/json" -d '{"retention":{"incidentRetentionDays":-5}}')
check_status "PUT retention.incidentRetentionDays=-5 rejected with 400" 400 "$status"

# Clear back to null (keep forever) -- explicit null, not omission, so this
# proves null-clears-an-explicit-override too, not just "never set."
retention_clear_resp=$(curl -sS -X PUT "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/json" \
  -d '{"retention":{"auditRetentionDays":null,"incidentRetentionDays":null,"findingRetentionDays":null}}')
retention_cleared=$(echo "$retention_clear_resp" | python3 -c "import sys,json; r=json.load(sys.stdin)['retention']; print(r['auditRetentionDays'] is None and r['incidentRetentionDays'] is None and r['findingRetentionDays'] is None)")
check_status "explicit null clears all three retention overrides back to keep-forever" "True" "$retention_cleared"

echo "== 8b. Capability denial for org:settings:write (viewer and tenant-admin) =="
# org:settings:write is deliberately super-admin-only -- tenant-admin must be
# denied too, not just viewer (authz/permissions.go's builtinRoleCapabilities
# excludes it from tenant-admin's list on purpose). Reuses section 4b's
# TEST_VIEWER_ID viewer fixture pattern; adds an equivalent tenant-admin one.
TEST_VIEWER_ID="usr_smoketest0000000000000"
viewer_hash=$(docker run --rm "$HUB_IMAGE" hash-password "smoke-test-password" | tr -d '\r\n')
TEST_TENANT_ADMIN_ID="usr_smoketest0000000000002"
tenant_admin_hash=$(docker run --rm "$HUB_IMAGE" hash-password "smoke-test-password" | tr -d '\r\n')
docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -v ON_ERROR_STOP=1 >/dev/null <<SQL
DO \$\$
DECLARE org_id text;
BEGIN
  SELECT id INTO org_id FROM organisations LIMIT 1;
  DELETE FROM refresh_tokens WHERE user_id IN ('$TEST_VIEWER_ID', '$TEST_TENANT_ADMIN_ID');
  DELETE FROM grants WHERE principal_id IN ('$TEST_VIEWER_ID', '$TEST_TENANT_ADMIN_ID');
  DELETE FROM users WHERE id IN ('$TEST_VIEWER_ID', '$TEST_TENANT_ADMIN_ID');
  INSERT INTO users (id, tenant_id, email, display_name, password_hash, must_change_password)
  VALUES ('$TEST_VIEWER_ID', org_id, 'smoketest-viewer@localhost', 'Smoke Test Viewer', '$viewer_hash', false);
  INSERT INTO grants (id, tenant_id, principal_type, principal_id, role_id, scope, granted_by)
  VALUES ('grt_smoketest0000000000000', org_id, 'user', '$TEST_VIEWER_ID', 'viewer', '{"type":"AllClusters"}', '$TEST_VIEWER_ID');
  INSERT INTO users (id, tenant_id, email, display_name, password_hash, must_change_password)
  VALUES ('$TEST_TENANT_ADMIN_ID', org_id, 'smoketest-tenantadmin@localhost', 'Smoke Test Tenant Admin', '$tenant_admin_hash', false);
  INSERT INTO grants (id, tenant_id, principal_type, principal_id, role_id, scope, granted_by)
  VALUES ('grt_smoketest0000000000002', org_id, 'user', '$TEST_TENANT_ADMIN_ID', 'tenant-admin', '{"type":"AllClusters"}', '$TEST_TENANT_ADMIN_ID');
END \$\$;
SQL

viewer_token=$(curl -sS -X POST "$API/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"smoketest-viewer@localhost","password":"smoke-test-password"}' | json_field accessToken)
tenant_admin_token=$(curl -sS -X POST "$API/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"smoketest-tenantadmin@localhost","password":"smoke-test-password"}' | json_field accessToken)

if [[ -n "$viewer_token" && -n "$tenant_admin_token" ]]; then
  echo "  PASS: viewer and tenant-admin smoke-test users can both log in"
  PASS=$((PASS + 1))
else
  echo "  FAIL: viewer and/or tenant-admin smoke-test user could not log in"
  FAIL=$((FAIL + 1))
fi

status=$(curl -sS -o /dev/null -w "%{http_code}" "$API/api/v1/admin/settings" -H "Authorization: Bearer $viewer_token")
check_status "viewer denied GET /admin/settings (403)" 403 "$status"
status=$(curl -sS -o /dev/null -w "%{http_code}" -X PUT "$API/api/v1/admin/settings" \
  -H "Authorization: Bearer $viewer_token" -H "Content-Type: application/json" -d '{}')
check_status "viewer denied PUT /admin/settings (403)" 403 "$status"

status=$(curl -sS -o /dev/null -w "%{http_code}" "$API/api/v1/admin/settings" -H "Authorization: Bearer $tenant_admin_token")
check_status "tenant-admin denied GET /admin/settings (403 -- org:settings:write is super-admin-only)" 403 "$status"
status=$(curl -sS -o /dev/null -w "%{http_code}" -X PUT "$API/api/v1/admin/settings" \
  -H "Authorization: Bearer $tenant_admin_token" -H "Content-Type: application/json" -d '{}')
check_status "tenant-admin denied PUT /admin/settings (403 -- org:settings:write is super-admin-only)" 403 "$status"

status=$(curl -sS -o /dev/null -w "%{http_code}" "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token")
check_status "super-admin still allowed GET /admin/settings (200)" 200 "$status"

# The detection dry-run endpoint (internal/api/detection_dryrun.go) shares
# org:settings:write's exact scope -- same denial pattern as GET/PUT above.
dryrun_body='{"disabledDetectorIds":[],"stormProtectionMaxNewIncidents":null,"stormProtectionWindowSeconds":null}'
status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/detection/dry-run" \
  -H "Authorization: Bearer $viewer_token" -H "Content-Type: application/json" -d "$dryrun_body")
check_status "viewer denied POST /detection/dry-run (403)" 403 "$status"
status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/detection/dry-run" \
  -H "Authorization: Bearer $tenant_admin_token" -H "Content-Type: application/json" -d "$dryrun_body")
check_status "tenant-admin denied POST /detection/dry-run (403 -- org:settings:write is super-admin-only)" 403 "$status"
status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/detection/dry-run" \
  -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" -d "$dryrun_body")
check_status "super-admin allowed POST /detection/dry-run (200)" 200 "$status"

echo "== 8c. Detection settings validation (PUT .../settings' \"detection\" section, internal/api/settings.go's validateDetectionSettingsRequest) =="
# REST-layer validation checks only -- the actual hub-side enforcement (a
# disabled detector's findings never becoming an incident; storm protection
# capping new-incident creation) is exercised end to end over a real tunnel
# in section 7e above, which needs a live enrolled cluster; this section just
# proves the PUT boundary's own up-front rejections, the same style as 8a's
# retention validation checks.
status=$(curl -sS -o /dev/null -w "%{http_code}" -X PUT "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/json" -d '{"detection":{"disabledDetectorIds":["not-a-real-detector"]}}')
check_status "PUT detection.disabledDetectorIds with an unknown detector id rejected with 400" 400 "$status"

status=$(curl -sS -o /dev/null -w "%{http_code}" -X PUT "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/json" -d '{"detection":{"disabledDetectorIds":["k8s-warning-events","k8s-warning-events"]}}')
check_status "PUT detection.disabledDetectorIds with a duplicate entry rejected with 400" 400 "$status"

status=$(curl -sS -o /dev/null -w "%{http_code}" -X PUT "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/json" -d '{"detection":{"stormProtectionMaxNewIncidents":20}}')
check_status "PUT detection.stormProtectionMaxNewIncidents set without stormProtectionWindowSeconds rejected with 400" 400 "$status"

status=$(curl -sS -o /dev/null -w "%{http_code}" -X PUT "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/json" -d '{"detection":{"stormProtectionWindowSeconds":300}}')
check_status "PUT detection.stormProtectionWindowSeconds set without stormProtectionMaxNewIncidents rejected with 400" 400 "$status"

status=$(curl -sS -o /dev/null -w "%{http_code}" -X PUT "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/json" -d '{"detection":{"stormProtectionMaxNewIncidents":0,"stormProtectionWindowSeconds":300}}')
check_status "PUT detection.stormProtectionMaxNewIncidents=0 rejected with 400 (non-positive has no valid meaning)" 400 "$status"

detection_set_resp=$(curl -sS -X PUT "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/json" \
  -d '{"detection":{"disabledDetectorIds":["k8s-pod-conditions"],"stormProtectionMaxNewIncidents":20,"stormProtectionWindowSeconds":300}}')
verify_detection_set=$(python3 - "$detection_set_resp" <<'PYEOF'
import json, sys
resp = json.loads(sys.argv[1])
detection = resp.get("detection", {})
results = []
def check(cond, desc, detail=""):
    results.append((bool(cond), desc, detail))
check(detection.get("disabledDetectorIds") == ["k8s-pod-conditions"],
      "PUT response reflects disabledDetectorIds == [\"k8s-pod-conditions\"]", detection.get("disabledDetectorIds"))
check(detection.get("stormProtectionMaxNewIncidents") == 20, "PUT response reflects stormProtectionMaxNewIncidents == 20", detection.get("stormProtectionMaxNewIncidents"))
check(detection.get("stormProtectionWindowSeconds") == 300, "PUT response reflects stormProtectionWindowSeconds == 300", detection.get("stormProtectionWindowSeconds"))
# The other sections are untouched by a PUT that only mentions "detection".
check(resp.get("llm", {}).get("apiKeySet") is False, "PUT with only \"detection\" present leaves llm untouched (apiKeySet still false)", resp.get("llm", {}).get("apiKeySet"))
for passed, desc, detail in results:
    tag = "PASS" if passed else "FAIL"
    suffix = f" (got {detail})" if detail != "" else ""
    print(f"  {tag}: {desc}{suffix}")
PYEOF
)
echo "$verify_detection_set"
pass_count=$(echo "$verify_detection_set" | grep -c "^  PASS:")
fail_count=$(echo "$verify_detection_set" | grep -c "^  FAIL:")
PASS=$((PASS + pass_count))
FAIL=$((FAIL + fail_count))

get_after_detection_set=$(curl -sS "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token")
get_detection_max=$(echo "$get_after_detection_set" | python3 -c "import sys,json; print(json.load(sys.stdin)['detection']['stormProtectionMaxNewIncidents'])")
check_status "GET reflects the detection PUT even after re-fetching (stormProtectionMaxNewIncidents == 20)" "20" "$get_detection_max"

# POST /api/v1/detection/dry-run (internal/api/detection_dryrun.go) reuses
# validateDetectionSettingsRequest verbatim -- these are the SAME rejections
# 8c's own PUT checks above just proved, now proven again through the
# dry-run endpoint, confirming a candidate PUT would reject is rejected here
# identically, before a single query runs. No live-enrolled-cluster/tunnel
# fixture needed for these -- pure REST-boundary checks, same style as the
# PUT ones above.
status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/detection/dry-run" -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/json" -d '{"disabledDetectorIds":["not-a-real-detector"]}')
check_status "POST /detection/dry-run with an unknown detector id rejected with 400" 400 "$status"

status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/detection/dry-run" -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/json" -d '{"disabledDetectorIds":[],"stormProtectionMaxNewIncidents":20}')
check_status "POST /detection/dry-run with stormProtectionMaxNewIncidents set but no windowSeconds rejected with 400" 400 "$status"

status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/detection/dry-run" -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/json" -d '{"disabledDetectorIds":[],"stormProtectionMaxNewIncidents":0,"stormProtectionWindowSeconds":300}')
check_status "POST /detection/dry-run with stormProtectionMaxNewIncidents=0 rejected with 400" 400 "$status"

# The "days" query parameter is this endpoint's own, not shared with PUT --
# parseDetectionDryRunDays' own bounds (internal/api/detection_dryrun.go).
valid_dryrun_body='{"disabledDetectorIds":[],"stormProtectionMaxNewIncidents":null,"stormProtectionWindowSeconds":null}'
status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/detection/dry-run?days=0" -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/json" -d "$valid_dryrun_body")
check_status "POST /detection/dry-run?days=0 rejected with 400" 400 "$status"

status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/detection/dry-run?days=91" -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/json" -d "$valid_dryrun_body")
check_status "POST /detection/dry-run?days=91 (over the 90-day max) rejected with 400" 400 "$status"

status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/detection/dry-run?days=abc" -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/json" -d "$valid_dryrun_body")
check_status "POST /detection/dry-run?days=abc (non-numeric) rejected with 400" 400 "$status"

status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/detection/dry-run?days=30" -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/json" -d "$valid_dryrun_body")
check_status "POST /detection/dry-run?days=30 (valid, within bounds) accepted" 200 "$status"

echo "== 8d. Autonomy policy validation (PUT .../settings' \"autonomy\" section, internal/api/settings.go's validateAutonomySettingsRequest) =="
# REST-layer validation checks only, same style as 8c's detection checks --
# the actual live-effect-on-the-gate proof (a policy change governing the
# very next AI investigation with no hub restart) needs a real
# analyze-against-a-plan-proposing-model round trip, which happens in
# section 11b3f below (the only place a real incident + fake-llm-server +
# orchestrator + remediation gate are all live at once). STATUS.md §50's own
# flagged gap ("no DB-backed config exists yet") is what this whole section
# and 11b3f together close.
status=$(curl -sS -o /dev/null -w "%{http_code}" -X PUT "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/json" -d '{"autonomy":{"autoApproveMaxRisk":"critical"}}')
check_status "PUT autonomy.autoApproveMaxRisk with an unrecognized risk level rejected with 400" 400 "$status"

status=$(curl -sS -o /dev/null -w "%{http_code}" -X PUT "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/json" -d '{"autonomy":{"autoApproveMaxRisk":"forbidden"}}')
check_status "PUT autonomy.autoApproveMaxRisk=\"forbidden\" rejected with 400 (not modeled by internal/remediation.RiskLevel yet)" 400 "$status"

status=$(curl -sS -o /dev/null -w "%{http_code}" -X PUT "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/json" -d '{"autonomy":{"minConfidenceForAutoApprove":-0.01}}')
check_status "PUT autonomy.minConfidenceForAutoApprove=-0.01 rejected with 400 (outside [0,1])" 400 "$status"

status=$(curl -sS -o /dev/null -w "%{http_code}" -X PUT "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/json" -d '{"autonomy":{"minConfidenceForAutoApprove":1.01}}')
check_status "PUT autonomy.minConfidenceForAutoApprove=1.01 rejected with 400 (outside [0,1])" 400 "$status"

# The single most permissive-LOOKING combination this API accepts on format
# alone -- proves the API boundary validates shape, not "safety," which is
# exactly right: internal/remediation.Evaluate's hard high-risk+irreversible
# floor runs unconditionally regardless of what this section accepts (see
# internal/orchestrator's TestResolveAutonomyPolicyCannotWeakenSafetyFloor
# for the test that proves that end to end, and 11b3f below for the live
# proof that this section's writes genuinely do take effect on the very next
# analysis).
autonomy_set_resp=$(curl -sS -X PUT "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/json" \
  -d '{"autonomy":{"autoApproveMaxRisk":"high","minConfidenceForAutoApprove":0,"requireReversibleForAutoApprove":false}}')
verify_autonomy_set=$(python3 - "$autonomy_set_resp" <<'PYEOF'
import json, sys
resp = json.loads(sys.argv[1])
autonomy = resp.get("autonomy", {})
results = []
def check(cond, desc, detail=""):
    results.append((bool(cond), desc, detail))
check(autonomy.get("autoApproveMaxRisk") == "high", "PUT response reflects autoApproveMaxRisk == \"high\"", autonomy.get("autoApproveMaxRisk"))
check(autonomy.get("minConfidenceForAutoApprove") == 0, "PUT response reflects minConfidenceForAutoApprove == 0", autonomy.get("minConfidenceForAutoApprove"))
check(autonomy.get("requireReversibleForAutoApprove") is False, "PUT response reflects requireReversibleForAutoApprove == false", autonomy.get("requireReversibleForAutoApprove"))
check(autonomy.get("effectiveAutoApproveMaxRisk") == "high", "effectiveAutoApproveMaxRisk == \"high\" (the just-set override, not the hardcoded default)", autonomy.get("effectiveAutoApproveMaxRisk"))
# The other sections are untouched by a PUT that only mentions "autonomy".
check(resp.get("llm", {}).get("apiKeySet") is False, "PUT with only \"autonomy\" present leaves llm untouched (apiKeySet still false)", resp.get("llm", {}).get("apiKeySet"))
for passed, desc, detail in results:
    tag = "PASS" if passed else "FAIL"
    suffix = f" (got {detail})" if detail != "" else ""
    print(f"  {tag}: {desc}{suffix}")
PYEOF
)
echo "$verify_autonomy_set"
pass_count=$(echo "$verify_autonomy_set" | grep -c "^  PASS:")
fail_count=$(echo "$verify_autonomy_set" | grep -c "^  FAIL:")
PASS=$((PASS + pass_count))
FAIL=$((FAIL + fail_count))

# Clear back to null/default (the safe baseline) -- explicit null/true, not
# omission, proving null-clears-an-explicit-override here too.
autonomy_clear_resp=$(curl -sS -X PUT "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/json" \
  -d '{"autonomy":{"autoApproveMaxRisk":null,"minConfidenceForAutoApprove":null,"requireReversibleForAutoApprove":true}}')
autonomy_cleared=$(echo "$autonomy_clear_resp" | python3 -c "import sys,json; a=json.load(sys.stdin)['autonomy']; print(a['autoApproveMaxRisk'] is None and a['minConfidenceForAutoApprove'] is None and a['requireReversibleForAutoApprove'] is True and a['effectiveAutoApproveMaxRisk']=='low')")
check_status "explicit null/true clears both nullable autonomy overrides back to the hardcoded default (effective ceiling back to low)" "True" "$autonomy_cleared"

echo "== 8e. Cost settings validation (PUT .../settings' \"cost\" section, internal/api/settings.go's validateCostSettingsRequest) =="
# REST-layer validation checks only, same style as 8c/8d's checks -- the
# actual live cost_usd computation and daily-spend-ceiling enforcement are
# exercised end to end with a real agent/tunnel/fake-llm-server in section
# 15 below, which needs a live enrolled cluster; this section just proves
# the PUT boundary's own up-front rejections.
status=$(curl -sS -o /dev/null -w "%{http_code}" -X PUT "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/json" -d '{"cost":{"pricePerMillionInputTokens":2}}')
check_status "PUT cost with only pricePerMillionInputTokens set (partial price table) rejected with 400" 400 "$status"

status=$(curl -sS -o /dev/null -w "%{http_code}" -X PUT "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/json" -d '{"cost":{"pricePerMillionInputTokens":2,"pricePerMillionCachedTokens":0.2}}')
check_status "PUT cost with two of three price fields set (still partial) rejected with 400" 400 "$status"

status=$(curl -sS -o /dev/null -w "%{http_code}" -X PUT "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/json" -d '{"cost":{"pricePerMillionInputTokens":-1,"pricePerMillionCachedTokens":0,"pricePerMillionOutputTokens":0}}')
check_status "PUT cost with a negative price rejected with 400" 400 "$status"

status=$(curl -sS -o /dev/null -w "%{http_code}" -X PUT "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/json" -d '{"cost":{"dailySpendCeilingUsd":0}}')
check_status "PUT cost.dailySpendCeilingUsd == 0 rejected with 400 (non-positive has no valid meaning)" 400 "$status"

status=$(curl -sS -o /dev/null -w "%{http_code}" -X PUT "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/json" -d '{"cost":{"dailySpendCeilingUsd":-5}}')
check_status "PUT cost.dailySpendCeilingUsd < 0 rejected with 400" 400 "$status"

cost_set_resp=$(curl -sS -X PUT "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/json" \
  -d '{"cost":{"pricePerMillionInputTokens":2,"pricePerMillionCachedTokens":0.2,"pricePerMillionOutputTokens":10,"dailySpendCeilingUsd":5}}')
verify_cost_set=$(python3 - "$cost_set_resp" <<'PYEOF'
import json, sys
resp = json.loads(sys.argv[1])
cost = resp.get("cost", {})
results = []
def check(cond, desc, detail=""):
    results.append((bool(cond), desc, detail))
check(cost.get("pricePerMillionInputTokens") == 2, "PUT response reflects pricePerMillionInputTokens == 2", cost.get("pricePerMillionInputTokens"))
check(cost.get("pricePerMillionCachedTokens") == 0.2, "PUT response reflects pricePerMillionCachedTokens == 0.2", cost.get("pricePerMillionCachedTokens"))
check(cost.get("pricePerMillionOutputTokens") == 10, "PUT response reflects pricePerMillionOutputTokens == 10", cost.get("pricePerMillionOutputTokens"))
check(cost.get("pricingConfigured") is True, "PUT response shows pricingConfigured == true once all three are set", cost.get("pricingConfigured"))
check(cost.get("dailySpendCeilingUsd") == 5, "PUT response reflects dailySpendCeilingUsd == 5", cost.get("dailySpendCeilingUsd"))
# The other sections are untouched by a PUT that only mentions "cost".
check(resp.get("llm", {}).get("apiKeySet") is False, "PUT with only \"cost\" present leaves llm untouched (apiKeySet still false)", resp.get("llm", {}).get("apiKeySet"))
for passed, desc, detail in results:
    tag = "PASS" if passed else "FAIL"
    suffix = f" (got {detail})" if detail != "" else ""
    print(f"  {tag}: {desc}{suffix}")
PYEOF
)
echo "$verify_cost_set"
pass_count=$(echo "$verify_cost_set" | grep -c "^  PASS:")
fail_count=$(echo "$verify_cost_set" | grep -c "^  FAIL:")
PASS=$((PASS + pass_count))
FAIL=$((FAIL + fail_count))

# All-null clears pricing/ceiling back to "not configured"/"no ceiling" --
# same explicit-null-clears-an-override proof as autonomy's above.
cost_clear_resp=$(curl -sS -X PUT "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/json" \
  -d '{"cost":{"pricePerMillionInputTokens":null,"pricePerMillionCachedTokens":null,"pricePerMillionOutputTokens":null,"dailySpendCeilingUsd":null}}')
cost_cleared=$(echo "$cost_clear_resp" | python3 -c "import sys,json; c=json.load(sys.stdin)['cost']; print(c['pricePerMillionInputTokens'] is None and c['pricingConfigured'] is False and c['dailySpendCeilingUsd'] is None)")
check_status "explicit null for all four cost fields clears pricing/ceiling back to not-configured/no-ceiling" "True" "$cost_cleared"

# GET /api/v1/spend/today (spend.go) is gated on spend:read alone --
# deliberately narrower than org:settings:write above. viewer does NOT hold
# spend:read (authz-spec §5's matrix); tenant-admin does. Reuses this
# section's still-live viewer_token/tenant_admin_token fixtures from 8b,
# ahead of their cleanup just below.
status=$(curl -sS -o /dev/null -w "%{http_code}" "$API/api/v1/spend/today" -H "Authorization: Bearer $viewer_token")
check_status "viewer denied spend:read on GET /spend/today (403)" 403 "$status"
status=$(curl -sS -o /dev/null -w "%{http_code}" "$API/api/v1/spend/today" -H "Authorization: Bearer $tenant_admin_token")
check_status "tenant-admin (holds spend:read, unlike org:settings:write above) can read GET /spend/today (200)" 200 "$status"
status=$(curl -sS -o /dev/null -w "%{http_code}" "$API/api/v1/spend/today" -H "Authorization: Bearer $access_token")
check_status "super-admin can read GET /spend/today (200)" 200 "$status"

# Cleanup -- these are throwaway test fixtures, not application state.
docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -v ON_ERROR_STOP=1 >/dev/null <<SQL
DELETE FROM refresh_tokens WHERE user_id IN ('$TEST_VIEWER_ID', '$TEST_TENANT_ADMIN_ID');
DELETE FROM grants WHERE principal_id IN ('$TEST_VIEWER_ID', '$TEST_TENANT_ADMIN_ID');
DELETE FROM users WHERE id IN ('$TEST_VIEWER_ID', '$TEST_TENANT_ADMIN_ID');
SQL

# Reset org_settings back to fully cleared -- unlike section 4b/6's fixtures,
# this is a real singleton row, not a disposable one, so it's left in a
# known, empty state for whatever runs against this stack next, exactly as
# this section found it before its own baseline-forcing PUT above ran.
curl -sS -X PUT "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/json" -d "$clear_all_body" >/dev/null

echo "== 9. Audit log (GET /api/v1/audit-events, audit:read, super-admin-only) =="
# internal/api/audit.go -- read-only, additive to (not a replacement for)
# argusctl's independent hash-chain verification tool. Reuses events every
# earlier section already generated (login, enrollment-token issuance,
# cluster accept, settings PUTs, capability denials) rather than manufacturing
# fresh ones just for this section -- by this point there are already dozens
# of real rows to filter/paginate over.

status=$(curl -sS -o /dev/null -w "%{http_code}" "$API/api/v1/audit-events")
check_status "GET /audit-events with no auth" 401 "$status"

status=$(curl -sS -o /dev/null -w "%{http_code}" "$API/api/v1/audit-events" \
  -H "Authorization: Bearer $access_token")
check_status "GET /audit-events as super-admin (audit:read)" 200 "$status"

audit_resp=$(curl -sS "$API/api/v1/audit-events" -H "Authorization: Bearer $access_token")
verify_audit_list=$(python3 - "$audit_resp" <<'PYEOF'
import json, sys
resp = json.loads(sys.argv[1])
results = []
def check(cond, desc, detail=""):
    results.append((bool(cond), desc, detail))
events = resp.get("auditEvents", [])
check(isinstance(events, list) and len(events) > 0,
      "GET /audit-events returns at least one event (earlier sections already generated real writes)", len(events))
# BUGS.md 113: "action" (internal/api/audit.go's auditEventSummary) is a
# real field of every list element, derived server-side from
# capability/details for the events that have no capability of their own —
# this set was missing it.
EXPECTED_KEYS = {
    "id", "occurredAt", "actorId", "actorEmail", "actorDisplayName",
    "actorAuthMethod", "sourceIp", "capability", "clusterId",
    "clusterDisplayName", "outcome", "action", "detailsSummary",
}
if events:
    check(set(events[0].keys()) == EXPECTED_KEYS, "audit event list element has exactly the specified keys", sorted(events[0].keys()))
    ordering_ok = all(events[i]["occurredAt"] >= events[i + 1]["occurredAt"] for i in range(len(events) - 1))
    check(ordering_ok, "GET /audit-events is ordered by occurredAt DESC (most recent first)")
    check(all(e.get("outcome") in ("success", "denied", "error") for e in events),
          "every event's outcome is one of the three documented values")
for passed, desc, detail in results:
    tag = "PASS" if passed else "FAIL"
    suffix = f" (got {detail})" if detail != "" else ""
    print(f"  {tag}: {desc}{suffix}")
PYEOF
)
echo "$verify_audit_list"
pass_count=$(echo "$verify_audit_list" | grep -c "^  PASS:")
fail_count=$(echo "$verify_audit_list" | grep -c "^  FAIL:")
PASS=$((PASS + pass_count))
FAIL=$((FAIL + fail_count))

echo "== 9a. A known write (section 8's org:settings:write PUTs) shows up via ?capability= =="
settings_audit_resp=$(curl -sS "$API/api/v1/audit-events?capability=org%3Asettings%3Awrite" \
  -H "Authorization: Bearer $access_token")
verify_settings_audit=$(python3 - "$settings_audit_resp" <<'PYEOF'
import json, sys
resp = json.loads(sys.argv[1])
results = []
def check(cond, desc, detail=""):
    results.append((bool(cond), desc, detail))
events = resp.get("auditEvents", [])
check(len(events) > 0, "?capability=org:settings:write returns at least one event (section 8's PUTs)", len(events))
check(all(e.get("capability") == "org:settings:write" for e in events),
      "every returned event actually has capability == org:settings:write")
check(any(e.get("outcome") == "success" for e in events), "at least one of section 8's settings writes recorded as outcome == success")
for passed, desc, detail in results:
    tag = "PASS" if passed else "FAIL"
    suffix = f" (got {detail})" if detail != "" else ""
    print(f"  {tag}: {desc}{suffix}")
PYEOF
)
echo "$verify_settings_audit"
pass_count=$(echo "$verify_settings_audit" | grep -c "^  PASS:")
fail_count=$(echo "$verify_settings_audit" | grep -c "^  FAIL:")
PASS=$((PASS + pass_count))
FAIL=$((FAIL + fail_count))

if [[ -n "${cluster_id:-}" ]]; then
  echo "== 9b. A known write (section 6's cluster:accept for this run's cluster) shows up via ?capability=, and its clusterId/clusterDisplayName resolve =="
  accept_audit_resp=$(curl -sS "$API/api/v1/audit-events?capability=cluster%3Aaccept" \
    -H "Authorization: Bearer $access_token")
  verify_accept_audit=$(python3 - "$accept_audit_resp" "$cluster_id" <<'PYEOF'
import json, sys
resp = json.loads(sys.argv[1])
cluster_id = sys.argv[2]
results = []
def check(cond, desc, detail=""):
    results.append((bool(cond), desc, detail))
events = resp.get("auditEvents", [])
matching = [e for e in events if e.get("clusterId") == cluster_id]
check(len(matching) >= 1, "?capability=cluster:accept includes this run's own accept event", len(matching))
if matching:
    check(matching[0].get("outcome") == "success", "that event's outcome == success", matching[0].get("outcome"))
    check(matching[0].get("clusterDisplayName") == "smoketest-cluster",
          "that event's clusterDisplayName resolves via the LEFT JOIN to clusters", matching[0].get("clusterDisplayName"))
for passed, desc, detail in results:
    tag = "PASS" if passed else "FAIL"
    suffix = f" (got {detail})" if detail != "" else ""
    print(f"  {tag}: {desc}{suffix}")
PYEOF
)
  echo "$verify_accept_audit"
  pass_count=$(echo "$verify_accept_audit" | grep -c "^  PASS:")
  fail_count=$(echo "$verify_accept_audit" | grep -c "^  FAIL:")
  PASS=$((PASS + pass_count))
  FAIL=$((FAIL + fail_count))
fi

echo "== 9c. ?since=/?until= actually narrow results =="
far_future=$(date -u -d "+1 hour" +%Y-%m-%dT%H:%M:%SZ)
since_future_resp=$(curl -sS "$API/api/v1/audit-events?since=$far_future" -H "Authorization: Bearer $access_token")
verify_since_future=$(python3 - "$since_future_resp" <<'PYEOF'
import json, sys
resp = json.loads(sys.argv[1])
results = []
def check(cond, desc, detail=""):
    results.append((bool(cond), desc, detail))
events = resp.get("auditEvents", [])
check(len(events) == 0, "?since=<one hour in the future> returns zero events", len(events))
for passed, desc, detail in results:
    tag = "PASS" if passed else "FAIL"
    suffix = f" (got {detail})" if detail != "" else ""
    print(f"  {tag}: {desc}{suffix}")
PYEOF
)
echo "$verify_since_future"
pass_count=$(echo "$verify_since_future" | grep -c "^  PASS:")
fail_count=$(echo "$verify_since_future" | grep -c "^  FAIL:")
PASS=$((PASS + pass_count))
FAIL=$((FAIL + fail_count))

until_past_resp=$(curl -sS "$API/api/v1/audit-events?until=2000-01-01T00%3A00%3A00Z" \
  -H "Authorization: Bearer $access_token")
verify_until_past=$(python3 - "$until_past_resp" <<'PYEOF'
import json, sys
resp = json.loads(sys.argv[1])
results = []
def check(cond, desc, detail=""):
    results.append((bool(cond), desc, detail))
events = resp.get("auditEvents", [])
check(len(events) == 0, "?until=2000-01-01 (long before this run started) returns zero events", len(events))
for passed, desc, detail in results:
    tag = "PASS" if passed else "FAIL"
    suffix = f" (got {detail})" if detail != "" else ""
    print(f"  {tag}: {desc}{suffix}")
PYEOF
)
echo "$verify_until_past"
pass_count=$(echo "$verify_until_past" | grep -c "^  PASS:")
fail_count=$(echo "$verify_until_past" | grep -c "^  FAIL:")
PASS=$((PASS + pass_count))
FAIL=$((FAIL + fail_count))

echo "== 9d. ?actor= narrows to a specific actor =="
actor_filtered=$(curl -sS "$API/api/v1/audit-events?actor=admin%40localhost" \
  -H "Authorization: Bearer $access_token")
verify_actor_filter=$(python3 - "$actor_filtered" "$audit_resp" <<'PYEOF'
import json, sys
resp = json.loads(sys.argv[1])
unfiltered = json.loads(sys.argv[2])
results = []
def check(cond, desc, detail=""):
    results.append((bool(cond), desc, detail))
events = resp.get("auditEvents", [])
check(len(events) > 0, "?actor=admin@localhost returns at least one event", len(events))
check(all((e.get("actorEmail") or "").lower() == "admin@localhost" for e in events),
      "every returned event's actorEmail really matches admin@localhost")
if len(unfiltered.get("auditEvents", [])) > len(events):
    check(True, "?actor= filter actually narrows results (unfiltered list has other actors' events too)",
          f"{len(events)} of {len(unfiltered.get('auditEvents', []))}")
else:
    print("  NOTE: unfiltered /audit-events currently returns only admin@localhost's own events in this run "
          "-- correctness is verified above, but this run can't demonstrate the filter shrinking the result set.")
for passed, desc, detail in results:
    tag = "PASS" if passed else "FAIL"
    suffix = f" (got {detail})" if detail != "" else ""
    print(f"  {tag}: {desc}{suffix}")
PYEOF
)
echo "$verify_actor_filter"
pass_count=$(echo "$verify_actor_filter" | grep -c "^  PASS:")
fail_count=$(echo "$verify_actor_filter" | grep -c "^  FAIL:")
PASS=$((PASS + pass_count))
FAIL=$((FAIL + fail_count))

echo "== 9e. Pagination (limit/cursor keyset scheme) =="
page1=$(curl -sS "$API/api/v1/audit-events?limit=1" -H "Authorization: Bearer $access_token")
verify_page1=$(python3 - "$page1" <<'PYEOF'
import json, sys
resp = json.loads(sys.argv[1])
results = []
def check(cond, desc, detail=""):
    results.append((bool(cond), desc, detail))
events = resp.get("auditEvents", [])
check(len(events) == 1, "?limit=1 returns exactly one event", len(events))
check(bool(resp.get("nextCursor")), "a full page (limit reached) includes a non-empty nextCursor")
for passed, desc, detail in results:
    tag = "PASS" if passed else "FAIL"
    suffix = f" (got {detail})" if detail != "" else ""
    print(f"  {tag}: {desc}{suffix}")
print(f"FIRST_ID={events[0]['id'] if events else ''}")
print(f"NEXT_CURSOR={resp.get('nextCursor', '')}")
PYEOF
)
echo "$verify_page1" | grep -E "^  (PASS|FAIL):"
pass_count=$(echo "$verify_page1" | grep -c "^  PASS:")
fail_count=$(echo "$verify_page1" | grep -c "^  FAIL:")
PASS=$((PASS + pass_count))
FAIL=$((FAIL + fail_count))
first_id=$(echo "$verify_page1" | grep "^FIRST_ID=" | cut -d= -f2-)
next_cursor=$(echo "$verify_page1" | grep "^NEXT_CURSOR=" | cut -d= -f2-)

if [[ -n "$next_cursor" ]]; then
  # next_cursor is already URL-safe as-is: it's base64.RawURLEncoding on the
  # Go side (internal/api/audit.go's encodeAuditCursor), whose alphabet is
  # exactly [A-Za-z0-9-_] with no padding -- nothing here needs percent-
  # encoding before going into a query string.
  page2=$(curl -sS "$API/api/v1/audit-events?limit=1&cursor=${next_cursor}" \
    -H "Authorization: Bearer $access_token")
  verify_page2=$(python3 - "$page2" "$first_id" <<'PYEOF'
import json, sys
resp = json.loads(sys.argv[1])
first_id = sys.argv[2]
results = []
def check(cond, desc, detail=""):
    results.append((bool(cond), desc, detail))
events = resp.get("auditEvents", [])
check(len(events) == 1, "page 2 (?cursor=) also returns exactly one event", len(events))
if events:
    check(events[0]["id"] != first_id, "page 2's event is a genuinely different row from page 1's", events[0]["id"])
for passed, desc, detail in results:
    tag = "PASS" if passed else "FAIL"
    suffix = f" (got {detail})" if detail != "" else ""
    print(f"  {tag}: {desc}{suffix}")
PYEOF
)
  echo "$verify_page2"
  pass_count=$(echo "$verify_page2" | grep -c "^  PASS:")
  fail_count=$(echo "$verify_page2" | grep -c "^  FAIL:")
  PASS=$((PASS + pass_count))
  FAIL=$((FAIL + fail_count))
else
  echo "  FAIL: page 1 returned no nextCursor -- cannot test page 2"
  FAIL=$((FAIL + 1))
fi

echo "== 9f. GET /api/v1/audit-events/{id} (full record) =="
if [[ -n "$first_id" ]]; then
  status=$(curl -sS -o /dev/null -w "%{http_code}" "$API/api/v1/audit-events/$first_id")
  check_status "GET /audit-events/{id} with no auth" 401 "$status"

  status=$(curl -sS -o /dev/null -w "%{http_code}" "$API/api/v1/audit-events/not-a-real-audit-event-id" \
    -H "Authorization: Bearer $access_token")
  check_status "GET /audit-events/{id} with an unrecognized id" 404 "$status"

  detail_resp=$(curl -sS "$API/api/v1/audit-events/$first_id" -H "Authorization: Bearer $access_token")
  verify_detail=$(python3 - "$detail_resp" "$first_id" <<'PYEOF'
import json, sys
detail = json.loads(sys.argv[1])
first_id = sys.argv[2]
results = []
def check(cond, desc, detail_val=""):
    results.append((bool(cond), desc, detail_val))
# BUGS.md 113: same missing "action" as the list-element set above --
# auditEventDetail embeds auditEventSummary in full.
EXPECTED_KEYS = {
    "id", "occurredAt", "actorId", "actorEmail", "actorDisplayName",
    "actorAuthMethod", "sourceIp", "capability", "clusterId",
    "clusterDisplayName", "outcome", "action", "detailsSummary",
    "scope", "details", "prevHash", "hash",
}
check(set(detail.keys()) == EXPECTED_KEYS, "audit event detail has exactly the specified keys", sorted(detail.keys()))
check(detail.get("id") == first_id, "detail id matches the requested id", detail.get("id"))
check(bool(detail.get("hash")) and bool(detail.get("prevHash")),
      "detail includes this row's own non-empty hash and prevHash")
for passed, desc, detail_val in results:
    tag = "PASS" if passed else "FAIL"
    suffix = f" (got {detail_val})" if detail_val != "" else ""
    print(f"  {tag}: {desc}{suffix}")
PYEOF
)
  echo "$verify_detail"
  pass_count=$(echo "$verify_detail" | grep -c "^  PASS:")
  fail_count=$(echo "$verify_detail" | grep -c "^  FAIL:")
  PASS=$((PASS + pass_count))
  FAIL=$((FAIL + fail_count))
else
  echo "  FAIL: no audit event id available from section 9e -- skipping detail-endpoint checks"
  FAIL=$((FAIL + 1))
fi

echo "== 9g. Capability denial for audit:read (viewer AND tenant-admin -- super-admin only) =="
# audit:read is deliberately excluded even from tenant-admin (unlike most
# other capabilities, which tenant-admin does hold) -- authz/permissions.go's
# explicit comment on that exclusion, mirrored in this check.
TEST_VIEWER_ID="usr_smoketest0000000000000"
viewer_hash=$(docker run --rm "$HUB_IMAGE" hash-password "smoke-test-password" | tr -d '\r\n')
TEST_TENANT_ADMIN_ID="usr_smoketest0000000000002"
tenant_admin_hash=$(docker run --rm "$HUB_IMAGE" hash-password "smoke-test-password" | tr -d '\r\n')
docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -v ON_ERROR_STOP=1 >/dev/null <<SQL
DO \$\$
DECLARE org_id text;
BEGIN
  SELECT id INTO org_id FROM organisations LIMIT 1;
  DELETE FROM refresh_tokens WHERE user_id IN ('$TEST_VIEWER_ID', '$TEST_TENANT_ADMIN_ID');
  DELETE FROM grants WHERE principal_id IN ('$TEST_VIEWER_ID', '$TEST_TENANT_ADMIN_ID');
  DELETE FROM users WHERE id IN ('$TEST_VIEWER_ID', '$TEST_TENANT_ADMIN_ID');
  INSERT INTO users (id, tenant_id, email, display_name, password_hash, must_change_password)
  VALUES ('$TEST_VIEWER_ID', org_id, 'smoketest-viewer@localhost', 'Smoke Test Viewer', '$viewer_hash', false);
  INSERT INTO grants (id, tenant_id, principal_type, principal_id, role_id, scope, granted_by)
  VALUES ('grt_smoketest0000000000000', org_id, 'user', '$TEST_VIEWER_ID', 'viewer', '{"type":"AllClusters"}', '$TEST_VIEWER_ID');
  INSERT INTO users (id, tenant_id, email, display_name, password_hash, must_change_password)
  VALUES ('$TEST_TENANT_ADMIN_ID', org_id, 'smoketest-tenantadmin@localhost', 'Smoke Test Tenant Admin', '$tenant_admin_hash', false);
  INSERT INTO grants (id, tenant_id, principal_type, principal_id, role_id, scope, granted_by)
  VALUES ('grt_smoketest0000000000002', org_id, 'user', '$TEST_TENANT_ADMIN_ID', 'tenant-admin', '{"type":"AllClusters"}', '$TEST_TENANT_ADMIN_ID');
END \$\$;
SQL

viewer_token=$(curl -sS -X POST "$API/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"smoketest-viewer@localhost","password":"smoke-test-password"}' | json_field accessToken)
tenant_admin_token=$(curl -sS -X POST "$API/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"smoketest-tenantadmin@localhost","password":"smoke-test-password"}' | json_field accessToken)

if [[ -n "$viewer_token" && -n "$tenant_admin_token" ]]; then
  echo "  PASS: viewer and tenant-admin smoke-test users can both log in"
  PASS=$((PASS + 1))
else
  echo "  FAIL: viewer and/or tenant-admin smoke-test user could not log in"
  FAIL=$((FAIL + 1))
fi

status=$(curl -sS -o /dev/null -w "%{http_code}" "$API/api/v1/audit-events" -H "Authorization: Bearer $viewer_token")
check_status "viewer denied GET /audit-events (403)" 403 "$status"
status=$(curl -sS -o /dev/null -w "%{http_code}" "$API/api/v1/audit-events" -H "Authorization: Bearer $tenant_admin_token")
check_status "tenant-admin denied GET /audit-events (403 -- audit:read is super-admin-only, unlike tenant-admin's other capabilities)" 403 "$status"

if [[ -n "$first_id" ]]; then
  status=$(curl -sS -o /dev/null -w "%{http_code}" "$API/api/v1/audit-events/$first_id" -H "Authorization: Bearer $viewer_token")
  check_status "viewer denied GET /audit-events/{id} (403)" 403 "$status"
  status=$(curl -sS -o /dev/null -w "%{http_code}" "$API/api/v1/audit-events/$first_id" -H "Authorization: Bearer $tenant_admin_token")
  check_status "tenant-admin denied GET /audit-events/{id} (403)" 403 "$status"
fi

status=$(curl -sS -o /dev/null -w "%{http_code}" "$API/api/v1/audit-events" -H "Authorization: Bearer $access_token")
check_status "super-admin still allowed GET /audit-events (200)" 200 "$status"

echo "== 9h. GET /api/v1/audit-events/export (audit:read, super-admin-only, ?format=csv|json) =="
# internal/api/audit_export.go -- BACKLOG.md S3's "audit export" slice.
# Same capability as the rest of this table's surface (9f/9g above), so the
# no-auth/capability-denial checks below reuse the exact viewer/tenant-admin
# fixtures 9g already logged in, before this section's own cleanup runs.
export_since=$(date -u -d "-1 day" +%Y-%m-%dT%H:%M:%SZ)
export_until=$(date -u -d "+1 hour" +%Y-%m-%dT%H:%M:%SZ)

status=$(curl -sS -o /dev/null -w "%{http_code}" \
  "$API/api/v1/audit-events/export?since=$export_since&until=$export_until")
check_status "GET /audit-events/export with no auth" 401 "$status"

status=$(curl -sS -o /dev/null -w "%{http_code}" \
  "$API/api/v1/audit-events/export?since=$export_since&until=$export_until" \
  -H "Authorization: Bearer $viewer_token")
check_status "viewer denied GET /audit-events/export (403)" 403 "$status"
status=$(curl -sS -o /dev/null -w "%{http_code}" \
  "$API/api/v1/audit-events/export?since=$export_since&until=$export_until" \
  -H "Authorization: Bearer $tenant_admin_token")
check_status "tenant-admin denied GET /audit-events/export (403 -- audit:read is super-admin-only)" 403 "$status"

status=$(curl -sS -o /dev/null -w "%{http_code}" \
  "$API/api/v1/audit-events/export?since=$export_since&until=$export_until" \
  -H "Authorization: Bearer $access_token")
check_status "super-admin allowed GET /audit-events/export with default format (200)" 200 "$status"

export_json_resp=$(curl -sS -D /tmp/export_json_headers.$$ \
  "$API/api/v1/audit-events/export?format=json&since=$export_since&until=$export_until" \
  -H "Authorization: Bearer $access_token")
# BUGS.md 113: a 25-hour export window on a long-lived, actively-used dev
# stack can be big enough to hit ARG_MAX as a literal argv string (confirmed
# live) -- same json_arg_file fix as the /incidents checks above.
export_json_resp_file=$(json_arg_file "$export_json_resp")
verify_export_json=$(python3 - "$export_json_resp_file" <<'PYEOF'
import json, sys
results = []
def check(cond, desc, detail=""):
    results.append((bool(cond), desc, detail))
try:
    with open(sys.argv[1]) as f:
        rows = json.load(f)
    check(isinstance(rows, list), "?format=json response is a JSON array")
    check(len(rows) >= 1, "export contains at least one row", len(rows) if isinstance(rows, list) else "n/a")
    if isinstance(rows, list) and rows:
        EXPECTED_KEYS = {
            "id", "occurredAt", "actorId", "actorEmail", "actorDisplayName",
            "actorAuthMethod", "sourceIp", "capability", "scope", "clusterId",
            "clusterDisplayName", "outcome", "action", "detailsSummary",
            "details", "prevHash", "hash",
        }
        check(set(rows[0].keys()) == EXPECTED_KEYS, "export row has exactly the specified keys", sorted(rows[0].keys()))
except Exception as e:
    check(False, f"?format=json response parses as JSON: {e}")
for passed, desc, detail in results:
    tag = "PASS" if passed else "FAIL"
    suffix = f" (got {detail})" if detail != "" else ""
    print(f"  {tag}: {desc}{suffix}")
PYEOF
)
rm -f "$export_json_resp_file"
echo "$verify_export_json"
pass_count=$(echo "$verify_export_json" | grep -c "^  PASS:")
fail_count=$(echo "$verify_export_json" | grep -c "^  FAIL:")
PASS=$((PASS + pass_count))
FAIL=$((FAIL + fail_count))
if grep -qi '^Content-Disposition: attachment.*\.json' /tmp/export_json_headers.$$; then
  echo "  PASS: ?format=json response has an attachment Content-Disposition with a .json filename"
  PASS=$((PASS + 1))
else
  echo "  FAIL: ?format=json response missing the expected attachment Content-Disposition"
  FAIL=$((FAIL + 1))
fi
rm -f /tmp/export_json_headers.$$

export_csv_resp=$(curl -sS -D /tmp/export_csv_headers.$$ \
  "$API/api/v1/audit-events/export?format=csv&since=$export_since&until=$export_until" \
  -H "Authorization: Bearer $access_token")
export_csv_header_line=$(echo "$export_csv_resp" | head -n1)
if [[ "$export_csv_header_line" == "id,occurredAt,actorId,actorEmail,actorDisplayName,actorAuthMethod,sourceIp,capability,scope,clusterId,clusterDisplayName,outcome,action,detailsSummary,details,prevHash,hash" ]]; then
  echo "  PASS: ?format=csv response's header row has exactly the specified columns"
  PASS=$((PASS + 1))
else
  echo "  FAIL: ?format=csv header row = '$export_csv_header_line'"
  FAIL=$((FAIL + 1))
fi
export_csv_row_count=$(echo "$export_csv_resp" | tail -n +2 | grep -c .)
if [[ "$export_csv_row_count" -ge 1 ]]; then
  echo "  PASS: ?format=csv response has at least one data row ($export_csv_row_count)"
  PASS=$((PASS + 1))
else
  echo "  FAIL: ?format=csv response has no data rows"
  FAIL=$((FAIL + 1))
fi
if grep -qi '^Content-Type: text/csv' /tmp/export_csv_headers.$$; then
  echo "  PASS: ?format=csv response has a text/csv Content-Type"
  PASS=$((PASS + 1))
else
  echo "  FAIL: ?format=csv response missing the expected Content-Type"
  FAIL=$((FAIL + 1))
fi
rm -f /tmp/export_csv_headers.$$

status=$(curl -sS -o /dev/null -w "%{http_code}" \
  "$API/api/v1/audit-events/export?format=json&since=$export_since" \
  -H "Authorization: Bearer $access_token")
check_status "export missing ?until= is rejected (400 -- since/until are both required, unlike the paginated list endpoint)" 400 "$status"

too_wide_since=$(date -u -d "-100 days" +%Y-%m-%dT%H:%M:%SZ)
status=$(curl -sS -o /dev/null -w "%{http_code}" \
  "$API/api/v1/audit-events/export?format=json&since=$too_wide_since&until=$export_until" \
  -H "Authorization: Bearer $access_token")
check_status "export range wider than 92 days is rejected (400, not silently truncated)" 400 "$status"

status=$(curl -sS -o /dev/null -w "%{http_code}" \
  "$API/api/v1/audit-events/export?format=xml&since=$export_since&until=$export_until" \
  -H "Authorization: Bearer $access_token")
check_status "export with an unrecognized ?format= is rejected (400)" 400 "$status"

# Cleanup -- throwaway test fixtures, not application state.
docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -v ON_ERROR_STOP=1 >/dev/null <<SQL
DELETE FROM refresh_tokens WHERE user_id IN ('$TEST_VIEWER_ID', '$TEST_TENANT_ADMIN_ID');
DELETE FROM grants WHERE principal_id IN ('$TEST_VIEWER_ID', '$TEST_TENANT_ADMIN_ID');
DELETE FROM users WHERE id IN ('$TEST_VIEWER_ID', '$TEST_TENANT_ADMIN_ID');
SQL

echo "== 10. User/grant management (GET/POST /api/v1/users, POST/DELETE .../grants -- user:read, user:manage) =="
# internal/api/users.go, the AdminConsole "Users/roles/grants" sub-panel
# (lld/11-ui-design.md §3). Exercises: user creation with a server-generated
# one-shot temporary password + forced mustChangePassword; that the temp
# password actually authenticates; an initial grant created atomically with
# the user; granting and revoking an ADDITIONAL role via the two dedicated
# grant endpoints; that ResolveEffectivePermissions actually reflects the
# grant/revoke (not just that the write endpoints returned 2xx); capability
# denial for both user:manage and user:read; and the deliberately-rejected
# inputs (unknown role, ClusterGroup scope, duplicate email).

status=$(curl -sS -o /dev/null -w "%{http_code}" "$API/api/v1/users")
check_status "GET /users with no auth" 401 "$status"
status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/users" -H "Content-Type: application/json" -d '{"email":"nobody@localhost"}')
check_status "POST /users with no auth" 401 "$status"

NEWUSER_EMAIL="smoketest-newuser-$(date +%s)-$$@localhost"
create_user_resp=$(curl -sS -X POST "$API/api/v1/users" \
  -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" \
  -d "{\"email\":\"$NEWUSER_EMAIL\",\"displayName\":\"Smoke Test New User\",\"initialGrant\":{\"role\":\"viewer\",\"scope\":{\"type\":\"AllClusters\"}}}")

verify_create_user=$(python3 - "$create_user_resp" "$NEWUSER_EMAIL" <<'PYEOF'
import json, sys
resp = json.loads(sys.argv[1])
email = sys.argv[2]
results = []
def check(cond, desc, detail=""):
    results.append((bool(cond), desc, detail))

user = resp.get("user", {})
check(user.get("email") == email, "created user's email matches the request", user.get("email"))
check(user.get("mustChangePassword") is True, "created user has mustChangePassword == true", user.get("mustChangePassword"))
check(len(user.get("grants", [])) == 1, "created user has exactly the one initial grant", len(user.get("grants", [])))
if user.get("grants"):
    check(user["grants"][0].get("role") == "viewer", "initial grant role == viewer", user["grants"][0].get("role"))
    check(user["grants"][0].get("scope", {}).get("type") == "AllClusters", "initial grant scope == AllClusters", user["grants"][0].get("scope"))
temp_pw = resp.get("temporaryPassword", "")
check(len(temp_pw) >= 20, "response carries a high-entropy temporaryPassword", len(temp_pw))
check("password" not in json.dumps(user), "the nested \"user\" object itself never carries a password field")
for passed, desc, detail in results:
    tag = "PASS" if passed else "FAIL"
    suffix = f" (got {detail})" if detail != "" else ""
    print(f"  {tag}: {desc}{suffix}")
print(f"NEW_USER_ID={user.get('id','')}")
print(f"TEMP_PASSWORD={temp_pw}")
print(f"INITIAL_GRANT_ID={user['grants'][0]['id'] if user.get('grants') else ''}")
PYEOF
)
echo "$verify_create_user" | grep -E "^  (PASS|FAIL):"
pass_count=$(echo "$verify_create_user" | grep -c "^  PASS:")
fail_count=$(echo "$verify_create_user" | grep -c "^  FAIL:")
PASS=$((PASS + pass_count))
FAIL=$((FAIL + fail_count))
new_user_id=$(echo "$verify_create_user" | grep "^NEW_USER_ID=" | cut -d= -f2-)
temp_password=$(echo "$verify_create_user" | grep "^TEMP_PASSWORD=" | cut -d= -f2-)
initial_grant_id=$(echo "$verify_create_user" | grep "^INITIAL_GRANT_ID=" | cut -d= -f2-)

if [[ -n "$new_user_id" && -n "$temp_password" ]]; then
  new_user_login=$(curl -sS -X POST "$API/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$NEWUSER_EMAIL\",\"password\":\"$temp_password\"}")
  new_user_token=$(echo "$new_user_login" | json_field accessToken)
  new_user_must_change=$(echo "$new_user_login" | json_field mustChangePassword)

  if [[ -n "$new_user_token" ]]; then
    echo "  PASS: the newly created user's server-generated temporary password authenticates"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: could not log in as the newly created user with its temporary password -- response: $new_user_login"
    FAIL=$((FAIL + 1))
  fi
  check_status "login as the new user reports mustChangePassword == True (forced change)" "True" "$new_user_must_change"

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/users" \
    -H "Authorization: Bearer $new_user_token" -H "Content-Type: application/json" -d '{"email":"irrelevant@localhost"}')
  check_status "new user (viewer role) denied POST /users -- lacks user:manage (403)" 403 "$status"

  status=$(curl -sS -o /dev/null -w "%{http_code}" "$API/api/v1/users" -H "Authorization: Bearer $new_user_token")
  check_status "new user (viewer role) denied GET /users -- viewer lacks user:read too (403)" 403 "$status"

  echo "  -- Granting an additional role (resolver, AllClusters) via POST /users/{id}/grants --"
  create_grant_resp=$(curl -sS -X POST "$API/api/v1/users/$new_user_id/grants" \
    -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" \
    -d '{"role":"resolver","scope":{"type":"AllClusters"}}')
  grant_id=$(echo "$create_grant_resp" | json_field id)
  grant_role=$(echo "$create_grant_resp" | json_field role)
  if [[ -n "$grant_id" && "$grant_role" == "resolver" ]]; then
    echo "  PASS: POST /users/{id}/grants creates a resolver grant"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: POST /users/{id}/grants -- response: $create_grant_resp"
    FAIL=$((FAIL + 1))
  fi

  caps_after_grant=$(curl -sS "$API/api/v1/users/me/effective-permissions" -H "Authorization: Bearer $new_user_token")
  if echo "$caps_after_grant" | grep -q '"remediation:approve"'; then
    echo "  PASS: the new user's own effective-permissions reflect the resolver grant (remediation:approve present)"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: effective-permissions did not pick up the resolver grant -- response: $caps_after_grant"
    FAIL=$((FAIL + 1))
  fi

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/users/$new_user_id/grants" \
    -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" \
    -d '{"role":"not-a-real-role","scope":{"type":"AllClusters"}}')
  check_status "creating a grant with an unknown role is rejected" 400 "$status"

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/users/$new_user_id/grants" \
    -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" \
    -d '{"role":"viewer","scope":{"type":"ClusterGroup","clusterGroupId":"clg_bogus"}}')
  check_status "creating a grant with scope type ClusterGroup is rejected -- unsupported in this UI/API round" 400 "$status"

  if [[ -n "$grant_id" ]]; then
    status=$(curl -sS -o /dev/null -w "%{http_code}" -X DELETE "$API/api/v1/users/$new_user_id/grants/$grant_id")
    check_status "DELETE .../grants/{grantId} with no auth" 401 "$status"

    revoke_resp=$(curl -sS -X DELETE "$API/api/v1/users/$new_user_id/grants/$grant_id" -H "Authorization: Bearer $access_token")
    revoke_status_field=$(echo "$revoke_resp" | json_field status)
    check_status "revoking the resolver grant reports status == revoked" "revoked" "$revoke_status_field"

    status=$(curl -sS -o /dev/null -w "%{http_code}" -X DELETE "$API/api/v1/users/$new_user_id/grants/$grant_id" \
      -H "Authorization: Bearer $access_token")
    check_status "re-revoking an already-revoked grant is rejected" 409 "$status"

    caps_after_revoke=$(curl -sS "$API/api/v1/users/me/effective-permissions" -H "Authorization: Bearer $new_user_token")
    if echo "$caps_after_revoke" | grep -q '"remediation:approve"'; then
      echo "  FAIL: effective-permissions still show remediation:approve after the resolver grant was revoked"
      FAIL=$((FAIL + 1))
    else
      echo "  PASS: effective-permissions no longer show remediation:approve after revoking the resolver grant"
      PASS=$((PASS + 1))
    fi
  fi

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X DELETE "$API/api/v1/users/$new_user_id/grants/not-a-real-grant-id" \
    -H "Authorization: Bearer $access_token")
  check_status "revoking a nonexistent grant id is rejected" 404 "$status"
fi

status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/users" \
  -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" -d "{\"email\":\"$NEWUSER_EMAIL\"}")
check_status "creating a second user with the same (now-taken) email is rejected" 409 "$status"

if [[ -n "$new_user_id" ]]; then
  list_resp=$(curl -sS "$API/api/v1/users" -H "Authorization: Bearer $access_token")
  if echo "$list_resp" | grep -q "$new_user_id"; then
    echo "  PASS: GET /users (super-admin) lists the newly created user"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: GET /users did not list user $new_user_id"
    FAIL=$((FAIL + 1))
  fi
fi

echo "== 10a. Password self-service change (PUT /users/me/password) + admin reset (POST /users/{id}/reset-password) =="
# internal/api/auth.go's handleChangePassword and internal/api/users.go's
# handleResetPassword -- closes the exact gap the task brief flagged: every
# mustChangePassword account got nagged by AppShell.tsx's banner with no way
# to actually act on it, and there was no admin reset-password action either.
# Reuses section 10's already-created $new_user_id/$NEWUSER_EMAIL/
# $temp_password fixture rather than standing up a third throwaway user --
# its cleanup block (right after this section) still applies unchanged.

if [[ -n "$new_user_id" && -n "$temp_password" ]]; then
  status=$(curl -sS -o /dev/null -w "%{http_code}" -X PUT "$API/api/v1/users/me/password" \
    -H "Content-Type: application/json" -d '{"currentPassword":"x","newPassword":"irrelevant-but-long-enough"}')
  check_status "PUT /users/me/password with no auth" 401 "$status"

  # A fresh login for this section's own token pair -- section 10 already
  # spent $new_user_token on a couple of 403 checks (an access token isn't
  # single-use, so that alone wouldn't matter), but it never captured a
  # refresh token, and this section needs one to prove refresh-token
  # revocation too.
  fresh_login=$(curl -sS -X POST "$API/api/v1/auth/login" -H "Content-Type: application/json" \
    -d "{\"email\":\"$NEWUSER_EMAIL\",\"password\":\"$temp_password\"}")
  fresh_access=$(echo "$fresh_login" | json_field accessToken)
  fresh_refresh=$(echo "$fresh_login" | json_field refreshToken)

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X PUT "$API/api/v1/users/me/password" \
    -H "Authorization: Bearer $fresh_access" -H "Content-Type: application/json" \
    -d '{"currentPassword":"totally-wrong","newPassword":"a-brand-new-long-enough-password"}')
  check_status "self-service change with the WRONG current password is rejected" 401 "$status"

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X PUT "$API/api/v1/users/me/password" \
    -H "Authorization: Bearer $fresh_access" -H "Content-Type: application/json" \
    -d "{\"currentPassword\":\"$temp_password\",\"newPassword\":\"short\"}")
  check_status "self-service change to a password shorter than the minimum length is rejected" 400 "$status"

  change_headers=$(curl -sS -D - -o /tmp/argus-smoke-chpw -X PUT "$API/api/v1/users/me/password" \
    -H "Authorization: Bearer $fresh_access" -H "Content-Type: application/json" \
    -d "{\"currentPassword\":\"$temp_password\",\"newPassword\":\"a-brand-new-long-enough-password\"}")
  change_resp=$(cat /tmp/argus-smoke-chpw); rm -f /tmp/argus-smoke-chpw
  new_access=$(echo "$change_resp" | json_field accessToken)
  # B164: a fresh refresh token still IS issued on a password change — it is
  # just delivered as an HttpOnly cookie now rather than in the body, so the
  # old "both fields present" check would report a regression that is not one.
  # The two assertions immediately after this already prove the real property
  # (the pre-change refresh token and access token are both revoked).
  new_refresh="$(grep -ci 'set-cookie:.*argus_refresh' <<<"$change_headers" || true)"
  change_must_change=$(echo "$change_resp" | json_field mustChangePassword)
  check_status "a successful self-service change reports mustChangePassword == False" "False" "$change_must_change"
  if [[ -n "$new_access" && "$new_refresh" != "0" ]]; then
    echo "  PASS: a successful self-service change returns a fresh access token and re-sets the refresh cookie (no forced logout)"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: successful change-password response missing a fresh token pair -- response: $change_resp"
    FAIL=$((FAIL + 1))
  fi

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/auth/refresh" \
    -H "Content-Type: application/json" -d "{\"refreshToken\":\"$fresh_refresh\"}")
  check_status "the OLD refresh token (from before the change) is now revoked" 401 "$status"

  status=$(curl -sS -o /dev/null -w "%{http_code}" "$API/api/v1/users/me/effective-permissions" -H "Authorization: Bearer $fresh_access")
  check_status "the OLD access token (from before the change) is rejected immediately, not just at its natural 15m expiry" 401 "$status"

  status=$(curl -sS -o /dev/null -w "%{http_code}" "$API/api/v1/users/me/effective-permissions" -H "Authorization: Bearer $new_access")
  check_status "the NEW access token returned by the change works right away" 200 "$status"

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/auth/login" \
    -H "Content-Type: application/json" -d "{\"email\":\"$NEWUSER_EMAIL\",\"password\":\"$temp_password\"}")
  check_status "the OLD (temporary) password no longer authenticates after a self-service change" 401 "$status"

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/auth/login" \
    -H "Content-Type: application/json" -d "{\"email\":\"$NEWUSER_EMAIL\",\"password\":\"a-brand-new-long-enough-password\"}")
  check_status "the NEW self-chosen password authenticates" 200 "$status"

  echo "  -- Admin reset-password (POST /users/{id}/reset-password, user:manage) --"

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/users/$new_user_id/reset-password")
  check_status "POST /users/{id}/reset-password with no auth" 401 "$status"

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/users/$new_user_id/reset-password" -H "Authorization: Bearer $new_access")
  check_status "the target user (viewer role) is denied resetting their OWN password via the admin endpoint -- lacks user:manage" 403 "$status"

  # A live session, captured right before the reset, to prove the reset ends
  # an ALREADY-ISSUED session -- not merely what a future login would get.
  presession=$(curl -sS -X POST "$API/api/v1/auth/login" -H "Content-Type: application/json" \
    -d "{\"email\":\"$NEWUSER_EMAIL\",\"password\":\"a-brand-new-long-enough-password\"}")
  presession_access=$(echo "$presession" | json_field accessToken)
  presession_refresh=$(echo "$presession" | json_field refreshToken)

  reset_resp=$(curl -sS -X POST "$API/api/v1/users/$new_user_id/reset-password" -H "Authorization: Bearer $access_token")
  reset_temp_password=$(echo "$reset_resp" | json_field temporaryPassword)
  if [[ ${#reset_temp_password} -ge 20 ]]; then
    echo "  PASS: admin reset-password returns a high-entropy temporary password"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: admin reset-password response -- $reset_resp"
    FAIL=$((FAIL + 1))
  fi
  if ! echo "$reset_resp" | grep -q "a-brand-new-long-enough-password"; then
    echo "  PASS: the reset response never echoes back the user's old (self-chosen) password"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: reset response leaked the old password -- $reset_resp"
    FAIL=$((FAIL + 1))
  fi

  status=$(curl -sS -o /dev/null -w "%{http_code}" "$API/api/v1/users/me/effective-permissions" -H "Authorization: Bearer $presession_access")
  check_status "the target's PRE-RESET access token is rejected immediately after an admin reset" 401 "$status"

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/auth/refresh" \
    -H "Content-Type: application/json" -d "{\"refreshToken\":\"$presession_refresh\"}")
  check_status "the target's PRE-RESET refresh token is revoked immediately after an admin reset" 401 "$status"

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/auth/login" \
    -H "Content-Type: application/json" -d "{\"email\":\"$NEWUSER_EMAIL\",\"password\":\"a-brand-new-long-enough-password\"}")
  check_status "the target's pre-reset (self-chosen) password no longer authenticates" 401 "$status"

  if [[ -n "$reset_temp_password" ]]; then
    postreset_login=$(curl -sS -X POST "$API/api/v1/auth/login" -H "Content-Type: application/json" \
      -d "{\"email\":\"$NEWUSER_EMAIL\",\"password\":\"$reset_temp_password\"}")
    postreset_must_change=$(echo "$postreset_login" | json_field mustChangePassword)
    check_status "the new admin-issued temporary password authenticates, with mustChangePassword forced True again" "True" "$postreset_must_change"
  fi

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/users/not-a-real-user-id/reset-password" -H "Authorization: Bearer $access_token")
  check_status "resetting a nonexistent user's password is rejected" 404 "$status"
fi

echo "== 10b. User lifecycle -- disable/enable (POST /users/{id}/disable, POST /users/{id}/enable, user:manage) =="
# internal/api/users.go's handleDisableUser/handleEnableUser -- closes the
# other half of the gap this round's task brief flagged directly: "user
# lifecycle management is missing, there is no mechanism to delete a user,
# just adding user exist." disabled_at was already selected by
# handleListUsers and already checked by handleLogin's `WHERE ...
# disabled_at IS NULL` clause before this task -- there was just no
# endpoint anywhere that ever SET it. This section proves: a disable ends
# an already-issued session immediately (not just future logins), a
# disabled user's own correct password is rejected at login, re-enabling
# restores the ability to log in, both actions are idempotent-conflict
# (409) rather than silently repeatable, both 404 on an unknown user id,
# both 403 without user:manage, and the last-remaining-super-admin
# self-disable guardrail actually blocks that one specific case while
# leaving every other disable (a non-super-admin, or a super-admin
# self-disabling while another active super-admin still exists) unblocked.
# Reuses section 10's $new_user_id/$NEWUSER_EMAIL fixture, still enrolled
# as a plain viewer at this point (its only extra grant, resolver, was
# revoked back in section 10) -- cleaned up by the same cleanup block this
# section runs immediately before.
#
# Important: section 10a's LAST action on this fixture was an ADMIN
# password reset, which bumped token_generation and revoked every refresh
# token this user had -- including $new_access/$new_refresh from earlier in
# that same section. So by this point the user's real current password is
# $reset_temp_password (10a's admin-issued one), not the self-chosen
# "a-brand-new-long-enough-password" it superseded, and $new_access is
# itself already a dead token -- every check below needs a token/password
# captured AFTER that reset, not reused from before it.

if [[ -n "$new_user_id" && -n "$reset_temp_password" ]]; then
  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/users/$new_user_id/disable")
  check_status "POST /users/{id}/disable with no auth" 401 "$status"
  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/users/$new_user_id/enable")
  check_status "POST /users/{id}/enable with no auth" 401 "$status"

  # A fresh login as the target -- $new_access (from before 10a's admin
  # reset) is already a dead token by now, so it would 401 on the generation
  # check before ever reaching the capability check this is meant to prove.
  viewer_relogin=$(curl -sS -X POST "$API/api/v1/auth/login" -H "Content-Type: application/json" \
    -d "{\"email\":\"$NEWUSER_EMAIL\",\"password\":\"$reset_temp_password\"}")
  viewer_relogin_access=$(echo "$viewer_relogin" | json_field accessToken)

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/users/$new_user_id/disable" -H "Authorization: Bearer $viewer_relogin_access")
  check_status "the target user (viewer role) is denied disabling itself via this endpoint -- lacks user:manage" 403 "$status"

  # A live session, captured right before the disable, to prove disable ends
  # an ALREADY-ISSUED session immediately -- the same technique section 10a
  # used for the admin reset-password case.
  predisable_login=$(curl -sS -X POST "$API/api/v1/auth/login" -H "Content-Type: application/json" \
    -d "{\"email\":\"$NEWUSER_EMAIL\",\"password\":\"$reset_temp_password\"}")
  predisable_access=$(echo "$predisable_login" | json_field accessToken)
  predisable_refresh=$(echo "$predisable_login" | json_field refreshToken)

  disable_resp=$(curl -sS -X POST "$API/api/v1/users/$new_user_id/disable" -H "Authorization: Bearer $access_token")
  disable_status_field=$(echo "$disable_resp" | json_field status)
  check_status "disabling the user reports status == disabled" "disabled" "$disable_status_field"

  status=$(curl -sS -o /dev/null -w "%{http_code}" "$API/api/v1/users/me/effective-permissions" -H "Authorization: Bearer $predisable_access")
  check_status "the target's PRE-DISABLE access token is rejected immediately after a disable" 401 "$status"

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/auth/refresh" \
    -H "Content-Type: application/json" -d "{\"refreshToken\":\"$predisable_refresh\"}")
  check_status "the target's PRE-DISABLE refresh token is revoked immediately after a disable" 401 "$status"

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/auth/login" \
    -H "Content-Type: application/json" -d "{\"email\":\"$NEWUSER_EMAIL\",\"password\":\"$reset_temp_password\"}")
  check_status "a fresh login attempt with the disabled user's correct password is rejected" 401 "$status"

  list_after_disable=$(curl -sS "$API/api/v1/users" -H "Authorization: Bearer $access_token")
  if echo "$list_after_disable" | python3 -c "
import json, sys
users = json.load(sys.stdin).get('users', [])
u = next((u for u in users if u.get('id') == '$new_user_id'), None)
sys.exit(0 if u and u.get('disabledAt') else 1)
"; then
    echo "  PASS: GET /users shows a non-null disabledAt for the disabled user"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: GET /users did not show a non-null disabledAt for $new_user_id"
    FAIL=$((FAIL + 1))
  fi

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/users/$new_user_id/disable" -H "Authorization: Bearer $access_token")
  check_status "disabling an already-disabled user is rejected" 409 "$status"

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/users/not-a-real-user-id/disable" -H "Authorization: Bearer $access_token")
  check_status "disabling a nonexistent user is rejected" 404 "$status"

  echo "  -- Re-enabling --"

  enable_resp=$(curl -sS -X POST "$API/api/v1/users/$new_user_id/enable" -H "Authorization: Bearer $access_token")
  enable_status_field=$(echo "$enable_resp" | json_field status)
  check_status "enabling the user reports status == enabled" "enabled" "$enable_status_field"

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/auth/login" \
    -H "Content-Type: application/json" -d "{\"email\":\"$NEWUSER_EMAIL\",\"password\":\"$reset_temp_password\"}")
  check_status "the re-enabled user's correct password authenticates again" 200 "$status"

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/users/$new_user_id/enable" -H "Authorization: Bearer $access_token")
  check_status "enabling an already-enabled user is rejected" 409 "$status"

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/users/not-a-real-user-id/enable" -H "Authorization: Bearer $access_token")
  check_status "enabling a nonexistent user is rejected" 404 "$status"
fi

echo "  -- Last-remaining-super-admin self-disable guardrail --"
# Deliberately never actually disables the bootstrap super-admin this whole
# script authenticates as ($access_token): the one case that matters here
# is proving the guardrail BLOCKS that specific self-disable, not carrying
# it out -- sections 11-13, still ahead, need $access_token to keep working.

bootstrap_effperms=$(curl -sS "$API/api/v1/users/me/effective-permissions" -H "Authorization: Bearer $access_token")
bootstrap_user_id=$(echo "$bootstrap_effperms" | json_field userId)

TEMPADMIN_EMAIL="smoketest-tempadmin-$(date +%s)-$$@localhost"
create_tempadmin_resp=$(curl -sS -X POST "$API/api/v1/users" \
  -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" \
  -d "{\"email\":\"$TEMPADMIN_EMAIL\",\"displayName\":\"Smoke Test Temp Super-Admin\",\"initialGrant\":{\"role\":\"super-admin\",\"scope\":{\"type\":\"AllClusters\"}}}")
tempadmin_id=$(echo "$create_tempadmin_resp" | python3 -c "import json,sys; print(json.load(sys.stdin).get('user',{}).get('id',''))")
tempadmin_temp_password=$(echo "$create_tempadmin_resp" | json_field temporaryPassword)

TEMPTENANTADMIN_EMAIL="smoketest-temptenantadmin-$(date +%s)-$$@localhost"
create_temptenantadmin_resp=$(curl -sS -X POST "$API/api/v1/users" \
  -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" \
  -d "{\"email\":\"$TEMPTENANTADMIN_EMAIL\",\"displayName\":\"Smoke Test Temp Tenant-Admin\",\"initialGrant\":{\"role\":\"tenant-admin\",\"scope\":{\"type\":\"AllClusters\"}}}")
temptenantadmin_id=$(echo "$create_temptenantadmin_resp" | python3 -c "import json,sys; print(json.load(sys.stdin).get('user',{}).get('id',''))")
temptenantadmin_temp_password=$(echo "$create_temptenantadmin_resp" | json_field temporaryPassword)

if [[ -n "$tempadmin_id" && -n "$tempadmin_temp_password" && -n "$temptenantadmin_id" && -n "$temptenantadmin_temp_password" && -n "$bootstrap_user_id" ]]; then
  tempadmin_login=$(curl -sS -X POST "$API/api/v1/auth/login" -H "Content-Type: application/json" \
    -d "{\"email\":\"$TEMPADMIN_EMAIL\",\"password\":\"$tempadmin_temp_password\"}")
  tempadmin_access=$(echo "$tempadmin_login" | json_field accessToken)

  temptenantadmin_login=$(curl -sS -X POST "$API/api/v1/auth/login" -H "Content-Type: application/json" \
    -d "{\"email\":\"$TEMPTENANTADMIN_EMAIL\",\"password\":\"$temptenantadmin_temp_password\"}")
  temptenantadmin_access=$(echo "$temptenantadmin_login" | json_field accessToken)

  # A self-disable by a NON-super-admin (here, tenant-admin) needs no
  # last-super-admin check at all, regardless of how many super-admins
  # exist -- the task brief's own explicit exclusion.
  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/users/$temptenantadmin_id/disable" -H "Authorization: Bearer $temptenantadmin_access")
  check_status "a tenant-admin can self-disable with no last-super-admin check at all" 200 "$status"

  # There are now TWO active super-admins (bootstrap + tempadmin) -- a
  # super-admin self-disabling here must be ALLOWED, since another active
  # super-admin (bootstrap) remains to administer the system afterward.
  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/users/$tempadmin_id/disable" -H "Authorization: Bearer $tempadmin_access")
  check_status "a super-admin CAN self-disable while another active super-admin still exists" 200 "$status"

  # Now bootstrap is the ONLY active, non-disabled super-admin left. Its own
  # self-disable must be BLOCKED -- this is the actual guardrail under test.
  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/users/$bootstrap_user_id/disable" -H "Authorization: Bearer $access_token")
  check_status "the last remaining active super-admin is blocked from self-disabling" 409 "$status"

  # Prove the block actually prevented the mutation, not just returned a
  # misleading status code: the bootstrap session must still work fully.
  status=$(curl -sS -o /dev/null -w "%{http_code}" "$API/api/v1/users" -H "Authorization: Bearer $access_token")
  check_status "the bootstrap super-admin's own session still works after the blocked self-disable attempt" 200 "$status"
else
  echo "  FAIL: could not set up the temp super-admin/tenant-admin fixtures for the guardrail test"
  FAIL=$((FAIL + 1))
fi

# Cleanup -- throwaway test fixtures, not application state. The initial
# grants (still active on whichever of these were never revoked above) are
# cleaned up here too, not left dangling. The bootstrap super-admin itself
# was never touched (the guardrail blocked every attempt), so nothing to
# restore for it.
docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -v ON_ERROR_STOP=1 >/dev/null <<SQL
DELETE FROM refresh_tokens WHERE user_id IN (SELECT id FROM users WHERE lower(email) IN (lower('$NEWUSER_EMAIL'), lower('$TEMPADMIN_EMAIL'), lower('$TEMPTENANTADMIN_EMAIL')));
DELETE FROM grants WHERE principal_id IN (SELECT id FROM users WHERE lower(email) IN (lower('$NEWUSER_EMAIL'), lower('$TEMPADMIN_EMAIL'), lower('$TEMPTENANTADMIN_EMAIL')));
DELETE FROM users WHERE lower(email) IN (lower('$NEWUSER_EMAIL'), lower('$TEMPADMIN_EMAIL'), lower('$TEMPTENANTADMIN_EMAIL'));
SQL

echo "== 11. AI investigation loop (POST /incidents/{id}/analyze, real tool-calling, real tunnel) =="
# internal/api/analyze.go's real bounded, tool-calling investigation loop
# (internal/llm/toolloop.go, ADR-2 / lld/07-analysis-contracts.md), replacing
# the old context-free one-shot call. Unlike section 6's comment ("does NOT
# exercise the live mTLS tunnel itself... run the actual agent for that"),
# THIS section deliberately does run a real `go run ./cmd/agent` process in
# the background — proving hub asks a model what to do -> model requests a
# tool -> hub calls the real agent over the real tunnel -> agent executes
# against whatever Kubernetes access this environment has (in practice,
# none — every tool call comes back a clean, well-formed error, which is
# itself evidence the loop must be able to interpret and continue past, not
# a reason to fail) is the one thing no earlier section proves. The model
# itself is scripts/fake-llm-server, a hand-rolled OpenAI-tool-calling-
# compatible stand-in (see its own doc comment for why it can't just import
# internal/llm's — deliberately unexported — wire types).
#
# There is no API to create an incident/finding directly (findings only
# ever arrive via a real detector or the tunnel's Finding message, and this
# section's cluster has no real cluster behind it to detect anything with)
# -- so, like section 4b/6/8b's throwaway fixtures, this section inserts the
# incident/finding rows directly via psql rather than inventing a fake
# detector just for this.

FAKE_LLM_PORT=19091
AGENT_DATA_DIR=$(mktemp -d)
AGENT_LOG=$(mktemp)
FAKE_LLM_LOG=$(mktemp)
BIN_DIR=$(mktemp -d)

# Not a `trap ... RETURN` (this is top-level script code, not a function --
# RETURN traps never fire here) -- called explicitly at the end of this
# section instead, which is reached on every path below (there's no early
# `exit`/`return` inside this section), and safe to call more than once if
# that ever changes (kill/rm-rf are both idempotent-enough for cleanup).
cleanup_section11() {
  # BACKLOG.md E4/BUGS.md 91: decommission (not just kill the tunnel) BEFORE
  # anything else. This section's agent now points at a REAL cluster with a
  # deterministic fingerprint (sha256(kube-system namespace UID)) instead of
  # the random one an unreachable-cluster agent generates -- found live: a
  # cluster this section leaves merely `Disconnected` (killing the agent
  # process, the ONLY cleanup this used to need) still has `archived_at IS
  # NULL`, and handleEnroll's fingerprint-collision check
  # (`internal/api/enroll.go`) is keyed on exactly that column, not on
  # connection state -- so the very NEXT run of this script re-enrolling the
  # SAME physical disposable cluster was rejected 409 "already enrolled"
  # before ever reaching pendingApproval, deterministically, every time,
  # after the first run ever succeeds. Decommissioning sets `archived_at`,
  # freeing the fingerprint for the next run. Best-effort: a section that
  # never got as far as enrolling (section11_cluster_id empty) has nothing
  # to decommission.
  if [[ -n "${section11_cluster_id:-}" ]]; then
    curl -sS -X POST "$API/api/v1/clusters/$section11_cluster_id/decommission" \
      -H "Authorization: Bearer $access_token" >/dev/null 2>&1
  fi
  [[ -n "${AGENT_PID:-}" ]] && kill "$AGENT_PID" >/dev/null 2>&1
  [[ -n "${FAKE_LLM_PID:-}" ]] && kill "$FAKE_LLM_PID" >/dev/null 2>&1
  rm -rf "$AGENT_DATA_DIR" "$AGENT_LOG" "$FAKE_LLM_LOG" "$BIN_DIR"
  # BACKLOG.md E4/BUGS.md 91: real cluster state, not a throwaway hub-side
  # fixture -- leaving it around costs nothing on a disposable cluster, but
  # deleting it keeps the NEXT run's 11b3d replica-count assertion (== 4,
  # against a freshly created replicas=1 object) meaningful rather than
  # trivially "already 4 from last time." Best-effort: a missing kubeconfig
  # here (already reported as a FAIL above) must not make cleanup itself
  # blow up the rest of the script.
  [[ -f "$DISPOSABLE_KUBECONFIG" ]] && kubectl --kubeconfig "$DISPOSABLE_KUBECONFIG" delete deployment smoketest-deploy -n default --ignore-not-found >/dev/null 2>&1
}

# Built once and launched as real binaries, NOT `go run ...`: `go run`'s PID
# is a wrapper around a separately-forked compiled binary, and killing the
# wrapper does not reliably kill that child on every `go` toolchain/platform
# -- confirmed the hard way while first writing this section (killing the
# `go run` PID left the actual fake-llm-server/agent process still bound to
# its port and still holding its tunnel connection, which silently defeated
# both 11b's "switch to a never-concluding model" and 11c's "disconnect the
# cluster" steps). A real, directly-launched binary's PID is the process
# that actually needs killing.
go build -o "$BIN_DIR/fake-llm-server" ./scripts/fake-llm-server
go build -o "$BIN_DIR/agent" ./cmd/agent

"$BIN_DIR/fake-llm-server" -addr ":$FAKE_LLM_PORT" -mode toolloop >"$FAKE_LLM_LOG" 2>&1 &
FAKE_LLM_PID=$!

section11_token=$(curl -sS -X POST "$API/api/v1/clusters/enrollment-tokens" \
  -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" -d '{"ttlClass":"B"}' | json_field token)

# BACKLOG.md E4/BUGS.md 91: KUBECONFIG points this agent at the real
# disposable kind cluster (rather than at nothing, per this section's
# original "works even without a live target cluster" design) so
# get_gitops_ownership below can genuinely resolve. Loud, not silent, if
# the cluster this whole section now depends on isn't there -- reverting to
# a "no reachable cluster" degradation defeats the exact bug this fixes.
if [[ ! -f "$DISPOSABLE_KUBECONFIG" ]]; then
  echo "  FAIL: disposable cluster kubeconfig not found at $DISPOSABLE_KUBECONFIG -- see RUNBOOK.md's 'Standing test infrastructure' section to recreate it (kind create cluster --name argus-disposable ...), or set ARGUS_DISPOSABLE_KUBECONFIG"
  FAIL=$((FAIL + 1))
fi

ARGUS_ENROLLMENT_TOKEN="$section11_token" ARGUS_HUB_API_URL="$API" \
  ARGUS_CLUSTER_DISPLAY_NAME="smoketest-toolloop-cluster" ARGUS_AGENT_DATA_DIR="$AGENT_DATA_DIR" \
  KUBECONFIG="$DISPOSABLE_KUBECONFIG" \
  "$BIN_DIR/agent" >"$AGENT_LOG" 2>&1 &
AGENT_PID=$!

section11_cluster_id=""
for _ in $(seq 1 30); do
  section11_cluster_id=$(grep 'is pendingApproval' "$AGENT_LOG" | grep -oP '"cluster_id":"\K[^"]+' | head -1)
  [[ -n "$section11_cluster_id" ]] && break
  sleep 1
done
register_smoketest_cluster "$section11_cluster_id"

if [[ -n "$section11_cluster_id" ]]; then
  echo "  PASS: real agent process enrolled (cluster $section11_cluster_id, pendingApproval)"
  PASS=$((PASS + 1))
else
  if agent_enrollment_blocked "$AGENT_LOG"; then
    echo "  SKIP: the target cluster is already enrolled in this hub, so a second enrollment is correctly refused (409 already-enrolled) -- decommission it first, or point ARGUS_DISPOSABLE_KUBECONFIG at an unenrolled cluster, to exercise this section"
  else
    echo "  FAIL: real agent process never reached pendingApproval -- see agent log: $AGENT_LOG"
    FAIL=$((FAIL + 1))
  fi
fi

if [[ -n "$section11_cluster_id" ]]; then
  curl -sS -X POST "$API/api/v1/clusters/$section11_cluster_id/accept" -H "Authorization: Bearer $access_token" >/dev/null

  section11_state=""
  for _ in $(seq 1 20); do
    section11_state=$(curl -sS "$API/api/v1/clusters/$section11_cluster_id" -H "Authorization: Bearer $access_token" | json_field state)
    [[ "$section11_state" == "Active" ]] && break
    sleep 1
  done
  check_status "real agent's tunnel promotes the cluster to Active" "Active" "$section11_state"

  # BACKLOG.md E4/BUGS.md 91: the real object 11b3/11b3d/11b3e/11b3f's
  # workload_key names (apps/v1/Deployment|default|smoketest-deploy) has to
  # actually exist on the disposable cluster before get_gitops_ownership is
  # ever asked about it -- deleted-then-recreated so repeated runs of this
  # script start from the same known replica count (1) every time, rather
  # than accumulating whatever a previous run's real 11b3d scale left behind.
  kubectl --kubeconfig "$DISPOSABLE_KUBECONFIG" delete deployment smoketest-deploy -n default --ignore-not-found >/dev/null 2>&1
  kubectl --kubeconfig "$DISPOSABLE_KUBECONFIG" create deployment smoketest-deploy -n default --image=nginx:alpine --replicas=1 >/dev/null 2>&1
  kubectl --kubeconfig "$DISPOSABLE_KUBECONFIG" wait --for=condition=Available deployment/smoketest-deploy -n default --timeout=60s >/dev/null 2>&1
  smoketest_deploy_uid=$(kubectl --kubeconfig "$DISPOSABLE_KUBECONFIG" get deployment smoketest-deploy -n default -o jsonpath='{.metadata.uid}' 2>/dev/null)
  if [[ -n "$smoketest_deploy_uid" ]]; then
    echo "  PASS: real object apps/v1/Deployment default/smoketest-deploy exists on the disposable cluster (uid $smoketest_deploy_uid) for ownership resolution below"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: could not create/observe apps/v1/Deployment default/smoketest-deploy on the disposable cluster ($DISPOSABLE_KUBECONFIG)"
    FAIL=$((FAIL + 1))
  fi

  activate_fake_llm_provider "http://host.docker.internal:$FAKE_LLM_PORT" "smoketest-toolloop-model"

  SECTION11_INC_COMPLETE="inc_smoketesttoolloop0000001"
  SECTION11_FND_COMPLETE="fnd_smoketesttoolloop0000001"
  now_ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -v ON_ERROR_STOP=1 >/dev/null <<SQL
DO \$\$
DECLARE tid text;
BEGIN
  SELECT tenant_id INTO tid FROM clusters WHERE id = '$section11_cluster_id';
  INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
  VALUES ('$SECTION11_INC_COMPLETE', tid, '$section11_cluster_id', 'smoketest-toolloop-fp-1', 'high', 'Detected', '$now_ts', '$now_ts', 1);
  INSERT INTO findings (id, tenant_id, cluster_id, detector_id, detector_version, fingerprint, gvk, namespace, object_name, occurrence_count, severity, occurred_at, incident_id)
  VALUES ('$SECTION11_FND_COMPLETE', tid, '$section11_cluster_id', 'pod-status', '0.1.0', 'smoketest-toolloop-fp-1', 'v1/Pod', 'default', 'smoketest-pod', 3, 'high', '$now_ts', '$SECTION11_INC_COMPLETE');
END \$\$;
SQL

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/incidents/$SECTION11_INC_COMPLETE/analyze")
  check_status "POST .../analyze with no token" 401 "$status"

  analyze_resp=$(analyze_and_wait "$SECTION11_INC_COMPLETE" /tmp/smoketest_analyze_complete.json)
  check_status "POST .../analyze against a connected cluster is accepted (202) and its analysis lands" 202 "$analyze_resp"

  verify_complete=$(python3 - "$(cat /tmp/smoketest_analyze_complete.json)" <<'PYEOF'
import json, sys
d = json.loads(sys.argv[1])
results = []
def check(cond, desc, detail=""):
    results.append((bool(cond), desc, detail))
check(d.get("status") == "complete", "status == complete", d.get("status"))
check(d.get("rootCause", {}).get("statement", "") != "", "rootCause.statement is non-empty")
check(isinstance(d.get("confidence"), float), "confidence is a number", d.get("confidence"))
check(d.get("partialReason") is None, "partialReason is null on a complete result", d.get("partialReason"))
check(d.get("suggestedNextSteps") is None, "suggestedNextSteps is null on a complete result", d.get("suggestedNextSteps"))
chain = d.get("causalChain", [])
check(len(chain) == 3, "causalChain has exactly 3 steps (the fake model's scripted get_events/get_owner_chain/get_logs)", len(chain))
if len(chain) == 3:
    tools_called = [step["toolCalls"][0]["tool"] for step in chain if step.get("toolCalls")]
    check(tools_called == ["get_events", "get_owner_chain", "get_logs"],
          "the 3 tool calls are the scripted sequence, in order, each actually routed to the real agent", tools_called)
    # BACKLOG.md E4/BUGS.md 91: this section's agent is now pointed at a
    # real, reachable disposable cluster (so §11b3 onward can resolve real
    # ownership) -- but THIS fixture's own finding names a Pod
    # ("smoketest-pod") that was never created there, only referenced in
    # findings.object_name. That changes what "real, well-formed" means per
    # call, and it is worth being precise rather than reverting to a blanket
    # "no reachable cluster" claim that is no longer true for this agent:
    # get_events is a LIST with a field selector -- against a real API
    # server, a selector matching nothing is an ordinary, error-free EMPTY
    # result, not a failure. get_owner_chain and get_logs are both a GET on
    # the named Pod specifically, which genuinely does not exist, so those
    # two still come back as real, well-formed NotFound-shaped errors.
    tool_errors = [step["toolCalls"][0].get("error") for step in chain]
    check(not tool_errors[0], "get_events against a real cluster succeeds with an empty result (no matching Pod, not a failure)", tool_errors[0])
    check(bool(tool_errors[1]), "get_owner_chain's error is populated -- a real NotFound came back over the real tunnel for a Pod that was never created", tool_errors[1])
    check(bool(tool_errors[2]), "get_logs' error is populated -- a real NotFound came back over the real tunnel for a Pod that was never created", tool_errors[2])
check(d.get("iterations") == 4, "iterations == 4 (3 tool-calling rounds + 1 concluding round)", d.get("iterations"))
# Token/cost accounting: fake-llm-server's "toolloop" mode returns
# prompt_tokens=50/completion_tokens=20 on every one of its 4 calls, plus a
# cached_tokens=30 hit on calls 2-4 (the stable system+facts prefix) -- so
# the real, summed-across-every-round totals must be 200/90/80, never just
# the last round's 50/30/20 (which is what a bug reporting only the final
# round's usage would produce instead).
check(d.get("tokensBilledIn") == 200, "tokensBilledIn == 200 (summed across all 4 rounds, not just the last round's 50)", d.get("tokensBilledIn"))
check(d.get("tokensCacheRead") == 90, "tokensCacheRead == 90 (summed cached_tokens from rounds 2-4)", d.get("tokensCacheRead"))
check(d.get("tokensOut") == 80, "tokensOut == 80 (summed across all 4 rounds, not just the last round's 20)", d.get("tokensOut"))
check(d.get("costUsd") == 0, "costUsd == 0 (an honest zero -- no per-model pricing table exists in this codebase)", d.get("costUsd"))
for passed, desc, detail in results:
    tag = "PASS" if passed else "FAIL"
    suffix = f" (got {detail})" if detail != "" else ""
    print(f"  {tag}: {desc}{suffix}")
PYEOF
)
  echo "$verify_complete"
  pass_count=$(echo "$verify_complete" | grep -c "^  PASS:")
  fail_count=$(echo "$verify_complete" | grep -c "^  FAIL:")
  PASS=$((PASS + pass_count))
  FAIL=$((FAIL + fail_count))

  db_row=$(docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -t -A -F'|' -c \
    "SELECT prompt_version, confidence IS NOT NULL, iterations FROM analyses WHERE incident_id = '$SECTION11_INC_COMPLETE';")
  if [[ "$db_row" == "v2-tool-loop|t|4" ]]; then
    echo "  PASS: analyses row persisted with prompt_version=v2-tool-loop, a non-null confidence, iterations=4"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: analyses row = '$db_row', want 'v2-tool-loop|t|4'"
    FAIL=$((FAIL + 1))
  fi

  # Token/cost accounting persisted for real, not as the placeholders this
  # task closed: tokens_billed_in/tokens_cache_read/tokens_out must be the
  # real sums across all 4 model round-trips (200/90/80, per the fake-llm-server
  # script above), and cost_usd is an honest, documented 0 (no pricing table
  # exists in this codebase) -- never a fabricated non-zero number.
  db_tokens_row=$(docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -t -A -F'|' -c \
    "SELECT tokens_billed_in, tokens_cache_read, tokens_out, cost_usd FROM analyses WHERE incident_id = '$SECTION11_INC_COMPLETE';")
  if [[ "$db_tokens_row" == "200|90|80|0.0000" ]]; then
    echo "  PASS: analyses row's token/cost columns hold real, summed-across-every-round numbers (200|90|80|0.0000)"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: analyses token/cost columns = '$db_tokens_row', want '200|90|80|0.0000'"
    FAIL=$((FAIL + 1))
  fi

  detail_resp=$(curl -sS "$API/api/v1/incidents/$SECTION11_INC_COMPLETE" -H "Authorization: Bearer $access_token")
  detail_status=$(echo "$detail_resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('analysis',{}).get('status',''))")
  check_status "GET /incidents/{id}'s embedded analysis re-reads status == complete from the DB" "complete" "$detail_status"

  # costUsd is compared via float(...), not the raw decoded value: Go's
  # encoding/json renders a zero float64 as the bytes "0", not "0.0" -- a
  # textually different but numerically identical JSON number. Comparing
  # the raw string would make this assertion fragile to that harmless
  # encoding choice rather than testing the actual token/cost totals.
  detail_tokens=$(echo "$detail_resp" | python3 -c \
    "import sys,json; a=json.load(sys.stdin).get('analysis',{}); print(f\"{a.get('tokensBilledIn')}|{a.get('tokensCacheRead')}|{a.get('tokensOut')}|{float(a.get('costUsd', 0))}\")")
  check_status "GET /incidents/{id}'s embedded analysis surfaces the same real token/cost totals (200|90|80|0.0)" "200|90|80|0.0" "$detail_tokens"

  echo "-- 11b. Iteration bound -> PartialAnalysis --"
  kill "$FAKE_LLM_PID" >/dev/null 2>&1
  wait "$FAKE_LLM_PID" 2>/dev/null
  "$BIN_DIR/fake-llm-server" -addr ":$FAKE_LLM_PORT" -mode never-conclude >"$FAKE_LLM_LOG" 2>&1 &
  FAKE_LLM_PID=$!
  sleep 1

  SECTION11_INC_PARTIAL="inc_smoketesttoolloop0000002"
  SECTION11_FND_PARTIAL="fnd_smoketesttoolloop0000002"
  now_ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -v ON_ERROR_STOP=1 >/dev/null <<SQL
DO \$\$
DECLARE tid text;
BEGIN
  SELECT tenant_id INTO tid FROM clusters WHERE id = '$section11_cluster_id';
  INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
  VALUES ('$SECTION11_INC_PARTIAL', tid, '$section11_cluster_id', 'smoketest-toolloop-fp-2', 'medium', 'Detected', '$now_ts', '$now_ts', 1);
  INSERT INTO findings (id, tenant_id, cluster_id, detector_id, detector_version, fingerprint, gvk, namespace, object_name, occurrence_count, severity, occurred_at, incident_id)
  VALUES ('$SECTION11_FND_PARTIAL', tid, '$section11_cluster_id', 'pod-status', '0.1.0', 'smoketest-toolloop-fp-2', 'v1/Pod', 'default', 'ghost-pod', 5, 'medium', '$now_ts', '$SECTION11_INC_PARTIAL');
END \$\$;
SQL

  analyze_partial_resp=$(analyze_and_wait "$SECTION11_INC_PARTIAL" /tmp/smoketest_analyze_partial.json)
  check_status "POST .../analyze against a never-concluding model is still accepted (202) and its analysis lands (a partial result is not a failure response)" 202 "$analyze_partial_resp"

  verify_partial=$(python3 - "$(cat /tmp/smoketest_analyze_partial.json)" <<'PYEOF'
import json, sys
d = json.loads(sys.argv[1])
results = []
def check(cond, desc, detail=""):
    results.append((bool(cond), desc, detail))
check(d.get("status") == "partial", "status == partial", d.get("status"))
check(d.get("rootCause") is None, "rootCause is null on a partial result", d.get("rootCause"))
check(d.get("confidence") is None, "confidence is null on a partial result -- never a fabricated number", d.get("confidence"))
check(d.get("partialReason") == "iteration_limit", "partialReason == iteration_limit", d.get("partialReason"))
check(bool(d.get("suggestedNextSteps")), "suggestedNextSteps is populated", d.get("suggestedNextSteps"))
check(len(d.get("causalChain", [])) == d.get("iterations"), "causalChain length == iterations (every round produced a step)", (len(d.get("causalChain", [])), d.get("iterations")))
# A bound-hit (partial) investigation still made `iterations` real, billed
# LLM calls -- its token/cost accounting must be just as real as a complete
# result's, never zeroed out for not reaching a conclusion. fake-llm-server's
# "never-conclude" mode reports 50 prompt / 20 completion tokens on every
# call, plus a 30-token cache hit on every round after the first (computed
# against d["iterations"] rather than a hardcoded count, since the exact
# iteration bound is this hub's own configured value, not this script's).
iters = d.get("iterations") or 0
want_in = 50 * iters
want_cache_read = 30 * max(iters - 1, 0)
want_out = 20 * iters
check(d.get("tokensBilledIn") == want_in, f"tokensBilledIn == {want_in} (50 * {iters} rounds, summed across every round)", d.get("tokensBilledIn"))
check(d.get("tokensCacheRead") == want_cache_read, f"tokensCacheRead == {want_cache_read} (30 cached on every round after the first)", d.get("tokensCacheRead"))
check(d.get("tokensOut") == want_out, f"tokensOut == {want_out} (20 * {iters} rounds)", d.get("tokensOut"))
check(d.get("costUsd") == 0, "costUsd == 0 on a partial result too (honest zero, no pricing table exists)", d.get("costUsd"))
check(iters > 0 and d.get("tokensBilledIn", 0) > 0 and d.get("tokensOut", 0) > 0,
      "a partial (bound-hit) result still reports real, non-zero accumulated token usage")
for passed, desc, detail in results:
    tag = "PASS" if passed else "FAIL"
    suffix = f" (got {detail})" if detail != "" else ""
    print(f"  {tag}: {desc}{suffix}")
PYEOF
)
  echo "$verify_partial"
  pass_count=$(echo "$verify_partial" | grep -c "^  PASS:")
  fail_count=$(echo "$verify_partial" | grep -c "^  FAIL:")
  PASS=$((PASS + pass_count))
  FAIL=$((FAIL + fail_count))

  db_row_partial=$(docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -t -A -F'|' -c \
    "SELECT confidence IS NULL, root_cause->>'status' FROM analyses WHERE incident_id = '$SECTION11_INC_PARTIAL';")
  if [[ "$db_row_partial" == "t|partial" ]]; then
    echo "  PASS: partial analysis persisted with confidence NULL and root_cause->>'status' == 'partial'"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: analyses row = '$db_row_partial', want 't|partial'"
    FAIL=$((FAIL + 1))
  fi

  db_tokens_partial=$(docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -t -A -F'|' -c \
    "SELECT tokens_billed_in > 0, tokens_cache_read > 0, tokens_out > 0, cost_usd FROM analyses WHERE incident_id = '$SECTION11_INC_PARTIAL';")
  if [[ "$db_tokens_partial" == "t|t|t|0.0000" ]]; then
    echo "  PASS: partial analysis's tokens_billed_in/tokens_cache_read/tokens_out are real and non-zero, cost_usd is an honest 0.0000"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: partial analysis token/cost columns = '$db_tokens_partial', want 't|t|t|0.0000' (a bound-hit investigation still made real, billed LLM calls)"
    FAIL=$((FAIL + 1))
  fi

  echo "-- 11b2. Live-editable analysis bounds (PUT /api/v1/admin/settings' analysis section) --"
  # Proves the actual point of this task: PUT a low maxIterations while the
  # hub is already up (no restart), then confirm the very next analysis
  # actually stops at that lower bound instead of the old hardcoded 8 --
  # not just that the settings API reflects the new value back. Reuses the
  # still-running "never-conclude" fake-llm-server from 11b (a model that
  # always requests another tool call) so the ONLY thing that can make this
  # investigation stop is the iteration bound itself.
  put_bounds_resp=$(curl -sS -X PUT "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" \
    -d '{"analysis":{"maxIterations":2,"timeLimitSeconds":null}}')
  put_bounds_max=$(echo "$put_bounds_resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('analysis',{}).get('maxIterations'))")
  check_status "PUT .../settings' analysis.maxIterations round-trips as 2" "2" "$put_bounds_max"

  get_bounds_resp=$(curl -sS "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token")
  get_bounds_effective=$(echo "$get_bounds_resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('analysis',{}).get('effectiveMaxIterations'))")
  check_status "GET .../settings' analysis.effectiveMaxIterations reflects the new override (2)" "2" "$get_bounds_effective"

  SECTION11_INC_LOWBOUND="inc_smoketesttoolloop0000004"
  SECTION11_FND_LOWBOUND="fnd_smoketesttoolloop0000004"
  now_ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -v ON_ERROR_STOP=1 >/dev/null <<SQL
DO \$\$
DECLARE tid text;
BEGIN
  SELECT tenant_id INTO tid FROM clusters WHERE id = '$section11_cluster_id';
  INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
  VALUES ('$SECTION11_INC_LOWBOUND', tid, '$section11_cluster_id', 'smoketest-toolloop-fp-4', 'medium', 'Detected', '$now_ts', '$now_ts', 1);
  INSERT INTO findings (id, tenant_id, cluster_id, detector_id, detector_version, fingerprint, gvk, namespace, object_name, occurrence_count, severity, occurred_at, incident_id)
  VALUES ('$SECTION11_FND_LOWBOUND', tid, '$section11_cluster_id', 'pod-status', '0.1.0', 'smoketest-toolloop-fp-4', 'v1/Pod', 'default', 'lowbound-pod', 2, 'medium', '$now_ts', '$SECTION11_INC_LOWBOUND');
END \$\$;
SQL

  analyze_lowbound_resp=$(analyze_and_wait "$SECTION11_INC_LOWBOUND" /tmp/smoketest_analyze_lowbound.json)
  check_status "POST .../analyze under the live-edited bound is still accepted (202) and its analysis lands" 202 "$analyze_lowbound_resp"

  lowbound_status=$(json_field status < /tmp/smoketest_analyze_lowbound.json)
  lowbound_iterations=$(json_field iterations < /tmp/smoketest_analyze_lowbound.json)
  lowbound_reason=$(json_field partialReason < /tmp/smoketest_analyze_lowbound.json)
  check_status "status == partial, stopped by the new lower bound, not the old default of 8" "partial" "$lowbound_status"
  check_status "iterations == 2 (the live-edited maxIterations), never the old hardcoded default" "2" "$lowbound_iterations"
  check_status "partialReason == iteration_limit" "iteration_limit" "$lowbound_reason"

  # Reset the override back to "unconfigured" -- explicit JSON null, not
  # omission, per analysis.maxIterations/timeLimitSeconds' documented
  # always-taken-as-given contract -- so 11c and any later section run under
  # the ordinary hardcoded default again.
  curl -sS -X PUT "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" \
    -d '{"analysis":{"maxIterations":null,"timeLimitSeconds":null}}' >/dev/null

  echo "-- 11b3. Plan authoring is gated by ownership determination (Phase 2, slice 2, seen through F17) --"
  # internal/llm's proposedPlan parsing and internal/orchestrator's real
  # Detected -> Investigating -> ... wiring, driven by a real analyze call
  # against the real connected agent, exactly like 11/11b above, just with a
  # fake model that proposes a plan instead of concluding with prose alone.
  #
  # BACKLOG.md E4 / BUGS.md 91: this subsection through 11b3f used to assert
  # the plan actually reaches AwaitingApproval and drives the approval queue,
  # then got degraded to asserting Diagnosed/no-plan once F17
  # (internal/api/routing.go's gatherOwnershipFacts) made get_gitops_ownership
  # a precondition for offering any plan at all, and this section's agent had
  # no reachable Kubernetes API to ask — confirmed live at the time:
  # `gatherOwnershipFacts: get_gitops_ownership for ...: gateway: cluster ...:
  # tool "get_gitops_ownership" failed: no reachable cluster`. BUGS.md 91's
  # fix is exactly what restores this: the agent above is now pointed (via
  # KUBECONFIG) at a real, disposable `kind` cluster, and the object this
  # fixture's workload_key names (apps/v1/Deployment default/smoketest-deploy,
  # created for real right after the cluster went Active) genuinely exists
  # there — so ownership resolves (no GitOps annotations -> Unmanaged ->
  # resolution.RouteFor routes in-place), and the fake model's scripted
  # ScaleDeployment plan reaches remediation.Evaluate and is offered for real
  # approval, restoring what this subsection was originally built to prove.
  kill "$FAKE_LLM_PID" >/dev/null 2>&1
  wait "$FAKE_LLM_PID" 2>/dev/null
  # The scripted reads target smoketest-deploy's real pod, so they answer.
  # Against a pod that does not exist two of the three fail, and the hub
  # correctly caps a mostly-unread conclusion's confidence at 0.6
  # (internal/llm/evidence_coverage.go) instead of the scripted 0.75 that
  # the gate assertions below are written against.
  smoketest_pod=$(kubectl --kubeconfig "$DISPOSABLE_KUBECONFIG" get pods -n default -l app=smoketest-deploy \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
  "$BIN_DIR/fake-llm-server" -addr ":$FAKE_LLM_PORT" -mode toolloop-plan -pod "${smoketest_pod:-smoketest-pod}" >"$FAKE_LLM_LOG" 2>&1 &
  FAKE_LLM_PID=$!
  sleep 1

  SECTION11_INC_PLAN="inc_smoketesttoolloop0000005"
  SECTION11_FND_PLAN="fnd_smoketesttoolloop0000005"
  now_ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -v ON_ERROR_STOP=1 >/dev/null <<SQL
DO \$\$
DECLARE tid text;
BEGIN
  SELECT tenant_id INTO tid FROM clusters WHERE id = '$section11_cluster_id';
  -- object_key/workload_key (BUGS.md 87): internal/api/routing.go's
  -- ownershipQueryTarget reads these BEFORE analysis runs to ask the
  -- (real, connected) agent who owns this object, in this codebase's wire
  -- convention "<gvk>|<namespace>|<name>" (internal/api/repository_change.go's
  -- pickOwnershipQueryTuple). workload_key wins when present, naming the
  -- stable Deployment the fake model's scripted ScaleDeployment plan already
  -- targets ("smoketest-deploy") rather than the Pod findings.object_name
  -- names — object_key is set too, purely so this fixture matches what a
  -- real pod-status finding would actually populate.
  INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count, object_key, workload_key)
  VALUES ('$SECTION11_INC_PLAN', tid, '$section11_cluster_id', 'smoketest-toolloop-fp-5', 'high', 'Detected', '$now_ts', '$now_ts', 1, 'v1/Pod|default|smoketest-pod', 'apps/v1/Deployment|default|smoketest-deploy');
  INSERT INTO findings (id, tenant_id, cluster_id, detector_id, detector_version, fingerprint, gvk, namespace, object_name, occurrence_count, severity, occurred_at, incident_id)
  VALUES ('$SECTION11_FND_PLAN', tid, '$section11_cluster_id', 'pod-status', '0.1.0', 'smoketest-toolloop-fp-5', 'v1/Pod', 'default', 'smoketest-pod', 4, 'high', '$now_ts', '$SECTION11_INC_PLAN');
END \$\$;
SQL

  # Pre-condition: this incident is still Detected before analysis runs —
  # proves Detected -> Investigating -> AwaitingApproval is a real
  # transition sequence, not "it was already AwaitingApproval somehow."
  pre_state=$(docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -t -A -c \
    "SELECT state FROM incidents WHERE id = '$SECTION11_INC_PLAN';")
  check_status "fixture incident starts in Detected, before analysis runs" "Detected" "$pre_state"

  analyze_plan_resp=$(analyze_and_wait "$SECTION11_INC_PLAN" /tmp/smoketest_analyze_plan.json)
  check_status "POST .../analyze against a plan-proposing model is accepted (202) and its analysis lands" 202 "$analyze_plan_resp"

  verify_plan=$(python3 - "$(cat /tmp/smoketest_analyze_plan.json)" <<'PYEOF'
import json, sys
d = json.loads(sys.argv[1])
results = []
def check(cond, desc, detail=""):
    results.append((bool(cond), desc, detail))
check(d.get("status") == "complete", "status == complete", d.get("status"))
# AwaitingApproval, not Diagnosed: ownership now resolves for real against
# the disposable cluster's real smoketest-deploy object (no GitOps
# annotations -> Unmanaged -> resolution.RouteFor routes in-place), so the
# plan reaches remediation.Evaluate and is offered for approval.
check(d.get("incidentState") == "AwaitingApproval",
      "incidentState == AwaitingApproval (ownership resolved against the real disposable-cluster object -- route: in-place)",
      d.get("incidentState"))
check(bool(d.get("stateReason")), "stateReason is a non-empty explanation")
plan = d.get("plan") or {}
check(plan.get("actionType") == "ScaleDeployment", "plan.actionType == ScaleDeployment", plan.get("actionType"))
check(plan.get("targetGvk") == "apps/v1/Deployment", "plan.targetGvk == apps/v1/Deployment", plan.get("targetGvk"))
check(plan.get("targetNamespace") == "default", "plan.targetNamespace == default", plan.get("targetNamespace"))
check(plan.get("targetName") == "smoketest-deploy", "plan.targetName == smoketest-deploy", plan.get("targetName"))
params = plan.get("params") or {}
if isinstance(params, str):
    params = json.loads(params or "{}")
check(params.get("replicas") == 4, "plan.params.replicas == 4", params)
check(plan.get("riskLevel") == "medium", "plan.riskLevel == medium", plan.get("riskLevel"))
check(plan.get("reversible") is True, "plan.reversible == true", plan.get("reversible"))
check(plan.get("gateOutcome") == "NeedsApproval",
      "plan.gateOutcome == NeedsApproval (medium risk / 0.75 confidence, under DefaultAutonomyPolicy's ceiling)",
      plan.get("gateOutcome"))
check(bool(plan.get("gateReason")), "plan.gateReason is a non-empty explanation")
check(str(plan.get("id", "")).startswith("plan_"), "plan.id is a real, prefixed ULID", plan.get("id"))
for passed, desc, detail in results:
    tag = "PASS" if passed else "FAIL"
    suffix = f" (got {detail})" if detail != "" else ""
    print(f"  {tag}: {desc}{suffix}")
PYEOF
)
  echo "$verify_plan"
  pass_count=$(echo "$verify_plan" | grep -c "^  PASS:")
  fail_count=$(echo "$verify_plan" | grep -c "^  FAIL:")
  PASS=$((PASS + pass_count))
  FAIL=$((FAIL + fail_count))

  section11_plan_id=$(python3 -c "import json; print((json.load(open('/tmp/smoketest_analyze_plan.json')).get('plan') or {}).get('id',''))")

  post_state=$(docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -t -A -c \
    "SELECT state FROM incidents WHERE id = '$SECTION11_INC_PLAN';")
  check_status "incidents row itself is now AwaitingApproval (real DB state, not just the response body)" "AwaitingApproval" "$post_state"

  # `||` on a boolean operand casts it via its own textual representation
  # ("true"/"false"), NOT psql's own "t"/"f" display abbreviation for a raw
  # boolean COLUMN -- confirmed live (the first version of this check
  # expected "t" and failed against a real "true").
  rec_row=$(docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -t -A -F'|' -c \
    "SELECT action_type || '|' || risk_level || '|' || gate_outcome || '|' || (analysis_id IS NOT NULL) FROM remediation_recommendations WHERE incident_id = '$SECTION11_INC_PLAN';")
  check_status "a real remediation_recommendations row was persisted (ScaleDeployment/medium/NeedsApproval, analysis_id set)" \
    "ScaleDeployment|medium|NeedsApproval|true" "$rec_row"

  echo "-- 11b3a. Approval queue lists a real, actionable plan --"
  approvals_resp=$(curl -sS "$API/api/v1/approvals" -H "Authorization: Bearer $access_token")
  verify_queue=$(python3 - "$approvals_resp" "$SECTION11_INC_PLAN" <<'PYEOF'
import json, sys
d = json.loads(sys.argv[1])
incident_id = sys.argv[2]
results = []
def check(cond, desc, detail=""):
    results.append((bool(cond), desc, detail))
items = d.get("approvals", [])
matches = [x for x in items if x.get("incidentId") == incident_id]
check(len(matches) == 1, "the fixture incident appears exactly once in GET /approvals", len(matches))
if matches:
    m = matches[0]
    check(m.get("severity") == "high", "queue entry severity == high", m.get("severity"))
    plan = m.get("plan") or {}
    check(plan.get("gateOutcome") == "NeedsApproval", "queue entry plan.gateOutcome == NeedsApproval", plan.get("gateOutcome"))
    check(bool(plan.get("gateReason")), "queue entry plan.gateReason is non-empty")
    check(m.get("alreadyApproved") is False, "alreadyApproved == false (not yet decided)", m.get("alreadyApproved"))
    check(m.get("confidence") == 0.75, "confidence == 0.75 (the fake model's scripted value)", m.get("confidence"))
for passed, desc, detail in results:
    tag = "PASS" if passed else "FAIL"
    suffix = f" (got {detail})" if detail != "" else ""
    print(f"  {tag}: {desc}{suffix}")
PYEOF
)
  echo "$verify_queue"
  pass_count=$(echo "$verify_queue" | grep -c "^  PASS:")
  fail_count=$(echo "$verify_queue" | grep -c "^  FAIL:")
  PASS=$((PASS + pass_count))
  FAIL=$((FAIL + fail_count))

  echo "-- 11b3b. Capability gating: a viewer is denied both the queue and the write actions --"
  TEST_VIEWER_ID="usr_smoketest0000000000000"
  viewer_hash=$(docker run --rm "$HUB_IMAGE" hash-password "smoke-test-password" | tr -d '\r\n')
  docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -v ON_ERROR_STOP=1 >/dev/null <<SQL
DO \$\$
DECLARE org_id text;
BEGIN
  SELECT id INTO org_id FROM organisations LIMIT 1;
  DELETE FROM refresh_tokens WHERE user_id = '$TEST_VIEWER_ID';
  DELETE FROM grants WHERE principal_id = '$TEST_VIEWER_ID';
  DELETE FROM users WHERE id = '$TEST_VIEWER_ID';
  INSERT INTO users (id, tenant_id, email, display_name, password_hash, must_change_password)
  VALUES ('$TEST_VIEWER_ID', org_id, 'smoketest-viewer@localhost', 'Smoke Test Viewer', '$viewer_hash', false);
  INSERT INTO grants (id, tenant_id, principal_type, principal_id, role_id, scope, granted_by)
  VALUES ('grt_smoketest0000000000000', org_id, 'user', '$TEST_VIEWER_ID', 'viewer', '{"type":"AllClusters"}', '$TEST_VIEWER_ID');
END \$\$;
SQL
  viewer_token=$(curl -sS -X POST "$API/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"smoketest-viewer@localhost","password":"smoke-test-password"}' | json_field accessToken)

  status=$(curl -sS -o /dev/null -w "%{http_code}" "$API/api/v1/approvals" -H "Authorization: Bearer $viewer_token")
  check_status "viewer denied GET /approvals (403, remediation:approve)" 403 "$status"
  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/incidents/$SECTION11_INC_PLAN/approve" -H "Authorization: Bearer $viewer_token")
  check_status "viewer denied POST .../approve (403, remediation:approve)" 403 "$status"
  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/incidents/$SECTION11_INC_PLAN/reject" \
    -H "Authorization: Bearer $viewer_token" -H "Content-Type: application/json" -d '{"reason":"x"}')
  check_status "viewer denied POST .../reject (403, remediation:reject)" 403 "$status"

  docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -v ON_ERROR_STOP=1 >/dev/null <<SQL
DELETE FROM refresh_tokens WHERE user_id = '$TEST_VIEWER_ID';
DELETE FROM grants WHERE principal_id = '$TEST_VIEWER_ID';
DELETE FROM users WHERE id = '$TEST_VIEWER_ID';
SQL

  echo "-- 11b3c. Reject requires a non-empty reason (400 before touching anything) --"
  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/incidents/$SECTION11_INC_PLAN/reject" \
    -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" -d '{}')
  check_status "reject with no reason field returns 400" 400 "$status"

  echo "-- 11b3d. Approve executes a real, in-place change against the disposable cluster --"
  # BACKLOG.md E4 / BUGS.md 91: was degraded to "correctly refuses an
  # incident that was never AwaitingApproval" once F17 made ownership
  # resolution untestable here -- see 11b3's header comment. Restored: this
  # is section 11's one real exercise of a SUCCESSFUL approve, and unlike the
  # pre-F17 assertion this replaces (written before internal/api/remediation_exec.go's
  # executor existed, when approve only recorded a decision), approving now
  # genuinely calls executeApprovedPlan -- a REAL scale of the REAL
  # smoketest-deploy Deployment on the disposable cluster, verified below
  # against the live object itself, not just the response body.
  approve_resp=$(curl -sS -o /tmp/smoketest_approve.json -w "%{http_code}" -X POST \
    "$API/api/v1/incidents/$SECTION11_INC_PLAN/approve" -H "Authorization: Bearer $access_token")
  check_status "POST .../approve on a real AwaitingApproval plan returns 200" 200 "$approve_resp"

  verify_approve=$(python3 - "$(cat /tmp/smoketest_approve.json)" <<'PYEOF'
import json, sys
d = json.loads(sys.argv[1])
results = []
def check(cond, desc, detail=""):
    results.append((bool(cond), desc, detail))
check(d.get("verdict") == "approved", "verdict == approved", d.get("verdict"))
# executeApprovedPlan runs synchronously inside the approve request itself
# (internal/api/approvals.go) -- Validating is where a successfully executed,
# reversible in-place change lands pending ValidationSweeper's own later
# resolve/reopen decision, never AwaitingApproval again.
check(d.get("incidentState") == "Validating", "incidentState == Validating (approved and really executed)", d.get("incidentState"))
check("executed" in (d.get("message") or "").lower(), "message says the change was actually executed, not merely recorded", d.get("message"))
for passed, desc, detail in results:
    tag = "PASS" if passed else "FAIL"
    suffix = f" (got {detail})" if detail != "" else ""
    print(f"  {tag}: {desc}{suffix}")
PYEOF
)
  echo "$verify_approve"
  pass_count=$(echo "$verify_approve" | grep -c "^  PASS:")
  fail_count=$(echo "$verify_approve" | grep -c "^  FAIL:")
  PASS=$((PASS + pass_count))
  FAIL=$((FAIL + fail_count))

  db_state_after_approve=$(docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -t -A -c \
    "SELECT state FROM incidents WHERE id = '$SECTION11_INC_PLAN';")
  check_status "incidents.state itself is Validating in the DB (real state, not just the response body)" "Validating" "$db_state_after_approve"

  # Same "||" boolean-cast note as the rec_row check above -- "true", not "t".
  decision_row=$(docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -t -A -F'|' -c \
    "SELECT verdict || '|' || (actor_id IS NOT NULL) FROM remediation_approval_decisions WHERE incident_id = '$SECTION11_INC_PLAN';")
  check_status "a real remediation_approval_decisions row was recorded (verdict=approved, a real actor)" "approved|true" "$decision_row"

  # The actual point of this whole fixture: the LIVE object, on the real
  # disposable cluster, genuinely changed -- not a claim in a response body.
  live_replicas=$(kubectl --kubeconfig "$DISPOSABLE_KUBECONFIG" get deployment smoketest-deploy -n default -o jsonpath='{.spec.replicas}' 2>/dev/null)
  check_status "the real smoketest-deploy Deployment on the disposable cluster now has spec.replicas == 4" "4" "$live_replicas"

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/incidents/$SECTION11_INC_PLAN/approve" -H "Authorization: Bearer $access_token")
  check_status "approving it again is refused (409, no longer AwaitingApproval)" 409 "$status"

  echo "-- 11b3f. A live policy edit changes the SAME plan's gate outcome --"
  # BACKLOG.md E4 / BUGS.md 91: was degraded to "gate-verdict effect not
  # observable here" once F17 made ownership resolution untestable in this
  # section -- see 11b3's header comment for the full history. Restored, now
  # that ownership resolves for real: this is the actual point of the
  # subsection, not just the PUT/GET mechanics -- the SAME incident's SAME
  # plan resolves to a DIFFERENT gate outcome (NeedsApproval -> AutoApprove)
  # purely because the autonomy policy changed underneath it, live, with no
  # hub restart. AutoApprove still routes to AwaitingApproval, not a
  # different incidentState (internal/orchestrator/orchestrator.go's
  # advanceForPlan: "Deliberately the SAME next state as NeedsApproval" --
  # unattended execution, gated separately, is the only thing that acts on
  # AutoApprove without a human) -- so what changes here is plan.gateOutcome
  # and plan.gateReason, verified below, not incidentState.
  #
  # Closes STATUS.md §50's own flagged gap: DefaultAutonomyPolicy used to be
  # the only source internal/orchestrator.Advance consulted; this proves the
  # real, DB-backed override (internal/settings, migration
  # 000028_autonomy_policy) actually persists, reads back live, AND changes
  # what the gate actually decides.
  #
  # Reuses the same still-running "toolloop-plan" fake-llm-server as 11b3
  # above (confidence 0.75, riskLevel "medium", reversible true) against a
  # FRESH incident, so this subsection's own PUT can't be accused of having
  # raced 11b3d's state. It runs BEFORE 11b3e on purpose: once 11b3e rejects
  # a ScaleDeployment for smoketest-deploy, the gate correctly refuses to
  # auto-approve that same action on that same workload again
  # (internal/orchestrator/recurrence.go's demoteIfPreviouslyRejected).
  SECTION11_INC_POLICY="inc_smoketesttoolloop0000006"
  SECTION11_FND_POLICY="fnd_smoketesttoolloop0000006"
  now_ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -v ON_ERROR_STOP=1 >/dev/null <<SQL
DO \$\$
DECLARE tid text;
BEGIN
  SELECT tenant_id INTO tid FROM clusters WHERE id = '$section11_cluster_id';
  -- object_key/workload_key (BUGS.md 87) -- see 11b3's fixture above for why.
  INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count, object_key, workload_key)
  VALUES ('$SECTION11_INC_POLICY', tid, '$section11_cluster_id', 'smoketest-toolloop-fp-6', 'high', 'Detected', '$now_ts', '$now_ts', 1, 'v1/Pod|default|smoketest-pod', 'apps/v1/Deployment|default|smoketest-deploy');
  INSERT INTO findings (id, tenant_id, cluster_id, detector_id, detector_version, fingerprint, gvk, namespace, object_name, occurrence_count, severity, occurred_at, incident_id)
  VALUES ('$SECTION11_FND_POLICY', tid, '$section11_cluster_id', 'pod-status', '0.1.0', 'smoketest-toolloop-fp-6', 'v1/Pod', 'default', 'smoketest-pod', 4, 'high', '$now_ts', '$SECTION11_INC_POLICY');
END \$\$;
SQL

  baseline_analyze_resp=$(analyze_and_wait "$SECTION11_INC_POLICY" /tmp/smoketest_policy_before.json)
  check_status "baseline analyze (DefaultAutonomyPolicy still in force) is accepted (202) and its analysis lands" 202 "$baseline_analyze_resp"
  before_state=$(json_field incidentState < /tmp/smoketest_policy_before.json)
  check_status "before the policy change: incidentState == AwaitingApproval (ownership resolved, real plan offered)" "AwaitingApproval" "$before_state"
  before_gate=$(python3 -c "import json; print((json.load(open('/tmp/smoketest_policy_before.json')).get('plan') or {}).get('gateOutcome',''))")
  check_status "before the policy change: gateOutcome == NeedsApproval (medium risk / 0.75 confidence, under DefaultAutonomyPolicy's ceiling)" "NeedsApproval" "$before_gate"

  # Now raise the ceiling to medium and drop the confidence floor to 0.5 —
  # both needed, since the fixed plan is medium-risk at confidence 0.75:
  # raising the risk ceiling alone would still fall through to NeedsApproval
  # on confidence (0.75 < DefaultAutonomyPolicy's 0.90), and vice versa.
  policy_put_resp=$(curl -sS -o /dev/null -w "%{http_code}" -X PUT "$API/api/v1/admin/settings" \
    -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" \
    -d '{"autonomy":{"autoApproveMaxRisk":"medium","minConfidenceForAutoApprove":0.5,"requireReversibleForAutoApprove":true}}')
  check_status "PUT autonomy.autoApproveMaxRisk=medium/minConfidenceForAutoApprove=0.5 accepted" 200 "$policy_put_resp"

  get_after_policy_put=$(curl -sS "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token")
  effective_risk=$(echo "$get_after_policy_put" | python3 -c "import sys,json; print(json.load(sys.stdin)['autonomy']['effectiveAutoApproveMaxRisk'])")
  check_status "GET reflects the new effective ceiling (medium) immediately, no hub restart" "medium" "$effective_risk"

  # Re-run the SAME investigation against the SAME incident (incident
  # :reanalyse is explicitly invokable from any state, per
  # orchestrator.MarkInvestigating's own doc comment) -- the fake model
  # returns the identical scripted plan/confidence both times; only the
  # policy changed in between.
  after_analyze_resp=$(analyze_and_wait "$SECTION11_INC_POLICY" /tmp/smoketest_policy_after.json)
  check_status "re-analyze after the policy change is accepted (202) and its analysis lands" 202 "$after_analyze_resp"
  after_state=$(json_field incidentState < /tmp/smoketest_policy_after.json)
  check_status "AFTER the policy change: still AwaitingApproval -- AutoApprove routes here too (a human, or unattended execution if enabled, acts on it next)" "AwaitingApproval" "$after_state"
  after_gate=$(python3 -c "import json; print((json.load(open('/tmp/smoketest_policy_after.json')).get('plan') or {}).get('gateOutcome',''))")
  check_status "AFTER the policy change: gateOutcome == AutoApprove -- the SAME plan, the SAME confidence, a DIFFERENT verdict, purely from the live policy edit" "AutoApprove" "$after_gate"

  db_state_after_policy=$(docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -t -A -c \
    "SELECT state FROM incidents WHERE id = '$SECTION11_INC_POLICY';")
  check_status "incidents.state itself is AwaitingApproval in the DB (real state, not just the response body)" "AwaitingApproval" "$db_state_after_policy"

  db_gate_after_policy=$(docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -t -A -c \
    "SELECT gate_outcome FROM remediation_recommendations WHERE incident_id = '$SECTION11_INC_POLICY' ORDER BY created_at DESC LIMIT 1;")
  check_status "the latest remediation_recommendations row itself carries gate_outcome=AutoApprove (real DB state, a fresh row per re-analysis, not just the response body)" "AutoApprove" "$db_gate_after_policy"

  # Restore the safe, conservative baseline immediately -- this is a real,
  # persistent singleton row, same discipline section 8's clear_all_body
  # follows, not a throwaway fixture.
  curl -sS -X PUT "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" \
    -d '{"autonomy":{"autoApproveMaxRisk":null,"minConfidenceForAutoApprove":null,"requireReversibleForAutoApprove":true}}' >/dev/null

  echo "-- 11b3e. Reject transitions a real AwaitingApproval plan to Dismissed --"
  # BACKLOG.md E4 / BUGS.md 91: was degraded the same way 11b3d was -- see
  # its header comment. Needs its OWN incident/plan (11b3d's has already been
  # approved and executed, so it is no longer AwaitingApproval to reject).
  SECTION11_INC_REJECT="inc_smoketesttoolloop0000007"
  SECTION11_FND_REJECT="fnd_smoketesttoolloop0000007"
  now_ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -v ON_ERROR_STOP=1 >/dev/null <<SQL
DO \$\$
DECLARE tid text;
BEGIN
  SELECT tenant_id INTO tid FROM clusters WHERE id = '$section11_cluster_id';
  INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count, object_key, workload_key)
  VALUES ('$SECTION11_INC_REJECT', tid, '$section11_cluster_id', 'smoketest-toolloop-fp-7', 'high', 'Detected', '$now_ts', '$now_ts', 1, 'v1/Pod|default|smoketest-pod', 'apps/v1/Deployment|default|smoketest-deploy');
  INSERT INTO findings (id, tenant_id, cluster_id, detector_id, detector_version, fingerprint, gvk, namespace, object_name, occurrence_count, severity, occurred_at, incident_id)
  VALUES ('$SECTION11_FND_REJECT', tid, '$section11_cluster_id', 'pod-status', '0.1.0', 'smoketest-toolloop-fp-7', 'v1/Pod', 'default', 'smoketest-pod', 4, 'high', '$now_ts', '$SECTION11_INC_REJECT');
END \$\$;
SQL

  analyze_reject_resp=$(analyze_and_wait "$SECTION11_INC_REJECT" /tmp/smoketest_analyze_reject.json)
  check_status "POST .../analyze for the reject fixture is accepted (202) and its analysis lands" 202 "$analyze_reject_resp"
  reject_fixture_state=$(json_field incidentState < /tmp/smoketest_analyze_reject.json)
  check_status "the reject fixture reaches AwaitingApproval too, same as 11b3's" "AwaitingApproval" "$reject_fixture_state"

  reject_resp=$(curl -sS -o /tmp/smoketest_reject.json -w "%{http_code}" -X POST \
    "$API/api/v1/incidents/$SECTION11_INC_REJECT/reject" -H "Authorization: Bearer $access_token" \
    -H "Content-Type: application/json" -d '{"reason":"smoke-test: not a real fix, rejecting on purpose"}')
  check_status "POST .../reject (with a reason) on a real AwaitingApproval incident returns 200" 200 "$reject_resp"

  # Rejecting a PLAN must not close the INCIDENT (code review finding 6).
  # This asserted "Dismissed" until 2026-09-05, which was the bug written down
  # as a passing test: Dismissed is terminal and means "needs no action from
  # ARGUS", so refusing an unsafe fix silently dropped a live fault out of the
  # queue. See internal/orchestrator's StatePlanRejected.
  reject_state=$(json_field incidentState < /tmp/smoketest_reject.json)
  check_status "reject transitions incidentState to PlanRejected, not Dismissed" "PlanRejected" "$reject_state"

  db_state_after_reject=$(docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -t -A -c \
    "SELECT state FROM incidents WHERE id = '$SECTION11_INC_REJECT';")
  check_status "incidents.state itself is PlanRejected in the DB (real state, not just the response body)" "PlanRejected" "$db_state_after_reject"

  # ...and it is still in the queue, counted as needing a human. The whole
  # point of the new state is that the incident does not disappear: the fault
  # is unchanged and the next move is a person's.
  rejected_still_counted=$(curl -sS "$API/api/v1/incidents?requiresAction=true&limit=200" -H "Authorization: Bearer $access_token" | python3 -c \
    "import sys,json; print(any(x.get('id')=='$SECTION11_INC_REJECT' for x in json.load(sys.stdin).get('incidents',[])))")
  check_status "the rejected incident still appears under ?requiresAction=true (the fault is live; only the plan was refused)" "True" "$rejected_still_counted"

  reject_row=$(docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -t -A -F'|' -c \
    "SELECT verdict || '|' || reason FROM remediation_approval_decisions WHERE incident_id = '$SECTION11_INC_REJECT';")
  check_status "a real remediation_approval_decisions row was recorded (verdict=rejected, with the given reason)" \
    "rejected|smoke-test: not a real fix, rejecting on purpose" "$reject_row"

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/incidents/$SECTION11_INC_REJECT/reject" \
    -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" -d '{"reason":"x"}')
  check_status "rejecting it again is refused (409, no longer AwaitingApproval)" 409 "$status"

  final_queue_resp=$(curl -sS "$API/api/v1/approvals" -H "Authorization: Bearer $access_token")
  final_queue_has_it=$(echo "$final_queue_resp" | python3 -c \
    "import sys,json; print(any(x.get('incidentId')=='$SECTION11_INC_REJECT' for x in json.load(sys.stdin).get('approvals',[])))")
  check_status "the incident whose plan was rejected no longer appears in the approval queue" "False" "$final_queue_has_it"

  echo "-- 11c. Disconnected cluster -> 503, no pointless loop, no analyses row written --"
  kill "$AGENT_PID" >/dev/null 2>&1
  wait "$AGENT_PID" 2>/dev/null
  sleep 1

  SECTION11_INC_DISCONNECTED="inc_smoketesttoolloop0000003"
  SECTION11_FND_DISCONNECTED="fnd_smoketesttoolloop0000003"
  now_ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -v ON_ERROR_STOP=1 >/dev/null <<SQL
DO \$\$
DECLARE tid text;
BEGIN
  SELECT tenant_id INTO tid FROM clusters WHERE id = '$section11_cluster_id';
  INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
  VALUES ('$SECTION11_INC_DISCONNECTED', tid, '$section11_cluster_id', 'smoketest-toolloop-fp-3', 'low', 'Detected', '$now_ts', '$now_ts', 1);
  INSERT INTO findings (id, tenant_id, cluster_id, detector_id, detector_version, fingerprint, gvk, namespace, object_name, occurrence_count, severity, occurred_at, incident_id)
  VALUES ('$SECTION11_FND_DISCONNECTED', tid, '$section11_cluster_id', 'pod-status', '0.1.0', 'smoketest-toolloop-fp-3', 'v1/Pod', 'default', 'x', 1, 'low', '$now_ts', '$SECTION11_INC_DISCONNECTED');
END \$\$;
SQL

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/incidents/$SECTION11_INC_DISCONNECTED/analyze" -H "Authorization: Bearer $access_token")
  check_status "POST .../analyze against a disconnected cluster fails fast with 503, not a pointless/partial loop" 503 "$status"

  analyses_count=$(docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -t -A -c \
    "SELECT count(*) FROM analyses WHERE incident_id = '$SECTION11_INC_DISCONNECTED';")
  if [[ "$analyses_count" == "0" ]]; then
    echo "  PASS: no analyses row was written for the disconnected-cluster attempt"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: expected 0 analyses rows for the disconnected-cluster attempt, got $analyses_count"
    FAIL=$((FAIL + 1))
  fi

  # Cleanup -- throwaway fixtures, not application state. Decisions before
  # recommendations (remediation_approval_decisions.recommendation_id
  # REFERENCES remediation_recommendations(id) — FK order matters here).
  # evidence/analysis_embeddings before analyses for the same reason (BUGS.md
  # 113's discovery while verifying this task's own fix): neither
  # `evidence.analysis_id` nor `analysis_embeddings.analysis_id` is
  # ON DELETE CASCADE, so a real investigation's own recorded tool calls and
  # (once internal/knowledge's backfill sweep reaches it) embedding row block
  # this DELETE FROM analyses with a foreign-key violation under
  # ON_ERROR_STOP=1 -- which previously aborted this whole block silently,
  # leaving findings/incidents behind to accumulate across every run this
  # script ever made (confirmed live: found 17 leaked `inc_smoketest%` rows,
  # some dating back far enough to starve internal/autoanalyze's
  # oldest-first candidate query -- filed separately).
  #
  # BACKLOG.md E4/BUGS.md 91: executions before recommendations too, added
  # here for the identical reason -- found live the moment 11b3d started
  # producing a REAL remediation_executions row (remediation_executions
  # .recommendation_id REFERENCES remediation_recommendations(id), no
  # cascade): "update or delete on table remediation_recommendations
  # violates foreign key constraint remediation_executions_recommendation_id
  # _fkey". Before this fix, section 11 never executed anything for real, so
  # this table was always empty for these fixtures and the gap never fired.
  docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -v ON_ERROR_STOP=1 >/dev/null <<SQL
DELETE FROM remediation_approval_decisions WHERE incident_id LIKE 'inc_smoketesttoolloop%';
DELETE FROM remediation_execution_attempts WHERE incident_id LIKE 'inc_smoketesttoolloop%';
DELETE FROM remediation_executions WHERE incident_id LIKE 'inc_smoketesttoolloop%';
DELETE FROM remediation_recommendations WHERE incident_id LIKE 'inc_smoketesttoolloop%';
DELETE FROM evidence WHERE analysis_id IN (SELECT id FROM analyses WHERE incident_id LIKE 'inc_smoketesttoolloop%');
DELETE FROM analysis_embeddings WHERE incident_id LIKE 'inc_smoketesttoolloop%';
DELETE FROM analyses WHERE incident_id LIKE 'inc_smoketesttoolloop%';
DELETE FROM findings WHERE incident_id LIKE 'inc_smoketesttoolloop%';
DELETE FROM incidents WHERE id LIKE 'inc_smoketesttoolloop%';
SQL
  # BUGS.md 113: no need to clear "llm" here any more -- the smoketest AI
  # provider row activate_fake_llm_provider created stays active (and is
  # simply repointed at each subsequent section's own fake-llm-server) until
  # this whole script's EXIT trap restores whatever was active before it
  # ever ran.
else
  echo "  SKIP: no enrolled cluster for section 11 -- skipping the rest of it"
fi

cleanup_section11

echo "== 12. Decommissioning a cluster with a live tunnel forcibly cuts it (Gateway.Disconnect) =="
# Answers, and verifies, the two real gaps flagged directly against this
# codebase: "when we decommission a cluster, how do we remove the agent from
# the cluster as well? will it keep trying to connect?"
#
#  (a) Before this task, a tunnel connection already open at the moment of
#      decommission just kept running (heartbeats, etc.) until it happened
#      to drop on its own -- only a subsequent RECONNECT attempt was ever
#      refused (lookupClusterBySerial's clusterState check,
#      internal/gateway/server.go). internal/gateway.Gateway.Disconnect,
#      called from handleDecommissionCluster right after the state update
#      commits, closes that gap by force-closing any live connection the
#      instant a cluster is archived. This section verifies exactly that,
#      machine-checkably.
#  (b) Nothing in the protocol can tell the agent "you are permanently
#      done, stop trying" -- decommissioning only ever updates the hub's own
#      records, so the real argus-agent process keeps running in-cluster
#      and keeps retrying with backoff forever, indistinguishable to it from
#      an ordinary network blip, until a human runs `helm uninstall
#      argus-agent -n argus-system --kube-context <ctx>` inside that cluster.
#      That's not something a script can verify by itself (it's a fact about
#      what does NOT happen, forever) -- it's stated explicitly instead, in
#      ConfirmDecommissionModal.tsx's post-decommission message and in
#      README.md's cluster-management section.
#
# Uses a REAL cmd/agent binary (built and run the same way section 11 does,
# and for the same reason its own comment gives: `go run`'s wrapper PID
# isn't reliably killable), not scripts/simulate-finding -- only a real
# agent has the real reconnect-with-backoff loop
# (internal/agent/client.go's serveTunnelForever) whose own log output can
# prove BOTH halves of this in one place: that its live session actually
# ended right away, AND that its very next automatic reconnect attempt was
# refused.

SECTION12_BIN_DIR=$(mktemp -d)
SECTION12_AGENT_DATA_DIR=$(mktemp -d)
SECTION12_AGENT_LOG=$(mktemp)

cleanup_section12() {
  [[ -n "${SECTION12_AGENT_PID:-}" ]] && kill "$SECTION12_AGENT_PID" >/dev/null 2>&1
  rm -rf "$SECTION12_BIN_DIR" "$SECTION12_AGENT_DATA_DIR" "$SECTION12_AGENT_LOG"
}

go build -o "$SECTION12_BIN_DIR/agent" ./cmd/agent

section12_token=$(curl -sS -X POST "$API/api/v1/clusters/enrollment-tokens" \
  -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" -d '{"ttlClass":"B"}' | json_field token)

ARGUS_ENROLLMENT_TOKEN="$section12_token" ARGUS_HUB_API_URL="$API" \
  ARGUS_CLUSTER_DISPLAY_NAME="smoketest-decommission-cluster" ARGUS_AGENT_DATA_DIR="$SECTION12_AGENT_DATA_DIR" \
  "$SECTION12_BIN_DIR/agent" >"$SECTION12_AGENT_LOG" 2>&1 &
SECTION12_AGENT_PID=$!

section12_cluster_id=""
for _ in $(seq 1 30); do
  section12_cluster_id=$(grep 'is pendingApproval' "$SECTION12_AGENT_LOG" | grep -oP '"cluster_id":"\K[^"]+' | head -1)
  [[ -n "$section12_cluster_id" ]] && break
  sleep 1
done
register_smoketest_cluster "$section12_cluster_id"

if [[ -n "$section12_cluster_id" ]]; then
  echo "  PASS: real agent process enrolled (cluster $section12_cluster_id, pendingApproval)"
  PASS=$((PASS + 1))
else
  if agent_enrollment_blocked "$SECTION12_AGENT_LOG"; then
    echo "  SKIP: the target cluster is already enrolled in this hub, so a second enrollment is correctly refused (409 already-enrolled) -- decommission it first, or point ARGUS_DISPOSABLE_KUBECONFIG at an unenrolled cluster, to exercise this section"
  else
    echo "  FAIL: real agent process never reached pendingApproval -- see agent log: $SECTION12_AGENT_LOG"
    FAIL=$((FAIL + 1))
  fi
fi

if [[ -n "$section12_cluster_id" ]]; then
  curl -sS -X POST "$API/api/v1/clusters/$section12_cluster_id/accept" -H "Authorization: Bearer $access_token" >/dev/null

  section12_state=""
  for _ in $(seq 1 20); do
    section12_state=$(curl -sS "$API/api/v1/clusters/$section12_cluster_id" -H "Authorization: Bearer $access_token" | json_field state)
    [[ "$section12_state" == "Active" ]] && break
    sleep 1
  done
  check_status "real agent's tunnel promotes the cluster to Active before decommissioning" "Active" "$section12_state"

  # Baseline count of "tunnel session ended" lines -- normally 0 (the first
  # tunnel session hasn't ended yet), but read from the log rather than
  # assumed, so the loop below is correct even if that ever changes.
  ended_pattern='tunnel session ended|hub sent terminal signal'
  before_ended_count=$(grep -cE "$ended_pattern" "$SECTION12_AGENT_LOG")

  decommission_status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST \
    "$API/api/v1/clusters/$section12_cluster_id/decommission" -H "Authorization: Bearer $access_token")
  check_status "POST .../decommission while the tunnel is live returns 200" 200 "$decommission_status"

  decommission_state=$(curl -sS "$API/api/v1/clusters/$section12_cluster_id" -H "Authorization: Bearer $access_token" | json_field state)
  check_status "cluster state is Archived immediately after decommissioning" "Archived" "$decommission_state"

  # The actual point of this section: the agent's LIVE session -- still the
  # exact same process, never killed or restarted -- must notice its
  # connection died within a few seconds of decommissioning, not merely on
  # its next heartbeat (every 30s) or never. Before Gateway.Disconnect
  # existed, this would have hung open indefinitely; this loop fails the
  # section (rather than hanging) if that ever regresses. A SECOND line
  # proves the further half too: the agent's own automatic reconnect attempt
  # afterward was also refused rather than allowed back in. The hub refuses
  # it with a terminal signal naming the decommission ("hub sent terminal
  # signal"), on which the agent backs off for tunnelTerminalBackoff instead
  # of retrying; a bare close reads "tunnel session ended". Either counts.
  target_ended_count=$((before_ended_count + 2))
  current_ended_count="$before_ended_count"
  reached=false
  for _ in $(seq 1 40); do
    current_ended_count=$(grep -cE "$ended_pattern" "$SECTION12_AGENT_LOG")
    if [[ "$current_ended_count" -ge "$target_ended_count" ]]; then
      reached=true
      break
    fi
    sleep 1
  done

  if [[ "$reached" == true ]]; then
    echo "  PASS: the agent's live tunnel session ended right away when decommissioned, and its very next automatic reconnect attempt was refused too ($current_ended_count session-ended/refused events observed within 40s -- not left dangling)"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: expected >= $target_ended_count 'tunnel session ended'/'hub sent terminal signal' log lines within 40s of decommissioning, got $current_ended_count -- see agent log: $SECTION12_AGENT_LOG"
    grep -E 'tunnel|terminal' "$SECTION12_AGENT_LOG" | tail -8 | cut -c1-300 | sed 's/^/    agent: /'
    FAIL=$((FAIL + 1))
  fi

  # Bonus, best-effort corroboration from the HUB's own side -- not required
  # for the PASS/FAIL above (already conclusive from the agent's own log),
  # since docker compose's log buffering/availability isn't something this
  # script controls.
  if docker compose -f "$COMPOSE_FILE" logs hub-api 2>/dev/null | grep -q "while Archived"; then
    echo "  PASS: hub-api's own logs show it refusing the decommissioned cluster's reconnect attempt (clusterState check)"
    PASS=$((PASS + 1))
  else
    echo "  NOTE: could not find the hub-side 'while Archived -- closing' log line (informational only -- the agent-log-based check above is authoritative)"
  fi
else
  echo "  SKIP: no enrolled cluster for section 12 -- skipping the rest of it"
fi

cleanup_section12

echo "== 13. Automatic investigation (internal/autoanalyze poller, PUT /admin/settings' automation section) =="
# This section now verifies a genuine CHECKLIST of individually-selectable
# severities (migration 000024_auto_analysis_severities), not the single
# ordered "minimum severity" this replaced: an admin can select e.g. {high,
# critical} while leaving medium out, or select {medium} alone while
# leaving the MORE severe high/critical out -- a combination no single
# "at or above this floor" threshold could ever express. Uses the same
# real-agent + real-tunnel + scripts/fake-llm-server infrastructure
# section 11 already established (built fresh here, in its own bin dir,
# since section 11's own binaries and processes are already torn down by
# cleanup_section11 by the time this section runs), and the same "insert
# incident/finding rows directly via psql" technique section 11 uses (no
# API to create one directly).
#
# 13: severities = {high, critical} -- proves the checklist auto-analyzes
#     every SELECTED severity (not just one), while medium (unselected)
#     is left alone.
# 13b: severities = {medium} ONLY -- the shape a threshold could never
#      express: medium (the least severe of the three fixtures) is
#      auto-analyzed while high and critical (both MORE severe) are NOT,
#      proving this is real set membership, not a relabeled threshold.
# 13c: disabled entirely -- no automatic attempts at all, unchanged
#      behavior from before this task.
# 13d: enabled, but severities = {} (nothing checked) -- proves the "empty
#      selection" semantic is "nothing gets auto-analyzed," never "every
#      severity qualifies" the way the old field's null used to mean (see
#      internal/settings.Config's AutoAnalysisSeverities doc comment).
#
# Each sub-section polls (rather than a single fixed sleep) for
# internal/autoanalyze.DefaultPollInterval's tick to do its work.

SECTION13_BIN_DIR=$(mktemp -d)
SECTION13_AGENT_DATA_DIR=$(mktemp -d)
SECTION13_AGENT_LOG=$(mktemp)
SECTION13_FAKE_LLM_LOG=$(mktemp)
SECTION13_FAKE_LLM_PORT=19092

cleanup_section13() {
  [[ -n "${SECTION13_AGENT_PID:-}" ]] && kill "$SECTION13_AGENT_PID" >/dev/null 2>&1
  [[ -n "${SECTION13_FAKE_LLM_PID:-}" ]] && kill "$SECTION13_FAKE_LLM_PID" >/dev/null 2>&1
  rm -rf "$SECTION13_BIN_DIR" "$SECTION13_AGENT_DATA_DIR" "$SECTION13_AGENT_LOG" "$SECTION13_FAKE_LLM_LOG"
  # Leave automation switched off, same "don't leak this section's config
  # into whatever runs after it" discipline as always -- but NOT the AI
  # provider (BUGS.md 113): the smoketest provider row
  # activate_fake_llm_provider created stays active, repointed by whichever
  # section runs next, until this whole script's EXIT trap restores
  # whatever was active before it ever ran.
  curl -sS -X PUT "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" \
    -d '{"automation":{"autoAnalysisEnabled":false,"autoAnalysisSeverities":[]}}' >/dev/null
}

go build -o "$SECTION13_BIN_DIR/fake-llm-server" ./scripts/fake-llm-server
go build -o "$SECTION13_BIN_DIR/agent" ./cmd/agent

"$SECTION13_BIN_DIR/fake-llm-server" -addr ":$SECTION13_FAKE_LLM_PORT" -mode toolloop >"$SECTION13_FAKE_LLM_LOG" 2>&1 &
SECTION13_FAKE_LLM_PID=$!

section13_token=$(curl -sS -X POST "$API/api/v1/clusters/enrollment-tokens" \
  -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" -d '{"ttlClass":"B"}' | json_field token)

ARGUS_ENROLLMENT_TOKEN="$section13_token" ARGUS_HUB_API_URL="$API" \
  ARGUS_CLUSTER_DISPLAY_NAME="smoketest-autoanalyze-cluster" ARGUS_AGENT_DATA_DIR="$SECTION13_AGENT_DATA_DIR" \
  "$SECTION13_BIN_DIR/agent" >"$SECTION13_AGENT_LOG" 2>&1 &
SECTION13_AGENT_PID=$!

section13_cluster_id=""
for _ in $(seq 1 30); do
  section13_cluster_id=$(grep 'is pendingApproval' "$SECTION13_AGENT_LOG" | grep -oP '"cluster_id":"\K[^"]+' | head -1)
  [[ -n "$section13_cluster_id" ]] && break
  sleep 1
done
register_smoketest_cluster "$section13_cluster_id"

if [[ -n "$section13_cluster_id" ]]; then
  echo "  PASS: real agent process enrolled (cluster $section13_cluster_id, pendingApproval)"
  PASS=$((PASS + 1))
else
  if agent_enrollment_blocked "$SECTION13_AGENT_LOG"; then
    echo "  SKIP: the target cluster is already enrolled in this hub, so a second enrollment is correctly refused (409 already-enrolled) -- decommission it first, or point ARGUS_DISPOSABLE_KUBECONFIG at an unenrolled cluster, to exercise this section"
  else
    echo "  FAIL: real agent process never reached pendingApproval -- see agent log: $SECTION13_AGENT_LOG"
    FAIL=$((FAIL + 1))
  fi
fi

if [[ -n "$section13_cluster_id" ]]; then
  curl -sS -X POST "$API/api/v1/clusters/$section13_cluster_id/accept" -H "Authorization: Bearer $access_token" >/dev/null

  section13_state=""
  for _ in $(seq 1 20); do
    section13_state=$(curl -sS "$API/api/v1/clusters/$section13_cluster_id" -H "Authorization: Bearer $access_token" | json_field state)
    [[ "$section13_state" == "Active" ]] && break
    sleep 1
  done
  check_status "real agent's tunnel promotes the cluster to Active" "Active" "$section13_state"

  activate_fake_llm_provider "http://host.docker.internal:$SECTION13_FAKE_LLM_PORT" "smoketest-autoanalyze-model"

  automation_put_resp=$(curl -sS -X PUT "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" \
    -d '{"automation":{"autoAnalysisEnabled":true,"autoAnalysisSeverities":["high","critical"]}}')
  automation_enabled=$(echo "$automation_put_resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['automation']['autoAnalysisEnabled'])")
  automation_severities=$(echo "$automation_put_resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['automation']['autoAnalysisSeverities'])")
  check_status "PUT .../settings' automation section round-trips autoAnalysisEnabled=True" "True" "$automation_enabled"
  check_status "PUT .../settings' automation section round-trips autoAnalysisSeverities=[high, critical]" "['high', 'critical']" "$automation_severities"

  invalid_severity_status=$(curl -sS -o /dev/null -w "%{http_code}" -X PUT "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" \
    -d '{"automation":{"autoAnalysisEnabled":true,"autoAnalysisSeverities":["urgent"]}}')
  check_status "PUT .../settings' rejects an unrecognized entry in automation.autoAnalysisSeverities" 400 "$invalid_severity_status"

  duplicate_severity_status=$(curl -sS -o /dev/null -w "%{http_code}" -X PUT "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" \
    -d '{"automation":{"autoAnalysisEnabled":true,"autoAnalysisSeverities":["high","high"]}}')
  check_status "PUT .../settings' rejects a duplicate entry in automation.autoAnalysisSeverities" 400 "$duplicate_severity_status"

  # Restore the real {high, critical} selection -- the two checks above each
  # attempted (and were rejected) with a bad body, so the settings row is
  # still exactly what it was before them, but this makes that explicit
  # rather than relying on the rejected PUTs having had no effect.
  curl -sS -X PUT "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" \
    -d '{"automation":{"autoAnalysisEnabled":true,"autoAnalysisSeverities":["high","critical"]}}' >/dev/null

  SECTION13_INC_HIGH="inc_smoketestautoanalyze001"
  SECTION13_FND_HIGH="fnd_smoketestautoanalyze001"
  SECTION13_INC_MEDIUM="inc_smoketestautoanalyze002"
  SECTION13_FND_MEDIUM="fnd_smoketestautoanalyze002"
  SECTION13_INC_CRITICAL="inc_smoketestautoanalyze003"
  SECTION13_FND_CRITICAL="fnd_smoketestautoanalyze003"
  now_ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -v ON_ERROR_STOP=1 >/dev/null <<SQL
DO \$\$
DECLARE tid text;
BEGIN
  SELECT tenant_id INTO tid FROM clusters WHERE id = '$section13_cluster_id';
  INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
  VALUES ('$SECTION13_INC_HIGH', tid, '$section13_cluster_id', 'smoketest-autoanalyze-fp-high', 'high', 'Detected', '$now_ts', '$now_ts', 1);
  INSERT INTO findings (id, tenant_id, cluster_id, detector_id, detector_version, fingerprint, gvk, namespace, object_name, occurrence_count, severity, occurred_at, incident_id)
  VALUES ('$SECTION13_FND_HIGH', tid, '$section13_cluster_id', 'pod-status', '0.1.0', 'smoketest-autoanalyze-fp-high', 'v1/Pod', 'default', 'autoanalyze-high-pod', 3, 'high', '$now_ts', '$SECTION13_INC_HIGH');
  INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
  VALUES ('$SECTION13_INC_MEDIUM', tid, '$section13_cluster_id', 'smoketest-autoanalyze-fp-medium', 'medium', 'Detected', '$now_ts', '$now_ts', 1);
  INSERT INTO findings (id, tenant_id, cluster_id, detector_id, detector_version, fingerprint, gvk, namespace, object_name, occurrence_count, severity, occurred_at, incident_id)
  VALUES ('$SECTION13_FND_MEDIUM', tid, '$section13_cluster_id', 'pod-status', '0.1.0', 'smoketest-autoanalyze-fp-medium', 'v1/Pod', 'default', 'autoanalyze-medium-pod', 2, 'medium', '$now_ts', '$SECTION13_INC_MEDIUM');
  INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
  VALUES ('$SECTION13_INC_CRITICAL', tid, '$section13_cluster_id', 'smoketest-autoanalyze-fp-critical', 'critical', 'Detected', '$now_ts', '$now_ts', 1);
  INSERT INTO findings (id, tenant_id, cluster_id, detector_id, detector_version, fingerprint, gvk, namespace, object_name, occurrence_count, severity, occurred_at, incident_id)
  VALUES ('$SECTION13_FND_CRITICAL', tid, '$section13_cluster_id', 'pod-status', '0.1.0', 'smoketest-autoanalyze-fp-critical', 'v1/Pod', 'default', 'autoanalyze-critical-pod', 1, 'critical', '$now_ts', '$SECTION13_INC_CRITICAL');
END \$\$;
SQL

  # Polls rather than a single fixed sleep -- internal/autoanalyze.DefaultPollInterval
  # is 15s, so this allows up to 3 ticks (45s) before declaring failure, the
  # same "loop with sleep 1, bounded iteration count" pattern section 12
  # uses above rather than guessing one exact sleep duration. Waits for BOTH
  # selected severities (high and critical), not just one, since the whole
  # point here is that every severity in the set gets picked up, not just
  # whichever happens to be the highest.
  section13_both_analyzed=false
  for _ in $(seq 1 50); do
    both_analyzed_count=$(docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -t -A -c \
      "SELECT count(*) FROM analyses WHERE incident_id IN ('$SECTION13_INC_HIGH', '$SECTION13_INC_CRITICAL');" | tr -d '[:space:]')
    if [[ "$both_analyzed_count" == "2" ]]; then
      section13_both_analyzed=true
      break
    fi
    sleep 1
  done

  if [[ "$section13_both_analyzed" == true ]]; then
    echo "  PASS: both the high- and critical-severity incidents got a real analyses row automatically, with no POST .../analyze call, within one poll interval"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: the high/critical incidents never both got an automatic analysis within 50s -- see hub-api logs"
    FAIL=$((FAIL + 1))
  fi

  medium_analysis_count=$(docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -t -A -c \
    "SELECT count(*) FROM analyses WHERE incident_id = '$SECTION13_INC_MEDIUM';" | tr -d '[:space:]')
  check_status "the medium-severity incident (not in the {high, critical} selection) was NOT automatically analyzed" "0" "$medium_analysis_count"

  high_attempted=$(docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -t -A -c \
    "SELECT auto_analysis_attempted_at IS NOT NULL FROM incidents WHERE id = '$SECTION13_INC_HIGH';" | tr -d '[:space:]')
  critical_attempted=$(docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -t -A -c \
    "SELECT auto_analysis_attempted_at IS NOT NULL FROM incidents WHERE id = '$SECTION13_INC_CRITICAL';" | tr -d '[:space:]')
  medium_attempted=$(docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -t -A -c \
    "SELECT auto_analysis_attempted_at IS NOT NULL FROM incidents WHERE id = '$SECTION13_INC_MEDIUM';" | tr -d '[:space:]')
  check_status "the high incident is marked auto_analysis_attempted_at (won't be re-attempted automatically)" "t" "$high_attempted"
  check_status "the critical incident is marked auto_analysis_attempted_at (won't be re-attempted automatically)" "t" "$critical_attempted"
  check_status "the medium incident is NOT marked attempted (it was never eligible, not a failed attempt)" "f" "$medium_attempted"

  # The actual point of this section, made explicit: the medium incident
  # still requires (and accepts) a manual click, exactly the behavior this
  # task's checklist is supposed to leave untouched for anything not
  # selected.
  manual_analyze_status=$(analyze_and_wait "$SECTION13_INC_MEDIUM" /tmp/smoketest_analyze_manual_analyze_status.json)
  check_status "the medium incident can still be analyzed by a manual POST .../analyze" 202 "$manual_analyze_status"
  check_status "...and the background run completed (no analysisError on the incident)" "None" "$(python3 -c "import json; print(json.load(open('/tmp/smoketest_analyze_manual_analyze_status.json')).get('analysisError'))")"

  echo "-- 13b. severities = {medium} ONLY -- the shape a single ordered threshold could never express: medium (less severe) is auto-analyzed while high/critical (MORE severe) are deliberately excluded --"
  curl -sS -X PUT "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" \
    -d '{"automation":{"autoAnalysisEnabled":true,"autoAnalysisSeverities":["medium"]}}' >/dev/null

  SECTION13_INC_MEDIUM2="inc_smoketestautoanalyze004"
  SECTION13_FND_MEDIUM2="fnd_smoketestautoanalyze004"
  SECTION13_INC_HIGH2="inc_smoketestautoanalyze005"
  SECTION13_FND_HIGH2="fnd_smoketestautoanalyze005"
  SECTION13_INC_CRITICAL2="inc_smoketestautoanalyze006"
  SECTION13_FND_CRITICAL2="fnd_smoketestautoanalyze006"
  now_ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -v ON_ERROR_STOP=1 >/dev/null <<SQL
DO \$\$
DECLARE tid text;
BEGIN
  SELECT tenant_id INTO tid FROM clusters WHERE id = '$section13_cluster_id';
  INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
  VALUES ('$SECTION13_INC_MEDIUM2', tid, '$section13_cluster_id', 'smoketest-autoanalyze-fp-medium2', 'medium', 'Detected', '$now_ts', '$now_ts', 1);
  INSERT INTO findings (id, tenant_id, cluster_id, detector_id, detector_version, fingerprint, gvk, namespace, object_name, occurrence_count, severity, occurred_at, incident_id)
  VALUES ('$SECTION13_FND_MEDIUM2', tid, '$section13_cluster_id', 'pod-status', '0.1.0', 'smoketest-autoanalyze-fp-medium2', 'v1/Pod', 'default', 'autoanalyze-medium2-pod', 1, 'medium', '$now_ts', '$SECTION13_INC_MEDIUM2');
  INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
  VALUES ('$SECTION13_INC_HIGH2', tid, '$section13_cluster_id', 'smoketest-autoanalyze-fp-high2', 'high', 'Detected', '$now_ts', '$now_ts', 1);
  INSERT INTO findings (id, tenant_id, cluster_id, detector_id, detector_version, fingerprint, gvk, namespace, object_name, occurrence_count, severity, occurred_at, incident_id)
  VALUES ('$SECTION13_FND_HIGH2', tid, '$section13_cluster_id', 'pod-status', '0.1.0', 'smoketest-autoanalyze-fp-high2', 'v1/Pod', 'default', 'autoanalyze-high2-pod', 1, 'high', '$now_ts', '$SECTION13_INC_HIGH2');
  INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
  VALUES ('$SECTION13_INC_CRITICAL2', tid, '$section13_cluster_id', 'smoketest-autoanalyze-fp-critical2', 'critical', 'Detected', '$now_ts', '$now_ts', 1);
  INSERT INTO findings (id, tenant_id, cluster_id, detector_id, detector_version, fingerprint, gvk, namespace, object_name, occurrence_count, severity, occurred_at, incident_id)
  VALUES ('$SECTION13_FND_CRITICAL2', tid, '$section13_cluster_id', 'pod-status', '0.1.0', 'smoketest-autoanalyze-fp-critical2', 'v1/Pod', 'default', 'autoanalyze-critical2-pod', 1, 'critical', '$now_ts', '$SECTION13_INC_CRITICAL2');
END \$\$;
SQL

  section13_medium2_analyzed=false
  for _ in $(seq 1 50); do
    medium2_analysis_count=$(docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -t -A -c \
      "SELECT count(*) FROM analyses WHERE incident_id = '$SECTION13_INC_MEDIUM2';" | tr -d '[:space:]')
    if [[ "$medium2_analysis_count" == "1" ]]; then
      section13_medium2_analyzed=true
      break
    fi
    sleep 1
  done

  if [[ "$section13_medium2_analyzed" == true ]]; then
    echo "  PASS: with severities = {medium}, the medium-severity incident got a real analyses row automatically"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: the medium-severity incident never got an automatic analysis within 50s under severities = {medium} -- see hub-api logs"
    FAIL=$((FAIL + 1))
  fi

  # The crux of this sub-section: high and critical are MORE severe than
  # medium, but they are NOT in the selected set, so they must be left
  # completely untouched -- something a single "at or above" threshold
  # could never do (any threshold that includes medium necessarily also
  # includes everything above it).
  high2_analysis_count=$(docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -t -A -c \
    "SELECT count(*) FROM analyses WHERE incident_id = '$SECTION13_INC_HIGH2';" | tr -d '[:space:]')
  critical2_analysis_count=$(docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -t -A -c \
    "SELECT count(*) FROM analyses WHERE incident_id = '$SECTION13_INC_CRITICAL2';" | tr -d '[:space:]')
  check_status "with severities = {medium}, the MORE severe high incident was NOT automatically analyzed (impossible to express with a single threshold)" "0" "$high2_analysis_count"
  check_status "with severities = {medium}, the MORE severe critical incident was NOT automatically analyzed (impossible to express with a single threshold)" "0" "$critical2_analysis_count"

  echo "-- 13c. Disabled entirely -> no automatic attempts at all --"
  curl -sS -X PUT "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" \
    -d '{"automation":{"autoAnalysisEnabled":false,"autoAnalysisSeverities":[]}}' >/dev/null

  SECTION13_INC_DISABLED="inc_smoketestautoanalyze007"
  SECTION13_FND_DISABLED="fnd_smoketestautoanalyze007"
  now_ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -v ON_ERROR_STOP=1 >/dev/null <<SQL
DO \$\$
DECLARE tid text;
BEGIN
  SELECT tenant_id INTO tid FROM clusters WHERE id = '$section13_cluster_id';
  INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
  VALUES ('$SECTION13_INC_DISABLED', tid, '$section13_cluster_id', 'smoketest-autoanalyze-fp-disabled', 'critical', 'Detected', '$now_ts', '$now_ts', 1);
  INSERT INTO findings (id, tenant_id, cluster_id, detector_id, detector_version, fingerprint, gvk, namespace, object_name, occurrence_count, severity, occurred_at, incident_id)
  VALUES ('$SECTION13_FND_DISABLED', tid, '$section13_cluster_id', 'pod-status', '0.1.0', 'smoketest-autoanalyze-fp-disabled', 'v1/Pod', 'default', 'autoanalyze-disabled-pod', 1, 'critical', '$now_ts', '$SECTION13_INC_DISABLED');
END \$\$;
SQL
  sleep 20
  disabled_analysis_count=$(docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -t -A -c \
    "SELECT count(*) FROM analyses WHERE incident_id = '$SECTION13_INC_DISABLED';" | tr -d '[:space:]')
  check_status "with automation switched back off, even a critical-severity incident is NOT automatically analyzed" "0" "$disabled_analysis_count"

  echo "-- 13d. Enabled, but severities = {} (nothing checked) -> nothing gets auto-analyzed, NOT 'every severity' --"
  # This is the one subtle semantic decision this task made explicit
  # (internal/settings.Config's AutoAnalysisSeverities doc comment): an
  # empty checklist visually implies "nothing chosen," and the safe,
  # unsurprising reading of that state is "nothing is eligible," never a
  # silent "auto-analyze everything" -- the OPPOSITE of what the superseded
  # single-threshold field's null used to mean.
  curl -sS -X PUT "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" \
    -d '{"automation":{"autoAnalysisEnabled":true,"autoAnalysisSeverities":[]}}' >/dev/null

  SECTION13_INC_EMPTYSET="inc_smoketestautoanalyze008"
  SECTION13_FND_EMPTYSET="fnd_smoketestautoanalyze008"
  now_ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -v ON_ERROR_STOP=1 >/dev/null <<SQL
DO \$\$
DECLARE tid text;
BEGIN
  SELECT tenant_id INTO tid FROM clusters WHERE id = '$section13_cluster_id';
  INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
  VALUES ('$SECTION13_INC_EMPTYSET', tid, '$section13_cluster_id', 'smoketest-autoanalyze-fp-emptyset', 'critical', 'Detected', '$now_ts', '$now_ts', 1);
  INSERT INTO findings (id, tenant_id, cluster_id, detector_id, detector_version, fingerprint, gvk, namespace, object_name, occurrence_count, severity, occurred_at, incident_id)
  VALUES ('$SECTION13_FND_EMPTYSET', tid, '$section13_cluster_id', 'pod-status', '0.1.0', 'smoketest-autoanalyze-fp-emptyset', 'v1/Pod', 'default', 'autoanalyze-emptyset-pod', 1, 'critical', '$now_ts', '$SECTION13_INC_EMPTYSET');
END \$\$;
SQL
  sleep 20
  emptyset_analysis_count=$(docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -t -A -c \
    "SELECT count(*) FROM analyses WHERE incident_id = '$SECTION13_INC_EMPTYSET';" | tr -d '[:space:]')
  check_status "with automation ENABLED but severities = {} (nothing checked), a critical-severity incident is still NOT automatically analyzed" "0" "$emptyset_analysis_count"

  # Cleanup -- throwaway fixtures, not application state. evidence/
  # analysis_embeddings before analyses -- see section 11's cleanup comment
  # (BUGS.md 113) for why: neither FK is ON DELETE CASCADE.
  docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -v ON_ERROR_STOP=1 >/dev/null <<SQL
DELETE FROM evidence WHERE analysis_id IN (SELECT id FROM analyses WHERE incident_id LIKE 'inc_smoketestautoanalyze%');
DELETE FROM analysis_embeddings WHERE incident_id LIKE 'inc_smoketestautoanalyze%';
DELETE FROM analyses WHERE incident_id LIKE 'inc_smoketestautoanalyze%';
DELETE FROM findings WHERE incident_id LIKE 'inc_smoketestautoanalyze%';
DELETE FROM incidents WHERE id LIKE 'inc_smoketestautoanalyze%';
SQL
else
  echo "  SKIP: no enrolled cluster for section 13 -- skipping the rest of it"
fi

cleanup_section13

echo "== 14. Insights (GET /api/v1/insights, incident:read + analysis:read) =="
# Real, fleet-wide aggregate reporting over incidents/findings/analyses
# (internal/api/insights.go) -- lld/11-ui-design.md §15.1's last unbuilt
# named screen. No create API exists for any of the three tables this
# reads, same as sections 4b/6/8b/11/13 above -- so this section inserts
# its own small, clearly-unique-prefixed fixture set directly via psql,
# spanning two different clusters, three different fingerprints/
# namespaces, and a mix of complete/partial analyses across different
# days, then asserts the endpoint's real SQL aggregation actually reflects
# it -- not just that it returns 200.

status=$(curl -sS -o /dev/null -w "%{http_code}" "$API/api/v1/insights")
check_status "GET /insights with no auth" 401 "$status"

# investigationOutcomes/costAndTokens are genuinely fleet-wide, not scoped
# to this section's own fixtures -- every earlier section that wrote
# analyses rows (11, 13) already deleted them in its own cleanup above, but
# this measures the table's actual state rather than assuming it's empty,
# so the assertions below hold regardless of what (if anything) earlier
# sections left behind.
insights_baseline_total=$(psql_scalar "SELECT count(*) FROM analyses;")
insights_baseline_partial=$(psql_scalar "SELECT count(*) FROM analyses WHERE COALESCE(root_cause->>'status','complete') = 'partial';")

# BUGS.md 121: INSIGHTS_CLUSTER_A used to be section 6/7's own smoketest-
# cluster ($cluster_id). By the time this section runs, section 7e's own
# storm-protection test has put well over a thousand real findings on that
# exact cluster (its own real ceiling/disabled-detector checks, over a real
# mTLS tunnel) -- issueClasses/noisyNamespaces are both `LIMIT insightsTopN`
# ranked by count DESC (internal/api/insights.go), so that flood outranked
# this section's own tiny (occurrenceCount 1-5) fixtures on every run,
# regardless of whether the ranking logic itself is correct (it is).
# internal/api/insights.go never joins/filters on clusters.state, so a bare
# enroll (no accept, no cert/tunnel -- this section only ever inserts rows
# directly via psql below, never over a real tunnel) is a "fresh cluster"
# fully sufficient for this section's purposes.
INSIGHTS_CSR_DIR=$(mktemp -d)
openssl ecparam -genkey -name prime256v1 -noout -out "$INSIGHTS_CSR_DIR/key.pem" 2>/dev/null
openssl req -new -key "$INSIGHTS_CSR_DIR/key.pem" -subj "/CN=smoketest-insights-fingerprint" -out "$INSIGHTS_CSR_DIR/csr.pem" 2>/dev/null
insights_cluster_fp="smoketest-insights-cluster-fp-$(date +%s)-$$"

insights_enroll_token=$(curl -sS -X POST "$API/api/v1/clusters/enrollment-tokens" \
  -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" -d '{"ttlClass":"B"}' | json_field token)
insights_enroll_payload=$(python3 - "$insights_enroll_token" "$INSIGHTS_CSR_DIR/csr.pem" "$insights_cluster_fp" <<'PYEOF'
import json, sys
token, csr_path, fingerprint = sys.argv[1], sys.argv[2], sys.argv[3]
csr = open(csr_path).read()
print(json.dumps({
    "token": token,
    "csrPem": csr,
    "clusterFingerprint": fingerprint,
    "displayName": "smoketest-insights-cluster",
}))
PYEOF
)
insights_enroll_resp=$(curl -sS -X POST "$API/api/v1/clusters/enroll" -H "Content-Type: application/json" -d "$insights_enroll_payload")
INSIGHTS_CLUSTER_A=$(echo "$insights_enroll_resp" | json_field clusterId)
register_smoketest_cluster "$INSIGHTS_CLUSTER_A"
rm -rf "$INSIGHTS_CSR_DIR"

if [[ -n "$INSIGHTS_CLUSTER_A" ]]; then
  echo "  PASS: enrolled a fresh throwaway cluster for section 14's issue-class/noisy-namespace fixtures (BUGS.md 121, cluster $INSIGHTS_CLUSTER_A)"
  PASS=$((PASS + 1))
else
  echo "  FAIL: could not enroll a fresh cluster for section 14 -- enroll response: $insights_enroll_resp"
  FAIL=$((FAIL + 1))
fi

INSIGHTS_CLUSTER_B="$section13_cluster_id"

if [[ -n "$INSIGHTS_CLUSTER_A" && -n "$INSIGHTS_CLUSTER_B" && "$INSIGHTS_CLUSTER_A" != "$INSIGHTS_CLUSTER_B" ]]; then
  insights_tid=$(psql_scalar "SELECT tenant_id FROM clusters WHERE id = '$INSIGHTS_CLUSTER_A';")
  ts_today=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  ts_2d=$(date -u -d "2 days ago" +%Y-%m-%dT%H:%M:%SZ)
  ts_5d=$(date -u -d "5 days ago" +%Y-%m-%dT%H:%M:%SZ)

  docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -v ON_ERROR_STOP=1 >/dev/null <<SQL
-- Issue class "fp-a": the SAME fingerprint (namespace/kind/object name/
-- reason are all inputs to the hash, so every row below sharing it agrees
-- on all four) recurring across TWO different clusters -- three incidents
-- total, exactly the "same problem, more than one cluster" signal this
-- screen exists to surface.
INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count) VALUES
  ('inc_smoketestinsightsa001', '$insights_tid', '$INSIGHTS_CLUSTER_A', 'smoketest-insights-fp-a', 'high', 'Detected', '$ts_5d', '$ts_5d', 3),
  ('inc_smoketestinsightsa002', '$insights_tid', '$INSIGHTS_CLUSTER_A', 'smoketest-insights-fp-a', 'high', 'Resolved', '$ts_2d', '$ts_2d', 5),
  ('inc_smoketestinsightsa003', '$insights_tid', '$INSIGHTS_CLUSTER_B', 'smoketest-insights-fp-a', 'high', 'Detected', '$ts_today', '$ts_today', 2);
INSERT INTO findings (id, tenant_id, cluster_id, detector_id, detector_version, fingerprint, gvk, namespace, object_name, reason, occurrence_count, severity, occurred_at, incident_id) VALUES
  ('fnd_smoketestinsightsa001', '$insights_tid', '$INSIGHTS_CLUSTER_A', 'pod-status', '0.1.0', 'smoketest-insights-fp-a', 'v1/Pod', 'smoketest-insights-ns-a', 'payments-api', 'CrashLoopBackOff', 3, 'high', '$ts_5d', 'inc_smoketestinsightsa001'),
  ('fnd_smoketestinsightsa002', '$insights_tid', '$INSIGHTS_CLUSTER_A', 'pod-status', '0.1.0', 'smoketest-insights-fp-a', 'v1/Pod', 'smoketest-insights-ns-a', 'payments-api', 'CrashLoopBackOff', 5, 'high', '$ts_2d', 'inc_smoketestinsightsa002'),
  ('fnd_smoketestinsightsa003', '$insights_tid', '$INSIGHTS_CLUSTER_B', 'pod-status', '0.1.0', 'smoketest-insights-fp-a', 'v1/Pod', 'smoketest-insights-ns-a', 'payments-api', 'CrashLoopBackOff', 2, 'high', '$ts_today', 'inc_smoketestinsightsa003');

-- Issue class "fp-b": single cluster, single namespace, ImagePullBackOff --
-- the "not recurring across the fleet" contrast case.
INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count) VALUES
  ('inc_smoketestinsightsb001', '$insights_tid', '$INSIGHTS_CLUSTER_A', 'smoketest-insights-fp-b', 'medium', 'Detected', '$ts_today', '$ts_today', 2);
INSERT INTO findings (id, tenant_id, cluster_id, detector_id, detector_version, fingerprint, gvk, namespace, object_name, reason, occurrence_count, severity, occurred_at, incident_id) VALUES
  ('fnd_smoketestinsightsb001', '$insights_tid', '$INSIGHTS_CLUSTER_A', 'pod-status', '0.1.0', 'smoketest-insights-fp-b', 'v1/Pod', 'smoketest-insights-ns-b', 'checkout-worker', 'ImagePullBackOff', 1, 'medium', '$ts_today', 'inc_smoketestinsightsb001');

-- Issue class "fp-c": a third cluster (B again), third namespace, single
-- incident -- the long tail, and this one's analysis (below) is partial.
INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count) VALUES
  ('inc_smoketestinsightsc001', '$insights_tid', '$INSIGHTS_CLUSTER_B', 'smoketest-insights-fp-c', 'low', 'Detected', '$ts_today', '$ts_today', 1);
INSERT INTO findings (id, tenant_id, cluster_id, detector_id, detector_version, fingerprint, gvk, namespace, object_name, reason, occurrence_count, severity, occurred_at, incident_id) VALUES
  ('fnd_smoketestinsightsc001', '$insights_tid', '$INSIGHTS_CLUSTER_B', 'pod-status', '0.1.0', 'smoketest-insights-fp-c', 'v1/Pod', 'smoketest-insights-ns-c', 'batch-job', 'OOMKilled', 1, 'low', '$ts_today', 'inc_smoketestinsightsc001');

-- Two complete analyses (different days, real nonzero token counts, an
-- honest cost_usd of 0) and one partial (bound-hit) analysis -- the exact
-- status-tagged root_cause JSON shape internal/api/analyze.go's
-- persistAnalysis writes for real, not a bespoke shape invented for this
-- fixture.
INSERT INTO analyses (id, incident_id, tenant_id, cluster_id, prompt_version, model, causal_chain, ruled_out, root_cause, confidence, iterations, duration_ms, tokens_billed_in, tokens_cache_read, tokens_out, cost_usd, created_at) VALUES
  ('ana_smoketestinsights001', 'inc_smoketestinsightsa001', '$insights_tid', '$INSIGHTS_CLUSTER_A', 'v2-tool-loop', 'smoketest-insights-model', '[]', '[]',
   '{"status":"complete","statement":"payments-api is crash-looping due to a missing config secret"}', 0.82, 4, 1200, 400, 120, 150, 0, '$ts_5d'),
  ('ana_smoketestinsights002', 'inc_smoketestinsightsa003', '$insights_tid', '$INSIGHTS_CLUSTER_B', 'v2-tool-loop', 'smoketest-insights-model', '[]', '[]',
   '{"status":"complete","statement":"same missing config secret, second cluster"}', 0.77, 3, 900, 300, 90, 110, 0, '$ts_today'),
  ('ana_smoketestinsights003', 'inc_smoketestinsightsc001', '$insights_tid', '$INSIGHTS_CLUSTER_B', 'v2-tool-loop', 'smoketest-insights-model', '[]', '[]',
   '{"status":"partial","partialReason":"iteration_limit","suggestedNextSteps":["check memory limits","check for a memory leak"]}', NULL, 8, 4000, 900, 300, 260, 0, '$ts_today');
SQL

  insights_resp=$(curl -sS "$API/api/v1/insights" -H "Authorization: Bearer $access_token")
  # fp-b (one incident, one occurrence) ranks below the real findings the
  # disposable cluster's own agents have reported by now, so it can fall out
  # of the fleet-wide top 10. Cluster A carries only this section's fixtures.
  insights_a_resp=$(curl -sS "$API/api/v1/insights?clusterId=$INSIGHTS_CLUSTER_A" -H "Authorization: Bearer $access_token")

  verify_insights=$(python3 - "$insights_resp" "$insights_baseline_total" "$insights_baseline_partial" "$insights_a_resp" <<'PYEOF'
import json, sys, datetime
d = json.loads(sys.argv[1])
baseline_total = int(sys.argv[2])
baseline_partial = int(sys.argv[3])
d_cluster_a = json.loads(sys.argv[4])
results = []
def check(cond, desc, detail=""):
    results.append((bool(cond), desc, detail))

issue_by_fp = {c["fingerprint"]: c for c in d.get("issueClasses", [])}
a = issue_by_fp.get("smoketest-insights-fp-a")
check(a is not None, "issue class fp-a is present in issueClasses")
if a:
    check(a["incidentCount"] == 3, "fp-a incidentCount == 3 (two on cluster A, one on cluster B)", a["incidentCount"])
    check(a["clusterCount"] == 2, "fp-a clusterCount == 2 (recurring across two different clusters)", a["clusterCount"])
    check(a["totalOccurrences"] == 10, "fp-a totalOccurrences == 10 (3+5+2)", a["totalOccurrences"])
    check(a["sampleGvk"] == "v1/Pod", "fp-a sampleGvk", a["sampleGvk"])
    check(a["sampleNamespace"] == "smoketest-insights-ns-a", "fp-a sampleNamespace", a["sampleNamespace"])
    check(a["sampleObjectName"] == "payments-api", "fp-a sampleObjectName", a["sampleObjectName"])
    check(a["sampleReason"] == "CrashLoopBackOff", "fp-a sampleReason", a["sampleReason"])

b = {c["fingerprint"]: c for c in d_cluster_a.get("issueClasses", [])}.get("smoketest-insights-fp-b")
check(b is not None, "issue class fp-b is present in issueClasses")
if b:
    check(b["incidentCount"] == 1, "fp-b incidentCount == 1", b["incidentCount"])
    check(b["clusterCount"] == 1, "fp-b clusterCount == 1 (single cluster, not a recurring-across-fleet case)", b["clusterCount"])

ns_by_name = {n["namespace"]: n for n in d.get("noisyNamespaces", [])}
ns_a = ns_by_name.get("smoketest-insights-ns-a")
check(ns_a is not None, "noisy namespace smoketest-insights-ns-a is present")
if ns_a:
    check(ns_a["findingCount"] == 3, "ns-a findingCount == 3", ns_a["findingCount"])
    check(ns_a["incidentCount"] == 3, "ns-a incidentCount == 3", ns_a["incidentCount"])
    check(ns_a["clusterCount"] == 2, "ns-a clusterCount == 2", ns_a["clusterCount"])
ns_b = ns_by_name.get("smoketest-insights-ns-b")
check(ns_b is not None and ns_b["findingCount"] == 1, "noisy namespace smoketest-insights-ns-b has findingCount == 1", ns_b)
ns_c = ns_by_name.get("smoketest-insights-ns-c")
check(ns_c is not None and ns_c["findingCount"] == 1, "noisy namespace smoketest-insights-ns-c has findingCount == 1", ns_c)
names_in_order = [n["namespace"] for n in d.get("noisyNamespaces", [])]
if "smoketest-insights-ns-a" in names_in_order and "smoketest-insights-ns-b" in names_in_order:
    check(names_in_order.index("smoketest-insights-ns-a") < names_in_order.index("smoketest-insights-ns-b"),
          "ns-a (3 findings) ranks ahead of ns-b (1 finding) -- real ORDER BY, not incidental")

outcomes = d.get("investigationOutcomes", {})
check(outcomes.get("totalAnalyses") == baseline_total + 3, f"totalAnalyses == baseline({baseline_total}) + 3", outcomes.get("totalAnalyses"))
check(outcomes.get("partialCount") == baseline_partial + 1, f"partialCount == baseline({baseline_partial}) + 1", outcomes.get("partialCount"))
check(outcomes.get("completeCount") == (baseline_total - baseline_partial) + 2,
      "completeCount == baseline complete + 2", outcomes.get("completeCount"))
check(outcomes.get("completeRate") is not None, "completeRate is non-null once at least one analysis exists")
check(outcomes.get("avgIterations") is not None, "avgIterations is non-null once at least one analysis exists")

cost = d.get("costAndTokens", {})
check(cost.get("totalInvestigations") == baseline_total + 3, "costAndTokens.totalInvestigations matches the same baseline+3", cost.get("totalInvestigations"))
# BUGS.md 113: totalCostUsd sums cost_basis='metered' rows across this
# tenant's WHOLE history (internal/api/insights.go), not just "since pricing
# was last cleared" -- asserting a hard 0 assumed a stack that had never run
# a real metered investigation. This shared dev stack has (BACKLOG.md H1/H2
# document it directly: 16 legitimate fake-llm-server metered test fixtures,
# 2026-08-23 through -27, plus whatever this very script's own section 15
# has ever left behind on a previous run), so a real, non-negative number is
# the honest assertion here -- same "don't assume zero on a persistent
# stack" precedent section 8 already applies to cost.todaySpendUsd.
check(isinstance(cost.get("totalCostUsd"), (int, float)) and cost.get("totalCostUsd") >= 0,
      "totalCostUsd is a real, non-negative number (not asserted == 0: this tenant's history may already include real metered spend)",
      cost.get("totalCostUsd"))
check(isinstance(cost.get("costTrackingNote"), str) and "pricing" in cost.get("costTrackingNote", "").lower(),
      "costTrackingNote explains the honest zero", cost.get("costTrackingNote"))
trend = cost.get("dailyTrend", [])
check(len(trend) == 14, "dailyTrend has exactly 14 days", len(trend))
today_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
check(bool(trend) and trend[-1]["day"] == today_str, "dailyTrend's last entry is today (UTC)", trend[-1] if trend else None)
today_point = trend[-1] if trend else {}
check(today_point.get("investigations", 0) >= 2, "today's trend point counts at least the 2 analyses created today", today_point.get("investigations"))

not_built_ids = {n["id"] for n in d.get("notBuilt", [])}
# BUGS.md 113: estimatedToilSaved and spendVsValue joined
# internal/api/insights.go's notBuiltInsights after this assertion was
# written -- same "grew, script didn't" class as the settings/audit key
# sets above.
check(not_built_ids == {"calibrationCurve", "autonomyReadiness", "estimatedToilSaved", "spendVsValue"},
      "notBuilt lists exactly the four documented not-yet-built sections, nothing faked", sorted(not_built_ids))

for passed, desc, detail in results:
    tag = "PASS" if passed else "FAIL"
    suffix = f" (got {detail})" if detail != "" else ""
    print(f"  {tag}: {desc}{suffix}")
PYEOF
)
  echo "$verify_insights"
  pass_count=$(echo "$verify_insights" | grep -c "^  PASS:")
  fail_count=$(echo "$verify_insights" | grep -c "^  FAIL:")
  PASS=$((PASS + pass_count))
  FAIL=$((FAIL + fail_count))

  # Cleanup -- throwaway fixtures, not application state. evidence/
  # analysis_embeddings before analyses -- see section 11's cleanup comment
  # (BUGS.md 113) for why: neither FK is ON DELETE CASCADE.
  docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -v ON_ERROR_STOP=1 >/dev/null <<SQL
DELETE FROM evidence WHERE analysis_id IN (SELECT id FROM analyses WHERE incident_id LIKE 'inc_smoketestinsights%');
DELETE FROM analysis_embeddings WHERE incident_id LIKE 'inc_smoketestinsights%';
DELETE FROM analyses WHERE incident_id LIKE 'inc_smoketestinsights%';
DELETE FROM findings WHERE incident_id LIKE 'inc_smoketestinsights%';
DELETE FROM incidents WHERE id LIKE 'inc_smoketestinsights%';
SQL
else
  echo "  SKIP: no two distinct enrolled clusters available (need both section 6's and section 13's) -- skipping the rest of section 14"
fi

echo "== 15. Real cost_usd from operator-configured pricing, and the daily spend ceiling (manual allowed, automatic stopped) =="
# Closes the gap STATUS.md's cost-tracking entries and 04-consolidated-
# design.md §16.4 both flagged: analyses.cost_usd was always an honest 0
# because no per-model USD pricing table existed anywhere in this codebase,
# and no daily spend ceiling existed to check a real cost against. Uses the
# same real-agent + real-tunnel + scripts/fake-llm-server infrastructure
# sections 11/13 already established, in its own bin dir/port.
#
# fake-llm-server's request counter is GLOBAL to one running process, not
# per-investigation (see its own doc comment) -- only the FIRST investigation
# run against a freshly-started instance gets the scripted 3-tool-call-then-
# conclude sequence (4 model round-trips, tokens 200/90/80, deterministic);
# every investigation after that against the SAME process immediately hits
# its "default" branch (n>3) and concludes in one round with SOME smaller
# positive cost. So: the exact-dollar-figure assertion below uses the FIRST
# investigation only; the ceiling-crossing test that follows deliberately
# does not assume a second investigation's exact cost, just that it's real
# and positive -- the ceiling is set relative to spend actually observed via
# GET /spend/today, not a value precomputed by this script, so the test
# doesn't depend on that quirk at all.

SECTION15_BIN_DIR=$(mktemp -d)
SECTION15_AGENT_DATA_DIR=$(mktemp -d)
SECTION15_AGENT_LOG=$(mktemp)
SECTION15_FAKE_LLM_LOG=$(mktemp)
SECTION15_FAKE_LLM_PORT=19093

cleanup_section15() {
  [[ -n "${SECTION15_AGENT_PID:-}" ]] && kill "$SECTION15_AGENT_PID" >/dev/null 2>&1
  [[ -n "${SECTION15_FAKE_LLM_PID:-}" ]] && kill "$SECTION15_FAKE_LLM_PID" >/dev/null 2>&1
  rm -rf "$SECTION15_BIN_DIR" "$SECTION15_AGENT_DATA_DIR" "$SECTION15_AGENT_LOG" "$SECTION15_FAKE_LLM_LOG"
  # evidence/analysis_embeddings before analyses -- see section 11's cleanup
  # comment (BUGS.md 113) for why: neither FK is ON DELETE CASCADE.
  docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -v ON_ERROR_STOP=1 >/dev/null <<SQL
DELETE FROM evidence WHERE analysis_id IN (SELECT id FROM analyses WHERE incident_id LIKE 'inc_smoketestcost%');
DELETE FROM analysis_embeddings WHERE incident_id LIKE 'inc_smoketestcost%';
DELETE FROM analyses WHERE incident_id LIKE 'inc_smoketestcost%';
DELETE FROM findings WHERE incident_id LIKE 'inc_smoketestcost%';
DELETE FROM incidents WHERE id LIKE 'inc_smoketestcost%';
SQL
  # Leave cost pricing/ceiling cleared and automation off -- same "don't
  # leak this section's config into whatever runs after it" discipline
  # sections 11/13 apply to their own settings. NOT the AI provider
  # (BUGS.md 113): that's restored once, to whatever was active before this
  # script ever ran, by the EXIT trap at the very end of this run.
  curl -sS -X PUT "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" \
    -d '{"automation":{"autoAnalysisEnabled":false,"autoAnalysisSeverities":[]},"cost":{"pricePerMillionInputTokens":null,"pricePerMillionCachedTokens":null,"pricePerMillionOutputTokens":null,"dailySpendCeilingUsd":null}}' >/dev/null
}

go build -o "$SECTION15_BIN_DIR/fake-llm-server" ./scripts/fake-llm-server
go build -o "$SECTION15_BIN_DIR/agent" ./cmd/agent

"$SECTION15_BIN_DIR/fake-llm-server" -addr ":$SECTION15_FAKE_LLM_PORT" -mode toolloop >"$SECTION15_FAKE_LLM_LOG" 2>&1 &
SECTION15_FAKE_LLM_PID=$!

section15_token=$(curl -sS -X POST "$API/api/v1/clusters/enrollment-tokens" \
  -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" -d '{"ttlClass":"B"}' | json_field token)

ARGUS_ENROLLMENT_TOKEN="$section15_token" ARGUS_HUB_API_URL="$API" \
  ARGUS_CLUSTER_DISPLAY_NAME="smoketest-cost-cluster" ARGUS_AGENT_DATA_DIR="$SECTION15_AGENT_DATA_DIR" \
  "$SECTION15_BIN_DIR/agent" >"$SECTION15_AGENT_LOG" 2>&1 &
SECTION15_AGENT_PID=$!

section15_cluster_id=""
for _ in $(seq 1 30); do
  section15_cluster_id=$(grep 'is pendingApproval' "$SECTION15_AGENT_LOG" | grep -oP '"cluster_id":"\K[^"]+' | head -1)
  [[ -n "$section15_cluster_id" ]] && break
  sleep 1
done
register_smoketest_cluster "$section15_cluster_id"

if [[ -n "$section15_cluster_id" ]]; then
  echo "  PASS: real agent process enrolled (cluster $section15_cluster_id, pendingApproval)"
  PASS=$((PASS + 1))
else
  if agent_enrollment_blocked "$SECTION15_AGENT_LOG"; then
    echo "  SKIP: the target cluster is already enrolled in this hub, so a second enrollment is correctly refused (409 already-enrolled) -- decommission it first, or point ARGUS_DISPOSABLE_KUBECONFIG at an unenrolled cluster, to exercise this section"
  else
    echo "  FAIL: real agent process never reached pendingApproval -- see agent log: $SECTION15_AGENT_LOG"
    FAIL=$((FAIL + 1))
  fi
fi

if [[ -n "$section15_cluster_id" ]]; then
  curl -sS -X POST "$API/api/v1/clusters/$section15_cluster_id/accept" -H "Authorization: Bearer $access_token" >/dev/null

  section15_state=""
  for _ in $(seq 1 20); do
    section15_state=$(curl -sS "$API/api/v1/clusters/$section15_cluster_id" -H "Authorization: Bearer $access_token" | json_field state)
    [[ "$section15_state" == "Active" ]] && break
    sleep 1
  done
  check_status "real agent's tunnel promotes the cluster to Active" "Active" "$section15_state"

  activate_fake_llm_provider "http://host.docker.internal:$SECTION15_FAKE_LLM_PORT" "smoketest-cost-model"

  echo "-- 15a. Configure a real (test) per-token price; confirm the exact expected dollar figure --"
  # $5/Mtok input, $100/Mtok cached-read, $100/Mtok output -- deliberately
  # NOT real-world rates (this is a test price, chosen so 200/90/80 tokens
  # -- fake-llm-server's own deterministic first-investigation usage,
  # confirmed already in section 11 -- produce an exact, rounding-free
  # total: 200*5 + 90*100 + 80*100 = 1000+9000+8000 = 18000 per-million-
  # token-units = $0.018 exactly).
  cost_price_resp=$(curl -sS -X PUT "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" \
    -d '{"cost":{"pricePerMillionInputTokens":5,"pricePerMillionCachedTokens":100,"pricePerMillionOutputTokens":100,"dailySpendCeilingUsd":null}}')
  cost_pricing_configured=$(echo "$cost_price_resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['cost']['pricingConfigured'])")
  check_status "PUT cost pricing round-trips pricingConfigured == True" "True" "$cost_pricing_configured"

  baseline_spend=$(curl -sS "$API/api/v1/spend/today" -H "Authorization: Bearer $access_token" | python3 -c "import sys,json; print(json.load(sys.stdin)['todaySpendUsd'])")

  SECTION15_INC_VERIFY="inc_smoketestcostverify00001"
  SECTION15_FND_VERIFY="fnd_smoketestcostverify00001"
  now_ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -v ON_ERROR_STOP=1 >/dev/null <<SQL
DO \$\$
DECLARE tid text;
BEGIN
  SELECT tenant_id INTO tid FROM clusters WHERE id = '$section15_cluster_id';
  INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
  VALUES ('$SECTION15_INC_VERIFY', tid, '$section15_cluster_id', 'smoketest-cost-fp-verify', 'high', 'Detected', '$now_ts', '$now_ts', 1);
  INSERT INTO findings (id, tenant_id, cluster_id, detector_id, detector_version, fingerprint, gvk, namespace, object_name, occurrence_count, severity, occurred_at, incident_id)
  VALUES ('$SECTION15_FND_VERIFY', tid, '$section15_cluster_id', 'pod-status', '0.1.0', 'smoketest-cost-fp-verify', 'v1/Pod', 'default', 'smoketest-cost-pod', 1, 'high', '$now_ts', '$SECTION15_INC_VERIFY');
END \$\$;
SQL

  verify_analyze_resp=$(analyze_and_wait "$SECTION15_INC_VERIFY" /tmp/smoketest_cost_verify.json)
  check_status "POST .../analyze (first investigation against a fresh fake-llm-server) is accepted (202) and its analysis lands" 202 "$verify_analyze_resp"

  verify_cost_calc=$(python3 - "$(cat /tmp/smoketest_cost_verify.json)" <<'PYEOF'
import json, sys
d = json.loads(sys.argv[1])
results = []
def check(cond, desc, detail=""):
    results.append((bool(cond), desc, detail))
check(d.get("tokensBilledIn") == 200, "tokensBilledIn == 200 (fake-llm-server's deterministic first-investigation usage)", d.get("tokensBilledIn"))
check(d.get("tokensCacheRead") == 90, "tokensCacheRead == 90", d.get("tokensCacheRead"))
check(d.get("tokensOut") == 80, "tokensOut == 80", d.get("tokensOut"))
cost = d.get("costUsd")
check(isinstance(cost, (int, float)) and abs(cost - 0.018) < 1e-9,
      "costUsd == 0.018 exactly (200*$5/M + 90*$100/M + 80*$100/M), computed from real token counts and the configured price table",
      cost)
for passed, desc, detail in results:
    tag = "PASS" if passed else "FAIL"
    suffix = f" (got {detail})" if detail != "" else ""
    print(f"  {tag}: {desc}{suffix}")
PYEOF
)
  echo "$verify_cost_calc"
  pass_count=$(echo "$verify_cost_calc" | grep -c "^  PASS:")
  fail_count=$(echo "$verify_cost_calc" | grep -c "^  FAIL:")
  PASS=$((PASS + pass_count))
  FAIL=$((FAIL + fail_count))

  db_cost_usd=$(psql_scalar "SELECT cost_usd FROM analyses WHERE incident_id = '$SECTION15_INC_VERIFY';")
  check_status "the persisted analyses row's own cost_usd column == 0.0180 (numeric(10,4))" "0.0180" "$db_cost_usd"

  detail_cost=$(curl -sS "$API/api/v1/incidents/$SECTION15_INC_VERIFY" -H "Authorization: Bearer $access_token" | \
    python3 -c "import sys,json; a=json.load(sys.stdin)['analysis']; print(abs(a['costUsd'] - 0.018) < 1e-9)")
  check_status "GET /incidents/{id}'s embedded analysis surfaces the same real costUsd (~0.018)" "True" "$detail_cost"

  spend_after_verify=$(curl -sS "$API/api/v1/spend/today" -H "Authorization: Bearer $access_token")
  spend_after_verify_checks=$(python3 - "$spend_after_verify" "$baseline_spend" <<'PYEOF'
import json, sys
d = json.loads(sys.argv[1])
baseline = float(sys.argv[2])
results = []
def check(cond, desc, detail=""):
    results.append((bool(cond), desc, detail))
check(abs(d.get("todaySpendUsd", 0) - (baseline + 0.018)) < 1e-6,
      "GET /spend/today's todaySpendUsd increased by exactly the 0.018 this one real analysis cost",
      d.get("todaySpendUsd"))
check(d.get("pricingConfigured") is True, "GET /spend/today reflects pricingConfigured == true", d.get("pricingConfigured"))
check(d.get("ceilingBreached") is False, "no ceiling configured yet -- ceilingBreached == false (a no-op, not a confusing block on real spend)", d.get("ceilingBreached"))
for passed, desc, detail in results:
    tag = "PASS" if passed else "FAIL"
    suffix = f" (got {detail})" if detail != "" else ""
    print(f"  {tag}: {desc}{suffix}")
PYEOF
)
  echo "$spend_after_verify_checks"
  pass_count=$(echo "$spend_after_verify_checks" | grep -c "^  PASS:")
  fail_count=$(echo "$spend_after_verify_checks" | grep -c "^  FAIL:")
  PASS=$((PASS + pass_count))
  FAIL=$((FAIL + fail_count))

  echo "-- 15b. A low daily ceiling, set just above today's real spend so far; automatic investigation stops once crossed, manual still works --"
  spend_now=$(echo "$spend_after_verify" | python3 -c "import sys,json; print(json.load(sys.stdin)['todaySpendUsd'])")
  section15_ceiling=$(python3 -c "print(round($spend_now + 0.001, 6))")

  curl -sS -X PUT "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" \
    -d "{\"cost\":{\"pricePerMillionInputTokens\":5,\"pricePerMillionCachedTokens\":100,\"pricePerMillionOutputTokens\":100,\"dailySpendCeilingUsd\":$section15_ceiling}}" >/dev/null
  curl -sS -X PUT "$API/api/v1/admin/settings" -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" \
    -d '{"automation":{"autoAnalysisEnabled":true,"autoAnalysisSeverities":["high"]}}' >/dev/null

  SECTION15_INC_AUTO1="inc_smoketestcostauto0000001"
  SECTION15_FND_AUTO1="fnd_smoketestcostauto0000001"
  now_ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -v ON_ERROR_STOP=1 >/dev/null <<SQL
DO \$\$
DECLARE tid text;
BEGIN
  SELECT tenant_id INTO tid FROM clusters WHERE id = '$section15_cluster_id';
  INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
  VALUES ('$SECTION15_INC_AUTO1', tid, '$section15_cluster_id', 'smoketest-cost-fp-auto1', 'high', 'Detected', '$now_ts', '$now_ts', 1);
  INSERT INTO findings (id, tenant_id, cluster_id, detector_id, detector_version, fingerprint, gvk, namespace, object_name, occurrence_count, severity, occurred_at, incident_id)
  VALUES ('$SECTION15_FND_AUTO1', tid, '$section15_cluster_id', 'pod-status', '0.1.0', 'smoketest-cost-fp-auto1', 'v1/Pod', 'default', 'smoketest-cost-auto1-pod', 1, 'high', '$now_ts', '$SECTION15_INC_AUTO1');
END \$\$;
SQL

  # Under the ceiling (set just $0.001 above spend at this exact moment):
  # this first eligible incident should still be auto-analyzed -- the
  # ceiling check only ever blocks a NEW sweep from starting further work,
  # never a sweep already in flight (internal/autoanalyze's own doc
  # comment). Polls rather than a single fixed sleep, same bounded-iteration
  # pattern section 13 uses (up to 50s -- DefaultPollInterval is 15s).
  section15_auto1_done=false
  for _ in $(seq 1 50); do
    auto1_count=$(psql_scalar "SELECT count(*) FROM analyses WHERE incident_id = '$SECTION15_INC_AUTO1';")
    if [[ "$auto1_count" == "1" ]]; then
      section15_auto1_done=true
      break
    fi
    sleep 1
  done
  if [[ "$section15_auto1_done" == true ]]; then
    echo "  PASS: the first incident, still under the ceiling at sweep time, was auto-analyzed with no manual click"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: the first incident was never auto-analyzed within 50s -- see hub-api logs"
    FAIL=$((FAIL + 1))
  fi

  spend_after_auto1=$(curl -sS "$API/api/v1/spend/today" -H "Authorization: Bearer $access_token")
  breached_after_auto1=$(echo "$spend_after_auto1" | python3 -c "import sys,json; print(json.load(sys.stdin)['ceilingBreached'])")
  check_status "after the first automatic investigation's real cost lands, GET /spend/today reports ceilingBreached == True" "True" "$breached_after_auto1"

  echo "-- 15c. A second, later-arriving eligible incident is skipped entirely by the automatic path once the ceiling is breached --"
  SECTION15_INC_AUTO2="inc_smoketestcostauto0000002"
  SECTION15_FND_AUTO2="fnd_smoketestcostauto0000002"
  now_ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -v ON_ERROR_STOP=1 >/dev/null <<SQL
DO \$\$
DECLARE tid text;
BEGIN
  SELECT tenant_id INTO tid FROM clusters WHERE id = '$section15_cluster_id';
  INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
  VALUES ('$SECTION15_INC_AUTO2', tid, '$section15_cluster_id', 'smoketest-cost-fp-auto2', 'high', 'Detected', '$now_ts', '$now_ts', 1);
  INSERT INTO findings (id, tenant_id, cluster_id, detector_id, detector_version, fingerprint, gvk, namespace, object_name, occurrence_count, severity, occurred_at, incident_id)
  VALUES ('$SECTION15_FND_AUTO2', tid, '$section15_cluster_id', 'pod-status', '0.1.0', 'smoketest-cost-fp-auto2', 'v1/Pod', 'default', 'smoketest-cost-auto2-pod', 1, 'high', '$now_ts', '$SECTION15_INC_AUTO2');
END \$\$;
SQL

  # Wait out several poll intervals -- unlike 15b, this must NEVER become 1;
  # there's no "PASS the moment it happens" condition here, so this just
  # waits the full window and checks the end state.
  sleep 45

  auto2_count=$(psql_scalar "SELECT count(*) FROM analyses WHERE incident_id = '$SECTION15_INC_AUTO2';")
  check_status "the second eligible incident got NO automatic analysis across 3 poll ticks -- the ceiling stopped it entirely, not just delayed it" "0" "$auto2_count"

  auto2_attempted=$(psql_scalar "SELECT auto_analysis_attempted_at IS NOT NULL FROM incidents WHERE id = '$SECTION15_INC_AUTO2';")
  check_status "the second incident is NOT marked auto_analysis_attempted_at either -- skipped, not a failed attempt, so it remains eligible once the ceiling clears" "f" "$auto2_attempted"

  if docker compose -f "$COMPOSE_FILE" logs hub-api 2>/dev/null | grep -q "autoanalyze: daily spend ceiling reached"; then
    echo "  PASS: hub-api logs a clear, greppable line when the automatic path skips a sweep for the spend ceiling (not a silent no-op)"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: no 'autoanalyze: daily spend ceiling reached' line found in hub-api logs"
    FAIL=$((FAIL + 1))
  fi

  echo "-- 15d. A manual analyze on that same incident still works, deliberately not blocked by the ceiling --"
  manual_over_ceiling_resp=$(analyze_and_wait "$SECTION15_INC_AUTO2" /tmp/smoketest_analyze_manual_over_ceiling_resp.json)
  check_status "manual POST .../analyze on the second incident is still accepted (202) and its analysis lands even though the daily ceiling is breached" 202 "$manual_over_ceiling_resp"
  check_status "...and the background run completed (no analysisError on the incident)" "None" "$(python3 -c "import json; print(json.load(open('/tmp/smoketest_analyze_manual_over_ceiling_resp.json')).get('analysisError'))")"

  if docker compose -f "$COMPOSE_FILE" logs hub-api 2>/dev/null | grep -q "handleAnalyzeIncident: daily spend ceiling reached"; then
    echo "  PASS: hub-api logs a clear line noting the ceiling was breached even on the manual path that proceeded anyway"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: no 'handleAnalyzeIncident: daily spend ceiling reached' line found in hub-api logs"
    FAIL=$((FAIL + 1))
  fi

  final_spend_resp=$(curl -sS "$API/api/v1/spend/today" -H "Authorization: Bearer $access_token")
  final_spend_checks=$(python3 - "$final_spend_resp" "$section15_ceiling" <<'PYEOF'
import json, sys
d = json.loads(sys.argv[1])
ceiling = float(sys.argv[2])
results = []
def check(cond, desc, detail=""):
    results.append((bool(cond), desc, detail))
check(abs(d.get("dailySpendCeilingUsd", 0) - ceiling) < 1e-6, "GET /spend/today reflects the configured dailySpendCeilingUsd", d.get("dailySpendCeilingUsd"))
check(d.get("ceilingBreached") is True, "ceilingBreached is still True after the manual analyze that proceeded anyway", d.get("ceilingBreached"))
check(d.get("pricingConfigured") is True, "pricingConfigured is still True", d.get("pricingConfigured"))
for passed, desc, detail in results:
    tag = "PASS" if passed else "FAIL"
    suffix = f" (got {detail})" if detail != "" else ""
    print(f"  {tag}: {desc}{suffix}")
PYEOF
)
  echo "$final_spend_checks"
  pass_count=$(echo "$final_spend_checks" | grep -c "^  PASS:")
  fail_count=$(echo "$final_spend_checks" | grep -c "^  FAIL:")
  PASS=$((PASS + pass_count))
  FAIL=$((FAIL + fail_count))
fi

cleanup_section15

# Sections 1-15 above include real agent enrollment, live tunnels, and several
# 45-50s sleeps -- comfortably long enough in total to outlast a super-admin
# access token's 15-minute lifetime (authz.AccessTokenTTL). $access_token was
# minted back in section 2 and $refresh_token's whole chain was deliberately
# poisoned by section 5's reuse-detection test, so the simplest correct fix is
# a fresh login with the already-known $ADMIN_PASSWORD, exactly like section
# 2 itself did -- not threading a refresh through everything in between.
echo "  -- refreshing the super-admin session before sections 16-17 (the original access token from section 2 has long since expired) --"
admin_relogin_resp=$(curl -sS -X POST "$API/api/v1/auth/login" \
  -H "Content-Type: application/json" -d "{\"email\":\"admin@localhost\",\"password\":\"$ADMIN_PASSWORD\"}")
access_token=$(echo "$admin_relogin_resp" | json_field accessToken)
if [[ -n "$access_token" ]]; then
  echo "  PASS: re-authenticated as super-admin for sections 16-17"
  PASS=$((PASS + 1))
else
  echo "  FAIL: could not re-authenticate as super-admin -- response: $admin_relogin_resp"
  FAIL=$((FAIL + 1))
fi

echo "== 16. Custom roles (GET/POST/PUT/DELETE /api/v1/custom-roles -- user:read, role:manage) =="
# internal/api/custom_roles.go, BACKLOG.md S3: an admin-authored, named bundle
# of the existing capability catalogue. Exercises: no-auth on all 4 routes;
# capability denial for a viewer (lacks user:read AND role:manage) and for a
# tenant-admin composing a role that includes a capability tenant-admin
# itself does not hold (audit:read -- the no-escalation-through-delegation
# guard, one step before a grant); the deliberately-rejected inputs (reserved
# builtin name, unknown capability, empty capability set); successful
# create/list/update; and the in-use guard on delete (refuses while a grant
# still references the role, then succeeds once that grant is revoked).
#
# Reuses section 8b's TEST_VIEWER_ID/TEST_TENANT_ADMIN_ID viewer + tenant-admin
# fixture pattern, per argus-review's own instruction to reuse the script's
# existing viewer-fixture pattern for the capability-denial case.

status=$(curl -sS -o /dev/null -w "%{http_code}" "$API/api/v1/custom-roles")
check_status "GET /custom-roles with no auth" 401 "$status"
status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/custom-roles" -H "Content-Type: application/json" -d '{}')
check_status "POST /custom-roles with no auth" 401 "$status"
status=$(curl -sS -o /dev/null -w "%{http_code}" -X PUT "$API/api/v1/custom-roles/crole_bogus" -H "Content-Type: application/json" -d '{}')
check_status "PUT /custom-roles/{id} with no auth" 401 "$status"
status=$(curl -sS -o /dev/null -w "%{http_code}" -X DELETE "$API/api/v1/custom-roles/crole_bogus")
check_status "DELETE /custom-roles/{id} with no auth" 401 "$status"

TEST_VIEWER_ID="usr_smoketest0000000000000"
viewer_hash=$(docker run --rm "$HUB_IMAGE" hash-password "smoke-test-password" | tr -d '\r\n')
TEST_TENANT_ADMIN_ID="usr_smoketest0000000000002"
tenant_admin_hash=$(docker run --rm "$HUB_IMAGE" hash-password "smoke-test-password" | tr -d '\r\n')
docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -v ON_ERROR_STOP=1 >/dev/null <<SQL
DO \$\$
DECLARE org_id text;
BEGIN
  SELECT id INTO org_id FROM organisations LIMIT 1;
  DELETE FROM refresh_tokens WHERE user_id IN ('$TEST_VIEWER_ID', '$TEST_TENANT_ADMIN_ID');
  DELETE FROM grants WHERE principal_id IN ('$TEST_VIEWER_ID', '$TEST_TENANT_ADMIN_ID');
  DELETE FROM users WHERE id IN ('$TEST_VIEWER_ID', '$TEST_TENANT_ADMIN_ID');
  INSERT INTO users (id, tenant_id, email, display_name, password_hash, must_change_password)
  VALUES ('$TEST_VIEWER_ID', org_id, 'smoketest-viewer@localhost', 'Smoke Test Viewer', '$viewer_hash', false);
  INSERT INTO grants (id, tenant_id, principal_type, principal_id, role_id, scope, granted_by)
  VALUES ('grt_smoketest0000000000000', org_id, 'user', '$TEST_VIEWER_ID', 'viewer', '{"type":"AllClusters"}', '$TEST_VIEWER_ID');
  INSERT INTO users (id, tenant_id, email, display_name, password_hash, must_change_password)
  VALUES ('$TEST_TENANT_ADMIN_ID', org_id, 'smoketest-tenantadmin@localhost', 'Smoke Test Tenant Admin', '$tenant_admin_hash', false);
  INSERT INTO grants (id, tenant_id, principal_type, principal_id, role_id, scope, granted_by)
  VALUES ('grt_smoketest0000000000002', org_id, 'user', '$TEST_TENANT_ADMIN_ID', 'tenant-admin', '{"type":"AllClusters"}', '$TEST_TENANT_ADMIN_ID');
END \$\$;
SQL

viewer_token=$(curl -sS -X POST "$API/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"smoketest-viewer@localhost","password":"smoke-test-password"}' | json_field accessToken)
tenant_admin_token=$(curl -sS -X POST "$API/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"smoketest-tenantadmin@localhost","password":"smoke-test-password"}' | json_field accessToken)

if [[ -n "$viewer_token" && -n "$tenant_admin_token" ]]; then
  echo "  PASS: viewer and tenant-admin smoke-test users can both log in"
  PASS=$((PASS + 1))
else
  echo "  FAIL: viewer and/or tenant-admin smoke-test user could not log in"
  FAIL=$((FAIL + 1))
fi

status=$(curl -sS -o /dev/null -w "%{http_code}" "$API/api/v1/custom-roles" -H "Authorization: Bearer $viewer_token")
check_status "viewer denied GET /custom-roles -- lacks user:read (403)" 403 "$status"
status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/custom-roles" \
  -H "Authorization: Bearer $viewer_token" -H "Content-Type: application/json" -d '{"name":"irrelevant","capabilities":["cluster:read"]}')
check_status "viewer denied POST /custom-roles -- lacks role:manage (403)" 403 "$status"

SECTION16_ROLE_NAME="smoketest-custom-role-$(date +%s)-$$"
create_role_resp=$(curl -sS -X POST "$API/api/v1/custom-roles" \
  -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" \
  -d "{\"name\":\"$SECTION16_ROLE_NAME\",\"capabilities\":[\"cluster:read\",\"incident:read\"]}")
section16_role_id=$(echo "$create_role_resp" | json_field id)
if [[ -n "$section16_role_id" ]]; then
  echo "  PASS: POST /custom-roles creates a role (super-admin, role:manage)"
  PASS=$((PASS + 1))
else
  echo "  FAIL: POST /custom-roles -- response: $create_role_resp"
  FAIL=$((FAIL + 1))
fi

status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/custom-roles" \
  -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" \
  -d '{"name":"viewer","capabilities":["cluster:read"]}')
check_status "creating a custom role named after a builtin role is rejected" 400 "$status"

status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/custom-roles" \
  -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" \
  -d '{"name":"smoketest-bogus-cap-role","capabilities":["not:a:real:capability"]}')
check_status "creating a custom role with an unknown capability is rejected" 400 "$status"

status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/custom-roles" \
  -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" \
  -d '{"name":"smoketest-empty-cap-role","capabilities":[]}')
check_status "creating a custom role with an empty capability set is rejected" 400 "$status"

status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/custom-roles" \
  -H "Authorization: Bearer $tenant_admin_token" -H "Content-Type: application/json" \
  -d '{"name":"smoketest-escalation-role","capabilities":["audit:read"]}')
check_status "tenant-admin cannot compose a role including audit:read -- does not hold it itself (403, no-escalation-through-delegation)" 403 "$status"

if [[ -n "$section16_role_id" ]]; then
  list_resp=$(curl -sS "$API/api/v1/custom-roles" -H "Authorization: Bearer $access_token")
  if echo "$list_resp" | grep -q "$SECTION16_ROLE_NAME"; then
    echo "  PASS: GET /custom-roles lists the newly created role"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: GET /custom-roles did not list $SECTION16_ROLE_NAME -- response: $list_resp"
    FAIL=$((FAIL + 1))
  fi

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X PUT "$API/api/v1/custom-roles/$section16_role_id" \
    -H "Authorization: Bearer $viewer_token" -H "Content-Type: application/json" -d '{"capabilities":["cluster:read"]}')
  check_status "viewer denied PUT /custom-roles/{id} -- lacks role:manage (403)" 403 "$status"

  update_resp=$(curl -sS -X PUT "$API/api/v1/custom-roles/$section16_role_id" \
    -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" -d '{"capabilities":["incident:read"]}')
  if echo "$update_resp" | grep -q '"incident:read"' && ! echo "$update_resp" | grep -q '"cluster:read"'; then
    echo "  PASS: PUT /custom-roles/{id} replaces the capability set"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: PUT /custom-roles/{id} -- response: $update_resp"
    FAIL=$((FAIL + 1))
  fi

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X PUT "$API/api/v1/custom-roles/crole_bogus_id" \
    -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" -d '{"capabilities":["cluster:read"]}')
  check_status "PUT /custom-roles/{id} on an unknown id is rejected" 404 "$status"

  echo "  -- Assigning the custom role to a user via the SAME grant mechanism a builtin role uses --"
  section16_grant_resp=$(curl -sS -X POST "$API/api/v1/users/$TEST_VIEWER_ID/grants" \
    -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" \
    -d "{\"role\":\"$section16_role_id\",\"scope\":{\"type\":\"AllClusters\"}}")
  section16_grant_id=$(echo "$section16_grant_resp" | json_field id)

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X DELETE "$API/api/v1/custom-roles/$section16_role_id" \
    -H "Authorization: Bearer $access_token")
  check_status "DELETE /custom-roles/{id} refused while a grant still references it (409)" 409 "$status"

  if [[ -n "$section16_grant_id" ]]; then
    curl -sS -X DELETE "$API/api/v1/users/$TEST_VIEWER_ID/grants/$section16_grant_id" \
      -H "Authorization: Bearer $access_token" >/dev/null
  fi

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X DELETE "$API/api/v1/custom-roles/$section16_role_id" \
    -H "Authorization: Bearer $access_token")
  check_status "DELETE /custom-roles/{id} succeeds once the referencing grant is revoked (200)" 200 "$status"

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X DELETE "$API/api/v1/custom-roles/$section16_role_id" \
    -H "Authorization: Bearer $access_token")
  check_status "DELETE /custom-roles/{id} on an already-deleted id is rejected" 404 "$status"
fi

echo "== 17. Cluster groups (GET/POST/DELETE /api/v1/cluster-groups[/{id}/clusters[/{clusterId}]] -- cluster:read, cluster:group:manage) =="
# internal/api/cluster_groups.go, BACKLOG.md S3: named cluster subsets used as
# a ClusterGroup grant scope. Exercises: no-auth on all 5 routes; capability
# denial for a viewer (holds cluster:read so GET still succeeds, but is
# denied every write -- lacks cluster:group:manage); successful
# create/list/add/remove; the deliberately-rejected inputs (unknown cluster,
# unknown group, duplicate membership); and the in-use guard on delete
# (refuses while a ClusterGroup-scoped grant still references it, then
# succeeds once that grant is revoked). Reuses section 16's viewer/
# tenant-admin fixture (still live -- cleaned up at the end of this section).
#
# No dedicated "create a cluster" API exists outside the real enrollment flow
# (section 6/11/12/13 all use it) -- a bare clusters row is inserted directly
# here instead, the same direct-SQL-fixture convention section 11 already
# uses for incidents/findings it does not need a real detector to produce.

status=$(curl -sS -o /dev/null -w "%{http_code}" "$API/api/v1/cluster-groups")
check_status "GET /cluster-groups with no auth" 401 "$status"
status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/cluster-groups" -H "Content-Type: application/json" -d '{}')
check_status "POST /cluster-groups with no auth" 401 "$status"
status=$(curl -sS -o /dev/null -w "%{http_code}" -X DELETE "$API/api/v1/cluster-groups/clg_bogus")
check_status "DELETE /cluster-groups/{id} with no auth" 401 "$status"
status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/cluster-groups/clg_bogus/clusters" -H "Content-Type: application/json" -d '{}')
check_status "POST /cluster-groups/{id}/clusters with no auth" 401 "$status"
status=$(curl -sS -o /dev/null -w "%{http_code}" -X DELETE "$API/api/v1/cluster-groups/clg_bogus/clusters/cl_bogus")
check_status "DELETE /cluster-groups/{id}/clusters/{clusterId} with no auth" 401 "$status"

status=$(curl -sS -o /dev/null -w "%{http_code}" "$API/api/v1/cluster-groups" -H "Authorization: Bearer $viewer_token")
check_status "viewer allowed GET /cluster-groups -- holds cluster:read (200)" 200 "$status"
status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/cluster-groups" \
  -H "Authorization: Bearer $viewer_token" -H "Content-Type: application/json" -d '{"name":"irrelevant"}')
check_status "viewer denied POST /cluster-groups -- lacks cluster:group:manage (403)" 403 "$status"

SECTION17_GROUP_NAME="smoketest-cluster-group-$(date +%s)-$$"
create_group_resp=$(curl -sS -X POST "$API/api/v1/cluster-groups" \
  -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" \
  -d "{\"name\":\"$SECTION17_GROUP_NAME\"}")
section17_group_id=$(echo "$create_group_resp" | json_field id)
if [[ -n "$section17_group_id" ]]; then
  echo "  PASS: POST /cluster-groups creates a group (super-admin, cluster:group:manage)"
  PASS=$((PASS + 1))
else
  echo "  FAIL: POST /cluster-groups -- response: $create_group_resp"
  FAIL=$((FAIL + 1))
fi

status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/cluster-groups" \
  -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" -d '{"name":"   "}')
check_status "creating a cluster group with a blank name is rejected" 400 "$status"

SECTION17_CLUSTER_ID="cl_smoketestclustergrp00001"
register_smoketest_cluster "$SECTION17_CLUSTER_ID"
docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -v ON_ERROR_STOP=1 >/dev/null <<SQL
DO \$\$
DECLARE org_id text;
BEGIN
  SELECT id INTO org_id FROM organisations LIMIT 1;
  DELETE FROM clusters WHERE id = '$SECTION17_CLUSTER_ID';
  INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
  VALUES ('$SECTION17_CLUSTER_ID', org_id, 'smoketest-clustergroup-cluster', 'Active', 'shard-test', 'fp-$SECTION17_CLUSTER_ID');
END \$\$;
SQL

if [[ -n "$section17_group_id" ]]; then
  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/cluster-groups/$section17_group_id/clusters" \
    -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" -d '{"clusterId":"cl_does_not_exist"}')
  check_status "adding an unknown cluster to a group is rejected" 400 "$status"

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/cluster-groups/clg_does_not_exist/clusters" \
    -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" -d "{\"clusterId\":\"$SECTION17_CLUSTER_ID\"}")
  check_status "adding a cluster to an unknown group is rejected" 404 "$status"

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/cluster-groups/$section17_group_id/clusters" \
    -H "Authorization: Bearer $viewer_token" -H "Content-Type: application/json" -d "{\"clusterId\":\"$SECTION17_CLUSTER_ID\"}")
  check_status "viewer denied POST .../clusters -- lacks cluster:group:manage (403)" 403 "$status"

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/cluster-groups/$section17_group_id/clusters" \
    -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" -d "{\"clusterId\":\"$SECTION17_CLUSTER_ID\"}")
  check_status "adding a real cluster to the group succeeds (201)" 201 "$status"

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/cluster-groups/$section17_group_id/clusters" \
    -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" -d "{\"clusterId\":\"$SECTION17_CLUSTER_ID\"}")
  check_status "adding the same cluster to the group a second time conflicts (409)" 409 "$status"

  list_resp=$(curl -sS "$API/api/v1/cluster-groups" -H "Authorization: Bearer $access_token")
  if echo "$list_resp" | grep -q "$SECTION17_CLUSTER_ID"; then
    echo "  PASS: GET /cluster-groups reflects the new membership (clusterIds includes the added cluster)"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: GET /cluster-groups did not reflect the added membership -- response: $list_resp"
    FAIL=$((FAIL + 1))
  fi

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X DELETE "$API/api/v1/cluster-groups/$section17_group_id" \
    -H "Authorization: Bearer $access_token")
  check_status "DELETE /cluster-groups/{id} is unaffected by membership alone -- only an active grant blocks it (200)" 200 "$status"

  # Re-create the group (deleted above) to test the grant-based in-use guard
  # and remove-membership path independently.
  recreate_group_resp=$(curl -sS -X POST "$API/api/v1/cluster-groups" \
    -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" \
    -d "{\"name\":\"$SECTION17_GROUP_NAME-2\"}")
  section17_group_id=$(echo "$recreate_group_resp" | json_field id)

  curl -sS -X POST "$API/api/v1/cluster-groups/$section17_group_id/clusters" \
    -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" \
    -d "{\"clusterId\":\"$SECTION17_CLUSTER_ID\"}" >/dev/null

  section17_grant_resp=$(curl -sS -X POST "$API/api/v1/users/$TEST_VIEWER_ID/grants" \
    -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" \
    -d "{\"role\":\"viewer\",\"scope\":{\"type\":\"ClusterGroup\",\"clusterGroupId\":\"$section17_group_id\"}}")
  section17_grant_id=$(echo "$section17_grant_resp" | json_field id)

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X DELETE "$API/api/v1/cluster-groups/$section17_group_id" \
    -H "Authorization: Bearer $access_token")
  check_status "DELETE /cluster-groups/{id} refused while a ClusterGroup-scoped grant still references it (409)" 409 "$status"

  if [[ -n "$section17_grant_id" ]]; then
    curl -sS -X DELETE "$API/api/v1/users/$TEST_VIEWER_ID/grants/$section17_grant_id" \
      -H "Authorization: Bearer $access_token" >/dev/null
  fi

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X DELETE "$API/api/v1/cluster-groups/$section17_group_id/clusters/$SECTION17_CLUSTER_ID" \
    -H "Authorization: Bearer $viewer_token")
  check_status "viewer denied DELETE .../clusters/{clusterId} -- lacks cluster:group:manage (403)" 403 "$status"

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X DELETE "$API/api/v1/cluster-groups/$section17_group_id/clusters/$SECTION17_CLUSTER_ID" \
    -H "Authorization: Bearer $access_token")
  check_status "removing the cluster from the group succeeds once the grant is revoked (200)" 200 "$status"

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X DELETE "$API/api/v1/cluster-groups/$section17_group_id/clusters/$SECTION17_CLUSTER_ID" \
    -H "Authorization: Bearer $access_token")
  check_status "removing a cluster that is no longer a member is rejected" 404 "$status"

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X DELETE "$API/api/v1/cluster-groups/$section17_group_id" \
    -H "Authorization: Bearer $access_token")
  check_status "DELETE /cluster-groups/{id} succeeds once membership and grants are both cleared (200)" 200 "$status"

  status=$(curl -sS -o /dev/null -w "%{http_code}" -X DELETE "$API/api/v1/cluster-groups/$section17_group_id" \
    -H "Authorization: Bearer $access_token")
  check_status "DELETE /cluster-groups/{id} on an already-deleted id is rejected" 404 "$status"
fi

echo "== 18. Promotion reconciliation (POST /api/v1/incidents/reconcile-promotion -- incident:triage) =="
# internal/api/incident_promotion_reconcile.go. Migration 000092 drew the
# evidence boundary for new findings and deliberately left historical incident
# state alone, so incidents raised before it sit in the queue forever on
# evidence the hub would no longer promote. This closes them, through
# orchestrator.SetState, without touching a single findings row.
#
# Everything below is deliberately read-only: this section NEVER sends
# {"apply": true}. A smoke run must not close a developer's real incidents as
# a side effect of asserting that the route exists. The applying half is
# covered against a real Postgres by
# internal/api/incident_promotion_reconcile_db_test.go instead, which can build
# its own throwaway cluster and clean it up.

status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/incidents/reconcile-promotion" \
  -H "Authorization: Bearer $viewer_token" -H "Content-Type: application/json" -d '{}')
check_status "viewer denied POST /incidents/reconcile-promotion -- lacks incident:triage (403)" 403 "$status"

# A bulk close of incidents nobody reviewed must carry a reason somebody can
# audit, exactly as dismissing one incident by hand does. Rejected before
# anything is read, let alone written.
status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/incidents/reconcile-promotion" \
  -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" -d '{"apply": true}')
check_status "apply without a note is rejected (400)" 400 "$status"

reconcile_resp=$(curl -sS -X POST "$API/api/v1/incidents/reconcile-promotion" \
  -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" -d '{}')
reconcile_file=$(json_arg_file "$reconcile_resp")
python3 - "$reconcile_file" <<'PYEOF' && { echo "  PASS: dry run reports candidates and closes nothing"; PASS=$((PASS + 1)); } || { echo "  FAIL: dry run response was wrong -- $reconcile_resp"; FAIL=$((FAIL + 1)); }
import json, sys
r = json.load(open(sys.argv[1]))
# The default is a preview. A body that never said "apply" must never change
# anything, and the response has to say so rather than leave it inferred.
assert r["applied"] is False, r
assert r["closed"] == 0, r
assert isinstance(r["candidates"], int), r
assert isinstance(r["incidentsWithFindings"], int), r
# Every listed candidate is a preview entry: not closed, and carrying the
# evidence a reader needs to check the verdict rather than trust the count.
for inc in r["incidents"]:
    assert inc["closed"] is False, inc
    assert inc["findings"] > 0, inc
    assert inc["findingReasons"], inc
PYEOF
rm -f "$reconcile_file"

# Cleanup -- sections 16/17's shared viewer/tenant-admin fixture and the
# throwaway cluster row, none of which are application state worth keeping.
docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U postgres -d argus -v ON_ERROR_STOP=1 >/dev/null <<SQL
DELETE FROM refresh_tokens WHERE user_id IN ('$TEST_VIEWER_ID', '$TEST_TENANT_ADMIN_ID');
DELETE FROM grants WHERE principal_id IN ('$TEST_VIEWER_ID', '$TEST_TENANT_ADMIN_ID');
DELETE FROM users WHERE id IN ('$TEST_VIEWER_ID', '$TEST_TENANT_ADMIN_ID');
DELETE FROM cluster_group_members WHERE cluster_id = '$SECTION17_CLUSTER_ID';
SQL

# PROJECT.md B175. Called here rather than left to the EXIT trap alone so the
# result lands INSIDE the summary below — a cleanup nobody sees the verdict of
# is how this script leaked 171 clusters without anyone noticing. The trap
# still calls it, for the runs that never reach this line; the second call is
# a no-op.
echo "== 19. Cleanup (this run's own throwaway clusters) =="
cleanup_smoketest_clusters

echo ""
echo "================================================================"
echo " $PASS passed, $FAIL failed"
echo "================================================================"
[[ "$FAIL" -eq 0 ]]
